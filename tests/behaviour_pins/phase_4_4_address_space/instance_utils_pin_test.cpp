// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (instance_utils navigation primitives).
//
// authorising this file. IU pins lock the public *_async navigation/
// type-check primitives that build on AddressSpace + Node:
//
//   - find_child_id_by_browse_name_async (IU-A/B/C)
//   - find_child_method_accessor_by_browse_name_async (IU-D)
//   - find_child_variable_accessor_by_browse_name_async (IU-E)
//   - attach_exact_async (IU-F/G)
//   - attach_subtype_async (IU-H/I) - multi-hop HasSubtype walk
//   - read_variable_value_async (IU-J/K)
//
// Most pins drive against the production default_ns Namespace (parent + child
// real Nodes) - find_node and get_references complete inline on the calling
// thread, so std::promise + future on the main test thread is sufficient.
// IU-C / IU-H / IU-I / IU-K use FakeAsyncNamespace to either inject staged
// failures (IU-C, IU-K) or record per-iteration find_node invocations during
// the HasSubtype walk (IU-H, IU-I).
//
// Forbidden tokens (per runbook section 4): no `_coro\b`, no `Task<`, no
// `await_callback`. The IU pins drive *_async only.

#include <future>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "fake_async_namespace.h"
#include "fake_node.h"

#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_instance_utils.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"

namespace ua::test::behaviour_pins
{
namespace
{

class InstanceUtilsPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mAddressSpace = std::make_unique<AddressSpace>(
      AddressSpace::create(String{"urn:test:instance-utils:pin"}, mPool->executor()));
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

  // Create a real default_ns node and return its accessor.
  NodeAccessor create_real_node(const NodeId& id, NodeClass nodeClass)
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      id, nodeClass, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    auto result = p.get_future().get();
    EXPECT_TRUE(result.is_good()) << "precondition: create_node_async failed; status 0x" << std::hex
                                  << result.status_code().as_uint32();
    return result.value();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

}  // namespace

// ---------------------------------------------------------------------------
// IU-A - find_child_id_by_browse_name_async returns BadNodeIdUnknown + detail
//        when no child carries the searched browse name.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression at ua_instance_utils.cpp:209-212 that
// drops the BadNodeIdUnknown detail (or that returns Good with a default
// NodeId on iteration exhaustion) is caught by the status + non-null detail
// assertions.

TEST_F(InstanceUtilsPin, FindChildIdByBrowseNameReturnsBadNodeIdUnknownWhenNoMatch)
{
  const NodeId parentId{/*namespaceIndex=*/1u, std::string_view{"iu-a:parent"}};
  const NodeId childAId{/*namespaceIndex=*/1u, std::string_view{"iu-a:child-a"}};
  const NodeId childBId{/*namespaceIndex=*/1u, std::string_view{"iu-a:child-b"}};

  auto parent = create_real_node(parentId, NodeClass::Object);
  auto childA = create_real_node(childAId, NodeClass::Variable);
  auto childB = create_real_node(childBId, NodeClass::Variable);

  childA.set_browse_name(QualifiedName{0u, std::string_view{"A"}});
  childB.set_browse_name(QualifiedName{0u, std::string_view{"B"}});

  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{childAId},
    /*isForward=*/true);
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{childBId},
    /*isForward=*/true);

  std::promise<NodeIdResult> p;
  ua::instance_utils::find_child_id_by_browse_name_async(*mAddressSpace,
    parentId,
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{0u, std::string_view{"C"}},
    [&p](NodeIdResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr) << "iteration-exhausted failure must carry a detail";
  EXPECT_EQ(result.shared_detail()->source, "find_child_id_by_browse_name_async");
}

// ---------------------------------------------------------------------------
// IU-B - find_child_id_by_browse_name_async forwards parent-lookup failure
//        with status + ErrorDetail (lossless).
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression at ua_instance_utils.cpp:146-148 that
// drops the parent's shared_detail() (lossy substitution) breaks the
// "ErrorDetail propagation is highest priority" rule. The pin
// asserts pointer identity on the AddressSpace's NamespaceNotFound detail.

TEST_F(InstanceUtilsPin, FindChildIdByBrowseNamePropagatesParentLookupFailure)
{
  const NodeId unknownNsParent{/*namespaceIndex=*/99u, std::string_view{"iu-b:no-such-parent"}};

  std::promise<NodeIdResult> p;
  ua::instance_utils::find_child_id_by_browse_name_async(*mAddressSpace,
    unknownNsParent,
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{0u, std::string_view{"X"}},
    [&p](NodeIdResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "AddressSpace");
  EXPECT_EQ(result.shared_detail()->code, "NamespaceNotFound");
}

// ---------------------------------------------------------------------------
// IU-C - find_child_id_by_browse_name_async forwards a bad get_references
//        from the parent with status + ErrorDetail (pointer identity).
// ---------------------------------------------------------------------------
//
// Setup: a FakeAsyncNamespace returns a FakeNode parent and answers the read
// of its References with a staged failure. The flow's on_references_fetched at
// ua_instance_utils.cpp:173-176 must forward the bad status + detail.

TEST_F(InstanceUtilsPin, FindChildIdByBrowseNamePropagatesGetReferencesFailure)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:iu-c:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 0u);

  const NodeId parentId{fakeIndex, std::string_view{"iu-c:parent"}};
  auto fakeParent = std::make_shared<FakeNode>(parentId, NodeClass::Object);

  auto stagedDetail = make_error_detail("IuCStub", "stubbed by IU-C", "FakeNode");
  std::shared_ptr<const ErrorDetail> stagedDetailPtr{std::move(stagedDetail)};
  fakeNs->set_next_get_references(
    parentId, NodeAccessor::ReferencesResult{StatusCode{Status::BadInternalError}, stagedDetailPtr});

  // Inline mode: the lookup answers the FakeNode inline. The flow then reads
  // the parent's References, which the fake answers inline with the staged
  // failure.
  fakeNs->set_next_find_node_result(NodeResult{std::shared_ptr<Node>{fakeParent}});

  std::promise<NodeIdResult> p;
  ua::instance_utils::find_child_id_by_browse_name_async(*mAddressSpace,
    parentId,
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{0u, std::string_view{"X"}},
    [&p](NodeIdResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadInternalError);
  // Lossless propagation (pointer identity).
  EXPECT_EQ(result.shared_detail(), stagedDetailPtr);
}

// ---------------------------------------------------------------------------
// IU-D - find_child_method_accessor_by_browse_name_async returns
//        BadTypeMismatch when the resolved child is a Variable.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression at ua_instance_utils.cpp:1077-1085 that
// returns the NodeAccessor as a default-constructed MethodAccessor without
// the as<MethodAccessor>() check would yield a dangerous typed accessor
// against a Variable Node.

TEST_F(InstanceUtilsPin, FindChildMethodAccessorReturnsBadTypeMismatchOnVariableChild)
{
  const NodeId parentId{/*namespaceIndex=*/1u, std::string_view{"iu-d:parent"}};
  const NodeId variableChildId{/*namespaceIndex=*/1u, std::string_view{"iu-d:variable-op"}};

  auto parent = create_real_node(parentId, NodeClass::Object);
  auto variableChild = create_real_node(variableChildId, NodeClass::Variable);
  variableChild.set_browse_name(QualifiedName{0u, std::string_view{"Op"}});
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{variableChildId},
    /*isForward=*/true);

  std::promise<MethodAccessorResult> p;
  ua::instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    parentId,
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{0u, std::string_view{"Op"}},
    [&p](MethodAccessorResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadTypeMismatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "find_child_method_accessor_by_browse_name_async");
}

// ---------------------------------------------------------------------------
// IU-E - find_child_variable_accessor_by_browse_name_async returns
//        BadTypeMismatch when the resolved child is a Method.
// ---------------------------------------------------------------------------
//
// Bug this would catch: same shape as IU-D, but for VariableAccessor casts.

TEST_F(InstanceUtilsPin, FindChildVariableAccessorReturnsBadTypeMismatchOnMethodChild)
{
  const NodeId parentId{/*namespaceIndex=*/1u, std::string_view{"iu-e:parent"}};
  const NodeId methodChildId{/*namespaceIndex=*/1u, std::string_view{"iu-e:method-op"}};

  auto parent = create_real_node(parentId, NodeClass::Object);
  auto methodChild = create_real_node(methodChildId, NodeClass::Method);
  methodChild.set_browse_name(QualifiedName{0u, std::string_view{"Op"}});
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{methodChildId},
    /*isForward=*/true);

  std::promise<VariableAccessorResult> p;
  ua::instance_utils::find_child_variable_accessor_by_browse_name_async(*mAddressSpace,
    parentId,
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{0u, std::string_view{"Op"}},
    [&p](VariableAccessorResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadTypeMismatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "find_child_variable_accessor_by_browse_name_async");
}

// ---------------------------------------------------------------------------
// IU-F - attach_exact_async rejects a type-definition mismatch with
//        BadTypeMismatch + ErrorDetail.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression at ua_instance_utils.cpp:558-564 that
// drops the equality check (always returning Good) silently weakens the
// "exact type-def required" contract. The pin asserts the bad path.

TEST_F(InstanceUtilsPin, AttachExactRejectsTypeDefinitionMismatch)
{
  const NodeId existingId{/*namespaceIndex=*/1u, std::string_view{"iu-f:existing"}};
  const NodeId typeT1{/*namespaceIndex=*/1u, std::string_view{"iu-f:T1"}};
  const NodeId typeT2{/*namespaceIndex=*/1u, std::string_view{"iu-f:T2"}};

  auto existing = create_real_node(existingId, NodeClass::Object);
  create_real_node(typeT1, NodeClass::ObjectType);
  create_real_node(typeT2, NodeClass::ObjectType);
  existing.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
    ExpandedNodeId{typeT1},
    /*isForward=*/true);

  std::promise<VoidResult> p;
  ua::instance_utils::attach_exact_async(
    *mAddressSpace, existingId, typeT2, [&p](VoidResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadTypeMismatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "attach_exact_async");
}

// ---------------------------------------------------------------------------
// IU-G - attach_exact_async returns Good on a type-definition match.
// ---------------------------------------------------------------------------
//
// Falsifiability counterpart to IU-F: ensures the success branch actually
// fires Good (a regression that always returns BadTypeMismatch would be
// caught by IU-G but not IU-F).

TEST_F(InstanceUtilsPin, AttachExactReturnsGoodOnTypeDefinitionMatch)
{
  const NodeId existingId{/*namespaceIndex=*/1u, std::string_view{"iu-g:existing"}};
  const NodeId typeT1{/*namespaceIndex=*/1u, std::string_view{"iu-g:T1"}};

  auto existing = create_real_node(existingId, NodeClass::Object);
  create_real_node(typeT1, NodeClass::ObjectType);
  existing.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
    ExpandedNodeId{typeT1},
    /*isForward=*/true);

  std::promise<VoidResult> p;
  ua::instance_utils::attach_exact_async(
    *mAddressSpace, existingId, typeT1, [&p](VoidResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_good()) << "matching type-def must yield VoidResult Good; got 0x" << std::hex
                                << result.status_code().as_uint32();
}

// ---------------------------------------------------------------------------
// IU-H - attach_subtype_async walks the HasSubtype chain and succeeds when
//        baseTypeDef is reachable as a supertype of the existing node's
//        type definition.
// ---------------------------------------------------------------------------
//
// Setup: existing.HasTypeDefinition forward -> NodeId{fakeIdx, "Child"}.
// realChildType (default_ns) carries HasSubtype inverse ->
// NodeId{fakeIdx, "Base"}. fake stages one find_node result returning the
// real-ns ChildType accessor; the next walk_step iteration sees
// currentTypeId == baseTypeDef and completes without a second find_node hop.
//
// Bug this would catch: a regression that always equates currentTypeId
// directly without iterating (e.g. a missing recursive walk_step call after
// reading parentType) would leave currentTypeId at "Child" and either
// loop forever or fail mismatch. Asserting Good + at least one fake
// find_node call locks the iteration.

TEST_F(InstanceUtilsPin, AttachSubtypeWalksHasSubtypeChain)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:iu-h:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 0u);

  const NodeId existingId{/*namespaceIndex=*/1u, std::string_view{"iu-h:existing"}};
  const NodeId childTypeId{fakeIndex, std::string_view{"iu-h:Child"}};
  const NodeId baseTypeId{fakeIndex, std::string_view{"iu-h:Base"}};
  const NodeId realChildTypeId{/*namespaceIndex=*/1u, std::string_view{"iu-h:real-child-type"}};

  // existing in default_ns; HasTypeDefinition forward to childTypeId (in fake).
  auto existing = create_real_node(existingId, NodeClass::Object);
  existing.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
    ExpandedNodeId{childTypeId},
    /*isForward=*/true);

  // Real default_ns ChildType; HasSubtype inverse -> baseTypeId (in fake). The address space looks the
  // supertype up to check a HasSubtype between VariableTypes (NR-52); the fake answers that it has no such
  // Node.
  auto realChildType = create_real_node(realChildTypeId, NodeClass::ObjectType);
  fakeNs->set_next_find_node_result(NodeResult{StatusCode{Status::BadNodeIdUnknown}});
  realChildType.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype},
    ExpandedNodeId{baseTypeId},
    /*isForward=*/false);

  // Fake stages exactly one find_node - for childTypeId, returning
  // realChildType. The walker then reads HasSubtype inverse -> baseTypeId,
  // sees currentTypeId == baseTypeDef, and completes without a second
  // find_node hop into the fake.
  fakeNs->set_next_find_node_result(NodeResult{realChildType->shared_from_this()});
  // Calls the fake recorded while the References above were added precede the walker's.
  const std::size_t setupCalls = fakeNs->recorded_calls().size();

  std::promise<VoidResult> p;
  ua::instance_utils::attach_subtype_async(
    *mAddressSpace, existingId, baseTypeId, [&p](VoidResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_good()) << "Child-extends-Base chain must complete Good; got 0x" << std::hex
                                << result.status_code().as_uint32();

  auto recorded = fakeNs->recorded_calls();
  ASSERT_GE(recorded.size(), setupCalls + 1u)
    << "walker must call find_node into the fake at least once (Child resolution)";
  EXPECT_EQ(recorded[setupCalls].op, FakeAsyncNamespace::Op::FindNode);
  EXPECT_EQ(recorded[setupCalls].nodeId, childTypeId);
}

// ---------------------------------------------------------------------------
// IU-I - attach_subtype_async returns BadTypeMismatch when the existing
//        node's type definition does not reach baseTypeDef along the
//        HasSubtype chain.
// ---------------------------------------------------------------------------
//
// Setup: existing.HasTypeDefinition forward -> NodeId{fakeIdx, "Child"}.
// realChildType has NO HasSubtype reference - the walker fetches its
// references, finds no HasSubtype inverse, and calls mismatch().

TEST_F(InstanceUtilsPin, AttachSubtypeReturnsBadTypeMismatchOnMissingChain)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:iu-i:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 0u);

  const NodeId existingId{/*namespaceIndex=*/1u, std::string_view{"iu-i:existing"}};
  const NodeId childTypeId{fakeIndex, std::string_view{"iu-i:Child"}};
  const NodeId baseTypeId{fakeIndex, std::string_view{"iu-i:Base"}};
  const NodeId realChildTypeId{/*namespaceIndex=*/1u, std::string_view{"iu-i:real-child-type"}};

  auto existing = create_real_node(existingId, NodeClass::Object);
  existing.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
    ExpandedNodeId{childTypeId},
    /*isForward=*/true);

  // ChildType has NO HasSubtype reference - walker exits with mismatch.
  auto realChildType = create_real_node(realChildTypeId, NodeClass::ObjectType);

  fakeNs->set_next_find_node_result(NodeResult{realChildType->shared_from_this()});

  std::promise<VoidResult> p;
  ua::instance_utils::attach_subtype_async(
    *mAddressSpace, existingId, baseTypeId, [&p](VoidResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadTypeMismatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "attach_subtype_async");
}

// ---------------------------------------------------------------------------
// IU-J - read_variable_value_async rejects a non-Variable target with
//        BadTypeMismatch + ErrorDetail.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression at ua_instance_utils.cpp:636-642 that
// drops the as<VariableAccessor>() guard would attempt read_value_async on
// a Method node, undefined behaviour. Asserting BadTypeMismatch + detail
// catches it.

TEST_F(InstanceUtilsPin, ReadVariableValueRejectsNonVariableNode)
{
  const NodeId methodId{/*namespaceIndex=*/1u, std::string_view{"iu-j:method"}};
  create_real_node(methodId, NodeClass::Method);

  std::promise<DataValueResult> p;
  ua::instance_utils::read_variable_value_async(
    *mAddressSpace, methodId, [&p](DataValueResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadTypeMismatch);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "read_variable_value_async");
}

// ---------------------------------------------------------------------------
// IU-K - read_variable_value_async fails when the underlying read returns a
//        DataValue with a bad status, surfacing the DataValue's status.
// ---------------------------------------------------------------------------
//
// Setup: a FakeAsyncNamespace returns a FakeNode (Variable class) and
// answers the read of its Value with a staged Result-Good DataValue whose
// own status() is BadCommunicationError. The flow at
// ua_instance_utils.cpp:677-683 must surface that status with a detail.

TEST_F(InstanceUtilsPin, ReadVariableValueRejectsBadDataValueStatus)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:iu-k:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 0u);

  const NodeId variableId{fakeIndex, std::string_view{"iu-k:variable"}};
  auto fakeVariable = std::make_shared<FakeNode>(variableId, NodeClass::Variable);

  // DataValue carrying a bad status - Result-level is Good (so the wrapper
  // progresses past the is_bad() check) but the value's own status
  // signals BadCommunicationError.
  DataValue badDv{Variant{int32_t{0}}, StatusCode{Status::BadCommunicationError}};
  fakeNs->set_next_read_value(variableId, DataValueResult{badDv});

  fakeNs->set_next_find_node_result(NodeResult{std::shared_ptr<Node>{fakeVariable}});

  std::promise<DataValueResult> p;
  ua::instance_utils::read_variable_value_async(
    *mAddressSpace, variableId, [&p](DataValueResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadCommunicationError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->source, "read_variable_value_async");
}

}  // namespace ua::test::behaviour_pins
