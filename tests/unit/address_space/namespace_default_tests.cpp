// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include <fmt/core.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <latch>
#include <optional>
#include <string_view>
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_result.h"
#include "ua_default_namespace.h"
#include "ua_default_object_node.h"
#include "ua_default_variable_node.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_node_accessor.h"
#include "ua_localized_text.h"
#include "ua_log_level.h"
#include "ua_log_entry.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_namespace_items.h"
#include "ua_node_class.h"
#include "ua_node_description.h"
#include "ua_node_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_reference.h"
#include "ua_request_info.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_node_utilities.h"
#include "ua_encoding_limits.h"
#include "ua_variant.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include "ua_write_value.h"
#include <future>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

// API-6.1: a namespace's default access is always stated. There is no one-argument create_namespace, so
// `create_namespace(uri)` does not compile; granting nothing is written `create_namespace(uri, {})`.
template<class Space>
concept CreatesANamespaceFromItsUriAlone =
  requires(Space& space, std::string_view uri) { space.create_namespace(uri); };
static_assert(
  !CreatesANamespaceFromItsUriAlone<ua::AddressSpace>, "create_namespace must take the default access");
static_assert(
  requires(ua::AddressSpace& space, std::string_view uri) { space.create_namespace(uri, {}); },
  "create_namespace(uri, {}) grants nothing and must compile");

using namespace ua;

TEST(NamespaceDefaultTests, FindNode)
{
  boost::asio::thread_pool tp{1};
  auto ns = default_ns::Namespace::create("uri://my-namespace", tp.get_executor());
  NodeId nodeId{123};
  ns->create_node(nodeId, NodeClass::Object);

  // An in-memory namespace never declines: the answer is engaged, and good.
  const auto result = ns->find_node(nodeId, std::nullopt);
  ASSERT_TRUE(result.has_value()) << "an in-memory namespace has nothing to go away for";
  GTEST_ASSERT_TRUE(result->is_good());
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.6 and Part 4 section 5.7.2.2: a View has no TypeDefinitionNode from which to inherit
// mandatory Attribute values, so the default namespace must expose suitable defaults immediately
// at creation. EventNotifier is the paired control because its accessor already projects zero for
// an unset stored value; ContainsNoLoops must be equally readable rather than throwing on empty.
// @relation(AC-SVR-ADDRSP-018-MANDATORY-ATTRIBUTES-VALUED, scope=function)
TEST(NamespaceDefaultTests, NewViewDefaultsContainsNoLoopsAndEventNotifierAtCreation)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("urn:test:view-defaults", threadPool.get_executor());

  auto created = addressSpace.try_create_node_sync(NodeId{1, "fresh-view"}, NodeClass::View, {});
  ASSERT_TRUE(created.is_good());
  auto view = created.value().as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());

  EXPECT_FALSE(view->get_contains_no_loops());
  EXPECT_EQ(view->get_event_notifier().as_underlying_type(), 0u);

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A freshly materialised node is already an instance of its reported NodeClass. Mandatory
// class-specific Attributes therefore need concrete wire values before the node is published, even
// when the caller supplies no InitialAttributes. BaseDataType supplies VariableType DataType;
// CurrentRead and CurrentWrite preserve the fresh Variable value-source contract, and the remaining
// defaults are conservative false values.
// @relation(AC-SVR-ADDRSP-018-MANDATORY-ATTRIBUTES-VALUED, scope=function)
TEST(NamespaceDefaultTests, FreshNodesSeedMandatoryClassAttributeDefaultsBeforePublication)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace =
    AddressSpace::create("urn:test:mandatory-attribute-defaults", threadPool.get_executor());

  auto variableResult =
    addressSpace.try_create_node_sync(NodeId{1, "fresh-variable"}, NodeClass::Variable, {});
  ASSERT_TRUE(variableResult.is_good());
  const auto variable = variableResult.value().as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  EXPECT_TRUE(variable->get_access_level().test(AccessLevelType::Bit::CurrentRead));
  EXPECT_TRUE(variable->get_access_level().test(AccessLevelType::Bit::CurrentWrite));

  auto variableTypeResult =
    addressSpace.try_create_node_sync(NodeId{1, "fresh-variable-type"}, NodeClass::VariableType, {});
  ASSERT_TRUE(variableTypeResult.is_good());
  const auto variableType = variableTypeResult.value().as<VariableTypeAccessor>();
  ASSERT_TRUE(variableType.has_value());
  EXPECT_EQ(variableType->get_data_type(), NodeId{DataTypeId::BaseDataType});
  EXPECT_FALSE(variableType->get_is_abstract());

  auto objectTypeResult =
    addressSpace.try_create_node_sync(NodeId{1, "fresh-object-type"}, NodeClass::ObjectType, {});
  ASSERT_TRUE(objectTypeResult.is_good());
  const auto objectType = objectTypeResult.value().as<ObjectTypeAccessor>();
  ASSERT_TRUE(objectType.has_value());
  EXPECT_FALSE(objectType->get_is_abstract());

  auto referenceTypeResult =
    addressSpace.try_create_node_sync(NodeId{1, "fresh-reference-type"}, NodeClass::ReferenceType, {});
  ASSERT_TRUE(referenceTypeResult.is_good());
  const auto referenceType = referenceTypeResult.value().as<ReferenceTypeAccessor>();
  ASSERT_TRUE(referenceType.has_value());
  EXPECT_FALSE(referenceType->get_is_abstract());
  EXPECT_FALSE(referenceType->get_symmetric());

  auto dataTypeResult =
    addressSpace.try_create_node_sync(NodeId{1, "fresh-data-type"}, NodeClass::DataType, {});
  ASSERT_TRUE(dataTypeResult.is_good());
  const auto dataType = dataTypeResult.value().as<DataTypeAccessor>();
  ASSERT_TRUE(dataType.has_value());
  EXPECT_FALSE(dataType->get_is_abstract());

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-DIAG-012-NAMESPACE-MUTATOR-DETAIL, scope=function)
TEST(NamespaceDefaultTests, DeleteMissingNodeBuildsRichBadNodeIdUnknown)
{
  boost::asio::thread_pool threadPool{1};
  constexpr string_view namespaceUri{"urn:test:namespace-delete-detail"};
  auto namespaceInstance = default_ns::Namespace::create(namespaceUri, threadPool.get_executor());

  const NodeId presentId{0, "present"};
  const NodeId absentId{0, "absent"};
  ASSERT_NE(namespaceInstance->create_node(presentId, NodeClass::Object), nullptr);
  ASSERT_TRUE(namespaceInstance->delete_node(presentId, false).is_good())
    << "control: deleting a node owned by the namespace must succeed";

  const auto result = namespaceInstance->delete_node(absentId, false);
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNodeIdUnknown});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NodeNotFound");
  EXPECT_EQ(result.shared_detail()->summary, "Node does not exist in namespace");
  EXPECT_EQ(result.shared_detail()->source, "DefaultNamespace");
  ASSERT_EQ(result.shared_detail()->context.size(), 2u);
  EXPECT_EQ(result.shared_detail()->context[0].key, ContextKeys::nodeId.value());
  EXPECT_EQ(result.shared_detail()->context[0].value, to_string(absentId));
  EXPECT_EQ(result.shared_detail()->context[1].key, ContextKeys::namespaceUri.value());
  EXPECT_EQ(result.shared_detail()->context[1].value, namespaceUri);

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Helper: check whether a node has a reference with the given type and target.
static bool has_reference(
  const NodeAccessor& accessor, const NodeId& refType, const NodeId& targetId, bool isForward)
{
  auto refs = accessor.get_references_sync();
  for (const auto& ref : refs)
  {
    if (ref.type_id() == refType && ref.target_id() == ExpandedNodeId{targetId} &&
        ref.is_forward() == isForward)
    {
      return true;
    }
  }
  return false;
}

// @relation(AC-SVR-ADDRSP-253-IRDI-NOT-REASSIGNED, scope=function)
// @relation(AC-SVR-ADDRSP-256-URI-NOT-REASSIGNED, scope=function)
TEST(NamespaceDefaultTests, OrdinaryDeletedNodeIdRemainsReusable)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("urn:test:ordinary-reuse", threadPool.get_executor());
  const NodeId nodeId{1u, "ordinary-node"};
  ASSERT_TRUE(addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {}).is_good());
  ASSERT_TRUE(addressSpace.try_delete_node_sync(nodeId, false).is_good());

  EXPECT_TRUE(addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {}).is_good());
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// P3.a - BaseNode batch reference-add (add_references) + shared empty-ref sentinel.
//
// add_references adds a whole batch in one vector clone (the fast path adopts the batch directly when
// the node has no references yet) instead of cloning the reference vector once per add. These pin the
// observable behaviour: the batch lands in full, appends to an existing set, and - critically - the
// shared empty sentinel that fresh nodes start on is never mutated in place.

TEST(NamespaceDefaultTests, AddReferencesBatchAdoptedByFreshNode)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  const NodeId nodeId{1, "no-refs:fresh"};
  const NodeId targetA{1, "no-refs:targetA"};
  const NodeId targetB{1, "no-refs:targetB"};
  auto created = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  const NodeId hasProperty{ReferenceTypeId::HasProperty};

  const auto baseline = created.value().get_references_sync().size();

  std::vector<Reference> batch;
  batch.emplace_back(hasComponent, ExpandedNodeId{targetA}, /*isForward=*/true);
  batch.emplace_back(hasProperty, ExpandedNodeId{targetB}, /*isForward=*/true);
  created.value().add_references_sync(std::move(batch));

  EXPECT_EQ(created.value().get_references_sync().size(), baseline + 2);
  EXPECT_TRUE(has_reference(created.value(), hasComponent, targetA, true));
  EXPECT_TRUE(has_reference(created.value(), hasProperty, targetB, true));

  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, AddReferenceValuePreservesRemoteTargetDisplayNameMetadata)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto created = addressSpace.try_create_node_sync(NodeId{1, "remote-ref:source"}, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());

  const ExpandedNodeId remoteTarget{NodeId{5, 4242}, "urn:test:remote-target", /*serverIndex=*/1u};
  const Reference reference{NodeId{ReferenceTypeId::HasComponent},
    remoteTarget,
    /*isForward=*/true,
    LocalizedText{"", "Remote component"}};
  created.value().add_reference_sync(reference);

  const auto references = created.value().get_references_sync();
  const auto found = std::ranges::find(references, reference);
  ASSERT_NE(found, references.end());
  ASSERT_TRUE(found->target_display_name().has_value());
  EXPECT_EQ(found->target_display_name()->text(), "Remote component");

  const Reference renamed{NodeId{ReferenceTypeId::HasComponent},
    remoteTarget,
    /*isForward=*/true,
    LocalizedText{"", "Different presentation"}};
  EXPECT_EQ(reference, renamed) << "presentation metadata is not part of reference identity";

  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, AddReferencesBatchAppendsToNonEmptyNode)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  const NodeId nodeId{1, "append:node"};
  const NodeId targetFirst{1, "append:first"};
  const NodeId targetSecond{1, "append:second"};
  const NodeId targetThird{1, "append:third"};
  auto created = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
  ASSERT_TRUE(created.is_good());
  const NodeId hasComponent{ReferenceTypeId::HasComponent};

  const auto baseline = created.value().get_references_sync().size();

  // Seed one reference so the node is non-empty (forces the clone-and-append path, not the fast path).
  created.value().add_reference_sync(hasComponent, targetFirst, /*isForward=*/true);

  std::vector<Reference> batch;
  batch.emplace_back(hasComponent, ExpandedNodeId{targetSecond}, /*isForward=*/true);
  batch.emplace_back(hasComponent, ExpandedNodeId{targetThird}, /*isForward=*/true);
  created.value().add_references_sync(std::move(batch));

  EXPECT_EQ(created.value().get_references_sync().size(), baseline + 3);
  EXPECT_TRUE(has_reference(created.value(), hasComponent, targetFirst, true));
  EXPECT_TRUE(has_reference(created.value(), hasComponent, targetSecond, true));
  EXPECT_TRUE(has_reference(created.value(), hasComponent, targetThird, true));

  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, FreshNodesDoNotShareReferenceStateViaSentinel)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  // Two freshly-created nodes both start on the shared empty-reference sentinel. Mutating one must
  // not leak into the other - if add_references mutated the sentinel in place instead of
  // copy-on-write, node B would observe node A's reference.
  const NodeId nodeA{1, "sentinel:A"};
  const NodeId nodeB{1, "sentinel:B"};
  const NodeId target{1, "sentinel:target"};
  auto createdA = addressSpace.try_create_node_sync(nodeA, NodeClass::Object, {});
  auto createdB = addressSpace.try_create_node_sync(nodeB, NodeClass::Object, {});
  ASSERT_TRUE(createdA.is_good());
  ASSERT_TRUE(createdB.is_good());
  const NodeId hasComponent{ReferenceTypeId::HasComponent};

  const auto bCountBefore = createdB.value().get_references_sync().size();

  std::vector<Reference> batch;
  batch.emplace_back(hasComponent, ExpandedNodeId{target}, /*isForward=*/true);
  createdA.value().add_references_sync(std::move(batch));

  EXPECT_TRUE(has_reference(createdA.value(), hasComponent, target, true));
  EXPECT_EQ(createdB.value().get_references_sync().size(), bCountBefore)
    << "mutating node A must not change node B (shared empty sentinel must be copy-on-write)";
  EXPECT_FALSE(has_reference(createdB.value(), hasComponent, target, true));

  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, DeleteNodeCleansUpCrossNamespaceInverseReferences)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  // AddressSpace::create sets up:
  //   namespace 0 = NamespaceZero (OPC UA core)
  //   namespace 1 = application namespace ("urn:test")
  // Add a second application namespace at index 2.
  auto ns2 = default_ns::Namespace::create("urn:other", tp.get_executor());
  auto ns2Index = addressSpace.add_namespace_sync(ns2);
  ASSERT_EQ(ns2Index, 2);

  // Create a parent node in namespace 1 and a child node in namespace 2.
  const NodeId parentId{1, "parent"};
  const NodeId childId{2, "child"};

  auto parentResult = addressSpace.try_create_node_sync(parentId, NodeClass::Object, {});
  ASSERT_TRUE(parentResult.is_good());
  auto childResult = addressSpace.try_create_node_sync(childId, NodeClass::Object, {});
  ASSERT_TRUE(childResult.is_good());

  const NodeId hasComponent{ReferenceTypeId::HasComponent};

  // Add a forward HasComponent reference from parent -> child.
  parentResult.value().add_reference_sync(hasComponent, childId, /*isForward=*/true);
  // Add the inverse reference on the child back to the parent.
  childResult.value().add_reference_sync(hasComponent, parentId, /*isForward=*/false);

  // Verify both references exist.
  ASSERT_TRUE(has_reference(parentResult.value(), hasComponent, childId, true));
  ASSERT_TRUE(has_reference(childResult.value(), hasComponent, parentId, false));

  // Delete the parent node (namespace 1) with deleteForwardHierarchicalRefs=true.
  addressSpace.delete_node_sync(parentId, /*deleteForwardHierarchicalRefs=*/true);

  // Parent should be gone.
  ASSERT_TRUE(addressSpace.try_find_node_sync(parentId).is_bad());

  // Child should still exist.
  auto childAfter = addressSpace.try_find_node_sync(childId);
  ASSERT_TRUE(childAfter.is_good());

  // The inverse reference from child -> parent should have been cleaned up.
  EXPECT_FALSE(has_reference(childAfter.value(), hasComponent, parentId, false));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Deleting a node reports each Reference it held to a Node of another namespace, and the address space
// removes the other half there; a half already gone answers Uncertain_ReferenceNotDeleted. No reference to
// the deleted node is left, so nothing is wrong and nothing may be logged as wrong. A Session's diagnostics
// nodes are deleted this way whenever a Session closes.
TEST(NamespaceDefaultTests, DeletingANodeWithACrossNamespaceReferenceLogsNoDanglingReference)
{
  class WarningSink final : public LogSink
  {
  public:
    void log(const LogEntry& entry) override
    {
      if (entry.level < LogLevel::Warning)
        return;
      const std::lock_guard lock(mMutex);
      mWarnings += "\n  " + entry.message;
    }

    std::string warnings() const
    {
      const std::lock_guard lock(mMutex);
      return mWarnings;
    }

  private:
    mutable std::mutex mMutex;
    std::string mWarnings;
  };

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());
  auto sink = std::make_shared<WarningSink>();
  addressSpace.set_logger(Logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Debug), "test"});
  ASSERT_EQ(
    addressSpace.add_namespace_sync(default_ns::Namespace::create("urn:other", tp.get_executor())), 2);

  const NodeId parentId{1, "parent"};
  const NodeId childId{2, "child"};
  auto parent = addressSpace.try_create_node_sync(parentId, NodeClass::Object, {});
  ASSERT_TRUE(parent.is_good());
  auto child = addressSpace.try_create_node_sync(childId, NodeClass::Object, {});
  ASSERT_TRUE(child.is_good());
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  parent.value().add_reference_sync(hasComponent, childId, /*isForward=*/true);
  child.value().add_reference_sync(hasComponent, parentId, /*isForward=*/false);

  addressSpace.delete_node_sync(parentId, /*deleteForwardHierarchicalRefs=*/false);
  ::ua::test_utils::drain_with_timeout(tp);  // the repeated removal runs after the deletion is answered

  auto childAfter = addressSpace.try_find_node_sync(childId);
  ASSERT_TRUE(childAfter.is_good());
  EXPECT_FALSE(has_reference(childAfter.value(), hasComponent, parentId, false))
    << "control: the child keeps no reference to the deleted parent";
  EXPECT_EQ(sink->warnings(), "");
}

TEST(NamespaceDefaultTests, RemoveNonexistentReferenceReportsUncertain)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  const NodeId sourceId{1, "src"};
  const NodeId targetId{1, "tgt"};
  auto sourceResult = addressSpace.try_create_node_sync(sourceId, NodeClass::Object, {});
  ASSERT_TRUE(sourceResult.is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(targetId, NodeClass::Object, {}).is_good());

  const NodeId hasComponent{ReferenceTypeId::HasComponent};

  // Deleting a Reference that was never added is NOT success (Part 4 section 5.7.5) - it must report
  // Uncertain_ReferenceNotDeleted, not Good. A bogus Good lets a client believe a delete happened.
  auto missing = sourceResult.value().try_remove_reference_sync(hasComponent, targetId, /*isForward=*/true);
  EXPECT_FALSE(missing.is_good());
  EXPECT_FALSE(missing.is_bad());  // Uncertain severity, not Bad
  EXPECT_EQ(missing.status_code().as_status(), Status::UncertainReferenceNotDeleted);

  // Deleting a Reference that DOES exist returns Good.
  sourceResult.value().add_reference_sync(hasComponent, targetId, /*isForward=*/true);
  auto present = sourceResult.value().try_remove_reference_sync(hasComponent, targetId, /*isForward=*/true);
  EXPECT_TRUE(present.is_good());

  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, DeleteNodeCleansUpSameNamespaceInverseReferences)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  // Both nodes in namespace 1.
  const NodeId parentId{1, "parent"};
  const NodeId childId{1, "child"};

  auto parentResult = addressSpace.try_create_node_sync(parentId, NodeClass::Object, {});
  ASSERT_TRUE(parentResult.is_good());
  auto childResult = addressSpace.try_create_node_sync(childId, NodeClass::Object, {});
  ASSERT_TRUE(childResult.is_good());

  const NodeId hasComponent{ReferenceTypeId::HasComponent};

  parentResult.value().add_reference_sync(hasComponent, childId, true);
  childResult.value().add_reference_sync(hasComponent, parentId, false);

  // Delete parent.
  addressSpace.delete_node_sync(parentId, true);

  auto childAfter = addressSpace.try_find_node_sync(childId);
  ASSERT_TRUE(childAfter.is_good());

  // Inverse reference cleaned up within same namespace.
  EXPECT_FALSE(has_reference(childAfter.value(), hasComponent, parentId, false));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Ratified expectation change, 2026-09-20. This test previously asserted the opposite - that the
// inverse reference SURVIVES a single-node delete - and described the result as "stale" in its own
// comment. It was pinning a defect: the flag it passes means "do not cascade to descendant nodes"
// at the AddressSpace, but reaches the namespace as the spec's deleteTargetReferences and gated the
// only code that removes references pointing AT the deleted node. An owned subtree's destructor
// issues exactly this delete, so a server accumulated one reference to a destroyed node per
// instance it created - measured at one per session on SessionsDiagnosticsSummary.
//
// Deleting a node and leaving references to it is not a lighter form of deleting it, so the
// obligation is now stated the other way round: a deleted node is not referred to afterwards,
// whichever namespace the referrer lives in. The cascade decision is unaffected and still belongs
// to the AddressSpace.
TEST(NamespaceDefaultTests, DeletingANodeRemovesReferencesToItFromAnotherNamespace)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  auto ns2 = default_ns::Namespace::create("urn:other", tp.get_executor());
  addressSpace.add_namespace_sync(ns2);

  const NodeId parentId{1, "parent"};
  const NodeId childId{2, "child"};

  auto parentResult = addressSpace.try_create_node_sync(parentId, NodeClass::Object, {});
  ASSERT_TRUE(parentResult.is_good());
  auto childResult = addressSpace.try_create_node_sync(childId, NodeClass::Object, {});
  ASSERT_TRUE(childResult.is_good());

  const NodeId hasComponent{ReferenceTypeId::HasComponent};

  parentResult.value().add_reference_sync(hasComponent, childId, true);
  childResult.value().add_reference_sync(hasComponent, parentId, false);

  // Deleted on its own - no cascade to descendants. Cleanup of references TO it is not optional.
  addressSpace.delete_node_sync(parentId, false);

  auto childAfter = addressSpace.try_find_node_sync(childId);
  ASSERT_TRUE(childAfter.is_good()) << "the child is in another namespace and must survive";

  EXPECT_FALSE(has_reference(childAfter.value(), hasComponent, parentId, false))
    << "the child still refers to a node that no longer exists; a Browse from it would walk a "
       "reference to nothing, and one more accumulates every time this pattern repeats";
  ::ua::test_utils::drain_with_timeout(tp);
}

// ---------------------------------------------------------------------------
// Deletion-race: a super-type node deleted mid-walk (dangling HasSubtype
// inverse reference) must surface as a propagated BAD BoolResult, not a silent
// good `false`. get_super_type_async must forward the rich StatusCode
// (BadNodeIdUnknown + ErrorDetail) from the failed find_node_async instead of
// collapsing it to a good-nullopt that is indistinguishable from the genuine
// top-of-hierarchy terminus.
// ---------------------------------------------------------------------------

TEST(NamespaceDefaultTests, IsRefOfTypeSurfacesDeletedSuperTypeAsError)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  const NodeId subId{1, "SubRefType"};
  const NodeId superId{1, "SuperRefType"};

  auto subResult = addressSpace.try_create_node_sync(subId, NodeClass::ReferenceType, {});
  ASSERT_TRUE(subResult.is_good());
  auto superResult = addressSpace.try_create_node_sync(superId, NodeClass::ReferenceType, {});
  ASSERT_TRUE(superResult.is_good());

  // Delete the supertype B, then give the subtype A an INVERSE HasSubtype reference to it, so
  // get_super_type_id(A) resolves to a B that no longer exists - the dangling edge the deletion race
  // leaves, reproduced deterministically. Added before the delete, the address space would add B's forward
  // half too (NR-70 B8), and deleting B would remove both.
  addressSpace.try_delete_node_sync(superId, /*deleteForwardHierarchicalRefs=*/false);
  ASSERT_TRUE(addressSpace.try_find_node_sync(superId).is_bad());
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  subResult.value().add_reference_sync(hasSubtype, superId, /*isForward=*/false);

  BoolResult captured{false};
  std::atomic<bool> done{false};
  node_utils::is_ref_of_type_async(EncodingLimits{},
    addressSpace,
    /*allowSubTypes=*/true,
    subId,
    NodeId{ReferenceTypeId::HasEventSource},  // unrelated real ref type -> walk must climb past B
    [&](BoolResult result)
    {
      captured = std::move(result);
      done = true;
    });
  ::ua::test_utils::drain_with_timeout(tp);

  ASSERT_TRUE(done);
  EXPECT_TRUE(captured.is_bad());
  EXPECT_EQ(captured.status_code().as_status(), Status::BadNodeIdUnknown);
  EXPECT_NE(captured.status_code().shared_detail(), nullptr);
}

// Green-guard: a legitimate top-of-hierarchy terminus (no HasSubtype inverse
// reference) must remain a GOOD `false`, not become a spurious error. This
// proves the fix only changes the deletion-race case and not the normal
// subtype walk that terminates at the References root.
TEST(NamespaceDefaultTests, IsRefOfTypeReturnsFalseAtGenuineRootTerminus)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("urn:test", tp.get_executor());

  // A standalone ReferenceType node with no HasSubtype inverse reference: its
  // super-type walk terminates immediately at the genuine top-of-hierarchy.
  const NodeId subId{1, "StandaloneRefType"};
  auto subResult = addressSpace.try_create_node_sync(subId, NodeClass::ReferenceType, {});
  ASSERT_TRUE(subResult.is_good());

  BoolResult captured{true};
  std::atomic<bool> done{false};
  node_utils::is_ref_of_type_async(EncodingLimits{},
    addressSpace,
    /*allowSubTypes=*/true,
    subId,
    NodeId{ReferenceTypeId::HasEventSource},
    [&](BoolResult result)
    {
      captured = std::move(result);
      done = true;
    });
  ::ua::test_utils::drain_with_timeout(tp);

  ASSERT_TRUE(done);
  EXPECT_TRUE(captured.is_good());
  EXPECT_FALSE(captured.value());
}

// ---------------------------------------------------------------------------
// find_nodes (interface refactor P1) - base Namespace::find_nodes looping default
// exercised against the in-memory default_ns::Namespace (find_node completes
// inline, so the whole batch completes synchronously and in request order).
// ---------------------------------------------------------------------------

TEST(NamespaceDefaultTests, FindNodesReturnsResultsInRequestOrder)
{
  boost::asio::thread_pool tp{1};
  auto ns = default_ns::Namespace::create("uri://find-nodes-order", tp.get_executor());

  const NodeId idA{0, "find-nodes:A"};
  const NodeId idB{0, "find-nodes:B"};
  const NodeId idC{0, "find-nodes:C"};
  ns->create_node(idA, NodeClass::Object);
  ns->create_node(idB, NodeClass::Variable);
  ns->create_node(idC, NodeClass::Method);

  const std::vector<NodeId> ids{idA, idB, idC};
  int calls{0};
  std::optional<BatchResult<NodeResult>> batch;
  ns->find_nodes_async(RequestInfo{},
    std::span<const NodeId>{ids},
    std::nullopt,
    [&](BatchResult<NodeResult> result)
    {
      ++calls;
      batch = std::move(result);
    });

  // default_ns find_node fires inline, so the batch completes before return.
  EXPECT_EQ(calls, 1) << "find_nodes must complete its callback exactly once";
  ASSERT_TRUE(batch.has_value());
  EXPECT_TRUE(batch->batchStatus.is_good());
  ASSERT_EQ(batch->items.size(), ids.size());
  for (std::size_t i = 0; i < ids.size(); ++i)
  {
    ASSERT_TRUE(batch->items[i].is_good()) << "slot " << i << " must resolve";
    const NodeDescription description = batch->items[i].value()->attributes();
    EXPECT_EQ(description.node_id(), ids[i])
      << "slot " << i << " must hold the Node for the id at that request position";
  }
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, FindNodesEmptyInputYieldsEmptyGoodBatch)
{
  boost::asio::thread_pool tp{1};
  auto ns = default_ns::Namespace::create("uri://find-nodes-empty", tp.get_executor());

  int calls{0};
  std::optional<BatchResult<NodeResult>> batch;
  ns->find_nodes_async(RequestInfo{},
    std::span<const NodeId>{},
    std::nullopt,
    [&](BatchResult<NodeResult> result)
    {
      ++calls;
      batch = std::move(result);
    });

  EXPECT_EQ(calls, 1);
  ASSERT_TRUE(batch.has_value());
  EXPECT_TRUE(batch->batchStatus.is_good());
  EXPECT_TRUE(batch->items.empty());
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, FindNodesMixedGoodAndBadPreservesPositions)
{
  boost::asio::thread_pool tp{1};
  auto ns = default_ns::Namespace::create("uri://find-nodes-mixed", tp.get_executor());

  const NodeId idA{0, "find-nodes:present-A"};
  const NodeId missing{0, "find-nodes:absent"};
  const NodeId idB{0, "find-nodes:present-B"};
  ns->create_node(idA, NodeClass::Object);
  ns->create_node(idB, NodeClass::Object);

  const std::vector<NodeId> ids{idA, missing, idB};
  std::optional<BatchResult<NodeResult>> batch;
  ns->find_nodes_async(RequestInfo{},
    std::span<const NodeId>{ids},
    std::nullopt,
    [&](BatchResult<NodeResult> result) { batch = std::move(result); });

  ASSERT_TRUE(batch.has_value());
  EXPECT_TRUE(batch->batchStatus.is_good()) << "a per-item failure must not fail the batch as a whole";
  ASSERT_EQ(batch->items.size(), 3u);
  ASSERT_TRUE(batch->items[0].is_good());
  const NodeDescription firstDescription = batch->items[0].value()->attributes();
  EXPECT_EQ(firstDescription.node_id(), idA);
  EXPECT_TRUE(batch->items[1].is_bad());
  EXPECT_EQ(batch->items[1].status_code(), Status::BadNodeIdUnknown);
  // ErrorDetail propagation is the project's highest priority: the per-item rich
  // detail (NodeNotFound + node_id/namespace context) must survive being moved
  // into the batch, not be reduced to a bare StatusCode.
  ASSERT_NE(batch->items[1].shared_detail(), nullptr)
    << "the per-item find_node ErrorDetail must survive into the batch";
  EXPECT_EQ(batch->items[1].shared_detail()->source, "DefaultNamespace");
  ASSERT_TRUE(batch->items[2].is_good());
  const NodeDescription lastDescription = batch->items[2].value()->attributes();
  EXPECT_EQ(lastDescription.node_id(), idB);
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

// A Namespace whose find_nodes_async PARKS each per-id callback instead of completing it, so a
// test can fire completions in an arbitrary order. Used to falsify resolve_each's slot-by-index
// mapping under out-of-order completion.
class ManualCompletionNamespace : public Namespace
{
public:
  /// Arms nothing, so stopping is immediate. Stated explicitly because Namespace makes it a
  /// pure virtual: a namespace that DOES arm timers must stop them here, or the executor it
  /// was given never drains.
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  String uri() const override
  {
    return String{"urn:test:manual-completion"};
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> batchCallback) override
  {
    resolve_each(nodeIds,
      std::move(batchCallback),
      [this](const NodeId& nodeId, std::function<void(NodeResult)> callback)
      { mPending.emplace_back(nodeId, std::move(callback)); });
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery>,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem>, Duration,
    bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }

  std::size_t pending() const
  {
    return mPending.size();
  }

  // Fire the callback parked by the find_node call at index `callIndex`.
  void complete(std::size_t callIndex, NodeResult result)
  {
    mPending.at(callIndex).second(std::move(result));
  }

private:
  std::vector<std::pair<NodeId, std::function<void(NodeResult)>>> mPending;
};

// Collects a fixed-size callback batch, then starts every callback concurrently on dedicated test
// threads. Executor callbacks may enqueue into the batch but never block waiting for one another.
class ConcurrentCallbackBatch
{
public:
  explicit ConcurrentCallbackBatch(std::size_t expected) : mExpected(expected)
  {}

  ~ConcurrentCallbackBatch()
  {
    join();
  }

  void schedule(std::function<void()> callback)
  {
    std::vector<std::function<void()>> callbacks;
    {
      const std::lock_guard lock{mPendingMutex};
      mPending.push_back(std::move(callback));
      if (mPending.size() != mExpected)
      {
        return;
      }
      callbacks = std::move(mPending);
    }

    // Only these dedicated test threads wait. Executor callbacks merely enqueue into this batch
    // and return, so the stimulus cannot starve or deadlock the address-space pool.
    auto start = std::make_shared<std::latch>(1);
    std::vector<std::thread> workers;
    workers.reserve(callbacks.size());
    for (auto& pending : callbacks)
    {
      workers.emplace_back(
        [start, pending = std::move(pending)]() mutable
        {
          start->wait();
          pending();
        });
    }
    {
      const std::lock_guard lock{mWorkersMutex};
      for (auto& worker : workers)
      {
        mWorkers.push_back(std::move(worker));
      }
    }
    start->count_down();
  }

  void join()
  {
    std::vector<std::thread> workers;
    {
      const std::lock_guard lock{mWorkersMutex};
      workers.swap(mWorkers);
    }
    for (auto& worker : workers)
    {
      worker.join();
    }
  }

private:
  const std::size_t mExpected;
  std::mutex mPendingMutex;
  std::vector<std::function<void()>> mPending;
  std::mutex mWorkersMutex;
  std::vector<std::thread> mWorkers;
};

// A Namespace that defers each ordinary find_node onto a multi-threaded executor and can release
// selected find/delete completions through ConcurrentCallbackBatch. Exercises the base find_nodes
// accumulator and recursive-delete flow under genuinely concurrent collaborators; meaningful under
// TSan.
class PostingFindNodeNamespace : public Namespace
{
public:
  /// Arms nothing, so stopping is immediate. Stated explicitly because Namespace makes it a
  /// pure virtual: a namespace that DOES arm timers must stop them here, or the executor it
  /// was given never drains.
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  PostingFindNodeNamespace(
    std::shared_ptr<default_ns::Namespace> inner, boost::asio::any_io_executor executor)
    : mInner(std::move(inner)), mExecutor(std::move(executor))
  {}

  PostingFindNodeNamespace(std::shared_ptr<default_ns::Namespace> inner,
    boost::asio::any_io_executor executor, std::vector<NodeId> synchronizedFinds,
    std::vector<NodeId> failingDeletes = {})
    : mInner(std::move(inner)), mExecutor(std::move(executor)),
      mSynchronizedFinds(synchronizedFinds.begin(), synchronizedFinds.end()),
      mFindBatch(synchronizedFinds.empty()
                   ? nullptr
                   : std::make_shared<ConcurrentCallbackBatch>(synchronizedFinds.size())),
      mFailingDeletes(failingDeletes.begin(), failingDeletes.end()),
      mDeleteBatch(
        failingDeletes.empty() ? nullptr : std::make_shared<ConcurrentCallbackBatch>(failingDeletes.size()))
  {}

  String uri() const override
  {
    return mInner->uri();
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> batchCallback) override
  {
    resolve_each(nodeIds,
      std::move(batchCallback),
      [this](const NodeId& nodeId, std::function<void(NodeResult)> callback)
      {
        NodeId id = nodeId;  // copy: the span is only valid for the synchronous call
        auto inner = mInner;
        bool synchronize = false;
        {
          const std::lock_guard lock{mSynchronizedFindsMutex};
          synchronize = mSynchronizedFinds.erase(id) != 0;
        }
        if (synchronize)
        {
          mFindBatch->schedule([inner, id = std::move(id), callback = std::move(callback)]() mutable
            { callback(*inner->find_node(id, std::nullopt)); });
          return;
        }
        boost::asio::post(mExecutor,
          [inner, id = std::move(id), callback = std::move(callback)]() mutable
          { callback(*inner->find_node(id, std::nullopt)); });
      });
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mInner->create_nodes_async(request, nodes, std::move(complete));
  }

  /// Answers the Nodes named in failingDeletes with the injected failure, each from its own test thread
  /// (ConcurrentCallbackBatch), and the others as the inner namespace answers them; the call completes once
  /// every part has answered.
  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override
  {
    std::vector<std::size_t> failing;
    std::vector<std::size_t> passing;
    std::vector<NodeId> passingIds;
    {
      const std::lock_guard lock{mFailingDeletesMutex};
      for (std::size_t i = 0; i < nodes.size(); ++i)
      {
        if (mFailingDeletes.erase(nodes[i]) != 0)
        {
          failing.push_back(i);
        }
        else
        {
          passing.push_back(i);
          passingIds.push_back(nodes[i]);
        }
      }
    }
    if (failing.empty())
    {
      mInner->delete_nodes_async(request, nodes, halves, std::move(complete));
      return;
    }

    struct Collected
    {
      std::mutex mutex;
      BatchResult<DeleteNodeResult> batch;
      std::vector<VersionedNode> versioned;
      std::size_t remaining{0};
      std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete;
    };

    auto collected = std::make_shared<Collected>();
    for (std::size_t i = 0; i < nodes.size(); ++i)
    {
      collected->batch.items.emplace_back(StatusCode{Status::BadInternalError});
    }
    collected->remaining = failing.size() + (passing.empty() ? 0 : 1);
    collected->complete = std::move(complete);
    const auto answered = [collected]
    {
      std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> done;
      {
        const std::lock_guard lock{collected->mutex};
        if (--collected->remaining != 0)
        {
          return;
        }
        done = std::move(collected->complete);
      }
      done(std::move(collected->batch), std::move(collected->versioned));
    };

    if (!passing.empty())
    {
      mInner->delete_nodes_async(request,
        passingIds,
        halves,
        [collected, passing, answered](
          BatchResult<DeleteNodeResult> result, std::vector<VersionedNode> versioned)
        {
          {
            const std::lock_guard lock{collected->mutex};
            for (std::size_t k = 0; k < passing.size() && k < result.items.size(); ++k)
            {
              collected->batch.items[passing[k]] = std::move(result.items[k]);
            }
            for (auto& node : versioned)
            {
              collected->versioned.push_back(std::move(node));
            }
          }
          answered();
        });
    }
    for (const std::size_t position : failing)
    {
      mDeleteBatch->schedule(
        [collected, position, id = nodes[position], answered]() mutable
        {
          {
            const std::lock_guard lock{collected->mutex};
            collected->batch.items[position] = DeleteNodeResult{Status::BadInternalError,
              ErrorDetail::build(
                "InjectedConcurrentDeleteFailure", "Injected concurrent delete failure", "TestNamespace")
                .context(ContextKeys::nodeId, to_string(id))};
          }
          answered();
        });
    }
  }

  // An accessor's Reference changes go to the inner namespace, which looks their sources up itself: the finds
  // this namespace synchronizes are left for the recursive delete.
  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->add_references_async(request, changes, std::move(complete));
  }

  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->remove_references_async(request, changes, std::move(complete));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    mInner->read_references_async(request, queries, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  void join_concurrent_callbacks()
  {
    if (mFindBatch)
    {
      mFindBatch->join();
    }
    if (mDeleteBatch)
    {
      mDeleteBatch->join();
    }
  }

private:
  std::shared_ptr<default_ns::Namespace> mInner;
  boost::asio::any_io_executor mExecutor;
  std::mutex mSynchronizedFindsMutex;
  std::unordered_set<NodeId> mSynchronizedFinds;
  std::shared_ptr<ConcurrentCallbackBatch> mFindBatch;
  std::mutex mFailingDeletesMutex;
  std::unordered_set<NodeId> mFailingDeletes;
  std::shared_ptr<ConcurrentCallbackBatch> mDeleteBatch;

  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mInner->attach(context);
  }
};

}  // namespace

// find_nodes must map each result to its REQUEST position, independent of the
// order completions arrive in. Completing 2, 0, 1 (with distinct statuses) would
// produce [2,0,1] under a naive append-in-completion-order implementation; the
// slot-by-index default must still produce request order [0,1,2].
TEST(NamespaceDefaultTests, FindNodesPreservesRequestOrderUnderOutOfOrderCompletion)
{
  ManualCompletionNamespace ns;

  const std::vector<NodeId> ids{NodeId{0, "oo:0"}, NodeId{0, "oo:1"}, NodeId{0, "oo:2"}};
  int calls{0};
  std::optional<BatchResult<NodeResult>> batch;
  ns.find_nodes_async(RequestInfo{},
    std::span<const NodeId>{ids},
    std::nullopt,
    [&](BatchResult<NodeResult> result)
    {
      ++calls;
      batch = std::move(result);
    });

  ASSERT_EQ(ns.pending(), 3u);
  EXPECT_EQ(calls, 0) << "the loop guard must hold the batch callback until every item has completed";

  ns.complete(2, NodeResult{StatusCode{Status::BadInternalError}});
  EXPECT_EQ(calls, 0);
  ns.complete(0, NodeResult{StatusCode{Status::BadNodeIdUnknown}});
  EXPECT_EQ(calls, 0);
  ns.complete(1, NodeResult{StatusCode{Status::BadOutOfMemory}});
  EXPECT_EQ(calls, 1) << "the final completion must fire the batch exactly once";

  ASSERT_TRUE(batch.has_value());
  EXPECT_TRUE(batch->batchStatus.is_good());
  ASSERT_EQ(batch->items.size(), 3u);
  EXPECT_EQ(batch->items[0].status_code(), Status::BadNodeIdUnknown) << "request position 0";
  EXPECT_EQ(batch->items[1].status_code(), Status::BadOutOfMemory) << "request position 1";
  EXPECT_EQ(batch->items[2].status_code(), Status::BadInternalError) << "request position 2";
}

// find_nodes must collect genuinely concurrent find_node completions (fired on a
// multi-threaded pool) into the correct request-ordered slots and fire its batch
// callback exactly once. Run under the TSAN preset, this falsifies a regression
// of the accumulator's atomic counter to a plain/relaxed integer (data race on
// `remaining` / the slots).
TEST(NamespaceDefaultTests, FindNodesCollectsConcurrentCompletions)
{
  boost::asio::thread_pool pool{8};
  auto inner = default_ns::Namespace::create("urn:test:concurrent-find-nodes", pool.get_executor());

  constexpr std::size_t count = 64;
  std::vector<NodeId> ids;
  ids.reserve(count);
  for (std::size_t i = 0; i < count; ++i)
  {
    NodeId id{0, "concurrent:" + std::to_string(i)};
    inner->create_node(id, NodeClass::Object);
    ids.push_back(id);
  }

  PostingFindNodeNamespace ns{inner, pool.get_executor()};

  std::atomic<int> calls{0};
  std::promise<BatchResult<NodeResult>> promise;
  ns.find_nodes_async(RequestInfo{},
    std::span<const NodeId>{ids},
    std::nullopt,
    [&](BatchResult<NodeResult> result)
    {
      ++calls;
      promise.set_value(std::move(result));
    });

  auto batch = promise.get_future().get();
  EXPECT_EQ(calls.load(), 1) << "the batch callback must fire exactly once under concurrent completion";
  EXPECT_TRUE(batch.batchStatus.is_good());
  ASSERT_EQ(batch.items.size(), count);
  for (std::size_t i = 0; i < count; ++i)
  {
    ASSERT_TRUE(batch.items[i].is_good()) << "slot " << i;
    const NodeDescription description = batch.items[i].value()->attributes();
    EXPECT_EQ(description.node_id(), ids[i])
      << "slot " << i << " must map to its request position regardless of completion thread/order";
  }
  pool.join();
}

// Recursive deletion starts every child branch before waiting for any branch to finish. When the
// namespace completes those branches on different executor threads, each branch can discover its
// own descendant concurrently. The shared visited set must remain valid while those descendants
// are admitted; otherwise concurrent unordered_set insertion corrupts the flow and its destructor.
// @relation(AC-SVR-FILE-020-DELETE-RECURSIVE, scope=function)
TEST(NamespaceDefaultTests, RecursiveDeleteCompletesAcrossConcurrentSiblingBranches)
{
  constexpr std::size_t branches = 16;
  boost::asio::thread_pool pool{8};
  auto inner = default_ns::Namespace::create("urn:test:concurrent-recursive-delete", pool.get_executor());

  std::vector<NodeId> branchIds;
  branchIds.reserve(branches);
  for (std::size_t index = 0; index < branches; ++index)
  {
    branchIds.emplace_back(2, "recursive:branch:" + std::to_string(index));
  }

  auto concurrentNamespace =
    std::make_shared<PostingFindNodeNamespace>(inner, pool.get_executor(), branchIds);
  auto addressSpace = AddressSpace::create("urn:test:recursive-delete-owner", pool.get_executor());
  ASSERT_EQ(addressSpace.add_namespace_sync(concurrentNamespace), 2u);

  const NodeId rootId{2, "recursive:root"};
  auto root = addressSpace.try_create_node_sync(rootId, NodeClass::Object, {});
  ASSERT_TRUE(root.is_good());
  const NodeId hierarchicalReferences{ReferenceTypeId::HierarchicalReferences};

  std::vector<NodeId> leafIds;
  leafIds.reserve(branches);
  for (std::size_t index = 0; index < branches; ++index)
  {
    const auto& branchId = branchIds[index];
    NodeId leafId{2, "recursive:leaf:" + std::to_string(index)};
    auto branch = addressSpace.try_create_node_sync(branchId, NodeClass::Object, {});
    auto leaf = addressSpace.try_create_node_sync(leafId, NodeClass::Object, {});
    ASSERT_TRUE(branch.is_good());
    ASSERT_TRUE(leaf.is_good());

    root.value().add_reference_sync(hierarchicalReferences, branchId, /*isForward=*/true);
    branch.value().add_reference_sync(hierarchicalReferences, rootId, /*isForward=*/false);
    branch.value().add_reference_sync(hierarchicalReferences, leafId, /*isForward=*/true);
    leaf.value().add_reference_sync(hierarchicalReferences, branchId, /*isForward=*/false);
    leafIds.push_back(std::move(leafId));
  }

  std::promise<VoidResult> completion;
  auto completed = completion.get_future();
  addressSpace.delete_node_async(rootId,
    /*deleteForwardHierarchicallyReferencedNodes=*/true,
    ReferenceHalves::Both,
    [&completion](VoidResult result) { completion.set_value(std::move(result)); });

  ASSERT_EQ(completed.wait_for(std::chrono::seconds{10}), std::future_status::ready)
    << "concurrent recursive deletion did not complete";
  EXPECT_TRUE(completed.get().is_good());
  concurrentNamespace->join_concurrent_callbacks();
  EXPECT_TRUE(addressSpace.try_find_node_sync(rootId).is_bad());
  for (std::size_t index = 0; index < branches; ++index)
  {
    EXPECT_TRUE(addressSpace.try_find_node_sync(branchIds[index]).is_bad()) << "branch " << index;
    EXPECT_TRUE(addressSpace.try_find_node_sync(leafIds[index]).is_bad()) << "leaf " << index;
  }

  ::ua::test_utils::drain_with_timeout(pool);
}

// Concurrent child failures race to become the cascade result. The winner's status and complete
// ErrorDetail must be published before the final completion consumes it.
// @relation(AC-SVR-DIAG-012-NAMESPACE-MUTATOR-DETAIL, scope=function)
TEST(NamespaceDefaultTests, ConcurrentRecursiveDeleteFailurePreservesOneCompleteErrorDetail)
{
  constexpr std::size_t branches = 16;
  boost::asio::thread_pool pool{8};
  auto inner = default_ns::Namespace::create("urn:test:concurrent-recursive-failure", pool.get_executor());

  std::vector<NodeId> branchIds;
  branchIds.reserve(branches);
  for (std::size_t index = 0; index < branches; ++index)
  {
    branchIds.emplace_back(2, "recursive:failure:" + std::to_string(index));
  }

  auto concurrentNamespace =
    std::make_shared<PostingFindNodeNamespace>(inner, pool.get_executor(), std::vector<NodeId>{}, branchIds);
  auto addressSpace = AddressSpace::create("urn:test:recursive-failure-owner", pool.get_executor());
  ASSERT_EQ(addressSpace.add_namespace_sync(concurrentNamespace), 2u);

  const NodeId rootId{2, "recursive:failure:root"};
  auto root = addressSpace.try_create_node_sync(rootId, NodeClass::Object, {});
  ASSERT_TRUE(root.is_good());
  const NodeId hierarchicalReferences{ReferenceTypeId::HierarchicalReferences};
  for (const auto& branchId : branchIds)
  {
    auto branch = addressSpace.try_create_node_sync(branchId, NodeClass::Object, {});
    ASSERT_TRUE(branch.is_good());
    root.value().add_reference_sync(hierarchicalReferences, branchId, /*isForward=*/true);
    branch.value().add_reference_sync(hierarchicalReferences, rootId, /*isForward=*/false);
  }

  std::atomic<std::size_t> callbacks{0};
  std::promise<VoidResult> completion;
  auto completed = completion.get_future();
  addressSpace.delete_node_async(rootId,
    /*deleteForwardHierarchicallyReferencedNodes=*/true,
    ReferenceHalves::Both,
    [&callbacks, &completion](VoidResult result)
    {
      callbacks.fetch_add(1, std::memory_order_relaxed);
      completion.set_value(std::move(result));
    });

  ASSERT_EQ(completed.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  const auto result = completed.get();
  concurrentNamespace->join_concurrent_callbacks();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadInternalError);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "InjectedConcurrentDeleteFailure");
  EXPECT_EQ(result.shared_detail()->source, "TestNamespace");
  EXPECT_EQ(callbacks.load(std::memory_order_relaxed), 1u);

  ::ua::test_utils::drain_with_timeout(pool);
}

// ---------------------------------------------------------------------------
// write_attribute_async (interface refactor P1) - base Node::write_attribute_async
// bridges to the synchronous write_attribute, completing inline for the
// in-memory node and converting a thrown UaException into a bad VoidResult.
// ---------------------------------------------------------------------------

TEST(NamespaceDefaultTests, WriteAttributeAsyncAppliesValueInline)
{
  boost::asio::thread_pool tp{1};
  auto ns = default_ns::Namespace::create("uri://write-attr-async", tp.get_executor());

  const NodeId id{0, "write-attr:ok"};
  auto node = ns->create_node<default_ns::ObjectNode>(id);
  ASSERT_NE(node, nullptr);

  int calls{0};
  std::optional<VoidResult> result;
  node->write_attribute_async(AttributeId::WriteMask,
    Variant{uint32_t{0x7}},
    [&](VoidResult outcome)
    {
      ++calls;
      result = std::move(outcome);
    });

  EXPECT_EQ(calls, 1) << "in-memory write_attribute_async must complete inline";
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_good());

  const Variant readBack = node->read_attribute(AttributeId::WriteMask);
  ASSERT_FALSE(readBack.empty()) << "the written attribute must be readable back";
  EXPECT_EQ(readBack.as<uint32_t>(), 0x7u);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, WriteAttributeAsyncReportsErrorForInvalidAttribute)
{
  boost::asio::thread_pool tp{1};
  auto ns = default_ns::Namespace::create("uri://write-attr-async-bad", tp.get_executor());

  const NodeId id{0, "write-attr:bad"};
  auto node = ns->create_node<default_ns::ObjectNode>(id);
  ASSERT_NE(node, nullptr);

  // Value is not a valid attribute for an Object node; the synchronous
  // write_attribute throws BadAttributeIdInvalid, which the async bridge must
  // surface as a bad VoidResult (never throw out of the *_async surface).
  int calls{0};
  std::optional<VoidResult> result;
  node->write_attribute_async(AttributeId::Value,
    Variant{int32_t{42}},
    [&](VoidResult outcome)
    {
      ++calls;
      result = std::move(outcome);
    });

  EXPECT_EQ(calls, 1);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code(), Status::BadAttributeIdInvalid);
  EXPECT_NE(result->shared_detail(), nullptr) << "the converted exception must preserve its ErrorDetail";
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Create-with-attributes (interface refactor section 5.2) ---

// A node's initial static attributes are applied as part of the create op (not a post-create setter
// burst) and are readable immediately on the returned accessor.
TEST(NamespaceDefaultTests, CreateNodeAppliesInitialAttributes)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:cwa-apply", tp.get_executor());

  ua::InitialAttributes attributes;
  attributes.emplace_back(AttributeId::BrowseName, Variant{QualifiedName{0, "InitialName"}});
  attributes.emplace_back(AttributeId::Description, Variant{LocalizedText{"en", "seeded at create"}});

  auto createResult = addressSpace.try_create_node_sync(NodeId{4101}, NodeClass::Object, attributes);
  ASSERT_TRUE(createResult.is_good());
  auto accessor = createResult.value();

  EXPECT_EQ(accessor.get_browse_name(), QualifiedName(0, "InitialName"));
  auto description = accessor.read_attribute(AttributeId::Description);
  ASSERT_TRUE(description.is_localized_text());
  EXPECT_EQ(description.as<LocalizedText>().text(), String{"seeded at create"});
  ::ua::test_utils::drain_with_timeout(tp);
}

// An initial attribute the node rejects fails the whole create atomically: the create reports the
// rejecting status and the node is rolled back out of the namespace (never half-built).
TEST(NamespaceDefaultTests, CreateNodeRollsBackWhenInitialAttributeRejected)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:cwa-rollback", tp.get_executor());

  // A Variable's Value is not a creation Attribute (NodeDescription::try_from_attributes refuses it with
  // Bad_NodeAttributesInvalid), so the create must fail rather than leave a partially-built node.
  ua::InitialAttributes attributes;
  attributes.emplace_back(AttributeId::Value, Variant{int32_t{42}});

  const NodeId nodeId{4102};
  auto createResult = addressSpace.try_create_node_sync(nodeId, NodeClass::Variable, attributes);
  EXPECT_TRUE(createResult.is_bad());
  EXPECT_EQ(createResult.status_code(), Status::BadNodeAttributesInvalid);

  // Atomic rollback: the node must not exist after the failed create.
  auto findResult = addressSpace.try_find_node_sync(nodeId);
  EXPECT_TRUE(findResult.is_bad()) << "a rejected initial attribute must roll the node back out entirely";
  ::ua::test_utils::drain_with_timeout(tp);
}

// NodeAccessor::read_attribute returns the stored wire-form Variant - the same value the matching
// setter wrote - so attributes can be copied verbatim into a create-with-attributes set.
TEST(NamespaceDefaultTests, NodeAccessorReadAttributeReturnsStoredWireForm)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:cwa-read", tp.get_executor());

  auto createResult = addressSpace.try_create_node_sync(NodeId{4103}, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto accessor = createResult.value();

  accessor.set_browse_name(QualifiedName{0, "Probe"});
  auto wire = accessor.read_attribute(AttributeId::BrowseName);
  ASSERT_FALSE(wire.empty());
  EXPECT_EQ(wire.as<QualifiedName>(), QualifiedName(0, "Probe"));
  EXPECT_EQ(accessor.get_browse_name(), wire.as<QualifiedName>());
  ::ua::test_utils::drain_with_timeout(tp);
}

// The DisplayName text-size limit (OPC 10000-3) is enforced single-source in
// attribute_wire::display_name, so the setter path (and every create-with-attributes builder that
// encodes through it) rejects an oversize value; a value at the limit is accepted.
TEST(NamespaceDefaultTests, SetDisplayNameRejectsOversizeText)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:cwa-dn-size", tp.get_executor());
  auto createResult = addressSpace.try_create_node_sync(NodeId{4104}, NodeClass::Object, {});
  ASSERT_TRUE(createResult.is_good());
  auto accessor = createResult.value();

  EXPECT_THROW(accessor.set_display_name(LocalizedText{"en", std::string(513, 'x')}), UaException);
  EXPECT_NO_THROW(accessor.set_display_name(LocalizedText{"en", std::string(512, 'x')}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Facade find_nodes_async (P4: batched cross-namespace resolution) ---

// The facade groups a mixed-namespace request by owning namespace, resolves each subset, and
// reassembles the per-item results in request order; an unknown namespace index yields a per-item
// BadNodeIdUnknown without failing the batch.
TEST(NamespaceDefaultTests, FindNodesAsyncGroupsByNamespaceAndPreservesOrder)
{
  boost::asio::thread_pool tp{2};
  auto addressSpace = AddressSpace::create("uri:fn-batch", tp.get_executor());

  const NodeId inNs0{0, 7001};  // namespace 0
  const NodeId inAppNs{1, "appNode"};  // application namespace (index 1, created by AddressSpace::create)
  const NodeId unknownNs{9, 9999};  // no such namespace index
  ASSERT_TRUE(addressSpace.try_create_node_sync(inNs0, NodeClass::Object, {}).is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(inAppNs, NodeClass::Variable, {}).is_good());

  // Mixed namespaces, an unknown-namespace id, and a duplicate - order must be preserved exactly.
  const std::vector<NodeId> request{inNs0, unknownNs, inAppNs, inNs0};
  std::optional<BatchResult<NodeAccessorResult>> result;
  addressSpace.find_nodes_async(
    request, [&result](BatchResult<NodeAccessorResult> r) { result = std::move(r); });
  ::ua::test_utils::drain_with_timeout(tp);

  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->items.size(), 4u);
  EXPECT_TRUE(result->items[0].is_good());
  EXPECT_TRUE(result->items[1].is_bad());
  EXPECT_EQ(result->items[1].status_code(), Status::BadNodeIdUnknown);
  EXPECT_TRUE(result->items[2].is_good());
  EXPECT_TRUE(result->items[3].is_good());
  EXPECT_EQ(result->items[0].value().get_node_id(), inNs0);
  EXPECT_EQ(result->items[2].value().get_node_id(), inAppNs);
  EXPECT_EQ(result->items[3].value().get_node_id(), inNs0);
}

TEST(NamespaceDefaultTests, FindNodesAsyncEmptyRequestCompletesEmpty)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:fn-batch-empty", tp.get_executor());

  const std::vector<NodeId> request;
  std::optional<BatchResult<NodeAccessorResult>> result;
  addressSpace.find_nodes_async(
    request, [&result](BatchResult<NodeAccessorResult> r) { result = std::move(r); });
  ::ua::test_utils::drain_with_timeout(tp);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->items.empty());
  EXPECT_TRUE(result->batchStatus.is_good());
}

// ---------------------------------------------------------------------------
// enumerate_nodes (NodeSet export, Phase 2) - the in-memory default namespace
// snapshots its store and returns the full owned NodeId set; the base Namespace
// default declines with BadNotSupported; AddressSpace::enumerate_nodes_async
// routes by namespace index and reports BadNodeIdUnknown for an unknown index.
// ---------------------------------------------------------------------------

namespace
{

// Turn a list of NodeIds into a comparable set so enumeration assertions are
// order-independent (the store is an unordered_map).
std::set<NodeId> id_set(const std::vector<NodeId>& ids)
{
  return std::set<NodeId>{ids.begin(), ids.end()};
}

}  // namespace

TEST(NamespaceDefaultTests, EnumerateNodesReturnsAllOwnedNodeIds)
{
  boost::asio::thread_pool tp{1};
  auto ns = default_ns::Namespace::create("uri://enumerate-all", tp.get_executor());

  // Mix numeric and string identifiers across node classes.
  const std::vector<NodeId> created{
    NodeId{0, 5001}, NodeId{0, "enum:object"}, NodeId{0, 5002}, NodeId{0, "enum:variable"}};
  ns->create_node(created[0], NodeClass::Object);
  ns->create_node(created[1], NodeClass::Object);
  ns->create_node(created[2], NodeClass::Variable);
  ns->create_node(created[3], NodeClass::Variable);

  int calls{0};
  std::optional<Result<std::vector<NodeId>>> result;
  ns->enumerate_nodes_async(RequestInfo{},
    [&](Result<std::vector<NodeId>> outcome)
    {
      ++calls;
      result = std::move(outcome);
    });

  // In-memory enumeration completes inline, exactly once.
  EXPECT_EQ(calls, 1) << "enumerate_nodes must complete its callback exactly once";
  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->is_good());
  EXPECT_EQ(id_set(result->value()), id_set(created))
    << "enumerate_nodes must return exactly the NodeIds of every created node";
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NamespaceDefaultTests, EnumerateNodesOnEmptyNamespaceYieldsEmptyGoodResult)
{
  boost::asio::thread_pool tp{1};
  auto ns = default_ns::Namespace::create("uri://enumerate-empty", tp.get_executor());

  int calls{0};
  std::optional<Result<std::vector<NodeId>>> result;
  ns->enumerate_nodes_async(RequestInfo{},
    [&](Result<std::vector<NodeId>> outcome)
    {
      ++calls;
      result = std::move(outcome);
    });

  EXPECT_EQ(calls, 1);
  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->is_good());
  EXPECT_TRUE(result->value().empty());
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

// A minimal Namespace that does NOT override enumerate_nodes_async, so it inherits the
// base decline default. The pure virtuals are stubbed with BadNotImplemented
// (mirroring ManualCompletionNamespace above) - only enumerate_nodes_async is exercised.
class NonEnumerableNamespace : public Namespace
{
public:
  /// Arms nothing, so stopping is immediate. Stated explicitly because Namespace makes it a
  /// pure virtual: a namespace that DOES arm timers must stop them here, or the executor it
  /// was given never drains.
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    if (callback)
    {
      callback(VoidResult{});
    }
  }

  String uri() const override
  {
    return String{"urn:test:non-enumerable"};
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> batchCallback) override
  {
    resolve_each(nodeIds,
      std::move(batchCallback),
      [](const NodeId& /*nodeId*/, std::function<void(NodeResult)> callback)
      { callback(NodeResult{StatusCode{Status::BadNotImplemented}}); });
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery>,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem>, Duration,
    bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotImplemented}}, {}});
  }
};

}  // namespace

TEST(NamespaceDefaultTests, EnumerateNodesBaseDefaultDeclinesWithNotSupported)
{
  NonEnumerableNamespace ns;

  int calls{0};
  std::optional<Result<std::vector<NodeId>>> result;
  ns.enumerate_nodes_async(RequestInfo{},
    [&](Result<std::vector<NodeId>> outcome)
    {
      ++calls;
      result = std::move(outcome);
    });

  EXPECT_EQ(calls, 1);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code().as_status(), Status::BadNotSupported);
  ASSERT_NE(result->shared_detail(), nullptr) << "the decline default must carry its rich ErrorDetail";
  EXPECT_EQ(result->shared_detail()->source, "Namespace");
}

TEST(NamespaceDefaultTests, EnumerateNodesAsyncReturnsOwningNamespaceIds)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:enum-async", tp.get_executor());

  // AddressSpace::create seeds namespace 0 (core) and namespace 1 (application). Create our nodes
  // in the application namespace (index 1) so they are isolated from the NS0 seed.
  const std::vector<NodeId> created{NodeId{1, "enum-async:a"}, NodeId{1, 7100}, NodeId{1, "enum-async:b"}};
  for (const auto& id : created)
  {
    ASSERT_TRUE(addressSpace.try_create_node_sync(id, NodeClass::Object, {}).is_good());
  }

  std::optional<Result<std::vector<NodeId>>> result;
  addressSpace.enumerate_nodes_async(
    1, [&](Result<std::vector<NodeId>> outcome) { result = std::move(outcome); });
  ::ua::test_utils::drain_with_timeout(tp);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->is_good());
  EXPECT_EQ(id_set(result->value()), id_set(created))
    << "enumerate_nodes_async must return exactly the namespace's owned NodeIds";
}

TEST(NamespaceDefaultTests, EnumerateNodesAsyncUnknownNamespaceReportsBadNodeIdUnknown)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:enum-async-unknown", tp.get_executor());

  std::optional<Result<std::vector<NodeId>>> result;
  addressSpace.enumerate_nodes_async(
    99, [&](Result<std::vector<NodeId>> outcome) { result = std::move(outcome); });
  ::ua::test_utils::drain_with_timeout(tp);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(result->shared_detail(), nullptr);
  EXPECT_EQ(result->shared_detail()->source, "AddressSpace");
}

namespace
{

// The answers a batched member's completion received, and how many times it ran.
template<typename Answer>
class Answers
{
public:
  void receive(Answer answer)
  {
    {
      const std::lock_guard lock{mMutex};
      ++mCount;
      if (!mAnswer)
      {
        mAnswer = std::move(answer);
      }
    }
    mArrived.notify_all();
  }

  /// Waits up to five seconds for the first answer. @return false when none arrived.
  bool wait()
  {
    std::unique_lock lock{mMutex};
    return mArrived.wait_for(lock, std::chrono::seconds{5}, [this] { return mAnswer.has_value(); });
  }

  int count() const
  {
    const std::lock_guard lock{mMutex};
    return mCount;
  }

  Answer answer() const
  {
    const std::lock_guard lock{mMutex};
    return *mAnswer;
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mArrived;
  int mCount{0};
  std::optional<Answer> mAnswer;
};

/// Writes @p items through @p space's write_async as @p caller and waits for the answer.
BatchResult<VoidResult> write_and_wait(
  Namespace& space, const CallerInfo* caller, std::span<const ValueWriteItem> items)
{
  const auto answers = std::make_shared<Answers<BatchResult<VoidResult>>>();
  space.write_async(RequestInfo{},
    caller,
    items,
    [answers](BatchResult<VoidResult> written, std::vector<VersionedNode>)
    { answers->receive(std::move(written)); });
  EXPECT_TRUE(answers->wait()) << "the write was not answered";
  EXPECT_EQ(answers->count(), 1);
  return answers->count() == 0 ? BatchResult<VoidResult>{} : answers->answer();
}

WriteValue attribute_write(const NodeId& nodeId, AttributeId attributeId, Variant value)
{
  WriteValue write;
  write.node_id() = nodeId;
  write.attribute_id() = utils::to_underlying(attributeId);
  write.value() = DataValue{std::move(value)};
  return write;
}

// What a Method's CallHandler kept: the request it was given and the completion it answers later.
struct KeptCall
{
  std::mutex mutex;
  const CallMethodRequest* request{nullptr};
  std::function<void(CallResult)> answer;
};

}  // namespace

// Part 4 section 5.10.4.2: a non-Value Attribute written with a value of another type is refused with
// Bad_TypeMismatch and is not stored, whether the server writes it (no CallerInfo) or a Client does. The
// LocalizedText DisplayName is the control that a write of the right type is applied.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-07-THE-IN-MEMORY-WRITE-REFUSES-A-NON-VALUE-ATTRIBUTE-OF-ANOTHER-TYPE, scope=function)
TEST(InMemoryNamespaceWrite, ANonValueAttributeOfAnotherTypeIsRefused)
{
  boost::asio::thread_pool pool{1};
  const auto inMemory = default_ns::Namespace::create("urn:test:in-memory-write", pool.get_executor());
  Namespace& space = *inMemory;
  const CallerInfo client;
  for (const CallerInfo* caller : {static_cast<const CallerInfo*>(nullptr), &client})
  {
    SCOPED_TRACE(caller == nullptr ? "the server's write" : "a Client's write");
    const NodeId objectId{0, String{caller == nullptr ? "in-memory-write:server" : "in-memory-write:client"}};
    const auto object = inMemory->create_node(objectId, NodeClass::Object);
    ASSERT_NE(object, nullptr);
    const std::vector<WriteValue> before{
      attribute_write(
        objectId, AttributeId::DisplayName, Variant{LocalizedText{LocaleId{"en"}, String{"Before"}}}),
      attribute_write(objectId, AttributeId::WriteMask, Variant{uint32_t{0}})};
    const std::vector<ValueWriteItem> setUp{{*object, before[0]}, {*object, before[1]}};
    const auto set = write_and_wait(space, caller, setUp);
    ASSERT_EQ(set.items.size(), 2u) << to_string(set.batchStatus.status_code());
    ASSERT_TRUE(set.items[0].is_good() && set.items[1].is_good())
      << "the Object's DisplayName or WriteMask was not set";

    const std::vector<WriteValue> writes{
      attribute_write(objectId, AttributeId::DisplayName, Variant{String{"x"}}),
      attribute_write(objectId, AttributeId::WriteMask, Variant{int32_t{1}}),
      attribute_write(
        objectId, AttributeId::DisplayName, Variant{LocalizedText{LocaleId{"en"}, String{"After"}}})};
    const std::vector<ValueWriteItem> items{{*object, writes[0]}, {*object, writes[1]}, {*object, writes[2]}};

    const auto answer = write_and_wait(space, caller, items);

    ASSERT_EQ(answer.items.size(), 3u) << to_string(answer.batchStatus.status_code());
    EXPECT_EQ(answer.items[0].status_code().as_status(), Status::BadTypeMismatch)
      << "DisplayName as a String: " << to_string(answer.items[0].status_code());
    EXPECT_EQ(answer.items[1].status_code().as_status(), Status::BadTypeMismatch)
      << "WriteMask as an Int32: " << to_string(answer.items[1].status_code());
    EXPECT_TRUE(answer.items[2].is_good())
      << "DisplayName as a LocalizedText: " << to_string(answer.items[2].status_code());
    const NodeDescription described = object->attributes();
    EXPECT_EQ(described.display_name(), (LocalizedText{LocaleId{"en"}, String{"After"}}));
    EXPECT_EQ(described.write_mask(), std::optional<AttributeWriteMask>{AttributeWriteMask{}});
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// NR-66 and NR-2 rule 4: a call item's request is valid until call_async returns. A Method's handler that
// answers after the return reads the request it was given, not what the caller's item holds by then.
// @relation(AC-COMP-ADDRSP-NAMESPACE-INTERFACE-09-A-LATER-CALL-HANDLER-READS-THE-REQUEST-IT-WAS-GIVEN, scope=function)
TEST(InMemoryNamespaceCall, AHandlerAnsweringAfterTheReturnReadsTheRequestItWasGiven)
{
  boost::asio::thread_pool pool{1};
  const auto inMemory = default_ns::Namespace::create("urn:test:in-memory-call", pool.get_executor());
  const NodeId objectId{0, "in-memory-call:object"};
  const NodeId methodId{0, "in-memory-call:method"};
  const auto object = inMemory->create_node(objectId, NodeClass::Object);
  const auto method = inMemory->create_node(methodId, NodeClass::Method);
  ASSERT_NE(object, nullptr);
  ASSERT_NE(method, nullptr);
  ASSERT_NE(method->method_call_source(), nullptr);
  const auto kept = std::make_shared<KeptCall>();
  ASSERT_TRUE(method->method_call_source()
                ->set_call_handler(
                  [kept](const CallMethodRequest& request,
                    shared_ptr<const MethodCallContext>,
                    std::function<void(CallResult)>
                      callback)
                  {
                    const std::lock_guard lock{kept->mutex};
                    kept->request = &request;
                    kept->answer = std::move(callback);
                  })
                .is_good());

  CallMethodRequest given;
  given.object_id() = objectId;
  given.method_id() = methodId;
  given.input_arguments().payload().push_back(Variant{uint32_t{7}});
  auto request = std::make_unique<CallMethodRequest>(given);
  auto items = std::make_unique<std::vector<CallItem>>();
  items->push_back(CallItem{*object, *method, *request, nullptr});
  const auto called = std::make_shared<Answers<BatchResult<std::optional<CallResult>>>>();
  Namespace& space = *inMemory;
  space.call_async(RequestInfo{},
    nullptr,
    *items,
    [called](BatchResult<std::optional<CallResult>> answer) { called->receive(std::move(answer)); });

  request->input_arguments().payload()[0] = Variant{uint32_t{9}};
  items.reset();
  request.reset();
  const CallMethodRequest* handed{nullptr};
  std::function<void(CallResult)> answer;
  {
    const std::lock_guard lock{kept->mutex};
    handed = kept->request;
    answer = std::move(kept->answer);
  }
  ASSERT_NE(handed, nullptr) << "the handler was not called";
  ASSERT_TRUE(answer) << "the handler was not called";
  CallMethodResult result;
  result.output_arguments().payload().push_back(handed->input_arguments().payload()[0]);
  answer(CallResult{std::move(result)});

  ASSERT_TRUE(called->wait());
  EXPECT_EQ(called->count(), 1);
  const auto completed = called->answer();
  ASSERT_EQ(completed.items.size(), 1u) << to_string(completed.batchStatus.status_code());
  ASSERT_TRUE(completed.items[0].has_value()) << "the namespace declined the Method it holds";
  ASSERT_TRUE(completed.items[0]->is_good()) << to_string(completed.items[0]->status_code());
  const auto& outputs = completed.items[0]->value().output_arguments().payload();
  ASSERT_EQ(outputs.size(), 1u);
  ASSERT_TRUE(outputs[0].is_uint32()) << "the output argument is not a UInt32";
  EXPECT_EQ(outputs[0].as<uint32_t>(), 7u) << "the handler read the caller's item, not its own request";
  ::ua::test_utils::drain_with_timeout(pool);
}
