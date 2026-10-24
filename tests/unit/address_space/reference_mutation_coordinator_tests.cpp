// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_address_space_change_event_emitter.h"
#include "ua_address_space_change_events.h"
#include "ua_attribute_wire.h"
#include "ua_base_model_change_event_payload.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_default_object_node.h"
#include "ua_error_detail.h"
#include "ua_event_notifier_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_sinks.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_objecttype_id.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"

#include <boost/asio/thread_pool.hpp>

#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace ua;

/// Keeps a copy of every Event emitted to it.
class CapturingEventSink final : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    events.push_back(event.clone());
  }

  std::vector<std::unique_ptr<BaseEvent>> events;
};

/// Collects the changes a handler receives, which run later on the executor, and waits for them.
class ChangeLog
{
public:
  void add(const detail::AddressSpaceChange& change)
  {
    {
      const std::lock_guard lock{mMutex};
      mChanges.push_back(change);
    }
    mArrived.notify_all();
  }

  /// Waits until a change of @p kind has arrived; false when none did within the timeout.
  bool wait_for_kind(detail::AddressSpaceChangeKind kind)
  {
    std::unique_lock lock{mMutex};
    return mArrived.wait_for(lock,
      std::chrono::seconds{5},
      [&]
      { return std::ranges::any_of(mChanges, [kind](const auto& change) { return change.kind == kind; }); });
  }

  std::vector<detail::AddressSpaceChange> of_kind(detail::AddressSpaceChangeKind kind)
  {
    const std::lock_guard lock{mMutex};
    std::vector<detail::AddressSpaceChange> selected;
    std::ranges::copy_if(
      mChanges, std::back_inserter(selected), [kind](const auto& change) { return change.kind == kind; });
    return selected;
  }

private:
  std::mutex mMutex;
  std::condition_variable mArrived;
  std::vector<detail::AddressSpaceChange> mChanges;
};

class ReferenceMutationCoordinatorTest : public ::testing::Test
{
protected:
  ReferenceMutationCoordinatorTest()
    : mAddressSpace(AddressSpace::create("urn:test:reference-coordinator", mThreadPool.get_executor()))
  {}

  void SetUp() override
  {
    create_reference_type(NodeId{ReferenceTypeId::HasEventSource});
    create_reference_type(NodeId{ReferenceTypeId::HasNotifier});
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeAccessor create_object(const NodeId& nodeId, bool subscribable = true)
  {
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::Object, {});
    EXPECT_TRUE(created.is_good());
    auto accessor = std::move(created).value();
    EventNotifierType notifier;
    if (subscribable)
    {
      notifier.set(EventNotifierType::Bit::SubscribeToEvents);
    }
    accessor.as<ObjectAccessor>()->set_event_notifier(notifier);
    return accessor;
  }

  NodeAccessor create_reference_type(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::ReferenceType, {});
    EXPECT_TRUE(created.is_good());
    return std::move(created).value();
  }

  NodeAccessor create_variable_type(
    const NodeId& nodeId, string_view browseName, std::vector<uint32_t> dimensions)
  {
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::VariableType, {});
    EXPECT_TRUE(created.is_good());
    auto accessor = std::move(created).value();
    auto variableType = accessor.as<VariableTypeAccessor>();
    EXPECT_TRUE(variableType.has_value());
    variableType->set_browse_name(QualifiedName{nodeId.namespace_index(), browseName});
    variableType->set_data_type(NodeId{DataTypeId::Int32});
    variableType->set_value_rank(ValueRank{2});
    variableType->set_array_dimensions(std::move(dimensions));
    return accessor;
  }

  static bool has_reference(
    const NodeAccessor& holder, const NodeId& referenceType, const NodeId& target, bool isForward = true)
  {
    return std::ranges::any_of(holder.get_references_sync(),
      [&referenceType, &target, isForward](const Reference& reference)
      {
        return reference.type_id() == referenceType && reference.target_id() == ExpandedNodeId{target} &&
               reference.is_forward() == isForward;
      });
  }

  /// Runs the explicit event-graph check the way a server implementer would, after building.
  ///
  /// No Reference change validates the event graph - Part 3 7.17 is an obligation on the
  /// address space a server presents, and the implementer is the party who knows when a build is finished.
  /// So these tests now do what an implementer does: perform the mutations, then ask. The detector itself
  /// is unchanged; only when it runs has moved.
  VoidResult validate_event_graph() const
  {
    return mAddressSpace->try_validate_event_graph_sync();
  }

  static void expect_cycle_rejection(const VoidResult& result)
  {
    EXPECT_EQ(result.status_code(), Status::BadReferenceNotAllowed);
    ASSERT_NE(result.status_code().shared_detail(), nullptr);
    EXPECT_EQ(result.status_code().shared_detail()->code, "EventReferenceCycle");
    EXPECT_FALSE(result.status_code().shared_detail()->context.empty());
    ASSERT_NE(result.status_code().shared_detail()->cause, nullptr);
    EXPECT_EQ(result.status_code().shared_detail()->cause->code, "EventReferenceCycleTarget");
    EXPECT_FALSE(result.status_code().shared_detail()->cause->context.empty());
  }

  boost::asio::thread_pool mThreadPool{4};
  std::optional<AddressSpace> mAddressSpace;
};

// The AddressSpace generation is the public invalidation token for derived declaration caches. It
// advances for committed graph changes and must remain stable when a change is refused.
// @relation(AC-COMP-SVR-REFMUT-08-MODEL-GENERATION, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, ModelGenerationAdvancesOnlyForCommittedMutations)
{
  const auto beforeNodeAdd = mAddressSpace->model_generation();
  const NodeId sourceId{1, "generation:source"};
  auto source = create_object(sourceId);
  EXPECT_GT(mAddressSpace->model_generation(), beforeNodeAdd);

  const NodeId targetId{1, "generation:target"};
  auto target = create_object(targetId);
  const NodeId organizes{ReferenceTypeId::Organizes};

  const auto beforeReferenceAdd = mAddressSpace->model_generation();
  ASSERT_TRUE(source.try_add_reference_sync(organizes, targetId).is_good());
  EXPECT_GT(mAddressSpace->model_generation(), beforeReferenceAdd);

  const auto beforeReferenceRemove = mAddressSpace->model_generation();
  ASSERT_TRUE(source.try_remove_reference_sync(organizes, targetId).is_good());
  EXPECT_GT(mAddressSpace->model_generation(), beforeReferenceRemove);

  const NodeId deletedId{1, "generation:deleted"};
  auto deleted = create_object(deletedId);
  EXPECT_EQ(deleted.get_node_id(), deletedId);
  const auto beforeNodeDelete = mAddressSpace->model_generation();
  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(deletedId, false).is_good());
  EXPECT_GT(mAddressSpace->model_generation(), beforeNodeDelete);

  // A refused mutation must leave the generation alone, or a derived cache would invalidate itself over a
  // change that never happened. Demonstrated with a fixed ArrayDimensions violation, because that is a
  // rejection the mutation path still makes: the event-graph check moved off this path to
  // AddressSpace::validate_event_graph_async, so closing an event cycle now commits and legitimately advances
  // the generation.
  const NodeId dimensionSupertypeId{1, "generation:dimension-supertype"};
  const NodeId dimensionSubtypeId{1, "generation:dimension-subtype"};
  auto dimensionSupertype = create_variable_type(dimensionSupertypeId, "GenerationSupertype", {4, 0});
  create_variable_type(dimensionSubtypeId, "GenerationSubtype", {9, 7});
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  const auto beforeRejection = mAddressSpace->model_generation();

  const auto rejected = dimensionSupertype.try_add_reference_sync(hasSubtype, dimensionSubtypeId);

  EXPECT_EQ(rejected.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(rejected.shared_detail(), nullptr);
  EXPECT_EQ(rejected.shared_detail()->code, "SubtypeArrayDimensionChanged");
  EXPECT_EQ(mAddressSpace->model_generation(), beforeRejection);
  EXPECT_FALSE(has_reference(dimensionSupertype, hasSubtype, dimensionSubtypeId));
}

// Part 3 section 6.2.7 permits a subtype to fill a zero ArrayDimensions entry but forbids it from
// changing a non-zero entry fixed by its supertype. Part 4 section 5.7.3.4 assigns
// Bad_ReferenceNotAllowed to a Reference that violates the data model.
// @relation(AC-SVR-ADDRSP-132-ARRAYDIMENSIONS-FIXED-ON-SUBTYPE, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, VariableTypeSubtypeCannotRewriteAFixedArrayDimension)
{
  const NodeId supertypeId{1, "dimensions:supertype"};
  const NodeId validSubtypeId{1, "dimensions:valid-subtype"};
  const NodeId invalidSubtypeId{1, "dimensions:invalid-subtype"};
  auto supertype = create_variable_type(supertypeId, "DimensionSupertype", {4, 0});
  auto validSubtype = create_variable_type(validSubtypeId, "ValidDimensionSubtype", {4, 7});
  auto invalidSubtype = create_variable_type(invalidSubtypeId, "InvalidDimensionSubtype", {9, 7});
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};

  // The address space adds the inverse half on the subtype (NR-70 B8).
  ASSERT_TRUE(supertype.try_add_reference_sync(hasSubtype, validSubtypeId).is_good());

  const auto generationBeforeRejection = mAddressSpace->model_generation();
  const auto rejectedForward = supertype.try_add_reference_sync(hasSubtype, invalidSubtypeId);
  EXPECT_EQ(rejectedForward.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(rejectedForward.shared_detail(), nullptr);
  EXPECT_EQ(rejectedForward.shared_detail()->code, "SubtypeArrayDimensionChanged");
  EXPECT_EQ(mAddressSpace->model_generation(), generationBeforeRejection);
  EXPECT_FALSE(has_reference(supertype, hasSubtype, invalidSubtypeId));

  const auto rejectedInverse = invalidSubtype.try_add_reference_sync(hasSubtype, supertypeId, false);
  EXPECT_EQ(rejectedInverse.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(rejectedInverse.shared_detail(), nullptr);
  EXPECT_EQ(rejectedInverse.shared_detail()->code, "SubtypeArrayDimensionChanged");
  EXPECT_FALSE(has_reference(invalidSubtype, hasSubtype, supertypeId, false));
}

// Part 3 section 5.4 forbids the Server Object's membership of a View, not a Reference to it (NR-41): the
// Browse service keeps the Server Object out of every View by NodeId. Both endpoint-storage forms of an
// Organizes Reference between a View Node and the Server Object are therefore stored.
// @relation(AC-SVR-EVT-ATTR-007-VIEW-REFERENCE-TO-SERVER-OBJECT-STORED, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, AReferenceBetweenAViewAndTheServerObjectIsStored)
{
  const NodeId serverId{ObjectId::Server};
  auto server = create_object(serverId);
  const NodeId viewId{1, "server-membership:view"};
  auto createdView = mAddressSpace->try_create_node_sync(viewId, NodeClass::View, {});
  ASSERT_TRUE(createdView.is_good());
  auto view = std::move(createdView).value();
  const NodeId organizes{ReferenceTypeId::Organizes};

  const auto forward = view.try_add_reference_sync(organizes, serverId);
  EXPECT_EQ(forward.status_code(), Status::Good) << "the forward half from the View Node was refused";
  EXPECT_TRUE(has_reference(view, organizes, serverId));

  const auto inverse = server.try_add_reference_sync(organizes, viewId, false);
  EXPECT_EQ(inverse.status_code(), Status::Good) << "the inverse half from the Server Object was refused";
  EXPECT_TRUE(has_reference(server, organizes, viewId, false));
}

// Part 3 section 7.17 applies to the logical edge, whichever endpoint stores it. Both closing forms must
// fail before their copy-on-write snapshots are published.
// @relation(AC-SVR-ADDRSP-172-HASEVENTSOURCE-LOOP-FREE, scope=function)
// @relation(AC-COMP-SVR-REFMUT-01-ATOMIC-FINAL-GRAPH, scope=function)
// @relation(AC-COMP-SVR-REFMUT-07-PRODUCTION-ADAPTER, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, DirectAndInverseClosingEdgesBothCommitAndTheDetectorFindsEither)
{
  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
  const std::array<NodeId, 6> ids{NodeId{1, "direct:A"},
    NodeId{1, "direct:B"},
    NodeId{1, "direct:C"},
    NodeId{1, "inverse:A"},
    NodeId{1, "inverse:B"},
    NodeId{1, "inverse:C"}};
  std::vector<NodeAccessor> nodes;
  for (const auto& id : ids)
  {
    nodes.push_back(create_object(id));
  }

  // The closing edge now commits - the mutation path does not validate - so the detector is asked
  // afterwards, which is what a server implementer does once a build is finished. What is being proved is
  // unchanged: the detector finds the loop whichever endpoint stores the closing edge.
  nodes[0].add_reference_sync(hasEventSource, ids[1]);
  nodes[1].add_reference_sync(hasEventSource, ids[2]);
  ASSERT_TRUE(validate_event_graph().is_good()) << "three nodes in a chain are not a loop";

  ASSERT_TRUE(nodes[2].try_add_reference_sync(hasEventSource, ids[0]).is_good());
  EXPECT_TRUE(has_reference(nodes[2], hasEventSource, ids[0]));
  expect_cycle_rejection(validate_event_graph());

  // Undo it, so the inverse form is judged on its own rather than on the loop left behind.
  nodes[2].remove_reference_sync(hasEventSource, ids[0]);
  ASSERT_TRUE(validate_event_graph().is_good()) << "removing the closing edge must clear the loop";

  nodes[3].add_reference_sync(hasEventSource, ids[4]);
  nodes[4].add_reference_sync(hasEventSource, ids[5]);
  ASSERT_TRUE(validate_event_graph().is_good());

  ASSERT_TRUE(nodes[3].try_add_reference_sync(hasEventSource, ids[5], /*isForward=*/false).is_good());
  EXPECT_TRUE(has_reference(nodes[3], hasEventSource, ids[5], /*isForward=*/false));
  expect_cycle_rejection(validate_event_graph());
}

// Part 3 section 5.3.3.3 inherits loop and endpoint constraints into custom ReferenceTypes.
// @relation(AC-SVR-ADDRSP-172-HASEVENTSOURCE-LOOP-FREE, scope=function)
// @relation(AC-SVR-ADDRSP-173-HASNOTIFIER-TARGET-SUBSCRIBABLE, scope=function)
// @relation(AC-COMP-SVR-REFMUT-01-ATOMIC-FINAL-GRAPH, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, CustomEventFamilySubtypesInheritLoopAndNotifierConstraints)
{
  const NodeId customEventSource{1, "CustomEventSource"};
  const NodeId customNotifier{1, "CustomNotifier"};
  auto eventType = create_reference_type(customEventSource);
  auto notifierType = create_reference_type(customNotifier);
  eventType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ReferenceTypeId::HasEventSource}, false);
  notifierType.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubtype}, NodeId{ReferenceTypeId::HasNotifier}, false);

  const NodeId aId{1, "custom:A"};
  const NodeId bId{1, "custom:B"};
  const NodeId deadEndId{1, "custom:dead-end"};
  auto a = create_object(aId);
  auto b = create_object(bId);
  auto deadEnd = create_object(deadEndId, /*subscribable=*/false);
  // A custom subtype of HasEventSource inherits the loop constraint: the detector classifies by the live
  // HasSubtype closure, exactly as Part 3 7.17's "or of its subtypes" requires.
  a.add_reference_sync(customEventSource, bId);
  ASSERT_TRUE(b.try_add_reference_sync(customEventSource, aId).is_good());
  expect_cycle_rejection(validate_event_graph());
  b.remove_reference_sync(customEventSource, aId);
  ASSERT_TRUE(validate_event_graph().is_good());

  // And a custom subtype of HasNotifier inherits the notifier constraint: its target must be a
  // subscribable Object. This is a node-class rule rather than a loop, so it carries its own detail.
  ASSERT_TRUE(a.try_add_reference_sync(customNotifier, deadEndId).is_good());
  EXPECT_TRUE(has_reference(a, customNotifier, deadEndId));
  const auto verdict = validate_event_graph();
  EXPECT_EQ(verdict.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(verdict.status_code().shared_detail(), nullptr);
  EXPECT_EQ(verdict.status_code().shared_detail()->code, "EventReferenceTargetNotSubscribable");
}

// A batch is validated as one overlay, and making a previously ordinary custom ReferenceType an
// event-family subtype validates every pre-existing edge before the HasSubtype commit.
// @relation(AC-SVR-ADDRSP-172-HASEVENTSOURCE-LOOP-FREE, scope=function)
// @relation(AC-COMP-SVR-REFMUT-01-ATOMIC-FINAL-GRAPH, scope=function)
// @relation(AC-COMP-SVR-REFMUT-02-LIVE-TYPE-CLASSIFICATION, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, BatchOverlayAndReferenceTypeReclassificationValidateTheFinalGraph)
{
  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
  const NodeId aId{1, "batch:A"};
  const NodeId bId{1, "batch:B"};
  const NodeId cId{1, "batch:C"};
  auto a = create_object(aId);
  auto b = create_object(bId);
  auto c = create_object(cId);
  b.add_reference_sync(hasEventSource, cId);
  c.add_reference_sync(hasEventSource, aId);

  std::vector<Reference> overlay;
  overlay.emplace_back(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{cId}, true);
  overlay.emplace_back(hasEventSource, ExpandedNodeId{bId}, true);
  // A batch commits as one overlay, so both its references land; the detector then judges the graph that
  // overlay produced. Atomicity of the batch is what is being checked here, not the timing of the check.
  ASSERT_TRUE(a.try_add_references_sync(std::move(overlay)).is_good());
  EXPECT_TRUE(has_reference(a, NodeId{ReferenceTypeId::Organizes}, cId));
  EXPECT_TRUE(has_reference(a, hasEventSource, bId));
  expect_cycle_rejection(validate_event_graph());

  // Cleared, so the reclassification below is judged on its own edges.
  a.remove_reference_sync(hasEventSource, bId);
  ASSERT_TRUE(validate_event_graph().is_good());

  const NodeId customTypeId{1, "ReclassifiedEventSource"};
  auto customType = create_reference_type(customTypeId);
  const NodeId xId{1, "reclass:X"};
  const NodeId yId{1, "reclass:Y"};
  auto x = create_object(xId);
  auto y = create_object(yId);
  x.add_reference_sync(customTypeId, yId);
  y.add_reference_sync(customTypeId, xId);

  // X and Y already point at each other with an ordinary custom ReferenceType, which is no loop while that
  // type is ordinary.
  ASSERT_TRUE(validate_event_graph().is_good());

  // Making that type a subtype of HasEventSource reclassifies both existing edges, and the loop they now
  // form is the detector's to find. Classification is derived when the graph is checked, so it reads the
  // live HasSubtype hierarchy rather than anything cached at mutation time.
  ASSERT_TRUE(
    customType
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, hasEventSource, /*isForward=*/false)
      .is_good());
  EXPECT_TRUE(has_reference(customType,
    NodeId{ReferenceTypeId::HasSubtype},
    hasEventSource,
    /*isForward=*/false));
  expect_cycle_rejection(validate_event_graph());
}

// Deleting a ReferenceType removes it from the final HasSubtype graph even when the surviving
// supertype retains its peer-side edge. The deleted type therefore cannot keep ordinary references
// classified as event-family edges.
// @relation(AC-SVR-ADDRSP-172-HASEVENTSOURCE-LOOP-FREE, scope=function)
// @relation(AC-COMP-SVR-REFMUT-02-LIVE-TYPE-CLASSIFICATION, scope=function)
TEST_F(ReferenceMutationCoordinatorTest,
  DeletingReferenceTypeDropsClassificationEvenWhenPeerHasSubtypeReferenceRemains)
{
  const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
  const NodeId deletedTypeId{1, "DeletedEventSourceSubtype"};
  auto retainedDeletedType = create_reference_type(deletedTypeId);
  EXPECT_EQ(retainedDeletedType.get_node_id(), deletedTypeId);
  auto eventSourceType = mAddressSpace->find_node_sync(hasEventSource);
  eventSourceType.add_reference_sync(hasSubtype, deletedTypeId);

  const NodeId sourceId{1, "deleted-type:source"};
  const NodeId targetId{1, "deleted-type:target"};
  auto source = create_object(sourceId);
  auto target = create_object(targetId);
  source.add_reference_sync(deletedTypeId, targetId);

  // While the custom type IS a subtype of HasEventSource, the two edges form a loop the detector finds.
  ASSERT_TRUE(target.try_add_reference_sync(deletedTypeId, sourceId).is_good());
  EXPECT_TRUE(has_reference(target, deletedTypeId, sourceId));
  expect_cycle_rejection(validate_event_graph());

  // Delete the ReferenceType itself, which removes both halves of its HasSubtype, then give HasEventSource
  // back its peer-side HasSubtype edge, pointing at a node that no longer exists.
  const auto deleted = mAddressSpace->try_delete_node_sync(deletedTypeId, false);
  ASSERT_TRUE(deleted.is_good());
  ASSERT_TRUE(eventSourceType.try_add_reference_sync(hasSubtype, deletedTypeId).is_good());
  EXPECT_TRUE(has_reference(eventSourceType, hasSubtype, deletedTypeId));

  // The loop is still physically there - the same two references between source and target - but the type
  // holding it is gone, so classification no longer counts it as an event-family edge and the graph is
  // clean. That is the point: classification describes the live graph, and a surviving half-edge to a
  // deleted node does not keep a type classified.
  EXPECT_TRUE(has_reference(target, deletedTypeId, sourceId));
  EXPECT_TRUE(validate_event_graph().is_good())
    << "a deleted ReferenceType must stop classifying its references as event-family edges";
}

// Two opposite edges committed concurrently both commit - see the note in the body - and the loop they form
// is found by the explicit detector rather than refused at mutation time.
// @relation(AC-SVR-ADDRSP-172-HASEVENTSOURCE-LOOP-FREE, scope=function)
// @relation(AC-COMP-SVR-REFMUT-06-CONCURRENT-LINEARIZATION, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, ConcurrentOppositeEdgesBothCommitAndTheDetectorFindsTheLoop)
{
  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
  const NodeId aId{1, "concurrent:A"};
  const NodeId bId{1, "concurrent:B"};
  auto a = create_object(aId);
  auto b = create_object(bId);
  std::barrier start{3};
  std::array<VoidResult, 2> outcomes;
  std::thread first(
    [&]
    {
      start.arrive_and_wait();
      outcomes[0] = a.try_add_reference_sync(hasEventSource, bId);
    });
  std::thread second(
    [&]
    {
      start.arrive_and_wait();
      outcomes[1] = b.try_add_reference_sync(hasEventSource, aId);
    });
  start.arrive_and_wait();
  first.join();
  second.join();

  // Both commit. "Exactly one winner" was a consequence of validating on the mutation path: the loser was
  // the one whose edge would have closed a cycle. With the check moved to
  // AddressSpace::validate_event_graph_async neither is refused, so what the gate still guarantees is
  // linearisation - both mutations are applied, in some order, with no torn state - and the loop they form is
  // the detector's to find afterwards.
  EXPECT_TRUE(outcomes[0].is_good()) << outcomes[0].status_code().as_uint32();
  EXPECT_TRUE(outcomes[1].is_good()) << outcomes[1].status_code().as_uint32();
  EXPECT_TRUE(has_reference(a, hasEventSource, bId));
  EXPECT_TRUE(has_reference(b, hasEventSource, aId));
  expect_cycle_rejection(validate_event_graph());
}

// A delete racing a Reference change cannot leave an edge the explicit check misses, and a Node kept after
// its namespace is gone refuses a Reference change made on it.
// @relation(AC-SVR-ADDRSP-172-HASEVENTSOURCE-LOOP-FREE, scope=function)
// @relation(AC-COMP-SVR-REFMUT-03-EXPIRED-LIFETIME, scope=function)
// @relation(AC-COMP-SVR-REFMUT-05-WEAK-ENDPOINT-REGISTRY, scope=function)
// @relation(AC-COMP-SVR-REFMUT-07-PRODUCTION-ADAPTER, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, DeletionRaceAndExpiredCoordinatorCannotBypassTheInvariant)
{
  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
  const NodeId aId{1, "delete:A"};
  const NodeId bId{1, "delete:B"};
  auto a = create_object(aId);
  auto b = create_object(bId);
  b.add_reference_sync(hasEventSource, aId);

  std::barrier start{3};
  VoidResult addResult;
  VoidResult deleteResult;
  std::thread addThread(
    [&]
    {
      start.arrive_and_wait();
      addResult = a.try_add_reference_sync(hasEventSource, bId);
    });
  std::thread deleteThread(
    [&]
    {
      start.arrive_and_wait();
      deleteResult = mAddressSpace->try_delete_node_sync(bId, false);
    });
  start.arrive_and_wait();
  addThread.join();
  deleteThread.join();

  EXPECT_TRUE(deleteResult.is_good());
  EXPECT_TRUE(mAddressSpace->try_find_node_sync(bId).is_bad()) << "b should no longer resolve";

  // Three outcomes are reachable now that the mutation path does not validate, and each is asserted on its
  // own terms rather than by one statement weak enough to cover all of them. The message carries both
  // verdicts, because which outcome a run produced is the first thing anyone reading a failure needs.
  const bool edgePresent = has_reference(a, hasEventSource, bId);
  std::ostringstream outcomeText;
  outcomeText << "addResult=" << static_cast<uint32_t>(addResult.status_code().value())
              << " deleteResult=" << static_cast<uint32_t>(deleteResult.status_code().value()) << " a holds "
              << a.get_references_sync().size() << " reference(s)";
  const std::string outcome = outcomeText.str();

  if (addResult.is_bad())
  {
    // The add lost: refused against a holder or target that had gone. A refused mutation leaves nothing.
    EXPECT_FALSE(edgePresent) << "a refused add left its reference in the store; " << outcome;
  }
  else if (!edgePresent)
  {
    // The usual outcome: the add committed, the delete ran second and stripped the peer's edge into the
    // node it removed, so nothing dangles.
    SUCCEED() << outcome;
  }
  else
  {
    // The add landed after the delete had taken its view of b's peers, so a holds an event edge to a node
    // that is gone. The mutation path does not check that a target resolves, so this commits and reports
    // success; the check that finds it is the explicit one, which is the point of having it. Asserting the
    // detail code is what stops the dangling edge being silent.
    const auto dangling = validate_event_graph();
    EXPECT_EQ(dangling.status_code(), Status::BadReferenceNotAllowed) << outcome;
    ASSERT_NE(dangling.status_code().shared_detail(), nullptr) << outcome;
    EXPECT_EQ(dangling.status_code().shared_detail()->code, "EventReferenceTargetUnavailable") << outcome;
    // Removed, so the expiry assertions below read a graph the check accepts.
    a.remove_reference_sync(hasEventSource, bId);
    EXPECT_TRUE(validate_event_graph().is_good()) << outcome;
  }

  // A Node kept after its namespace is gone refuses a change. An accessor with no address space answers
  // Bad_Shutdown before it reaches the Node (COMP-ADDRSP-ACCESSOR-ROUTE-01), so the mutations are invoked on
  // the retained Node.
  const auto answered = [](auto invoke)
  {
    std::promise<VoidResult> done;
    invoke([&done](VoidResult result) { done.set_value(std::move(result)); });
    return done.get_future().get();
  };
  const Variant notifiesEvents =
    attribute_wire::event_notifier(EventNotifierType{EventNotifierType::Bit::SubscribeToEvents});
  auto standalone = default_ns::Namespace::create("urn:test:standalone", mThreadPool.get_executor());
  shared_ptr<default_ns::ObjectNode> retained =
    standalone->create_node<default_ns::ObjectNode>(NodeId{0, "standalone:A"});
  shared_ptr<default_ns::ObjectNode> target =
    standalone->create_node<default_ns::ObjectNode>(NodeId{0, "standalone:B"});
  for (const auto& node : {retained, target})
  {
    ASSERT_TRUE(answered(
      [&](auto done) {
        node->write_attribute_async(AttributeId::EventNotifier, notifiesEvents, std::move(done));
      }).is_good());
  }
  const auto addEventSource = [&]
  {
    return answered(
      [&](auto done) {
        retained->add_reference_async(
          hasEventSource, ExpandedNodeId{target->node_id()}, true, std::move(done));
      });
  };
  EXPECT_TRUE(addEventSource().is_good());
  standalone.reset();
  const auto expired = addEventSource();
  EXPECT_EQ(expired.status_code(), Status::BadInvalidState);
  ASSERT_NE(expired.status_code().shared_detail(), nullptr);
  EXPECT_EQ(expired.status_code().shared_detail()->code, "NamespaceUnavailable");
}

// The address space resolves both namespaces without introducing strong endpoint ownership and permits an
// acyclic cross-namespace event graph.
// @relation(AC-SVR-ADDRSP-172-HASEVENTSOURCE-LOOP-FREE, scope=function)
// @relation(AC-COMP-SVR-REFMUT-04-CROSS-NAMESPACE-RESOLUTION, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, ValidCrossNamespaceEventGraphCommits)
{
  auto secondNamespace =
    default_ns::Namespace::create("urn:test:reference-coordinator:second", mThreadPool.get_executor());
  const uint16_t secondIndex = mAddressSpace->add_namespace_sync(std::move(secondNamespace));
  const NodeId sourceId{1, "cross:source"};
  const NodeId targetId{secondIndex, "cross:target"};
  auto source = create_object(sourceId);
  auto target = create_object(targetId);

  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
  EXPECT_TRUE(source.try_add_reference_sync(hasEventSource, targetId).is_good());
  EXPECT_TRUE(target.try_add_reference_sync(hasEventSource, sourceId, /*isForward=*/false).is_good());
  EXPECT_TRUE(has_reference(source, hasEventSource, targetId));
  EXPECT_TRUE(has_reference(target, hasEventSource, sourceId, /*isForward=*/false));
}

// The deterministic half of the deletion race above: the mutation path does not check that a reference's
// target still resolves, so an event edge to a node that has just been deleted commits and reports success.
// Nothing about that is silent, and this states where it is caught - the explicit check names the target it
// could not resolve. Written as its own test because the race version only reaches this outcome when the
// scheduler happens to order it that way, and a claim only a lucky interleaving proves is not proven.
TEST_F(ReferenceMutationCoordinatorTest, AnEventEdgeToADeletedTargetCommitsAndTheCheckNamesTheTarget)
{
  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
  const NodeId sourceId{1, "dangling:source"};
  const NodeId targetId{1, "dangling:target"};
  auto source = create_object(sourceId);
  create_object(targetId);
  ASSERT_TRUE(validate_event_graph().is_good());

  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(targetId, false).is_good());
  ASSERT_TRUE(mAddressSpace->try_find_node_sync(targetId).is_bad());

  EXPECT_TRUE(source.try_add_reference_sync(hasEventSource, targetId).is_good())
    << "adding an event edge to a deleted target is expected to commit; the check, not the mutation, "
       "is what reports it";
  EXPECT_TRUE(has_reference(source, hasEventSource, targetId));

  const auto dangling = validate_event_graph();
  EXPECT_EQ(dangling.status_code(), Status::BadReferenceNotAllowed);
  ASSERT_NE(dangling.status_code().shared_detail(), nullptr);
  EXPECT_EQ(dangling.status_code().shared_detail()->code, "EventReferenceTargetUnavailable");

  source.remove_reference_sync(hasEventSource, targetId);
  EXPECT_TRUE(validate_event_graph().is_good()) << "removing the dangling edge must clear the finding";
}

// A cross-namespace boundary does not partition the event-reference graph. The second edge closes the same
// logical cycle as a local edge; it commits, and the address space's check, which walks every namespace,
// finds it. Two per-namespace detectors would each see half of this graph and each pass it.
// @relation(AC-SVR-ADDRSP-172-HASEVENTSOURCE-LOOP-FREE, scope=function)
// @relation(AC-COMP-SVR-REFMUT-01-ATOMIC-FINAL-GRAPH, scope=function)
// @relation(AC-COMP-SVR-REFMUT-04-CROSS-NAMESPACE-RESOLUTION, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, CrossNamespaceClosingCycleCommitsAndTheSharedDetectorFindsIt)
{
  auto secondNamespace =
    default_ns::Namespace::create("urn:test:reference-coordinator:closing", mThreadPool.get_executor());
  const uint16_t secondIndex = mAddressSpace->add_namespace_sync(std::move(secondNamespace));
  const NodeId sourceId{1, "cross-cycle:source"};
  const NodeId targetId{secondIndex, "cross-cycle:target"};
  auto source = create_object(sourceId);
  auto target = create_object(targetId);

  const NodeId hasEventSource{ReferenceTypeId::HasEventSource};
  ASSERT_TRUE(source.try_add_reference_sync(hasEventSource, targetId).is_good());

  // The loop closes across a namespace boundary, which is why the check walks every namespace: two
  // per-namespace detectors would each see half of this and each pass it.
  ASSERT_TRUE(target.try_add_reference_sync(hasEventSource, sourceId).is_good());
  EXPECT_TRUE(has_reference(source, hasEventSource, targetId));
  EXPECT_TRUE(has_reference(target, hasEventSource, sourceId));
  expect_cycle_rejection(validate_event_graph());
}

// Part 3 section section 5.6.2 and 9.33.1: a committed Value change on a Property carrying the SemanticChange
// AccessLevel bit identifies the Property's owner and that owner's TypeDefinition.
// @relation(AC-SVR-ADDRSP-088-SEMANTICCHANGEEVENT-RAISED, scope=function)
// @relation(AC-SVR-BASE-023-SEMANTICCHANGEEVENT, scope=function)
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-01-SEMANTIC-PAYLOAD, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, FlaggedPropertyValueWriteReportsItsOwnerAndType)
{
  const auto log = std::make_shared<ChangeLog>();
  detail::AddressSpaceChangeEvents::set_handler(
    *mAddressSpace, [log](const detail::AddressSpaceChange& change) { log->add(change); });

  const NodeId ownerId{1, "semantic:owner"};
  const NodeId propertyId{1, "semantic:property"};
  const NodeId ownerType{ObjectTypeId::BaseObjectType};
  auto owner = mAddressSpace->create_node_sync(ownerId, NodeClass::Object);
  owner.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, ownerType);
  auto property = mAddressSpace->create_node_sync(propertyId, NodeClass::Variable);
  auto variable = property.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->write_value_sync(double{1.0});
  variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
    AccessLevelType::Bit::CurrentWrite,
    AccessLevelType::Bit::SemanticChange});
  owner.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
  property.add_reference_sync(
    NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{ownerId}, /*isForward=*/false);

  variable->write_value_sync(double{2.0});

  // The in-memory namespace reports the change later, on the executor; a Model change made afterwards
  // marks the point by which a second Semantic change would have arrived. Linking a NodeVersion to an Object
  // is a change of a versioned Node, which raises one.
  ASSERT_TRUE(log->wait_for_kind(detail::AddressSpaceChangeKind::Semantic));
  auto marker = create_object(NodeId{1, "semantic:marker"});
  auto markerVersion =
    mAddressSpace->create_node_sync(NodeId{1, "semantic:marker-version"}, NodeClass::Variable);
  markerVersion.set_browse_name(QualifiedName{0, "NodeVersion"});
  auto markerVersionValue = markerVersion.as<VariableAccessor>();
  ASSERT_TRUE(markerVersionValue.has_value());
  markerVersionValue->write_value_sync(String{"1"});
  ASSERT_TRUE(marker.try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, markerVersion.get_node_id())
                .is_good());
  ASSERT_TRUE(log->wait_for_kind(detail::AddressSpaceChangeKind::Model));

  const auto semantic = log->of_kind(detail::AddressSpaceChangeKind::Semantic);
  ASSERT_EQ(semantic.size(), 1u);
  ASSERT_EQ(semantic.front().changes.size(), 1u);
  EXPECT_EQ(semantic.front().changes.front().affected, ownerId);
  EXPECT_EQ(semantic.front().changes.front().affectedType, ownerType);
}

// Part 3 section section 9.32.1-9.32.2 couples a versioned Variable's DataType change to both a NodeVersion
// advance and a ModelChangeEvent. An unversioned Variable is the negative control.
// @relation(AC-SVR-ADDRSP-245-NODEVERSION-MODELCHANGE-INVARIANT, scope=function)
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-02-VERSIONED-DATATYPE, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, VersionedDataTypeWriteAdvancesVersionAndReportsExactChange)
{
  std::vector<detail::AddressSpaceChange> changes;
  detail::AddressSpaceChangeEvents::set_handler(
    *mAddressSpace, [&changes](const detail::AddressSpaceChange& change) { changes.push_back(change); });

  const NodeId variableId{1, "datatype:versioned"};
  const NodeId unversionedId{1, "datatype:unversioned"};
  const NodeId versionId{1, "datatype:node-version"};
  const NodeId variableType{VariableTypeId::BaseDataVariableType};
  auto created = mAddressSpace->create_node_sync(variableId, NodeClass::Variable);
  auto variable = created.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_data_type(NodeId{DataTypeId::Int32});
  created.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, variableType);

  auto versionNode = mAddressSpace->create_node_sync(versionId, NodeClass::Variable);
  versionNode.set_browse_name(QualifiedName{0, "NodeVersion"});
  auto version = versionNode.as<VariableAccessor>();
  ASSERT_TRUE(version.has_value());
  version->write_value_sync(String{"before"});
  created.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, versionId);
  versionNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{variableId}, /*isForward=*/false);

  auto unversionedNode = mAddressSpace->create_node_sync(unversionedId, NodeClass::Variable);
  auto unversioned = unversionedNode.as<VariableAccessor>();
  ASSERT_TRUE(unversioned.has_value());
  // Linking the NodeVersion was itself a change of the Variable; the writes are counted from here.
  const auto beforeVersion = version->read_value_sync();
  changes.clear();
  unversioned->set_data_type(NodeId{DataTypeId::Double});
  EXPECT_TRUE(changes.empty()) << "the Variable without NodeVersion raised a change";

  variable->set_data_type(NodeId{DataTypeId::Double});

  const auto after = version->read_value_sync();
  const auto* afterText = after.value().try_as<String>();
  ASSERT_NE(afterText, nullptr);
  EXPECT_NE(after.value(), beforeVersion.value()) << "the DataType change left the NodeVersion unchanged";
  ASSERT_EQ(changes.size(), 1u);
  EXPECT_EQ(changes.front().kind, detail::AddressSpaceChangeKind::Model);
  EXPECT_FALSE(changes.front().unspecified);
  ASSERT_EQ(changes.front().changes.size(), 1u);
  EXPECT_EQ(changes.front().changes.front().affected, variableId);
  EXPECT_EQ(changes.front().changes.front().affectedType, variableType);
  EXPECT_EQ(changes.front().changes.front().verbs,
    static_cast<uint8_t>(static_cast<int32_t>(ModelChangeStructureVerbMask::DataTypeChanged)));

  const std::string versionAfterChange{static_cast<string_view>(*afterText)};
  variable->set_data_type(NodeId{DataTypeId::Double});

  const auto afterNoOp = version->read_value_sync();
  const auto* afterNoOpText = afterNoOp.value().try_as<String>();
  ASSERT_NE(afterNoOpText, nullptr);
  EXPECT_EQ(static_cast<string_view>(*afterNoOpText), versionAfterChange);
  EXPECT_EQ(changes.size(), 1u);
}

// A malformed published NodeVersion cannot be silently ignored after the DataType commit: the write is stored
// and answers the generic Uncertain with the exact ErrorDetail (delivery decision DL-22 as reversed).
// @relation(AC-SVR-ADDRSP-245-NODEVERSION-MODELCHANGE-INVARIANT, scope=function)
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-03-BOUNDARY-FAILURES, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, MalformedNodeVersionPreservesRichDataTypeWriteFailure)
{
  const NodeId variableId{1, "datatype:malformed"};
  const NodeId versionId{1, "datatype:malformed-version"};
  auto created = mAddressSpace->create_node_sync(variableId, NodeClass::Variable);
  auto variable = created.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_data_type(NodeId{DataTypeId::Int32});
  auto versionNode = mAddressSpace->create_node_sync(versionId, NodeClass::Variable);
  versionNode.set_browse_name(QualifiedName{0, "NodeVersion"});
  auto version = versionNode.as<VariableAccessor>();
  ASSERT_TRUE(version.has_value());
  version->write_value_sync(uint32_t{7});
  created.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, versionId);

  const auto result =
    variable->try_write_attribute_sync(AttributeId::DataType, Variant{NodeId{DataTypeId::Double}});

  EXPECT_EQ(result.status_code().as_uint32(), 0x40000000u) << to_string(result.status_code());
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NodeVersionTypeMismatch");
  EXPECT_EQ(variable->get_data_type(), NodeId{DataTypeId::Double}) << "the DataType was not stored";
}

// Part 3 section 5.6.2, Table 13: a change of a Variable's ValueRank or ArrayDimensions updates its
// NodeVersion, and section 9.32.2 ties each NodeVersion change to a ModelChangeEvent. No
// ModelChangeStructureVerbMask verb names these Attributes, so the Event is a BaseModelChangeEvent. The
// changes reach the emitter the Server wires to the address space. A repeated write and a Variable without
// NodeVersion are the controls.
// @relation(AC-SVR-ADDRSP-262-VALUERANK-ARRAYDIMENSIONS-ADVANCE-NODEVERSION, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, VersionedValueRankAndArrayDimensionsWritesAdvanceTheVersion)
{
  auto sink = std::make_shared<CapturingEventSink>();
  auto emitter = std::make_shared<server::AddressSpaceChangeEventEmitter>(sink);
  detail::AddressSpaceChangeEvents::set_handler(
    *mAddressSpace, [emitter](const detail::AddressSpaceChange& change) { emitter->emit(change); });

  const NodeId variableId{1, "shape:versioned"};
  const NodeId versionId{1, "shape:node-version"};
  const NodeId unversionedId{1, "shape:unversioned"};
  auto created = mAddressSpace->create_node_sync(variableId, NodeClass::Variable);
  auto variable = created.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_data_type(NodeId{DataTypeId::Int32});
  variable->set_value_rank(ValueRank{ValueRank::scalar});
  created.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});

  auto versionNode = mAddressSpace->create_node_sync(versionId, NodeClass::Variable);
  versionNode.set_browse_name(QualifiedName{0, "NodeVersion"});
  auto version = versionNode.as<VariableAccessor>();
  ASSERT_TRUE(version.has_value());
  version->write_value_sync(String{"before"});
  created.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, versionId);
  versionNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{variableId}, /*isForward=*/false);

  auto unversionedNode = mAddressSpace->create_node_sync(unversionedId, NodeClass::Variable);
  auto unversioned = unversionedNode.as<VariableAccessor>();
  ASSERT_TRUE(unversioned.has_value());
  unversioned->set_value_rank(ValueRank{ValueRank::scalar});
  // Linking the NodeVersion was itself a change of the Variable, raised before the link answered.
  const auto built = sink->events.size();

  const auto readVersion = [&version]() -> std::string
  {
    const auto value = version->read_value_sync();
    const auto* text = value.value().try_as<String>();
    return text == nullptr ? std::string{"<not a String>"} : std::string{static_cast<string_view>(*text)};
  };
  const auto expectOneBaseModelChange = [&sink](std::size_t index, const char* what)
  {
    ASSERT_GT(sink->events.size(), index) << what << " raised no Event";
    const auto* event = dynamic_cast<const BaseModelChangeEventPayload*>(sink->events[index].get());
    ASSERT_NE(event, nullptr) << what << " raised an Event that is not a ModelChangeEvent";
    EXPECT_EQ(event->eventType, NodeId{ObjectTypeId::BaseModelChangeEventType})
      << what << " raised an Event of type " << to_string(event->eventType);
    EXPECT_EQ(event->sourceNode, NodeId{ObjectId::Server});
  };

  const auto rankWrite =
    variable->try_write_attribute_sync(AttributeId::ValueRank, Variant{int32_t{ValueRank{1}.as_int32()}});
  ASSERT_TRUE(rankWrite.is_good()) << to_string(rankWrite.status_code());
  const auto afterRank = readVersion();
  EXPECT_NE(afterRank, "before") << "the ValueRank change left the NodeVersion unchanged";
  EXPECT_EQ(sink->events.size(), built + 1)
    << "the ValueRank change raised " << sink->events.size() - built << " Events";
  expectOneBaseModelChange(built, "the ValueRank change");

  const auto beforeRepeat = sink->events.size();
  const auto sameRank =
    variable->try_write_attribute_sync(AttributeId::ValueRank, Variant{int32_t{ValueRank{1}.as_int32()}});
  ASSERT_TRUE(sameRank.is_good()) << to_string(sameRank.status_code());
  EXPECT_EQ(readVersion(), afterRank) << "the repeated ValueRank write changed the NodeVersion";
  EXPECT_EQ(sink->events.size(), beforeRepeat) << "the repeated ValueRank write raised an Event";

  Array<uint32_t> dimensions;
  dimensions.payload() = {4};
  const auto dimensionsWrite =
    variable->try_write_attribute_sync(AttributeId::ArrayDimensions, Variant{std::move(dimensions)});
  ASSERT_TRUE(dimensionsWrite.is_good()) << to_string(dimensionsWrite.status_code());
  EXPECT_NE(readVersion(), afterRank) << "the ArrayDimensions change left the NodeVersion unchanged";
  EXPECT_EQ(sink->events.size(), beforeRepeat + 1)
    << "the ArrayDimensions change raised " << sink->events.size() - beforeRepeat << " Events";
  expectOneBaseModelChange(beforeRepeat, "the ArrayDimensions change");

  const auto beforeUnversioned = sink->events.size();
  const auto unversionedWrite =
    unversioned->try_write_attribute_sync(AttributeId::ValueRank, Variant{int32_t{ValueRank{1}.as_int32()}});
  ASSERT_TRUE(unversionedWrite.is_good()) << to_string(unversionedWrite.status_code());
  EXPECT_EQ(sink->events.size(), beforeUnversioned) << "the Variable without NodeVersion raised an Event";
}

// Part 3 section 5.6.2, Table 13 gives NodeVersion the DataType String. A ValueRank or ArrayDimensions write
// to a Variable whose NodeVersion is not a String is made, and its version step is not: the generic Uncertain
// with the NodeVersionTypeMismatch ErrorDetail (delivery decision DL-22 as reversed). The values read back
// are the control that the Attribute was stored; the writes run on the test thread, not the executor's.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-05-MALFORMED-NODEVERSION-ANSWERS-TYPE-MISMATCH, scope=function)
TEST_F(
  ReferenceMutationCoordinatorTest, MalformedNodeVersionPreservesRichValueRankAndArrayDimensionsWriteFailure)
{
  const NodeId variableId{1, "shape:malformed"};
  const NodeId versionId{1, "shape:malformed-version"};
  auto created = mAddressSpace->create_node_sync(variableId, NodeClass::Variable);
  auto variable = created.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_data_type(NodeId{DataTypeId::Int32});
  variable->set_value_rank(ValueRank{ValueRank::scalar});
  auto versionNode = mAddressSpace->create_node_sync(versionId, NodeClass::Variable);
  versionNode.set_browse_name(QualifiedName{0, "NodeVersion"});
  auto version = versionNode.as<VariableAccessor>();
  ASSERT_TRUE(version.has_value());
  version->write_value_sync(uint32_t{7});
  created.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, versionId);
  ASSERT_FALSE(variable->get_array_dimensions().has_value())
    << "precondition: the Variable has ArrayDimensions";

  const auto expectUncertainTypeMismatch = [](const VoidResult& result, const char* what)
  {
    EXPECT_EQ(result.status_code().as_uint32(), 0x40000000u)
      << what << " answered " << to_string(result.status_code());
    ASSERT_NE(result.shared_detail(), nullptr) << what << " carries no ErrorDetail";
    EXPECT_EQ(result.shared_detail()->code, "NodeVersionTypeMismatch");
  };

  const auto rankWrite =
    variable->try_write_attribute_sync(AttributeId::ValueRank, Variant{int32_t{ValueRank{1}.as_int32()}});
  expectUncertainTypeMismatch(rankWrite, "the ValueRank write");
  EXPECT_EQ(variable->get_value_rank().as_int32(), 1) << "the ValueRank was not stored";

  Array<uint32_t> dimensions;
  dimensions.payload() = {4};
  const auto dimensionsWrite =
    variable->try_write_attribute_sync(AttributeId::ArrayDimensions, Variant{std::move(dimensions)});
  expectUncertainTypeMismatch(dimensionsWrite, "the ArrayDimensions write");
  EXPECT_EQ(
    variable->get_array_dimensions(), (std::optional<std::vector<uint32_t>>{std::vector<uint32_t>{4}}))
    << "the ArrayDimensions were not stored";

  const auto versionAfter = version->read_value_sync();
  const auto* versionValue = versionAfter.value().try_as<uint32_t>();
  ASSERT_NE(versionValue, nullptr) << "the NodeVersion Value is no longer a UInt32";
  EXPECT_EQ(*versionValue, 7u);
}

// Change receivers are an SDK boundary. A throwing receiver is contained after the mutation and
// cannot convert a successful write into a second completion or an exception.
// @relation(AC-SVR-ADDRSP-088-SEMANTICCHANGEEVENT-RAISED, scope=function)
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-03-BOUNDARY-FAILURES, scope=function)
TEST_F(ReferenceMutationCoordinatorTest, ThrowingSemanticChangeReceiverIsContained)
{
  auto received = std::make_shared<std::promise<void>>();
  auto receivedFuture = received->get_future();
  detail::AddressSpaceChangeEvents::set_handler(*mAddressSpace,
    [received](const detail::AddressSpaceChange&)
    {
      try
      {
        received->set_value();
      }
      catch (const std::future_error&)
      {}
      throw std::runtime_error{"sentinel"};
    });
  const NodeId ownerId{1, "semantic:throw-owner"};
  const NodeId propertyId{1, "semantic:throw-property"};
  auto owner = mAddressSpace->create_node_sync(ownerId, NodeClass::Object);
  auto property = mAddressSpace->create_node_sync(propertyId, NodeClass::Variable);
  auto variable = property.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->write_value_sync(double{1.0});
  variable->set_access_level(
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::SemanticChange});
  owner.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
  property.add_reference_sync(
    NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{ownerId}, /*isForward=*/false);

  EXPECT_NO_THROW(variable->write_value_sync(double{2.0}));
  ASSERT_EQ(receivedFuture.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "the throwing receiver was not called";
  const auto written = variable->read_value_sync();
  ASSERT_NE(written.value().try_as<double>(), nullptr);
  EXPECT_EQ(*written.value().try_as<double>(), 2.0);
}

}  // namespace
