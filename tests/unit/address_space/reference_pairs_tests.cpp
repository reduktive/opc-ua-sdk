// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// The address space's route adds and removes the other half of a Reference in its target's namespace when its
// type is HasSubtype, HasEncoding, a hierarchical type or GeneratesEvent, or a subtype of one (NR-30 rule 2,
// as revised by NR-50, NR-68 item 7 and DL-115 (4), (5); NR-70 B8).
//
// The supertype and the DataType live in namespace A, the subtype and the encoding in namespace B. Both
// record each call they are sent and otherwise behave as the in-memory namespace.

#include <gtest/gtest.h>

#include "batch_recording_namespace.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor_route.h"
#include "ua_referencetype_id.h"
#include "ua_status_to_string.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <tuple>
#include <vector>

using namespace ua;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;

namespace
{

using namespace std::chrono_literals;
using Half = std::tuple<NodeId, NodeId, NodeId, bool>;

class ReferencePairs : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test", mThreadPool.get_executor()));
    mA = std::make_shared<BatchRecordingNamespace>("urn:test:reference-pairs:a", mThreadPool.get_executor());
    mB = std::make_shared<BatchRecordingNamespace>("urn:test:reference-pairs:b", mThreadPool.get_executor());
    auto indexA = mAddressSpace->try_add_namespace_sync(mA);
    auto indexB = mAddressSpace->try_add_namespace_sync(mB);
    ASSERT_TRUE(indexA.is_good() && indexB.is_good());
    mSupertype = NodeId{indexA.value(), String{"Supertype"}};
    mDataType = NodeId{indexA.value(), String{"DataType"}};
    mSubtype = NodeId{indexB.value(), String{"Subtype"}};
    mEncoding = NodeId{indexB.value(), String{"Encoding"}};
    for (const auto& [id, nodeClass] : {std::tuple{mSupertype, NodeClass::ObjectType},
           std::tuple{mSubtype, NodeClass::ObjectType},
           std::tuple{mDataType, NodeClass::DataType},
           std::tuple{mEncoding, NodeClass::Object}})
    {
      auto created = mAddressSpace->try_create_node_sync(id, nodeClass, {});
      ASSERT_TRUE(created.is_good()) << to_string(id) << ": " << to_string(created.status_code());
    }
    mA->reset();
    mB->reset();
  }

  void TearDown() override
  {
    mA.reset();
    mB.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeAccessor node(const NodeId& id)
  {
    auto found = mAddressSpace->try_find_node_sync(id);
    EXPECT_TRUE(found.is_good()) << to_string(id);
    return found.value();
  }

  /// Each half @p space was sent by @p member, as (source, ReferenceType, target, isForward).
  static std::vector<Half> halves_sent_to(const BatchRecordingNamespace& space, Member member)
  {
    std::vector<Half> halves;
    for (const auto& call : space.calls(member))
    {
      for (const auto& change : call.referenceChanges)
      {
        halves.emplace_back(change.source, change.referenceType, change.target.node_id(), change.isForward);
      }
    }
    return halves;
  }

  /// Whether @p holder holds the half (holder, @p type, @p target, @p isForward).
  bool holds(const NodeId& holder, const NodeId& type, const NodeId& target, bool isForward)
  {
    auto references = node(holder).try_get_references_sync();
    EXPECT_TRUE(references.is_good()) << to_string(references.status_code());
    for (const auto& reference : references.value())
    {
      if (reference.type_id() == type && reference.is_forward() == isForward &&
          reference.target_id() == ExpandedNodeId{target})
      {
        return true;
      }
    }
    return false;
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace;
  shared_ptr<BatchRecordingNamespace> mA;
  shared_ptr<BatchRecordingNamespace> mB;
  NodeId mSupertype;
  NodeId mSubtype;
  NodeId mDataType;
  NodeId mEncoding;
  const NodeId mHasSubtype{ReferenceTypeId::HasSubtype};
  const NodeId mHasEncoding{ReferenceTypeId::HasEncoding};
};

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-REQUIRED-PAIR-IS-ADDED-AND-REMOVED-ON-BOTH-SIDES, scope=function)
TEST_F(ReferencePairs, AHasEncodingAddedOrRemovedOnOneSideChangesBothHalves)
{
  const auto added = node(mDataType).try_add_reference_sync(mHasEncoding, ExpandedNodeId{mEncoding});
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
  EXPECT_EQ(halves_sent_to(*mB, Member::AddReferences),
    (std::vector<Half>{{mEncoding, mHasEncoding, mDataType, false}}));
  EXPECT_TRUE(holds(mEncoding, mHasEncoding, mDataType, false));

  const auto removed = node(mDataType).try_remove_reference_sync(mHasEncoding, ExpandedNodeId{mEncoding});
  ASSERT_TRUE(removed.is_good()) << to_string(removed.status_code());
  EXPECT_EQ(halves_sent_to(*mB, Member::RemoveReferences),
    (std::vector<Half>{{mEncoding, mHasEncoding, mDataType, false}}));
  EXPECT_FALSE(holds(mEncoding, mHasEncoding, mDataType, false));
}

// A type the address space does not pair, such as HasDictionaryEntry, is added on the side named only.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-REQUIRED-PAIR-IS-ADDED-AND-REMOVED-ON-BOTH-SIDES, scope=function)
TEST_F(ReferencePairs, AnUnpairedTypeAddedOnOneSideChangesOnlyThatHalf)
{
  const auto added =
    node(mSupertype)
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasDictionaryEntry}, ExpandedNodeId{mSubtype});
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
  EXPECT_TRUE(mB->calls(Member::AddReferences).empty());
}

// An Organizes, a hierarchical type, added or removed on one side has its other half added or removed in the
// target's namespace (DL-115 (5)); so has a GeneratesEvent.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-HIERARCHICAL-OR-GENERATES-EVENT-REFERENCE-IS-PAIRED, scope=function)
TEST_F(ReferencePairs, AHierarchicalOrGeneratesEventReferenceIsChangedOnBothSides)
{
  const NodeId organizes{ReferenceTypeId::Organizes};
  const NodeId generatesEvent{ReferenceTypeId::GeneratesEvent};
  ASSERT_TRUE(node(mSupertype).try_add_reference_sync(organizes, ExpandedNodeId{mSubtype}).is_good());
  ASSERT_TRUE(node(mSupertype).try_add_reference_sync(generatesEvent, ExpandedNodeId{mSubtype}).is_good());
  EXPECT_EQ(halves_sent_to(*mB, Member::AddReferences),
    (std::vector<Half>{
      {mSubtype, organizes, mSupertype, false}, {mSubtype, generatesEvent, mSupertype, false}}));
  EXPECT_TRUE(holds(mSubtype, organizes, mSupertype, false));
  EXPECT_TRUE(holds(mSubtype, generatesEvent, mSupertype, false));

  ASSERT_TRUE(
    node(mSubtype).try_remove_reference_sync(organizes, ExpandedNodeId{mSupertype}, false).is_good());
  EXPECT_FALSE(holds(mSupertype, organizes, mSubtype, true))
    << "removing the inverse half removes the forward";
}

// A type of another namespace that is a subtype of Organizes is paired as Organizes is, found by walking its
// supertypes; a subtype of NonHierarchicalReferences is not.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-HIERARCHICAL-OR-GENERATES-EVENT-REFERENCE-IS-PAIRED, scope=function)
TEST_F(ReferencePairs, ASubtypeOfAHierarchicalTypeInAnotherNamespaceIsPaired)
{
  const auto referenceType = [this](const std::string& name, ReferenceTypeId supertype)
  {
    const NodeId id{mSupertype.namespace_index(), String{name}};
    auto created = mAddressSpace->try_create_node_sync(id, NodeClass::ReferenceType, {});
    EXPECT_TRUE(created.is_good()) << name << ": " << to_string(created.status_code());
    EXPECT_TRUE(
      node(id).try_add_reference_sync(mHasSubtype, ExpandedNodeId{NodeId{supertype}}, false).is_good());
    return id;
  };
  const NodeId contains = referenceType("Contains", ReferenceTypeId::Organizes);
  const NodeId mentions = referenceType("Mentions", ReferenceTypeId::NonHierarchicalReferences);
  mB->reset();

  ASSERT_TRUE(node(mSupertype).try_add_reference_sync(contains, ExpandedNodeId{mSubtype}).is_good());
  ASSERT_TRUE(node(mSupertype).try_add_reference_sync(mentions, ExpandedNodeId{mSubtype}).is_good());
  EXPECT_EQ(
    halves_sent_to(*mB, Member::AddReferences), (std::vector<Half>{{mSubtype, contains, mSupertype, false}}));
}

// A failed other half of a type Part 3 only recommends bidirectional is logged; the change keeps its answer.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-REFUSED-RECOMMENDED-HALF-IS-ONLY-LOGGED, scope=function)
TEST_F(ReferencePairs, ARefusedHalfOfAHierarchicalReferenceIsLoggedAndSucceeds)
{
  mB->fail_reference_changes_of(mSubtype, StatusCode{Status::BadUserAccessDenied});

  const auto added =
    node(mSupertype).try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{mSubtype});
  EXPECT_TRUE(added.is_good()) << to_string(added.status_code());
  EXPECT_EQ(halves_sent_to(*mB, Member::AddReferences),
    (std::vector<Half>{{mSubtype, NodeId{ReferenceTypeId::Organizes}, mSupertype, false}}));
  EXPECT_TRUE(holds(mSupertype, NodeId{ReferenceTypeId::Organizes}, mSubtype, true));
}

// The other half is not added again when the target holds it already, also when it holds it as a subtype of
// the type sent, which identifies the same Reference (OPC 10000-3 4.3.4): the target keeps one inverse half.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-AN-OTHER-HALF-ALREADY-HELD-IS-NOT-DUPLICATED, scope=function)
TEST_F(ReferencePairs, AnOtherHalfAlreadyHeldIsNotAddedAgain)
{
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  const NodeId hasOrderedComponent{ReferenceTypeId::HasOrderedComponent};
  const NodeId organizes{ReferenceTypeId::Organizes};
  // The target's halves, added without their others.
  for (const auto& type : {hasOrderedComponent, organizes})
  {
    auto changes = std::make_shared<const std::vector<ReferenceChange>>(std::vector<ReferenceChange>{
      ReferenceChange{mSubtype, type, ExpandedNodeId{mSupertype}, false, false}});
    std::promise<std::vector<VoidResult>> answered;
    auto future = answered.get_future();
    ::ua::detail::NodeAccessorRoute::add_references(
      mAddressSpace->weak(),
      RequestInfo{},
      changes,
      [&answered](std::vector<VoidResult> answers) { answered.set_value(std::move(answers)); },
      /*addRequiredPairs=*/false);
    ASSERT_EQ(future.wait_for(10s), std::future_status::ready);
    ASSERT_TRUE(future.get().at(0).is_good());
  }

  EXPECT_TRUE(node(mSupertype).try_add_reference_sync(hasComponent, ExpandedNodeId{mSubtype}).is_good());
  EXPECT_TRUE(node(mSupertype).try_add_reference_sync(organizes, ExpandedNodeId{mSubtype}).is_good());

  auto references = node(mSubtype).try_get_references_sync();
  ASSERT_TRUE(references.is_good());
  const auto count = [&references](const NodeId& type)
  {
    return std::ranges::count_if(
      references.value(), [&type](const Reference& reference) { return reference.type_id() == type; });
  };
  EXPECT_EQ(count(hasOrderedComponent), 1) << "the inverse HasOrderedComponent stays the only half";
  EXPECT_EQ(count(hasComponent), 0) << "no inverse HasComponent is added beside it";
  EXPECT_EQ(count(organizes), 1);
}

// A target given by namespace URI is paired as its index form is.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-TARGET-GIVEN-BY-NAMESPACE-URI-IS-PAIRED, scope=function)
TEST_F(ReferencePairs, ATargetGivenByNamespaceUriIsPaired)
{
  const ExpandedNodeId byUri{NodeId{0, String{"Subtype"}}, "urn:test:reference-pairs:b"};

  const auto added = node(mSupertype).try_add_reference_sync(mHasSubtype, byUri);
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
  EXPECT_EQ(halves_sent_to(*mB, Member::AddReferences),
    (std::vector<Half>{{mSubtype, mHasSubtype, mSupertype, false}}));
  EXPECT_TRUE(holds(mSubtype, mHasSubtype, mSupertype, false));
}

// Deleting a Node removes the Organizes another namespace's Node holds to it: the address space added the
// deleted Node's inverse half with it, from which the delete finds the forward half (NR-30 rule 5).
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-DELETED-NODE-LEAVES-NO-PAIRED-REFERENCE-BEHIND, scope=function)
TEST_F(ReferencePairs, DeletingANodeRemovesTheOrganizesAnotherNamespaceHoldsToIt)
{
  const NodeId organizes{ReferenceTypeId::Organizes};
  ASSERT_TRUE(node(mSupertype).try_add_reference_sync(organizes, ExpandedNodeId{mSubtype}).is_good());

  const auto deleted = mAddressSpace->try_delete_node_sync(mSubtype, false);
  ASSERT_TRUE(deleted.is_good()) << to_string(deleted.status_code());
  EXPECT_FALSE(holds(mSupertype, organizes, mSubtype, true));
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-REFUSED-REQUIRED-HALF-FAILS-THE-ITEM-AND-NAMES-IT, scope=function)
TEST_F(ReferencePairs, ARefusedInverseHalfFailsTheItemAndNamesIt)
{
  mB->fail_reference_changes_of(mSubtype, StatusCode{Status::BadUserAccessDenied});

  const auto added = node(mSupertype).try_add_reference_sync(mHasSubtype, ExpandedNodeId{mSubtype});
  EXPECT_EQ(added.status_code().as_status(), Status::BadUserAccessDenied) << to_string(added.status_code());
  ASSERT_NE(added.shared_detail(), nullptr);
  EXPECT_EQ(added.shared_detail()->code, "OtherHalfNotAdded");
  EXPECT_TRUE(std::any_of(added.shared_detail()->context.begin(),
    added.shared_detail()->context.end(),
    [this](const auto& entry)
    { return entry.key == ContextKeys::nodeId.value() && entry.value == to_string(mSubtype); }))
    << "the ErrorDetail names the other half's Node";
  EXPECT_TRUE(holds(mSupertype, mHasSubtype, mSubtype, true)) << "nothing is undone";
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-REFUSED-FORWARD-HALF-OF-HAS-SUBTYPE-IS-ONLY-LOGGED, scope=function)
TEST_F(ReferencePairs, ARefusedForwardHalfOfHasSubtypeIsLoggedAndSucceeds)
{
  mA->fail_reference_changes_of(mSupertype, StatusCode{Status::BadUserAccessDenied});

  const auto added = node(mSubtype).try_add_reference_sync(mHasSubtype, ExpandedNodeId{mSupertype}, false);
  EXPECT_TRUE(added.is_good()) << to_string(added.status_code());
  EXPECT_EQ(halves_sent_to(*mA, Member::AddReferences),
    (std::vector<Half>{{mSupertype, mHasSubtype, mSubtype, true}}));
  EXPECT_TRUE(holds(mSubtype, mHasSubtype, mSupertype, false));
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-BOTH-HALVES-ITEM-IS-ONE-PAIR, scope=function)
TEST_F(ReferencePairs, ABothHalvesItemSendsOneCopyEach)
{
  const auto pair = ReferenceChange::both_halves(mSupertype, mHasSubtype, mSubtype);
  auto changes = std::make_shared<const std::vector<ReferenceChange>>(pair.begin(), pair.end());
  std::promise<std::vector<VoidResult>> answered;
  auto future = answered.get_future();
  ::ua::detail::NodeAccessorRoute::add_references(mAddressSpace->weak(),
    RequestInfo{},
    changes,
    [&answered](std::vector<VoidResult> answers) { answered.set_value(std::move(answers)); });
  ASSERT_EQ(future.wait_for(10s), std::future_status::ready);
  const auto answers = future.get();
  ASSERT_EQ(answers.size(), 2u);
  EXPECT_TRUE(answers[0].is_good() && answers[1].is_good());
  EXPECT_EQ(halves_sent_to(*mA, Member::AddReferences),
    (std::vector<Half>{{mSupertype, mHasSubtype, mSubtype, true}}));
  EXPECT_EQ(halves_sent_to(*mB, Member::AddReferences),
    (std::vector<Half>{{mSubtype, mHasSubtype, mSupertype, false}}));
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-BOTH-HALVES-ITEM-IS-ONE-PAIR, scope=function)
TEST_F(ReferencePairs, AddingTheInverseTheAddressSpaceAddedIsGood)
{
  ASSERT_TRUE(node(mSupertype).try_add_reference_sync(mHasSubtype, ExpandedNodeId{mSubtype}).is_good());

  const auto again = node(mSubtype).try_add_reference_sync(mHasSubtype, ExpandedNodeId{mSupertype}, false);
  EXPECT_TRUE(again.is_good()) << to_string(again.status_code());
  const NodeId unpaired{ReferenceTypeId::HasDictionaryEntry};
  ASSERT_TRUE(node(mSupertype).try_add_reference_sync(unpaired, ExpandedNodeId{mSubtype}).is_good());
  const auto unpairedAgain = node(mSupertype).try_add_reference_sync(unpaired, ExpandedNodeId{mSubtype});
  EXPECT_EQ(unpairedAgain.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << "a repeated add of a type the address space does not pair is still refused";
}

}  // namespace
