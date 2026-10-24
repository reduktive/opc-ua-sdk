// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The namespace-0 ReferenceType model in core (COMP-CORE-REFERENCE-TYPE-MODEL, NR-61, NR-68 item 8). Part 3
// section 4.3.4: "Any subtypes of concrete ReferenceTypes are considered to be equal to the base concrete
// ReferenceTypes when identifying References". None of these functions makes a lookup; an application
// ReferenceType is taken as it is.

#include <gtest/gtest.h>

#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_reference.h"
#include "ua_reference_type_model.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"

#include <cstdint>
#include <vector>

using namespace ua;

namespace
{

const NodeId hasComponent{ReferenceTypeId::HasComponent};
const NodeId hasOrderedComponent{ReferenceTypeId::HasOrderedComponent};
const NodeId hasProperty{ReferenceTypeId::HasProperty};
const NodeId organizes{ReferenceTypeId::Organizes};
const NodeId applicationType{2, uint32_t{6001}};
const NodeId notAReferenceType{ObjectId::Server};

}  // namespace

// The classes: a concrete subtype of a concrete type (HasOrderedComponent, HasNotifier), a concrete type
// under an abstract one (HasComponent, Organizes), an abstract type (Aggregates), a namespace-0 NodeId that
// is not a ReferenceType, and a NodeId outside namespace 0.
// @relation(AC-COMP-CORE-REFERENCE-TYPE-MODEL-01-IDENTITY-TYPE, scope=function)
TEST(ReferenceTypeModel, IdentityTypeIsTheBaseConcreteTypeForNamespaceZeroAndItselfOtherwise)
{
  EXPECT_EQ(reference_identity_type(hasOrderedComponent), hasComponent);
  EXPECT_EQ(
    reference_identity_type(NodeId{ReferenceTypeId::HasNotifier}), NodeId{ReferenceTypeId::HasEventSource});
  EXPECT_EQ(reference_identity_type(hasComponent), hasComponent);
  EXPECT_EQ(reference_identity_type(organizes), organizes);
  EXPECT_EQ(
    reference_identity_type(NodeId{ReferenceTypeId::Aggregates}), NodeId{ReferenceTypeId::Aggregates});
  EXPECT_EQ(reference_identity_type(notAReferenceType), notAReferenceType);
  EXPECT_EQ(reference_identity_type(applicationType), applicationType);
}

// NR-61: a namespace applying a ReferenceType hint may leave a Reference out only when the type is a
// namespace-0 type that neither is hinted nor is a namespace-0 subtype of a hinted one. HasProperty and
// Organizes under {HasComponent} are the only answers that let a Reference be left out;
// HierarchicalReferences is a supertype of HasProperty several levels up (through Aggregates and HasChild).
// @relation(AC-COMP-CORE-REFERENCE-TYPE-MODEL-02-MAY-MATCH-HINT, scope=function)
TEST(ReferenceTypeHint, MayMatchIsFalseOnlyForAnUnrelatedNamespaceZeroType)
{
  const std::vector<NodeId> hintHasComponent{hasComponent};
  EXPECT_TRUE(reference_type_may_match_hint(hasComponent, hintHasComponent));
  EXPECT_TRUE(reference_type_may_match_hint(hasOrderedComponent, hintHasComponent));
  EXPECT_FALSE(reference_type_may_match_hint(hasProperty, hintHasComponent));
  EXPECT_FALSE(reference_type_may_match_hint(organizes, hintHasComponent));
  EXPECT_TRUE(reference_type_may_match_hint(applicationType, hintHasComponent));
  EXPECT_TRUE(reference_type_may_match_hint(notAReferenceType, hintHasComponent));

  EXPECT_TRUE(reference_type_may_match_hint(hasProperty, std::vector<NodeId>{}));
  const std::vector<NodeId> hintHierarchical{NodeId{ReferenceTypeId::HierarchicalReferences}};
  EXPECT_TRUE(reference_type_may_match_hint(hasProperty, hintHierarchical));
}

// One good input and three bad ones, one per part of the identity: direction, target and identity type.
// @relation(AC-COMP-CORE-REFERENCE-TYPE-MODEL-03-SAME-REFERENCE, scope=function)
TEST(ReferenceIdentity, SameReferenceNeedsTheSameDirectionTargetAndIdentityType)
{
  const NodeId targetB{1, uint32_t{100}};
  const NodeId targetC{1, uint32_t{101}};
  const Reference held{hasComponent, ExpandedNodeId{targetB}, true};

  EXPECT_TRUE(
    held.identifies_same_reference_as(Reference{hasOrderedComponent, ExpandedNodeId{targetB}, true}));
  EXPECT_FALSE(
    held.identifies_same_reference_as(Reference{hasOrderedComponent, ExpandedNodeId{targetB}, false}));
  EXPECT_FALSE(
    held.identifies_same_reference_as(Reference{hasOrderedComponent, ExpandedNodeId{targetC}, true}));
  EXPECT_FALSE(held.identifies_same_reference_as(Reference{hasProperty, ExpandedNodeId{targetB}, true}));
}
