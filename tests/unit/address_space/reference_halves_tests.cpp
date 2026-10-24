// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Which halves of a Reference an accessor's add or removal changes (`ReferenceHalves`, DL-124 (3)). With
// `Both` an add also adds the other half of a paired type (hierarchical, GeneratesEvent, HasSubtype,
// HasEncoding and their subtypes), and a removal also removes the other half of a Reference of any type, on a
// target in this Server (OPC 10000-4 5.7.5.1, `deleteBidirectional` TRUE); a target in another Server keeps
// its half. With `ThisHalfOnly` only the named half changes (`deleteBidirectional` FALSE), except that a
// change that would leave alone a half OPC 10000-3 requires to be paired - either half of HasEncoding
// (5.8.4), or the subtype's inverse half of HasSubtype (5.5.2) - is refused with Bad_NotSupported and changes
// nothing.
//
// The rule is the address space's: each arm runs against the in-memory namespace and against a namespace
// written from the public headers alone (DescribedConformanceNamespace). The address space holds two
// namespaces of the kind under test, A and B; each Reference runs from a Node of A to a Node of B, so that
// its other half is changed in another namespace.
//
// These tests pass `ReferenceHalves` to the accessor's add and remove members, which the API before DL-124
// (3) does not take: none of them compiles against it.

#include <gtest/gtest.h>

#include "namespace_conformance/described_conformance_namespace.h"
#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_wire.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_namespace.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_reference_halves.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"

#include <boost/asio/thread_pool.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

using namespace ua;

namespace
{

// One namespace kind the arms run against; the address space holds two of it.
struct NamespaceKind
{
  std::string name;
  std::function<shared_ptr<Namespace>(const std::string& uri, boost::asio::any_io_executor)> make;
};

void PrintTo(const NamespaceKind& kind, std::ostream* out)
{
  *out << kind.name;
}

NamespaceKind in_memory_kind()
{
  return NamespaceKind{"InMemory",
    [](const std::string& uri, boost::asio::any_io_executor executor) -> shared_ptr<Namespace>
    {
      return default_ns::Namespace::create(uri, std::move(executor));
    }};
}

NamespaceKind described_nodes_kind()
{
  return NamespaceKind{"DescribedNodes",
    [](const std::string& uri, boost::asio::any_io_executor) -> shared_ptr<Namespace>
    {
      return std::make_shared<ua::test::DescribedConformanceNamespace>(String{uri});
    }};
}

const NodeId organizes{ReferenceTypeId::Organizes};
const NodeId hasDictionaryEntry{ReferenceTypeId::HasDictionaryEntry};
const NodeId hasEncoding{ReferenceTypeId::HasEncoding};
const NodeId hasSubtype{ReferenceTypeId::HasSubtype};

class ReferenceHalvesTest : public ::testing::TestWithParam<NamespaceKind>
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:reference-halves", mPool.get_executor()));
    mA = GetParam().make("urn:test:reference-halves:a", mPool.get_executor());
    mB = GetParam().make("urn:test:reference-halves:b", mPool.get_executor());
    ASSERT_NE(mA, nullptr);
    ASSERT_NE(mB, nullptr);
    auto indexA = mAddressSpace->try_add_namespace_sync(mA);
    ASSERT_TRUE(indexA.is_good()) << to_string(indexA.status_code());
    auto indexB = mAddressSpace->try_add_namespace_sync(mB);
    ASSERT_TRUE(indexB.is_good()) << to_string(indexB.status_code());
    mIndexA = indexA.value();
    mIndexB = indexB.value();
  }

  void TearDown() override
  {
    mA.reset();
    mB.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  NodeId create(uint16_t index, const std::string& name, NodeClass nodeClass = NodeClass::Object)
  {
    const NodeId nodeId{index, String{name}};
    const InitialAttributes attributes{
      {AttributeId::BrowseName, attribute_wire::browse_name(QualifiedName{index, String{name}})},
      {AttributeId::DisplayName, attribute_wire::display_name(LocalizedText{LocaleId{"en"}, String{name}})}};
    auto created = mAddressSpace->try_create_node_sync(nodeId, nodeClass, attributes);
    EXPECT_TRUE(created.is_good()) << name << ": " << to_string(created.status_code());
    return nodeId;
  }

  NodeAccessor node(const NodeId& nodeId)
  {
    return mAddressSpace->find_node_sync(nodeId);
  }

  // Stores the forward half on @p source and the inverse half on @p target, each named alone.
  void link(const NodeId& source, const NodeId& type, const NodeId& target)
  {
    (void)node(source).try_add_reference_sync(type, target, true, ReferenceHalves::Both);
    (void)node(target).try_add_reference_sync(type, ExpandedNodeId{source}, false, ReferenceHalves::Both);
    ASSERT_TRUE(holds(source, type, ExpandedNodeId{target}, true)) << to_string(source) << " lacks its half";
    ASSERT_TRUE(holds(target, type, ExpandedNodeId{source}, false)) << to_string(target) << " lacks its half";
  }

  // Whether @p holder holds the half of a @p type Reference to @p other in the direction @p isForward.
  bool holds(const NodeId& holder, const NodeId& type, const ExpandedNodeId& other, bool isForward)
  {
    auto references = node(holder).try_get_references_sync();
    if (!references.is_good())
    {
      ADD_FAILURE() << "the References of " << to_string(holder)
                    << " could not be read: " << to_string(references.status_code());
      return false;
    }
    for (const auto& reference : references.value())
    {
      if (reference.type_id() == type && reference.target_id() == other &&
          reference.is_forward() == isForward)
      {
        return true;
      }
    }
    return false;
  }

  static void expect_required_half_refusal(const VoidResult& answer, const char* what)
  {
    EXPECT_EQ(answer.status_code().as_status(), Status::BadNotSupported)
      << what << " answered " << to_string(answer.status_code());
    const auto detail = answer.shared_detail();
    ASSERT_NE(detail, nullptr) << what << " gave no ErrorDetail";
    EXPECT_EQ(detail->code, "RequiredOtherHalfLeftAlone") << what;
  }

  boost::asio::thread_pool mPool{2};
  std::optional<AddressSpace> mAddressSpace;
  shared_ptr<Namespace> mA;
  shared_ptr<Namespace> mB;
  uint16_t mIndexA{0};
  uint16_t mIndexB{0};
};

// A removal of both halves removes the target's half whatever the type: HasDictionaryEntry, which an add does
// not pair, loses the half its target holds. Control: a second HasDictionaryEntry to another target keeps
// both halves. Fails on the unchanged code, which removed the other half of a paired type only.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-BOTH-REMOVAL-REMOVES-THE-OTHER-HALF-OF-ANY-TYPE, scope=function)
TEST_P(ReferenceHalvesTest, ABothRemovalOfAnUnpairedTypeRemovesTheTargetsHalf)
{
  const NodeId x = create(mIndexA, "X");
  const NodeId y = create(mIndexB, "Y");
  const NodeId z = create(mIndexB, "Z");
  link(x, hasDictionaryEntry, y);
  link(x, hasDictionaryEntry, z);

  const auto removed = node(x).try_remove_reference_sync(hasDictionaryEntry, y, true, ReferenceHalves::Both);

  EXPECT_TRUE(removed.is_good()) << to_string(removed.status_code());
  EXPECT_FALSE(holds(x, hasDictionaryEntry, ExpandedNodeId{y}, true))
    << "X kept the half it was asked to remove";
  EXPECT_FALSE(holds(y, hasDictionaryEntry, ExpandedNodeId{x}, false))
    << "Y kept its half of a Reference whose both halves were removed";
  EXPECT_TRUE(holds(x, hasDictionaryEntry, ExpandedNodeId{z}, true)) << "the control: X lost its half to Z";
  EXPECT_TRUE(holds(z, hasDictionaryEntry, ExpandedNodeId{x}, false)) << "the control: Z lost its half";
}

// A removal of the named half alone leaves the target's half of Organizes, which a removal of both halves
// removes (the control, X to Z). Fails on the unchanged code, which removed both halves of a paired type.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-THIS-HALF-ONLY-REMOVAL-LEAVES-THE-OTHER-HALF, scope=function)
TEST_P(ReferenceHalvesTest, AThisHalfOnlyRemovalOfOrganizesLeavesTheTargetsHalf)
{
  const NodeId x = create(mIndexA, "X");
  const NodeId y = create(mIndexB, "Y");
  const NodeId z = create(mIndexB, "Z");
  link(x, organizes, y);
  link(x, organizes, z);

  const auto alone = node(x).try_remove_reference_sync(organizes, y, true, ReferenceHalves::ThisHalfOnly);
  const auto both = node(x).try_remove_reference_sync(organizes, z, true, ReferenceHalves::Both);

  EXPECT_TRUE(alone.is_good()) << to_string(alone.status_code());
  EXPECT_FALSE(holds(x, organizes, ExpandedNodeId{y}, true)) << "X kept the half it was asked to remove";
  EXPECT_TRUE(holds(y, organizes, ExpandedNodeId{x}, false)) << "Y lost its half to a removal of X's alone";
  EXPECT_TRUE(both.is_good()) << to_string(both.status_code());
  EXPECT_FALSE(holds(z, organizes, ExpandedNodeId{x}, false)) << "the control: Z kept its half";
}

// An add of the named half alone adds no other half, even of Organizes, which an add of both halves pairs
// (the control, X to Z). Fails on the unchanged code, which added the other half of a paired type.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-THIS-HALF-ONLY-ADD-ADDS-ONE-HALF, scope=function)
TEST_P(ReferenceHalvesTest, AThisHalfOnlyAddOfOrganizesAddsOneHalf)
{
  const NodeId x = create(mIndexA, "X");
  const NodeId y = create(mIndexB, "Y");
  const NodeId z = create(mIndexB, "Z");

  const auto alone = node(x).try_add_reference_sync(organizes, y, true, ReferenceHalves::ThisHalfOnly);
  const auto both = node(x).try_add_reference_sync(organizes, z, true, ReferenceHalves::Both);

  EXPECT_TRUE(alone.is_good()) << to_string(alone.status_code());
  EXPECT_TRUE(holds(x, organizes, ExpandedNodeId{y}, true)) << "X does not hold the half added";
  EXPECT_FALSE(holds(y, organizes, ExpandedNodeId{x}, false)) << "Y was given a half not asked for";
  EXPECT_TRUE(both.is_good()) << to_string(both.status_code());
  EXPECT_TRUE(holds(z, organizes, ExpandedNodeId{x}, false)) << "the control: Z was not given its half";
}

// Either half of HasEncoding alone, added or removed, is refused with Bad_NotSupported and the ErrorDetail
// RequiredOtherHalfLeftAlone, and nothing changes. Control: a removal of both halves answers Good and removes
// both. Fails on the unchanged code, which changed both halves and answered Good.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-THIS-HALF-ONLY-REFUSES-A-REQUIRED-PAIR, scope=function)
TEST_P(ReferenceHalvesTest, AThisHalfOnlyChangeOfEitherHasEncodingHalfIsRefusedAndChangesNothing)
{
  const NodeId dataType = create(mIndexA, "D", NodeClass::DataType);
  const NodeId encoding = create(mIndexB, "E");

  expect_required_half_refusal(
    node(dataType).try_add_reference_sync(hasEncoding, encoding, true, ReferenceHalves::ThisHalfOnly),
    "the add of the DataType's half alone");
  expect_required_half_refusal(node(encoding).try_add_reference_sync(
                                 hasEncoding, ExpandedNodeId{dataType}, false, ReferenceHalves::ThisHalfOnly),
    "the add of the encoding's half alone");
  EXPECT_FALSE(holds(dataType, hasEncoding, ExpandedNodeId{encoding}, true)) << "a refused add added a half";
  EXPECT_FALSE(holds(encoding, hasEncoding, ExpandedNodeId{dataType}, false)) << "a refused add added a half";

  link(dataType, hasEncoding, encoding);
  expect_required_half_refusal(
    node(dataType).try_remove_reference_sync(hasEncoding, encoding, true, ReferenceHalves::ThisHalfOnly),
    "the removal of the DataType's half alone");
  expect_required_half_refusal(node(encoding).try_remove_reference_sync(
                                 hasEncoding, ExpandedNodeId{dataType}, false, ReferenceHalves::ThisHalfOnly),
    "the removal of the encoding's half alone");
  EXPECT_TRUE(holds(dataType, hasEncoding, ExpandedNodeId{encoding}, true))
    << "a refused removal removed a half";
  EXPECT_TRUE(holds(encoding, hasEncoding, ExpandedNodeId{dataType}, false))
    << "a refused removal removed a half";

  const auto both =
    node(dataType).try_remove_reference_sync(hasEncoding, encoding, true, ReferenceHalves::Both);
  EXPECT_TRUE(both.is_good()) << "the control answered " << to_string(both.status_code());
  EXPECT_FALSE(holds(encoding, hasEncoding, ExpandedNodeId{dataType}, false)) << "the control left a half";
}

// The supertype's forward HasSubtype may be removed alone, leaving the subtype's inverse half; the subtype's
// inverse half alone is refused with Bad_NotSupported and stays, as does the supertype's half. Fails on the
// unchanged code, which removed both halves on either request and refused neither.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-THIS-HALF-ONLY-HASSUBTYPE-KEEPS-THE-SUBTYPES-HALF, scope=function)
TEST_P(ReferenceHalvesTest, AThisHalfOnlyRemovalOfHasSubtypeIsRefusedOnlyForTheSubtypesHalf)
{
  const NodeId supertype = create(mIndexA, "Supertype", NodeClass::ObjectType);
  const NodeId subtype = create(mIndexB, "Subtype", NodeClass::ObjectType);
  link(supertype, hasSubtype, subtype);

  expect_required_half_refusal(node(subtype).try_remove_reference_sync(
                                 hasSubtype, ExpandedNodeId{supertype}, false, ReferenceHalves::ThisHalfOnly),
    "the removal of the subtype's inverse half alone");
  EXPECT_TRUE(holds(subtype, hasSubtype, ExpandedNodeId{supertype}, false)) << "a refused removal removed it";
  EXPECT_TRUE(holds(supertype, hasSubtype, ExpandedNodeId{subtype}, true)) << "a refused removal removed it";

  const auto forward =
    node(supertype).try_remove_reference_sync(hasSubtype, subtype, true, ReferenceHalves::ThisHalfOnly);
  EXPECT_TRUE(forward.is_good()) << to_string(forward.status_code());
  EXPECT_FALSE(holds(supertype, hasSubtype, ExpandedNodeId{subtype}, true)) << "the supertype kept its half";
  EXPECT_TRUE(holds(subtype, hasSubtype, ExpandedNodeId{supertype}, false))
    << "the subtype lost its half to a removal of the supertype's alone";
}

// The subtype's inverse HasSubtype may be added alone, since the supertype's forward half is optional; the
// supertype's forward half alone is refused with Bad_NotSupported and not added, since the subtype must hold
// the inverse half (OPC 10000-3 5.3.3.3). Fails on the unchanged code, which added both halves on either
// request and refused neither.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-THIS-HALF-ONLY-HASSUBTYPE-KEEPS-THE-SUBTYPES-HALF, scope=function)
TEST_P(ReferenceHalvesTest, AThisHalfOnlyAddOfHasSubtypeIsRefusedOnlyForTheSupertypesHalf)
{
  const NodeId supertype = create(mIndexA, "AddSupertype", NodeClass::ObjectType);
  const NodeId subtype = create(mIndexB, "AddSubtype", NodeClass::ObjectType);

  expect_required_half_refusal(node(supertype).try_add_reference_sync(
                                 hasSubtype, ExpandedNodeId{subtype}, true, ReferenceHalves::ThisHalfOnly),
    "the add of the supertype's forward half alone");
  EXPECT_FALSE(holds(supertype, hasSubtype, ExpandedNodeId{subtype}, true)) << "a refused add added it";
  EXPECT_FALSE(holds(subtype, hasSubtype, ExpandedNodeId{supertype}, false)) << "a refused add added it";

  const auto inverse = node(subtype).try_add_reference_sync(
    hasSubtype, ExpandedNodeId{supertype}, false, ReferenceHalves::ThisHalfOnly);
  EXPECT_TRUE(inverse.is_good()) << to_string(inverse.status_code());
  EXPECT_TRUE(holds(subtype, hasSubtype, ExpandedNodeId{supertype}, false))
    << "the subtype's half was not added";
  EXPECT_FALSE(holds(supertype, hasSubtype, ExpandedNodeId{subtype}, true))
    << "the add of the subtype's half alone added the supertype's";
}

// A target in another Server keeps its half under Both: the removal of X's half to a remote target does not
// touch the local Node with the same NodeId, which holds an inverse half from X. The unchanged code already
// meets this rule (it paired local targets only), so this test is a guard that passes on it.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-REMOTE-TARGET-KEEPS-ITS-HALF, scope=function)
TEST_P(ReferenceHalvesTest, ABothRemovalKeepsTheHalfOfATargetInAnotherServer)
{
  const NodeId x = create(mIndexA, "X");
  const NodeId y = create(mIndexB, "Y");
  ExpandedNodeId remote{y};
  remote.server_index() = 1;
  ASSERT_TRUE(node(x)
                .try_add_reference_sync(hasDictionaryEntry, remote, true, ReferenceHalves::ThisHalfOnly)
                .is_good());
  ASSERT_TRUE(
    node(y)
      .try_add_reference_sync(hasDictionaryEntry, ExpandedNodeId{x}, false, ReferenceHalves::ThisHalfOnly)
      .is_good());

  const auto removed =
    node(x).try_remove_reference_sync(hasDictionaryEntry, remote, true, ReferenceHalves::Both);

  EXPECT_TRUE(removed.is_good()) << to_string(removed.status_code());
  EXPECT_FALSE(holds(x, hasDictionaryEntry, remote, true)) << "X kept the half it was asked to remove";
  EXPECT_TRUE(holds(y, hasDictionaryEntry, ExpandedNodeId{x}, false))
    << "a removal naming a target in another Server removed a half of a local Node";
}

// A batch takes one ReferenceHalves for all its References, and each is answered alone: under ThisHalfOnly
// the HasEncoding is refused and keeps both halves, while the Organizes beside it loses X's half only. The
// call answers the refusal. Fails on the unchanged code, which removed both halves of both and answered Good.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-THIS-HALF-ONLY-REFUSES-A-REQUIRED-PAIR, scope=function)
TEST_P(ReferenceHalvesTest, AThisHalfOnlyBatchRefusesTheRequiredPairAndRemovesTheRest)
{
  const NodeId x = create(mIndexA, "X", NodeClass::DataType);
  const NodeId y = create(mIndexB, "Y");
  const NodeId encoding = create(mIndexB, "E");
  link(x, organizes, y);
  link(x, hasEncoding, encoding);

  const auto removed = node(x).try_remove_references_sync(
    {Reference{organizes, ExpandedNodeId{y}, true}, Reference{hasEncoding, ExpandedNodeId{encoding}, true}},
    ReferenceHalves::ThisHalfOnly);

  expect_required_half_refusal(removed, "the batch");
  EXPECT_FALSE(holds(x, organizes, ExpandedNodeId{y}, true)) << "X kept the Organizes it was asked to remove";
  EXPECT_TRUE(holds(y, organizes, ExpandedNodeId{x}, false)) << "Y lost its half to a removal of X's alone";
  EXPECT_TRUE(holds(x, hasEncoding, ExpandedNodeId{encoding}, true)) << "a refused removal removed a half";
  EXPECT_TRUE(holds(encoding, hasEncoding, ExpandedNodeId{x}, false)) << "a refused removal removed a half";
}

}  // namespace

INSTANTIATE_TEST_SUITE_P(
  Namespaces, ReferenceHalvesTest, ::testing::Values(in_memory_kind(), described_nodes_kind()));
