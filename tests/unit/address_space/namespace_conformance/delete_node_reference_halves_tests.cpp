// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Which halves of a deleted Node's References a delete removes (`ReferenceHalves`; OPC 10000-4 5.7.4.1 and
// 5.7.4.2, Table 28). With `Both` (deleteTargetReferences TRUE) the delete removes the halves every other
// Node holds of a Reference to a deleted Node, in the deleted Node's namespace and in any other. With
// `ThisHalfOnly` (deleteTargetReferences FALSE) it removes only the deleted Nodes and the halves they hold:
// every other Node keeps its half, left unresolved (OPC 10000-3 4.3.4 allows a Reference to a Node that does
// not exist), is not changed, and is therefore neither versioned nor listed in the operation's
// ModelChangeEvent.
//
// Each arm runs against the in-memory namespace and against a namespace written from the public headers alone
// (DescribedConformanceNamespace). The address space holds two namespaces of the kind under test, A and B:
// the deleted Nodes are in A, and their referrers are in A (the same namespace) and in B (another namespace).
//
// These tests pass `ReferenceHalves` to `AddressSpace::try_delete_node_sync`, which the API before DL-124 (4)
// does not take: they do not compile against it.

#include <gtest/gtest.h>

#include "described_conformance_namespace.h"
#include "test_utilities.h"
#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_address_space_change_events.h"
#include "ua_application_configuration.h"
#include "ua_attribute_id.h"
#include "ua_attribute_wire.h"
#include "ua_data_type_registration.h"
#include "ua_data_value.h"
#include "ua_default_namespace.h"
#include "ua_encoding_limits.h"
#include "ua_expanded_node_id.h"
#include "ua_file_stream.h"
#include "ua_localized_text.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_reference_halves.h"
#include "ua_referencetype_id.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
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

uint8_t verb(ModelChangeStructureVerbMask mask)
{
  return static_cast<uint8_t>(static_cast<int32_t>(mask));
}

const NodeId organizes{ReferenceTypeId::Organizes};
const NodeId hasComponent{ReferenceTypeId::HasComponent};
const NodeId hasProperty{ReferenceTypeId::HasProperty};
const NodeId stringDataType{0, uint32_t{12}};

class DeleteNodeReferenceHalves : public ::testing::TestWithParam<NamespaceKind>
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(
      AddressSpace::create("urn:test:delete-node-reference-halves", mPool.get_executor()));
    mA = GetParam().make("urn:test:delete-node-reference-halves:a", mPool.get_executor());
    mB = GetParam().make("urn:test:delete-node-reference-halves:b", mPool.get_executor());
    ASSERT_NE(mA, nullptr);
    ASSERT_NE(mB, nullptr);
    auto indexA = mAddressSpace->try_add_namespace_sync(mA);
    ASSERT_TRUE(indexA.is_good()) << to_string(indexA.status_code());
    auto indexB = mAddressSpace->try_add_namespace_sync(mB);
    ASSERT_TRUE(indexB.is_good()) << to_string(indexB.status_code());
    mIndexA = indexA.value();
    mIndexB = indexB.value();
    detail::AddressSpaceChangeEvents::set_handler(*mAddressSpace,
      [this](const detail::AddressSpaceChange& change)
      {
        const std::lock_guard lock{mChangesMutex};
        mChanges.push_back(change);
      });
  }

  void TearDown() override
  {
    mA.reset();
    mB.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  /// Loads the OPC UA namespace's Nodes, so that the ReferenceType hierarchy a subtree delete walks exists.
  void load_namespace_zero()
  {
    const auto limits = make_encoding_limits(ApplicationConfig::load_default());
    auto lookup = namespace_array_utils::get_index_lookup_function(*mAddressSpace);
    const CodecNamespaceContext context{std::move(lookup), {}, {}, {}};
    register_ua_data_types_with_factory(context, &mStructureFactory, &mStructureFactory);
    FileStream input{"NodeSet2.xml"};
    input.open_for_read();
    auto nodeSets = xml::nodeset::Parser::parse(limits,
      input,
      mStructureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});
    auto importer = xml::nodeset::ImportEngine::create(limits, *mAddressSpace, nodeSets, {});
    importer->import_all_sync({}, {});
  }

  InitialAttributes names(uint16_t index, const std::string& name) const
  {
    return InitialAttributes{
      {AttributeId::BrowseName, attribute_wire::browse_name(QualifiedName{index, String{name}})},
      {AttributeId::DisplayName, attribute_wire::display_name(LocalizedText{LocaleId{"en"}, String{name}})}};
  }

  NodeId create_object(uint16_t index, const std::string& name)
  {
    const NodeId nodeId{index, String{name}};
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::Object, names(index, name));
    EXPECT_TRUE(created.is_good()) << name << ": " << to_string(created.status_code());
    return nodeId;
  }

  // Stores the forward half on @p source and the inverse half on @p target. An add that pairs the halves
  // itself answers the second add Bad_DuplicateReferenceNotAllowed, which is ignored; the halves are checked.
  void link(const NodeId& source, const NodeId& type, const NodeId& target)
  {
    (void)mAddressSpace->find_node_sync(source).try_add_reference_sync(type, target);
    (void)mAddressSpace->find_node_sync(target).try_add_reference_sync(type, ExpandedNodeId{source}, false);
    ASSERT_TRUE(holds(source, type, target, true)) << to_string(source) << " lacks its half";
    ASSERT_TRUE(holds(target, type, source, false)) << to_string(target) << " lacks its half";
  }

  // Whether @p node holds the half of a @p type Reference to @p other in the direction @p isForward.
  bool holds(const NodeId& node, const NodeId& type, const NodeId& other, bool isForward)
  {
    auto found = mAddressSpace->try_find_node_sync(node);
    if (!found.is_good())
    {
      ADD_FAILURE() << to_string(node) << " not found: " << to_string(found.status_code());
      return false;
    }
    auto references = found.value().try_get_references_sync();
    if (!references.is_good())
    {
      ADD_FAILURE() << "the References of " << to_string(node)
                    << " could not be read: " << to_string(references.status_code());
      return false;
    }
    for (const auto& reference : references.value())
    {
      if (reference.type_id() == type && reference.target_id() == ExpandedNodeId{other} &&
          reference.is_forward() == isForward)
      {
        return true;
      }
    }
    return false;
  }

  bool exists(const NodeId& node)
  {
    return mAddressSpace->try_find_node_sync(node).is_good();
  }

  // Gives @p node a NodeVersion Property, both halves of its HasProperty stored; returns the Property.
  NodeId version(const NodeId& node, uint16_t index, const std::string& name)
  {
    const NodeId property{index, String{name + ".NodeVersion"}};
    auto attributes = names(index, name);
    attributes[0].second = attribute_wire::browse_name(QualifiedName{0, "NodeVersion"});
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    accessLevel.set(AccessLevelType::Bit::CurrentWrite);
    attributes.emplace_back(AttributeId::DataType, attribute_wire::data_type(stringDataType));
    attributes.emplace_back(AttributeId::ValueRank, attribute_wire::value_rank(ValueRank{ValueRank::scalar}));
    attributes.emplace_back(AttributeId::AccessLevel, attribute_wire::access_level(accessLevel));
    auto variable = mAddressSpace->create_sync<VariableAccessor>(property, NodeClass::Variable, attributes);
    variable.write_value_sync(DataValue{Variant{String{"1"}}});
    link(node, hasProperty, property);
    return property;
  }

  Variant version_value(const NodeId& property)
  {
    auto variable = mAddressSpace->find_node_sync(property).as<VariableAccessor>();
    if (!variable.has_value())
    {
      ADD_FAILURE() << to_string(property) << " is not a Variable";
      return Variant{};
    }
    auto read = variable->try_read_value_sync();
    EXPECT_TRUE(read.is_good()) << to_string(read.status_code());
    return read.is_good() ? read.value().value() : Variant{};
  }

  void clear_changes()
  {
    const std::lock_guard lock{mChangesMutex};
    mChanges.clear();
  }

  // The verbs the events raised so far list for @p node, OR-ed; 0 when no event lists it.
  uint8_t listed_verbs(const NodeId& node)
  {
    const std::lock_guard lock{mChangesMutex};
    uint8_t verbs = 0;
    for (const auto& change : mChanges)
    {
      for (const auto& entry : change.changes)
      {
        if (entry.affected == node)
        {
          verbs = static_cast<uint8_t>(verbs | entry.verbs);
        }
      }
    }
    return verbs;
  }

  StructureFactory mStructureFactory;
  boost::asio::thread_pool mPool{2};
  std::optional<AddressSpace> mAddressSpace;
  shared_ptr<Namespace> mA;
  shared_ptr<Namespace> mB;
  uint16_t mIndexA{0};
  uint16_t mIndexB{0};
  std::mutex mChangesMutex;
  std::vector<detail::AddressSpaceChange> mChanges;
};

}  // namespace

// A ThisHalfOnly delete of X removes X and the halves X holds, and leaves the half Y (namespace B) and the
// half Z (namespace A, X's own) hold of their Organizes References to X. The control arm below deletes with
// Both.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-08-THIS-HALF-ONLY-LEAVES-OTHER-NODES-HALVES, scope=function)
TEST_P(DeleteNodeReferenceHalves, ThisHalfOnlyLeavesTheHalvesOtherNodesHoldInEveryNamespace)
{
  const NodeId x = create_object(mIndexA, "X");
  const NodeId y = create_object(mIndexB, "Y");
  const NodeId z = create_object(mIndexA, "Z");
  ASSERT_NO_FATAL_FAILURE(link(y, organizes, x));
  ASSERT_NO_FATAL_FAILURE(link(z, organizes, x));

  const auto deleted = mAddressSpace->try_delete_node_sync(
    x, /*deleteForwardHierarchicallyReferencedNodes=*/false, ReferenceHalves::ThisHalfOnly);

  ASSERT_TRUE(deleted.is_good()) << to_string(deleted.status_code());
  EXPECT_FALSE(exists(x));
  EXPECT_TRUE(holds(y, organizes, x, true)) << "the referrer in another namespace lost its half";
  EXPECT_TRUE(holds(z, organizes, x, true)) << "the referrer in the deleted Node's namespace lost its half";
}

// Control: a Both delete of X, the default, removes the halves Y (namespace B) and Z (namespace A) hold.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-08-BOTH-REMOVES-OTHER-NODES-HALVES, scope=function)
TEST_P(DeleteNodeReferenceHalves, BothRemovesTheHalvesOtherNodesHoldInEveryNamespace)
{
  const NodeId x = create_object(mIndexA, "X");
  const NodeId y = create_object(mIndexB, "Y");
  const NodeId z = create_object(mIndexA, "Z");
  ASSERT_NO_FATAL_FAILURE(link(y, organizes, x));
  ASSERT_NO_FATAL_FAILURE(link(z, organizes, x));

  const auto deleted = mAddressSpace->try_delete_node_sync(
    x, /*deleteForwardHierarchicallyReferencedNodes=*/false, ReferenceHalves::Both);

  ASSERT_TRUE(deleted.is_good()) << to_string(deleted.status_code());
  EXPECT_FALSE(exists(x));
  EXPECT_FALSE(holds(y, organizes, x, true)) << "the referrer in another namespace kept its half";
  EXPECT_FALSE(holds(z, organizes, x, true)) << "the referrer in the deleted Node's namespace kept its half";
}

// A ThisHalfOnly subtree delete of R (A) -> C (A) -> D (B) deletes all three, and the outside referrers U (B)
// of R, V (A) of C and W (B) of D keep their halves. The control deletes the same subtree with Both and finds
// every outside half gone.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-08-SUBTREE-THIS-HALF-ONLY-LEAVES-OUTSIDE-HALVES, scope=function)
TEST_P(DeleteNodeReferenceHalves, ASubtreeDeleteWithThisHalfOnlyLeavesTheOutsideReferrersHalves)
{
  load_namespace_zero();
  for (const ReferenceHalves halves : {ReferenceHalves::ThisHalfOnly, ReferenceHalves::Both})
  {
    const bool thisHalfOnly = halves == ReferenceHalves::ThisHalfOnly;
    const std::string suffix = thisHalfOnly ? "1" : "2";
    SCOPED_TRACE(thisHalfOnly ? "ThisHalfOnly" : "Both");
    const NodeId r = create_object(mIndexA, "R" + suffix);
    const NodeId c = create_object(mIndexA, "C" + suffix);
    const NodeId d = create_object(mIndexB, "D" + suffix);
    const NodeId u = create_object(mIndexB, "U" + suffix);
    const NodeId v = create_object(mIndexA, "V" + suffix);
    const NodeId w = create_object(mIndexB, "W" + suffix);
    ASSERT_NO_FATAL_FAILURE(link(r, hasComponent, c));
    ASSERT_NO_FATAL_FAILURE(link(c, hasComponent, d));
    ASSERT_NO_FATAL_FAILURE(link(u, organizes, r));
    ASSERT_NO_FATAL_FAILURE(link(v, organizes, c));
    ASSERT_NO_FATAL_FAILURE(link(w, organizes, d));

    const auto deleted =
      mAddressSpace->try_delete_node_sync(r, /*deleteForwardHierarchicallyReferencedNodes=*/true, halves);

    ASSERT_TRUE(deleted.is_good()) << to_string(deleted.status_code());
    EXPECT_FALSE(exists(r));
    EXPECT_FALSE(exists(c));
    EXPECT_FALSE(exists(d));
    EXPECT_EQ(holds(u, organizes, r, true), thisHalfOnly) << "U's half to the deleted root";
    EXPECT_EQ(holds(v, organizes, c, true), thisHalfOnly) << "V's half to the deleted child";
    EXPECT_EQ(holds(w, organizes, d, true), thisHalfOnly) << "W's half to the deleted grandchild";
  }
}

// A referrer that keeps its half is not changed: with ThisHalfOnly the versioned referrers P (B) and Q (A)
// keep their NodeVersions and no ModelChangeEvent of the delete lists them. The control deletes X2 with Both:
// P2 and Q2 advance and are listed ReferenceDeleted (NR-36 rule 2; OPC 10000-5 12.16).
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-08-A-REFERRER-THAT-KEEPS-ITS-HALF-IS-NOT-REPORTED, scope=function)
TEST_P(DeleteNodeReferenceHalves, AReferrerThatKeepsItsHalfIsNeitherVersionedNorReported)
{
  for (const ReferenceHalves halves : {ReferenceHalves::ThisHalfOnly, ReferenceHalves::Both})
  {
    const bool thisHalfOnly = halves == ReferenceHalves::ThisHalfOnly;
    const std::string suffix = thisHalfOnly ? "1" : "2";
    SCOPED_TRACE(thisHalfOnly ? "ThisHalfOnly" : "Both");
    const NodeId x = create_object(mIndexA, "X" + suffix);
    const NodeId p = create_object(mIndexB, "P" + suffix);
    const NodeId q = create_object(mIndexA, "Q" + suffix);
    NodeId pVersion;
    NodeId qVersion;
    ASSERT_NO_FATAL_FAILURE(pVersion = version(p, mIndexB, "P" + suffix));
    ASSERT_NO_FATAL_FAILURE(qVersion = version(q, mIndexA, "Q" + suffix));
    ASSERT_NO_FATAL_FAILURE(link(p, organizes, x));
    ASSERT_NO_FATAL_FAILURE(link(q, organizes, x));
    const Variant pBefore = version_value(pVersion);
    const Variant qBefore = version_value(qVersion);
    clear_changes();

    const auto deleted =
      mAddressSpace->try_delete_node_sync(x, /*deleteForwardHierarchicallyReferencedNodes=*/false, halves);

    // The delete answers after its event was raised (NR-46).
    ASSERT_TRUE(deleted.is_good()) << to_string(deleted.status_code());
    const uint8_t referenceDeleted = verb(ModelChangeStructureVerbMask::ReferenceDeleted);
    if (thisHalfOnly)
    {
      EXPECT_EQ(version_value(pVersion), pBefore) << "the referrer in another namespace was versioned";
      EXPECT_EQ(version_value(qVersion), qBefore)
        << "the referrer in the deleted Node's namespace was versioned";
      EXPECT_EQ(listed_verbs(p), 0u) << "the referrer in another namespace was listed";
      EXPECT_EQ(listed_verbs(q), 0u) << "the referrer in the deleted Node's namespace was listed";
    }
    else
    {
      EXPECT_NE(version_value(pVersion), pBefore);
      EXPECT_NE(version_value(qVersion), qBefore);
      EXPECT_EQ(listed_verbs(p) & referenceDeleted, referenceDeleted);
      EXPECT_EQ(listed_verbs(q) & referenceDeleted, referenceDeleted);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
  Namespaces, DeleteNodeReferenceHalves, ::testing::Values(in_memory_kind(), described_nodes_kind()));
