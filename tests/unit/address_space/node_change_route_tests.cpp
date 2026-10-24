// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// The address space creates and deletes Nodes through the namespaces' batched members (NR-70 B7a): a create
// is one `create_nodes_async` item, a delete one `delete_nodes_async` call per namespace with the other
// halves of its References removed by one `remove_references_async` per referrer namespace, and a subtree
// delete reads and deletes each level with one call per namespace, the deepest level first.
//
// The namespaces record each call the address space makes and otherwise behave as the in-memory namespace.

#include <gtest/gtest.h>

#include "batch_recording_namespace.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_data_type_registration.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_file_stream.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status_to_string.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace ua;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;
using Call = BatchRecordingNamespace::Call;

namespace
{

class NodeChangeRoute : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test", mThreadPool.get_executor()));
    for (auto [space, index, uri] : {std::tuple{&mA, &mIndexA, "urn:test:node-change:a"},
           std::tuple{&mB, &mIndexB, "urn:test:node-change:b"},
           std::tuple{&mD, &mIndexD, "urn:test:node-change:d"}})
    {
      *space = std::make_shared<BatchRecordingNamespace>(uri, mThreadPool.get_executor());
      auto added = mAddressSpace->try_add_namespace_sync(*space);
      ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
      *index = added.value();
    }
  }

  void TearDown() override
  {
    mA.reset();
    mB.reset();
    mD.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
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

  void create_object(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::Object, {});
    ASSERT_TRUE(created.is_good()) << to_string(nodeId) << ": " << to_string(created.status_code());
  }

  /// Gives @p source a forward Reference of @p type to @p target and @p target its inverse half.
  void link(const NodeId& source, ReferenceTypeId type, const NodeId& target)
  {
    auto sourceNode = mAddressSpace->try_find_node_sync(source);
    ASSERT_TRUE(sourceNode.is_good()) << to_string(source);
    auto targetNode = mAddressSpace->try_find_node_sync(target);
    ASSERT_TRUE(targetNode.is_good()) << to_string(target);
    auto forward = sourceNode.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{target}, true);
    ASSERT_TRUE(forward.is_good()) << to_string(forward.status_code());
    auto inverse = targetNode.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{source}, false);
    ASSERT_TRUE(inverse.is_good()) << to_string(inverse.status_code());
  }

  Status lookup(const NodeId& nodeId)
  {
    return mAddressSpace->try_find_node_sync(nodeId).status_code().as_status();
  }

  /// Whether @p holder holds a Reference, in either direction, whose target is @p target.
  bool holds_reference_to(const NodeId& holder, const NodeId& target)
  {
    auto node = mAddressSpace->try_find_node_sync(holder);
    if (!node.is_good())
    {
      return false;
    }
    auto references = node.value().try_get_references_sync();
    if (!references.is_good())
    {
      return false;
    }
    return std::any_of(references.value().begin(),
      references.value().end(),
      [&](const Reference& reference) { return reference.target_id() == ExpandedNodeId{target}; });
  }

  void reset_records()
  {
    for (const auto& space : {mA, mB, mD})
    {
      space->reset();
    }
  }

  static std::set<NodeId> named(const Call& call)
  {
    return {call.nodeIds.begin(), call.nodeIds.end()};
  }

  /// The NodeIds each call named, in call order.
  static std::vector<std::set<NodeId>> named_by_call(const std::vector<Call>& calls)
  {
    std::vector<std::set<NodeId>> result;
    result.reserve(calls.size());
    for (const auto& call : calls)
    {
      result.push_back(named(call));
    }
    return result;
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace;
  StructureFactory mStructureFactory;
  std::shared_ptr<BatchRecordingNamespace> mA;
  std::shared_ptr<BatchRecordingNamespace> mB;
  std::shared_ptr<BatchRecordingNamespace> mD;
  uint16_t mIndexA = 0;
  uint16_t mIndexB = 0;
  uint16_t mIndexD = 0;
};

}  // namespace

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-01-A-CREATE-IS-ONE-NODE-CREATION, scope=function)
TEST_F(NodeChangeRoute, ACreateIsOneNodeCreationSentToTheOwningNamespace)
{
  const NodeId x{mIndexB, "X"};
  const QualifiedName browseName{mIndexB, "X"};
  reset_records();

  auto created = mAddressSpace->try_create_node_sync(
    x, NodeClass::Object, {{AttributeId::BrowseName, Variant{browseName}}});
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());

  const auto calls = mB->calls(Member::CreateNodes);
  ASSERT_EQ(calls.size(), 1u) << "the create did not reach B as one create_nodes_async call";
  ASSERT_EQ(calls.front().creations.size(), 1u);
  const NodeCreation& creation = calls.front().creations.front();
  EXPECT_EQ(creation.nodeId, x);
  EXPECT_EQ(creation.nodeClass, NodeClass::Object);
  ASSERT_EQ(creation.attributes.size(), 1u);
  EXPECT_EQ(creation.attributes.front().first, AttributeId::BrowseName);
  EXPECT_EQ(creation.attributes.front().second, Variant{browseName});
  EXPECT_EQ(created.value().get_browse_name(), browseName);

  mB->answer_creations_without_node();
  auto withoutNode = mAddressSpace->try_create_node_sync(NodeId{mIndexB, "Y"}, NodeClass::Object, {});
  EXPECT_EQ(withoutNode.status_code().as_status(), Status::BadInternalError)
    << to_string(withoutNode.status_code());
  const auto detail = withoutNode.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "NamespaceAnsweredWithoutNode");
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-02-ONE-DELETE-CALL-AND-ONE-REMOVAL-CALL-PER-REFERRER-NAMESPACE, scope=function)
TEST_F(NodeChangeRoute, ADeleteIsOneCallAndItsRemovalsOneCallPerReferrerNamespace)
{
  const NodeId n{mIndexA, "N"};
  const NodeId r1{mIndexB, "R1"};
  const NodeId r2{mIndexB, "R2"};
  const NodeId r3{mIndexD, "R3"};
  for (const auto& id : {n, r1, r2, r3})
  {
    create_object(id);
  }
  for (const auto& r : {r1, r2, r3})
  {
    link(n, ReferenceTypeId::Organizes, r);
  }
  reset_records();

  const auto deleted = mAddressSpace->try_delete_node_sync(n, false);
  EXPECT_TRUE(deleted.is_good()) << to_string(deleted.status_code());

  const auto deletes = mA->calls(Member::DeleteNodes);
  ASSERT_EQ(deletes.size(), 1u) << "the delete did not reach A as one delete_nodes_async call";
  EXPECT_EQ(deletes.front().nodeIds, std::vector<NodeId>{n});

  const auto expectHalves =
    [&](const std::shared_ptr<BatchRecordingNamespace>& space, const char* name, std::set<NodeId> referrers)
  {
    const auto removals = space->calls(Member::RemoveReferences);
    ASSERT_EQ(removals.size(), 1u) << name
                                   << " did not receive the halves as one remove_references_async call";
    const auto& changes = removals.front().referenceChanges;
    ASSERT_EQ(changes.size(), referrers.size()) << name;
    std::set<NodeId> sources;
    for (const auto& change : changes)
    {
      sources.insert(change.source);
      EXPECT_EQ(change.referenceType, NodeId{ReferenceTypeId::Organizes}) << name;
      EXPECT_EQ(change.target, ExpandedNodeId{n}) << name;
      EXPECT_FALSE(change.isForward) << name << ": the referrer's half is the inverse one";
    }
    EXPECT_EQ(sources, referrers) << name;
  };
  expectHalves(mB, "B", {r1, r2});
  expectHalves(mD, "D", {r3});

  EXPECT_EQ(lookup(n), Status::BadNodeIdUnknown);
  for (const auto& r : {r1, r2, r3})
  {
    EXPECT_FALSE(holds_reference_to(r, n)) << to_string(r) << " still holds a Reference to N";
  }
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-03-ONE-CALL-PER-NAMESPACE-PER-LEVEL-DEEPEST-FIRST, scope=function)
TEST_F(NodeChangeRoute, ASubtreeDeleteIsOneCallPerNamespacePerLevelDeepestFirst)
{
  load_namespace_zero();
  const NodeId p{mIndexA, "P"};
  const NodeId c1{mIndexA, "C1"};
  const NodeId c2{mIndexB, "C2"};
  const NodeId c3{mIndexA, "C3"};
  const NodeId g1{mIndexA, "G1"};
  const NodeId g2{mIndexB, "G2"};
  for (const auto& id : {p, c1, c2, c3, g1, g2})
  {
    create_object(id);
  }
  link(p, ReferenceTypeId::HasComponent, c1);
  link(p, ReferenceTypeId::HasComponent, c2);
  link(p, ReferenceTypeId::HasComponent, c3);
  link(c1, ReferenceTypeId::HasComponent, g1);
  link(c2, ReferenceTypeId::HasComponent, g2);
  reset_records();

  const auto deleted = mAddressSpace->try_delete_node_sync(p, true);
  EXPECT_TRUE(deleted.is_good()) << to_string(deleted.status_code());
  for (const auto& id : {p, c1, c2, c3, g1, g2})
  {
    EXPECT_EQ(lookup(id), Status::BadNodeIdUnknown) << to_string(id) << " was not deleted";
  }

  const auto deletesA = mA->calls(Member::DeleteNodes);
  const auto deletesB = mB->calls(Member::DeleteNodes);
  EXPECT_EQ(named_by_call(deletesA), (std::vector<std::set<NodeId>>{{g1}, {c1, c3}, {p}}))
    << "A's delete_nodes_async calls are not one per level, deepest first";
  EXPECT_EQ(named_by_call(deletesB), (std::vector<std::set<NodeId>>{{g2}, {c2}}))
    << "B's delete_nodes_async calls are not one per level, deepest first";
  if (deletesA.size() == 3u && deletesB.size() == 2u)
  {
    // Each level starts after every call of the deeper level has been made.
    EXPECT_LT(deletesA[0].entered, deletesB[1].entered);
    EXPECT_LT(deletesB[0].entered, deletesA[1].entered);
    EXPECT_LT(deletesA[1].entered, deletesA[2].entered);
    EXPECT_LT(deletesB[1].entered, deletesA[2].entered);
  }

  EXPECT_EQ(
    named_by_call(mA->calls(Member::ReadReferences)), (std::vector<std::set<NodeId>>{{p}, {c1, c3}, {g1}}))
    << "A's References are not read with one call per level";
  EXPECT_EQ(named_by_call(mB->calls(Member::ReadReferences)), (std::vector<std::set<NodeId>>{{c2}, {g2}}))
    << "B's References are not read with one call per level";
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-03-A-CHILD-WHOSE-LOOKUP-FAILS-FAILS-THE-DELETE, scope=function)
TEST_F(NodeChangeRoute, AChildWhoseLookupFailsIsTheSubtreeDeletesAnswer)
{
  load_namespace_zero();
  const NodeId p{mIndexA, "P"};
  const NodeId c{mIndexB, "C"};
  create_object(p);
  create_object(c);
  link(p, ReferenceTypeId::HasComponent, c);
  // B cannot answer for C now; a Node that does not exist would answer Bad_NodeIdUnknown instead.
  mB->decline_single_lookups();
  mB->answer_lookup_of(c, StatusCode{Status::BadTimeout});
  reset_records();

  const auto deleted = mAddressSpace->try_delete_node_sync(p, true);
  EXPECT_EQ(deleted.status_code().as_status(), Status::BadTimeout) << to_string(deleted.status_code());
}
