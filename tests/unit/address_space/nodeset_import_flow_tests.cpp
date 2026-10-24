// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// A NodeSet import runs in phases (NR-31, NR-70 B7b): the Nodes are looked up, the missing ones created, then
// every Reference added as both halves, then the created Variables' Values written, each phase one call per
// namespace per chunk of its operation limit.
//
// The namespaces record each call the import makes and otherwise behave as the in-memory namespace.

#include <gtest/gtest.h>

#include "batch_recording_namespace.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_node_accessor.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_referencetype_id.h"
#include "ua_service_operation_limits.h"
#include "ua_status_to_string.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"
#include "ua_utilities.h"
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

using namespace ua;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;
using Call = BatchRecordingNamespace::Call;

namespace
{

constexpr std::string_view uriA = "urn:test:import-flow:a";
constexpr std::string_view uriB = "urn:test:import-flow:b";

// Objects A1, A2, A3 in A and B1, B2 in B; A1 Organizes A2, and A2 Organizes B1.
constexpr std::string_view twoNamespaces = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:import-flow:a</Uri><Uri>urn:test:import-flow:b</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;s=A1" BrowseName="1:A1">
    <References><Reference ReferenceType="i=35">ns=1;s=A2</Reference></References>
  </UAObject>
  <UAObject NodeId="ns=1;s=A2" BrowseName="1:A2">
    <References><Reference ReferenceType="i=35">ns=2;s=B1</Reference></References>
  </UAObject>
  <UAObject NodeId="ns=1;s=A3" BrowseName="1:A3"/>
  <UAObject NodeId="ns=2;s=B1" BrowseName="2:B1"/>
  <UAObject NodeId="ns=2;s=B2" BrowseName="2:B2"/>
</UANodeSet>)";

// X in A, organized by F and typed by T, both in B and outside the file.
constexpr std::string_view outsideTargets = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:import-flow:a</Uri><Uri>urn:test:import-flow:b</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;s=X" BrowseName="1:X">
    <References>
      <Reference ReferenceType="i=35" IsForward="false">ns=2;s=F</Reference>
      <Reference ReferenceType="i=40">ns=2;s=T</Reference>
    </References>
  </UAObject>
</UANodeSet>)";

// Two NodeVersion Properties in A, each with a Value: V.NodeVersion, which the test creates before the
// import, and N.NodeVersion, which the import creates.
constexpr std::string_view twoNodeVersions = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:import-flow:a</Uri><Uri>urn:test:import-flow:b</Uri></NamespaceUris>
  <UAVariable NodeId="ns=1;s=V.NodeVersion" BrowseName="NodeVersion" DataType="i=12">
    <Value><String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">99</String></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;s=N.NodeVersion" BrowseName="NodeVersion" DataType="i=12">
    <Value><String xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">5</String></Value>
  </UAVariable>
</UANodeSet>)";

class ImportFlow : public ::testing::Test
{
protected:
  void SetUp() override
  {
    build(std::nullopt);
  }

  void TearDown() override
  {
    release();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void release()
  {
    mA.reset();
    mB.reset();
    mAddressSpace.reset();
  }

  /// A fresh address space holding A and B, with @p limits.
  void build(std::optional<ServiceOperationLimits> limits)
  {
    release();
    mAddressSpace.emplace(AddressSpace::create("urn:test", mThreadPool.get_executor()));
    if (limits)
    {
      mAddressSpace->set_operation_limits(*limits);
    }
    for (auto [space, index, uri] :
      {std::tuple{&mA, &mIndexA, uriA}, std::tuple{&mB, &mIndexB, uriB}})
    {
      *space = std::make_shared<BatchRecordingNamespace>(uri, mThreadPool.get_executor());
      auto added = mAddressSpace->try_add_namespace_sync(*space);
      ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
      *index = added.value();
    }
  }

  VoidResult import(std::string_view nodeSetXml,
    std::optional<xml::nodeset::ImportEngine::ImportReferencePredicate> referenceFilter = std::nullopt)
  {
    const auto limits = make_encoding_limits(ApplicationConfig::load_default());
    memory_stream_device::ExternalReadOnly device{
      utils::span_of_char_to_span_of_byte(span<const char>{nodeSetXml.data(), nodeSetXml.size()})};
    MemoryStream input{device};
    auto nodeSets = xml::nodeset::Parser::parse(limits,
      input,
      mStructureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});
    auto engine = xml::nodeset::ImportEngine::create(limits, *mAddressSpace, nodeSets, {});
    return engine->try_import_all_sync({}, std::move(referenceFilter));
  }

  static std::vector<Call> calls_of(const BatchRecordingNamespace& space, Member member)
  {
    return space.calls(member);
  }

  static std::set<NodeId> created_by(const BatchRecordingNamespace& space)
  {
    std::set<NodeId> created;
    for (const auto& call : calls_of(space, Member::CreateNodes))
    {
      created.insert(call.nodeIds.begin(), call.nodeIds.end());
    }
    return created;
  }

  /// Each half @p space was sent, as (source, ReferenceType, target, isForward), once per time it was sent.
  static std::multiset<std::tuple<NodeId, NodeId, NodeId, bool>> halves_sent_to(const BatchRecordingNamespace& space)
  {
    std::multiset<std::tuple<NodeId, NodeId, NodeId, bool>> halves;
    for (const auto& call : calls_of(space, Member::AddReferences))
    {
      for (const auto& change : call.referenceChanges)
      {
        halves.emplace(change.source, change.referenceType, change.target.node_id(), change.isForward);
      }
    }
    return halves;
  }

  /// Whether every `create_nodes_async` call A and B received was made before their first
  /// `add_references_async` call.
  bool every_node_created_first() const
  {
    std::vector<Call> creates = calls_of(*mA, Member::CreateNodes);
    std::vector<Call> adds = calls_of(*mA, Member::AddReferences);
    for (auto& call : calls_of(*mB, Member::CreateNodes))
    {
      creates.push_back(std::move(call));
    }
    for (auto& call : calls_of(*mB, Member::AddReferences))
    {
      adds.push_back(std::move(call));
    }
    for (const auto& create : creates)
    {
      for (const auto& add : adds)
      {
        if (add.entered < create.entered)
        {
          return false;
        }
      }
    }
    return true;
  }

  NodeId a(std::string name) const
  {
    return NodeId{mIndexA, String{std::move(name)}};
  }

  NodeId b(std::string name) const
  {
    return NodeId{mIndexB, String{std::move(name)}};
  }

  /// The halves the two-namespace file gives A and B.
  void expect_the_two_namespace_halves()
  {
    const NodeId organizes{ReferenceTypeId::Organizes};
    EXPECT_EQ(halves_sent_to(*mA),
      (std::multiset<std::tuple<NodeId, NodeId, NodeId, bool>>{{a("A1"), organizes, a("A2"), true},
        {a("A2"), organizes, a("A1"), false},
        {a("A2"), organizes, b("B1"), true}}));
    EXPECT_EQ(halves_sent_to(*mB),
      (std::multiset<std::tuple<NodeId, NodeId, NodeId, bool>>{{b("B1"), organizes, a("A2"), false}}));
    EXPECT_EQ(created_by(*mA), (std::set<NodeId>{a("A1"), a("A2"), a("A3")}));
    EXPECT_EQ(created_by(*mB), (std::set<NodeId>{b("B1"), b("B2")}));
    EXPECT_TRUE(every_node_created_first());
  }

  boost::asio::thread_pool mThreadPool{2};
  StructureFactory mStructureFactory;
  std::optional<AddressSpace> mAddressSpace;
  shared_ptr<BatchRecordingNamespace> mA;
  shared_ptr<BatchRecordingNamespace> mB;
  uint16_t mIndexA{0};
  uint16_t mIndexB{0};
};

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-04-PHASES-ONE-CALL-PER-NAMESPACE-PER-CHUNK, scope=function)
TEST_F(ImportFlow, EachPhaseIsOneCallPerNamespaceAndEveryNodeIsCreatedFirst)
{
  const auto imported = import(twoNamespaces);
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());

  for (const auto& space : {mA, mB})
  {
    EXPECT_EQ(calls_of(*space, Member::CreateNodes).size(), 1u);
    EXPECT_EQ(calls_of(*space, Member::AddReferences).size(), 1u);
  }
  expect_the_two_namespace_halves();
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-04-PHASES-ONE-CALL-PER-NAMESPACE-PER-CHUNK, scope=function)
TEST_F(ImportFlow, ChunksFollowMaxNodesPerNodeManagement)
{
  ServiceOperationLimits limits;
  limits.maxNodesPerNodeManagement = 2;
  build(limits);

  const auto imported = import(twoNamespaces);
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());

  for (const auto& space : {mA, mB})
  {
    for (const auto member : {Member::CreateNodes, Member::AddReferences})
    {
      for (const auto& call : calls_of(*space, member))
      {
        EXPECT_LE(call.nodeIds.size(), 2u);
      }
    }
  }
  expect_the_two_namespace_halves();
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-07-A-DATA-TYPE-HAS-SUBTYPE-IN-THE-SAME-CALL-IS-SEEN, scope=function)
TEST_F(ImportFlow, AVariableTypesHasSubtypeIsAddedAfterItsDataTypesHasSubtype)
{
  // Counted's DataType Integer is a subtype of Measured's DataType Number only once Integer's HasSubtype is held,
  // and the file lists Counted first; one change per call keeps them apart.
  constexpr std::string_view typesAfterUse = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:import-flow:a</Uri></NamespaceUris>
  <UAVariableType NodeId="ns=1;s=Counted" BrowseName="1:Counted" DataType="ns=1;s=Integer">
    <References><Reference ReferenceType="i=45" IsForward="false">ns=1;s=Measured</Reference></References>
  </UAVariableType>
  <UAVariableType NodeId="ns=1;s=Measured" BrowseName="1:Measured" DataType="ns=1;s=Number"/>
  <UADataType NodeId="ns=1;s=Integer" BrowseName="1:Integer">
    <References><Reference ReferenceType="i=45" IsForward="false">ns=1;s=Number</Reference></References>
  </UADataType>
  <UADataType NodeId="ns=1;s=Number" BrowseName="1:Number"/>
</UANodeSet>)";
  ServiceOperationLimits limits;
  limits.maxNodesPerNodeManagement = 1;
  build(limits);

  const auto imported = import(typesAfterUse);
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-04-A-TARGET-OUTSIDE-THE-FILES-GETS-THE-OTHER-HALF, scope=function)
TEST_F(ImportFlow, AReferenceToANodeOutsideTheFilesGetsItsInverse)
{
  for (const auto& name : {"F", "T"})
  {
    auto created = mAddressSpace->try_create_node_sync(b(name), NodeClass::Object, {});
    ASSERT_TRUE(created.is_good()) << name << ": " << to_string(created.status_code());
  }
  mB->reset();

  const auto imported = import(outsideTargets);
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());

  auto folder = mAddressSpace->try_find_node_sync(b("F"));
  ASSERT_TRUE(folder.is_good());
  auto references = folder.value().try_get_references_sync();
  ASSERT_TRUE(references.is_good()) << to_string(references.status_code());
  EXPECT_TRUE(std::any_of(references.value().begin(),
    references.value().end(),
    [&](const Reference& reference)
    {
      return reference.type_id() == NodeId{ReferenceTypeId::Organizes} && reference.is_forward() &&
             reference.target_id() == ExpandedNodeId{a("X")};
    }));
  for (const auto& half : halves_sent_to(*mB))
  {
    EXPECT_NE(std::get<0>(half), b("T"));
  }
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-04-THE-FILTER-DECIDES-EACH-HALF-AS-ITS-HOLDER-HOLDS-IT, scope=function)
TEST_F(ImportFlow, AReferenceTheFilterDropsOnOneSideLosesThatHalf)
{
  // Every Reference to A2 is dropped: A1's Organizes to A2, and B1's inverse Organizes to A2.
  const NodeId a2InTheFile{1, String{"A2"}};
  const auto imported = import(twoNamespaces,
    [a2InTheFile](const xml::nodeset::Node&, const xml::nodeset::Node::Reference& reference)
    { return reference.targetId != a2InTheFile; });
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());

  const NodeId organizes{ReferenceTypeId::Organizes};
  EXPECT_EQ(halves_sent_to(*mA),
    (std::multiset<std::tuple<NodeId, NodeId, NodeId, bool>>{{a("A2"), organizes, a("A1"), false},
      {a("A2"), organizes, b("B1"), true}}));
  EXPECT_TRUE(halves_sent_to(*mB).empty());
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-04-THE-FILTER-DECIDES-EACH-HALF-AS-ITS-HOLDER-HOLDS-IT, scope=function)
TEST_F(ImportFlow, AHasSubtypeTheFilterDropsOnTheSupertypeIsNotAddedThere)
{
  // Subtype T names its supertype S; the filter drops every Reference to T, so S's forward half.
  constexpr std::string_view subtypes = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:import-flow:a</Uri></NamespaceUris>
  <UAObjectType NodeId="ns=1;s=S" BrowseName="1:S"/>
  <UAObjectType NodeId="ns=1;s=T" BrowseName="1:T">
    <References><Reference ReferenceType="i=45" IsForward="false">ns=1;s=S</Reference></References>
  </UAObjectType>
</UANodeSet>)";
  const NodeId tInTheFile{1, String{"T"}};
  const auto imported = import(subtypes,
    [tInTheFile](const xml::nodeset::Node&, const xml::nodeset::Node::Reference& reference)
    { return reference.targetId != tInTheFile; });
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());

  EXPECT_EQ(halves_sent_to(*mA),
    (std::multiset<std::tuple<NodeId, NodeId, NodeId, bool>>{
      {a("T"), NodeId{ReferenceTypeId::HasSubtype}, a("S"), false}}));
}

using ImportVersions = ImportFlow;

// NR-55 rule 3: the import writes no NodeVersion or ViewVersion to a Node that existed before it; the
// NodeVersion of an existing Node is its namespace's to advance. The created Property's Value is written: the
// control.
// @relation(AC-COMP-SVR-AS-CHANGE-EVENTS-06-AN-IMPORT-WRITES-NO-VERSION-TO-AN-EXISTING-NODE, scope=function)
TEST_F(ImportVersions, WritesNoVersionToANodeThatExistedBefore)
{
  auto existing = mAddressSpace->try_create_node_sync(a("V.NodeVersion"), NodeClass::Variable, {});
  ASSERT_TRUE(existing.is_good()) << to_string(existing.status_code());
  auto version = existing.value().as<VariableAccessor>();
  ASSERT_TRUE(version.has_value());
  version->write_value_sync(DataValue{Variant{String{"1"}}});
  mA->reset();

  const auto imported = import(twoNodeVersions);
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());

  std::set<NodeId> written;
  for (const auto& call : calls_of(*mA, Member::Write))
  {
    written.insert(call.nodeIds.begin(), call.nodeIds.end());
  }
  EXPECT_EQ(written.count(a("V.NodeVersion")), 0u)
    << "the import wrote the NodeVersion of a Node that existed before it";
  EXPECT_EQ(written.count(a("N.NodeVersion")), 1u)
    << "the import did not write the Value of the Property it created";
  const auto value = version->try_read_value_sync();
  ASSERT_TRUE(value.is_good()) << to_string(value.status_code());
  EXPECT_EQ(value.value().value(), Variant{String{"1"}});
}

}  // namespace
