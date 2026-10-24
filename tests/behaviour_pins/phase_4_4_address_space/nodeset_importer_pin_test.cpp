// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (NodeSet XML importer post-import state).
//
// authorising this file. NI pins exercise the importer's only public surface
// (sync entry - see the documenting note in the runbook section 4.8 NI-D entry):
// after Parser::parse + ImportEngine::import_all_sync, the AddressSpace must
// reflect the imported nodes and references.
//
// The importer's *_async/coro shape is 4.4b's territory; these pins lock the
// post-import AddressSpace state, which is observable via *_async (find_node,
// get_components) - that is what the 4.4b flip preserves.
//
// Forbidden tokens (per runbook section 4): no `_coro\b`, no `Task<`, no
// `await_callback`. Pins drive *_async only at observation points.

#include <cstddef>
#include <cstring>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_encoding_limits.h"
#include "ua_expanded_node_id.h"
#include "instantiation/ua_instantiation_options.h"
#include "instantiation/ua_instantiation_service.h"
#include "instantiation/ua_node_subtree.h"
#include "ua_memory_stream.h"
#include "ua_namespace_array.h"
#include "ua_nodeset_import.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

namespace ua::test::behaviour_pins
{
namespace
{

// Minimal NodeSet2 fragment defining one ObjectType OT (i=1000) carrying one
// mandatory Variable child V (i=1001). NS0 references (HasComponent=i=47,
// HasModellingRule=i=37, ModellingRule_Mandatory=i=78) point at NS0 NodeIds
// that aren't imported - that is fine, the importer only needs to encode the
// references; it does not validate target existence.
constexpr std::string_view minimalObjectTypeXml = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
    <NamespaceUris>
        <Uri>urn:test:ni-pin</Uri>
    </NamespaceUris>
    <UAObjectType NodeId="ns=1;i=1000" BrowseName="1:OT">
        <References>
            <Reference ReferenceType="i=47">ns=1;i=1001</Reference>
        </References>
    </UAObjectType>
    <UAVariable NodeId="ns=1;i=1001" BrowseName="1:V" DataType="i=6" ValueRank="-1">
        <References>
            <Reference ReferenceType="i=37">i=78</Reference>
            <Reference ReferenceType="i=47" IsForward="false">ns=1;i=1000</Reference>
        </References>
    </UAVariable>
</UANodeSet>
)";

constexpr std::string_view malformedXml = "<UANodeSet><not-closed";

class NodeSetImporterPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    // AddressSpace's application URI matches the NodeSet's NamespaceUri so
    // ns=1 in the NodeSet maps to ns=1 in the address space and the importer
    // does not need a NamespaceFactory.
    mAddressSpace =
      std::make_unique<AddressSpace>(AddressSpace::create(String{"urn:test:ni-pin"}, mPool->executor()));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  // Run Parser::parse + ImportEngine::import_all_sync against an in-memory XML
  // string. Throws via the parser on malformed input - used by NI-D.
  void import_xml(std::string_view xml)
  {
    StructureFactory structureFactory;
    EncodingLimits limits;
    memory_stream_device::ExternalReadOnly device{
      std::span<const std::byte>{reinterpret_cast<const std::byte*>(xml.data()), xml.size()}};
    MemoryStream<memory_stream_device::ExternalReadOnly> stream{device};

    auto nodeSets = ua::xml::nodeset::Parser::parse(limits,
      stream,
      structureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      ua::xml::nodeset::Parser::GetDependentModelCallback{});
    auto importer = ua::xml::nodeset::ImportEngine::create(limits, *mAddressSpace, nodeSets, /*factory=*/{});
    importer->import_all_sync({}, {});
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

}  // namespace

// ---------------------------------------------------------------------------
// NI-A - ImportEngine creates the ObjectType node with the correct browse name.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in the importer that drops UAObjectType
// nodes (or that mis-translates the browse name's namespace index from the
// NodeSet's local ns=1 to the server's ns) is caught by the find_node +
// get_browse_name observations.

TEST_F(NodeSetImporterPin, NodeSetImporterCreatesObjectTypeNode)
{
  ASSERT_NO_THROW(import_xml(minimalObjectTypeXml));

  const NodeId otId{1u, 1000u};
  std::promise<NodeAccessorResult> p;
  mAddressSpace->find_node_async(otId, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();

  ASSERT_TRUE(result.is_good()) << "imported ObjectType must be reachable; status 0x" << std::hex
                                << result.status_code().as_uint32();
  EXPECT_EQ(result.value().get_node_class(), NodeClass::ObjectType);
  const QualifiedName expectedBrowseName{1u, std::string_view{"OT"}};
  EXPECT_EQ(result.value().get_browse_name(), expectedBrowseName);
}

// ---------------------------------------------------------------------------
// NI-B - ImportEngine creates the mandatory Variable child and the OT-->-V
//        HasComponent forward reference.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression that drops the references on the OT
// node (or that fails to import the UAVariable node) would leave the type
// without any reachable child. Asserting that V is reachable AND that OT
// carries a HasComponent forward ref to V locks the import contract.

TEST_F(NodeSetImporterPin, NodeSetImporterCreatesMandatoryChildReference)
{
  ASSERT_NO_THROW(import_xml(minimalObjectTypeXml));

  const NodeId otId{1u, 1000u};
  const NodeId vId{1u, 1001u};

  // V is reachable as a Variable.
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->find_node_async(vId, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    auto result = p.get_future().get();
    ASSERT_TRUE(result.is_good());
    EXPECT_EQ(result.value().get_node_class(), NodeClass::Variable);
  }

  // OT has a HasComponent forward ref to V (asserted via get_components_async).
  std::promise<NodeAccessorResult> findOt;
  mAddressSpace->find_node_async(otId, [&findOt](NodeAccessorResult r) { findOt.set_value(std::move(r)); });
  auto otResult = findOt.get_future().get();
  ASSERT_TRUE(otResult.is_good());

  std::promise<NodeAccessor::ReferencesResult> getComp;
  otResult.value().get_components_async(
    [&getComp](NodeAccessor::ReferencesResult r) { getComp.set_value(std::move(r)); });
  auto compResult = getComp.get_future().get();
  ASSERT_TRUE(compResult.is_good());

  bool foundForwardToV = false;
  for (const auto& ref : compResult.value())
  {
    const auto target = ref.target_id();
    if (target.is_local() && target.node_id() == vId)
    {
      foundForwardToV = true;
      break;
    }
  }
  EXPECT_TRUE(foundForwardToV) << "OT must carry a HasComponent forward ref to V after import";
}

// ---------------------------------------------------------------------------
// NI-C - After import, the imported ObjectType is instantiable: the resulting
//        subtree contains the mandatory child V.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression that imports the ObjectType but skips
// the HasModellingRule reference would leave V in the type without the
// "mandatory" tag, so InstantiationService would not create the child on
// the new instance. Asserting the instance carries a "V"-named child locks
// the import-then-instantiate end-to-end shape.

TEST_F(NodeSetImporterPin, NodeSetImporterEnablesInstantiationOfImportedType)
{
  ASSERT_NO_THROW(import_xml(minimalObjectTypeXml));

  // Pre-create an Object parent in the same namespace.
  const NodeId parentId{1u, std::string_view{"ni-c:parent"}};
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      parentId, NodeClass::Object, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    ASSERT_TRUE(p.get_future().get().is_good());
  }

  const NodeId otId{1u, 1000u};
  InstantiationService service{*mAddressSpace};
  InstantiationOptions options;

  std::promise<NodeSubtreeResult> instP;
  service.instantiate_object_async(parentId,
    QualifiedName{0u, std::string_view{"MyInst"}},
    otId,
    options,
    [&instP](NodeSubtreeResult r) { instP.set_value(std::move(r)); });
  auto instResult = instP.get_future().get();
  ASSERT_TRUE(instResult.is_good()) << "instantiation of imported ObjectType failed; status 0x" << std::hex
                                    << instResult.status_code().as_uint32() << " detail="
                                    << (instResult.shared_detail() ? instResult.shared_detail()->code
                                                                   : "null");
  auto subtree = std::move(instResult).value();
  const auto rootId = subtree.root();

  // Walk the new instance's components - must find a child whose browse name
  // matches the imported declaration's "V" (in NS=1).
  std::promise<NodeAccessorResult> findRoot;
  mAddressSpace->find_node_async(rootId,

    [&findRoot](NodeAccessorResult r) { findRoot.set_value(std::move(r)); });
  auto rootResult = findRoot.get_future().get();
  ASSERT_TRUE(rootResult.is_good());

  std::promise<NodeAccessor::ReferencesResult> getComp;
  rootResult.value().get_components_async(
    [&getComp](NodeAccessor::ReferencesResult r) { getComp.set_value(std::move(r)); });
  auto compResult = getComp.get_future().get();
  ASSERT_TRUE(compResult.is_good());

  bool foundV = false;
  for (const auto& ref : compResult.value())
  {
    const auto target = ref.target_id();
    if (!target.is_local())
      continue;
    auto childResult = mAddressSpace->try_find_node_sync(target.node_id());
    if (!childResult.is_good())
      continue;
    if (childResult.value().get_browse_name().name() == "V")
    {
      foundV = true;
      break;
    }
  }
  EXPECT_TRUE(foundV) << "instance must carry the imported type's mandatory child 'V'";

  subtree.release();
}

// ---------------------------------------------------------------------------
// NI-D - Documenting test (sync entry).
//
// The import engine (ua_nodeset_import_engine.h) is async-canonical with sync
// wrappers (import_all_sync). This pin drives Parser::parse with malformed XML
// through the sync entry; the parser surfaces the failure as a thrown
// UaException (its existing error-reporting mechanism). Asserts:
//   (i) the failure is observable to the caller (exception thrown),
//   (ii) the AddressSpace is not mutated (the would-be-imported NodeId is
//        still BadNodeIdUnknown).
//
// This pin's role is to lock the post-import (or no-import-on-failure)
// AddressSpace state.
// ---------------------------------------------------------------------------

TEST_F(NodeSetImporterPin, NodeSetImporterPropagatesXmlParseFailure)
{
  // (i) Parser::parse must surface malformed XML as a thrown exception.
  EXPECT_ANY_THROW(import_xml(malformedXml));

  // (ii) AddressSpace is not mutated - the would-be-imported NodeId (i=1000)
  // remains unreachable.
  const NodeId otId{1u, 1000u};
  std::promise<NodeAccessorResult> p;
  mAddressSpace->find_node_async(otId, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
  auto result = p.get_future().get();
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
}

}  // namespace ua::test::behaviour_pins
