// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <future>
#include <set>
#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_argument.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_nodeset_import.h"
#include "ua_structure.h"
#include "ua_unknown_structure.h"

using namespace ua;

namespace
{

NamespaceFactory make_factory(boost::asio::thread_pool& pool)
{
  return [executor = pool.get_executor()](string_view uri) -> shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };
}

}  // namespace

// Happy path: the public facade imports every node, reports the allocated namespaces and an
// accurate node count, and the nodes are reachable in the address space afterwards.
TEST(NodeSetImportApiTest, ImportsAllNodesAndReportsSummary)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  const auto& summary = result.value();

  // The fixture declares two namespaces; both are newly allocated.
  EXPECT_EQ(summary.namespacesAllocated.size(), 2u);
  // Five nodes in the file: i=6001, i=7001, i=5001, i=5002, i=7002.
  EXPECT_EQ(summary.nodesImported, 5u);

  const auto customNs = addressSpace.namespace_array().get_namespace_index("urn:example:custom");
  ASSERT_NE(customNs, 0);
  auto found = addressSpace.try_find_sync<NodeAccessor>(NodeId{customNs, 5001u});
  EXPECT_TRUE(found.is_good());

  ::ua::test_utils::drain_with_timeout(tp);
}

// node_filter excludes nodes: keeping only file-local namespace 1 imports exactly the three
// ns=1 nodes and leaves the ns=2 nodes out of the address space.
TEST(NodeSetImportApiTest, NodeFilterExcludesNodes)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);
  options.nodeFilter = [](const NodeView& node)
  {
    return node.node_id().namespace_index() == 1;
  };

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  // ns=1 nodes: i=6001, i=5001, i=5002.
  EXPECT_EQ(result.value().nodesImported, 3u);

  const auto otherNs = addressSpace.namespace_array().get_namespace_index("urn:example:other");
  if (otherNs != 0)
  {
    auto excluded = addressSpace.try_find_sync<NodeAccessor>(NodeId{otherNs, 7001u});
    EXPECT_TRUE(excluded.is_bad()) << "ns=2 node should have been excluded by the node_filter";
  }

  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-AUTHZ-027-SUBSET-RISES-AND-NEVER-FALLS, scope=function)
TEST(NodeSetImportApiTest, FilteredImportRaisesOnlyStructuralNamespaceSubsetProperty)
{
  boost::asio::thread_pool pool{1};

  auto readBoolean = [](AddressSpace addressSpace, const NodeId& nodeId)
  {
    auto variable = addressSpace.try_find_sync<VariableAccessor>(nodeId);
    EXPECT_TRUE(variable.is_good());
    if (variable.is_bad())
    {
      return optional<bool>{};
    }
    auto value = variable.value().try_read_value_sync();
    EXPECT_TRUE(value.is_good());
    if (value.is_bad() || !value.value().value().is_boolean())
    {
      return optional<bool>{};
    }
    return optional<bool>{value.value().value().as<bool>()};
  };

  auto importFixture = [&pool](AddressSpace addressSpace, NodeSetImportOptions options)
  {
    FileStream stream{"NamespaceSubsetFixture.NodeSet2.xml"};
    stream.open_for_read();
    options.namespaceFactory = make_factory(pool);
    return try_import_nodeset_sync(std::move(addressSpace), stream, std::move(options));
  };

  auto completeAddressSpace = AddressSpace::create("", pool.get_executor());
  auto complete = importFixture(completeAddressSpace, NodeSetImportOptions{});
  ASSERT_TRUE(complete.is_good()) << complete.status_code().value();
  const auto completeNamespace =
    completeAddressSpace.namespace_array().get_namespace_index("urn:example:namespace-subset");
  const auto alreadySubsetNamespace =
    completeAddressSpace.namespace_array().get_namespace_index("urn:example:namespace-already-subset");
  EXPECT_EQ(readBoolean(completeAddressSpace, NodeId{completeNamespace, 5001u}), optional<bool>{false});
  EXPECT_EQ(readBoolean(completeAddressSpace, NodeId{completeNamespace, 5002u}), optional<bool>{false});
  EXPECT_EQ(readBoolean(completeAddressSpace, NodeId{alreadySubsetNamespace, 6001u}), optional<bool>{true});

  auto acceptingFilterAddressSpace = AddressSpace::create("", pool.get_executor());
  NodeSetImportOptions acceptingOptions;
  acceptingOptions.nodeFilter = [](const NodeView&)
  {
    return true;
  };
  auto accepted = importFixture(acceptingFilterAddressSpace, std::move(acceptingOptions));
  ASSERT_TRUE(accepted.is_good()) << accepted.status_code().value();
  const auto acceptingFilterNamespace =
    acceptingFilterAddressSpace.namespace_array().get_namespace_index("urn:example:namespace-subset");
  EXPECT_EQ(
    readBoolean(acceptingFilterAddressSpace, NodeId{acceptingFilterNamespace, 5001u}), optional<bool>{false});

  auto filteredAddressSpace = AddressSpace::create("", pool.get_executor());
  NodeSetImportOptions filteredOptions;
  filteredOptions.nodeFilter = [](const NodeView& node)
  {
    return node.node_id() != NodeId{1, 5003u};
  };
  auto filtered = importFixture(filteredAddressSpace, std::move(filteredOptions));
  ASSERT_TRUE(filtered.is_good()) << filtered.status_code().value();
  const auto filteredNamespace =
    filteredAddressSpace.namespace_array().get_namespace_index("urn:example:namespace-subset");
  const auto filteredAlreadySubsetNamespace =
    filteredAddressSpace.namespace_array().get_namespace_index("urn:example:namespace-already-subset");

  EXPECT_EQ(readBoolean(filteredAddressSpace, NodeId{filteredNamespace, 5001u}), optional<bool>{true});
  EXPECT_EQ(readBoolean(filteredAddressSpace, NodeId{filteredNamespace, 5002u}), optional<bool>{false});
  EXPECT_EQ(
    readBoolean(filteredAddressSpace, NodeId{filteredAlreadySubsetNamespace, 6001u}), optional<bool>{true});
  EXPECT_TRUE(filteredAddressSpace.try_find_sync<NodeAccessor>(NodeId{filteredNamespace, 5003u}).is_bad());

  ::ua::test_utils::drain_with_timeout(pool);
}

// Scope::TypeDefinitionsOnly imports the DataType but not the standalone instance nodes.
TEST(NodeSetImportApiTest, TypeDefinitionsOnlyScopeExcludesInstances)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);
  options.scope = NodeSetImportOptions::Scope::TypeDefinitionsOnly;

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();

  const auto customNs = addressSpace.namespace_array().get_namespace_index("urn:example:custom");
  ASSERT_NE(customNs, 0);

  // The DataType (i=6001) is a type definition and is imported.
  auto dataType = addressSpace.try_find_sync<NodeAccessor>(NodeId{customNs, 6001u});
  EXPECT_TRUE(dataType.is_good());

  // The standalone Object (i=5001) is an instance, not a type child, and is excluded.
  auto instance = addressSpace.try_find_sync<NodeAccessor>(NodeId{customNs, 5001u});
  EXPECT_TRUE(instance.is_bad());

  ::ua::test_utils::drain_with_timeout(tp);
}

// m1: the Summary's nodes_imported must reflect nodes ACTUALLY imported, not the number of times an
// internal predicate was invoked. Under TypeDefinitionsOnly the only type definition in the fixture is
// the DataType i=6001; the four instance nodes are excluded. The count must therefore be exactly 1.
// (Before the fix it was inflated because the counting predicate fired once per node-loop visit AND once
// per inbound reference target.)
TEST(NodeSetImportApiTest, TypeDefinitionsOnlySummaryCountsActualImports)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);
  options.scope = NodeSetImportOptions::Scope::TypeDefinitionsOnly;

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  // Exactly one node (the DataType i=6001) is a type definition; the rest are excluded instances.
  EXPECT_EQ(result.value().nodesImported, 1u);

  ::ua::test_utils::drain_with_timeout(tp);
}

// M2: the reference_filter must be honoured under TypeDefinitionsOnly, not silently dropped. The fixture's
// imported ObjectType (i=6010) carries HasSubtype (i=45) and HasProperty (i=46) references; the filter must
// be consulted for them. Falsifiability: before the fix the facade does not pass the reference predicate to
// import_type_definitions_only, so the filter is never invoked and `consulted` stays empty.
TEST(NodeSetImportApiTest, ReferenceFilterAppliesInTypeDefinitionsOnly)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"TypeDefinitionReferencesFixture.NodeSet2.xml"};
  stream.open_for_read();

  std::set<uint32_t> consulted;
  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);
  options.scope = NodeSetImportOptions::Scope::TypeDefinitionsOnly;
  options.referenceFilter = [&consulted](const ReferenceView& reference)
  {
    consulted.insert(reference.reference_type_id().identifier().get_numeric());
    // Drop HasProperty (i=46); keep everything else.
    return reference.reference_type_id().identifier().get_numeric() != 46u;
  };

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();

  // The filter was consulted for the type definition's references (proves it is wired into the
  // TypeDefinitionsOnly path). HasSubtype (45) and HasProperty (46) are both presented.
  EXPECT_TRUE(consulted.count(45u)) << "reference_filter was not consulted in TypeDefinitionsOnly scope";
  EXPECT_TRUE(consulted.count(46u)) << "reference_filter was not consulted in TypeDefinitionsOnly scope";

  // The ObjectType and its type-child property are still imported.
  const auto ns = addressSpace.namespace_array().get_namespace_index("urn:example:typedefs");
  ASSERT_NE(ns, 0);
  EXPECT_TRUE(addressSpace.try_find_sync<NodeAccessor>(NodeId{ns, 6010u}).is_good());
  EXPECT_TRUE(addressSpace.try_find_sync<NodeAccessor>(NodeId{ns, 6011u}).is_good());

  ::ua::test_utils::drain_with_timeout(tp);
}

// An unknown declared namespace with no NamespaceFactory yields a clean Result error - no crash.
TEST(NodeSetImportApiTest, UnknownNamespaceWithoutFactoryReturnsError)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;  // no namespace_factory

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  EXPECT_TRUE(result.is_bad());
  EXPECT_NE(result.error_detail(), nullptr);

  ::ua::test_utils::drain_with_timeout(tp);
}

// With a structure_resolver, a custom ExtensionObject *value* decodes, AND the NodeId nested in
// its field is namespace-translated transitively - exactly the coupling between structure
// resolution and translate-at-source.
TEST(NodeSetImportApiTest, StructureResolverDecodesAndTranslatesEmbeddedNodeId)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"StructValueTranslationFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);
  options.structureResolver = [](const NodeId& encodingId) -> std::unique_ptr<Structure>
  {
    if (encodingId == NodeId{Argument::defaultXmlEncodingId})
    {
      return make_unique<Argument>();
    }
    return nullptr;
  };

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();

  const auto customNs = addressSpace.namespace_array().get_namespace_index("urn:example:custom");
  ASSERT_NE(customNs, 0);
  ASSERT_NE(customNs, 1);

  auto var = addressSpace.try_find_sync<VariableAccessor>(NodeId{customNs, 5003u});
  ASSERT_TRUE(var.is_good());
  auto dv = var.value().try_read_value_sync();
  ASSERT_TRUE(dv.is_good());
  ASSERT_TRUE(dv.value().value().is_structure());

  const auto* argument = dynamic_cast<const Argument*>(&dv.value().value().as<Structure>());
  ASSERT_NE(argument, nullptr);
  // The struct-embedded DataType id (ns=1;i=6001 in the file) carries the SERVER index - proving
  // translation flowed transitively through the resolved structure.
  EXPECT_EQ(argument->data_type().namespace_index(), customNs);
  EXPECT_EQ(argument->data_type().identifier().get_numeric(), 6001u);

  ::ua::test_utils::drain_with_timeout(tp);
}

// Without a structure_resolver, an unrecognised ExtensionObject value fails the import cleanly
// (decoding error) rather than being silently mis-decoded / mis-translated.
TEST(NodeSetImportApiTest, MissingStructureResolverFailsCleanly)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"StructValueTranslationFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);
  // No structure_resolver: the Argument value cannot be instantiated.

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  EXPECT_TRUE(result.is_bad());
  ASSERT_NE(result.error_detail(), nullptr);
  // Like every per-node import failure, the error carries the offending node's source line:col as
  // the source.location context fact - the UAVariable with the unresolved value is on line 16, col 6.
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.error_detail(), ua::ContextKeys::sourceLocation.value()), "16:6");

  ::ua::test_utils::drain_with_timeout(tp);
}

// With on_unknown_structure = ImportOpaque, an unresolved ExtensionObject value imports as a preserved
// opaque structure rather than failing - the node is present and the value round-trips on read-back.
TEST(NodeSetImportApiTest, ImportOpaquePolicyStoresOpaqueValue)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"StructValueTranslationFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);
  options.onUnknownStructure = NodeSetImportOptions::OnUnknownStructure::ImportOpaque;

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(result.is_good()) << result.status_code().value();

  const auto customNs = addressSpace.namespace_array().get_namespace_index("urn:example:custom");
  ASSERT_NE(customNs, 0);
  auto var = addressSpace.try_find_sync<VariableAccessor>(NodeId{customNs, 5003u});
  ASSERT_TRUE(var.is_good());
  auto dv = var.value().try_read_value_sync();
  ASSERT_TRUE(dv.is_good());
  ASSERT_TRUE(dv.value().value().is_structure());
  // The value is preserved as an opaque (unresolved) ExtensionObject.
  EXPECT_NE(dynamic_cast<const UnknownStructure*>(&dv.value().value().as<Structure>()), nullptr);

  ::ua::test_utils::drain_with_timeout(tp);
}

// A malformed value (a NodeId referencing an out-of-range namespace index) fails the import, and
// the error carries the offending node's source line:col as the source.location context fact.
TEST(NodeSetImportApiTest, ErrorCarriesSourceLineAndColumn)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"BadNamespaceIndexFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);

  auto result = try_import_nodeset_sync(addressSpace, stream, options);
  ASSERT_TRUE(result.is_bad());
  ASSERT_NE(result.error_detail(), nullptr);

  // The UAVariable carrying the bad value is on line 7, column 6 of the fixture.
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.error_detail(), ua::ContextKeys::sourceLocation.value()), "7:6");

  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// Tier (b): parse-and-inspect read model.
// =============================================================================

// parse exposes the declared namespaces, the node set, and class-specific views, without touching
// any AddressSpace.
TEST(NodeSetImportApiTest, ParseExposesReadModel)
{
  boost::asio::thread_pool tp{1};  // only needed to keep the helper symmetric; parse is standalone

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  auto parsed = try_parse_nodeset_sync(stream, NodeSetParseOptions{});
  ASSERT_TRUE(parsed.is_good()) << parsed.status_code().value();
  const auto& document = *parsed.value();  // shared_ptr<const NodeSetDocument>

  // Two declared namespaces, reported in file-local order with file-local indices 1 and 2.
  ASSERT_EQ(document.declared_namespaces().size(), 2u);
  EXPECT_EQ(document.declared_namespaces()[0].uri, "urn:example:custom");
  EXPECT_EQ(document.declared_namespaces()[0].serverIndex, 1);
  EXPECT_EQ(document.declared_namespaces()[1].uri, "urn:example:other");
  EXPECT_EQ(document.declared_namespaces()[1].serverIndex, 2);

  // Five nodes total.
  EXPECT_EQ(document.nodes().size(), 5u);

  // find() by file-local id; the variable view exposes its DataType.
  auto variable = document.find(NodeId{1, 5002u});
  ASSERT_TRUE(variable.has_value());
  EXPECT_EQ(variable->node_class(), NodeClass::Variable);
  auto variableView = variable->as_variable();
  ASSERT_TRUE(variableView.has_value());
  EXPECT_EQ(variableView->data_type(), NodeId{17u});

  // The DataType node downcasts to a DataTypeView.
  auto dataType = document.find(NodeId{1, 6001u});
  ASSERT_TRUE(dataType.has_value());
  EXPECT_EQ(dataType->node_class(), NodeClass::DataType);
  auto dataTypeView = dataType->as_data_type();
  ASSERT_TRUE(dataTypeView.has_value());
  EXPECT_FALSE(dataTypeView->is_abstract());

  // MyObject (ns=1;i=5001) has two outgoing references in the file.
  auto object = document.find(NodeId{1, 5001u});
  ASSERT_TRUE(object.has_value());
  EXPECT_GE(object->references().size(), 2u);

  tp.join();
}

// Importing a parsed document yields the same result as the one-call tier-(a) import.
TEST(NodeSetImportApiTest, DocumentImportMatchesOneCall)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  auto parsed = try_parse_nodeset_sync(stream, NodeSetParseOptions{});
  ASSERT_TRUE(parsed.is_good()) << parsed.status_code().value();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(tp);

  auto summary = try_import_nodeset_sync(addressSpace, parsed.value(), options);
  ASSERT_TRUE(summary.is_good()) << summary.status_code().value();
  EXPECT_EQ(summary.value().nodesImported, 5u);
  EXPECT_EQ(summary.value().namespacesAllocated.size(), 2u);

  const auto customNs = addressSpace.namespace_array().get_namespace_index("urn:example:custom");
  ASSERT_NE(customNs, 0);
  EXPECT_TRUE(addressSpace.try_find_sync<NodeAccessor>(NodeId{customNs, 5001u}).is_good());

  ::ua::test_utils::drain_with_timeout(tp);
}

// import_nodeset_async is async-canonical and genuinely non-blocking: it runs on the address
// space's OWN executor (no separate work executor) and fires the completion there with the Result.
// There is no Stream overload - parse, then import the shared document.
TEST(NodeSetImportApiTest, ImportAsyncCompletesOnAddressSpaceExecutor)
{
  boost::asio::thread_pool serverPool{1};
  auto addressSpace = AddressSpace::create("", serverPool.get_executor());

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  auto parsed = try_parse_nodeset_sync(stream, NodeSetParseOptions{});
  ASSERT_TRUE(parsed.is_good()) << parsed.status_code().value();

  NodeSetImportOptions options;
  options.namespaceFactory = make_factory(serverPool);

  auto promise = std::make_shared<std::promise<Result<NodeSetImportSummary>>>();
  auto future = promise->get_future();
  import_nodeset_async(addressSpace,
    parsed.value(),
    std::move(options),
    [promise](Result<NodeSetImportSummary> result) { promise->set_value(std::move(result)); });

  // Block only on the main test thread (never on a pool thread).
  auto result = future.get();
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(result.value().nodesImported, 5u);

  ::ua::test_utils::drain_with_timeout(serverPool);
}

// import_nodeset_sync throws on the same failure that try_import_nodeset_sync reports.
TEST(NodeSetImportApiTest, SyncThrowsOnError)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  FileStream stream{"MultiNamespaceFixture.NodeSet2.xml"};
  stream.open_for_read();

  NodeSetImportOptions options;  // no namespace_factory

  EXPECT_THROW(import_nodeset_sync(addressSpace, stream, options), UaException);

  ::ua::test_utils::drain_with_timeout(tp);
}
