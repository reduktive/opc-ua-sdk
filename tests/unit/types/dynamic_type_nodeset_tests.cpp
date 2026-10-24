// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include "test_utilities.h"
#include <algorithm>
#include <chrono>
#include <future>
#include "ua_nodeset_parser.h"
#include "ua_nodeset_import.h"
#include "ua_nodeset_import_engine.h"
#include "ua_file_stream.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"
#include "ua_data_type_registration.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_application_configuration.h"
#include "ua_encoding_limits.h"
#include "ua_dynamic_type_registry.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_views.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_datatype_id.h"
#include "ua_variable_id.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"
#include "ua_type_loader.h"
#include "ua_address_space_model_access.h"
#include "ua_register_address_space_types.h"
#include "ua_attribute_id.h"
#include "ua_browse_direction.h"
#include "ua_browse_description.h"
#include "ua_browse_result.h"
#include "ua_read_value_id.h"
#include "ua_qualified_name.h"
#include "ua_browse_result_mask.h"

using namespace ua;

namespace ns = ua::xml::nodeset;

namespace
{

const EncodingLimits& test_limits()
{
  static EncodingLimits limits = []
  {
    const auto cfg = ApplicationConfig::load_default();
    return make_encoding_limits(cfg);
  }();
  return limits;
}

StackDepth test_stack_limit()
{
  auto cfg = ApplicationConfig::load_default();
  return StackDepth{cfg.execution_limits().decodeWorkLimit};
}

// D-R: NamespaceFactory is a callable - a lambda creating a default_ns namespace for the URI.
NamespaceFactory make_test_namespace_factory(boost::asio::any_io_executor executor)
{
  return [executor = std::move(executor)](string_view uri) -> shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };
}

/// Test fixture that parses the DI NodeSet (with UA core as a dependency),
/// imports into an address space, and registers types via the type loader.
class DynamicTypeNodeSetTest : public ::testing::Test
{
protected:
  std::vector<shared_ptr<ns::NodeSet>> mNodeSets;
  boost::asio::thread_pool mThreadPool{1};
  optional<AddressSpace> mAddressSpace;
  StructureFactory mStructureFactory;
  std::unique_ptr<DynamicTypeRegistry> mRegistry;

  void SetUp() override
  {
    register_ua_data_types_with_factory({}, &mStructureFactory, nullptr);
    mAddressSpace = AddressSpace::create("", mThreadPool.get_executor());
    mRegistry = std::make_unique<DynamicTypeRegistry>();

    auto limits = test_limits();

    FileStream diStream{"../_deps/uanodeset-src/DI/Opc.Ua.Di.NodeSet2.xml"};
    diStream.open_for_read();

    auto getDependency = [&limits, this](const ns::ModelTableEntry& model) -> unique_ptr<Stream>
    {
      if (model.model_uri() == String{"http://opcfoundation.org/UA/"})
      {
        auto stream = std::make_unique<FileStream>("NodeSet2.xml");
        stream->open_for_read();
        return stream;
      }
      return nullptr;
    };

    mNodeSets = ns::Parser::parse(limits,
      diStream,
      mStructureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      getDependency,
      ns::ParserOptions{.decodeVariantValues = false});

    // Import parsed NodeSets into the address space.
    auto namespaceFactory = make_test_namespace_factory(mThreadPool.get_executor());
    auto importer = ns::ImportEngine::create(limits, *mAddressSpace, mNodeSets, namespaceFactory);
    importer->import_all_sync({}, {});

    // Write the NamespaceArray value to node i=2255 so the type loader can read it.
    auto nsArrayNode = mAddressSpace->try_find_node_sync(NodeId{VariableId::Server_NamespaceArray});
    ASSERT_TRUE(nsArrayNode.is_good()) << "Server_NamespaceArray node must exist after import";
    auto varAccessor = nsArrayNode.value().as<VariableAccessor>();
    ASSERT_TRUE(varAccessor.has_value()) << "Server_NamespaceArray must be a variable";
    varAccessor->write_value_sync(mAddressSpace->namespace_array().get_namespace_array());
  }

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }
};

}  // namespace

// =============================================================================
// Test: Load DI NodeSet and register all types
// =============================================================================

TEST_F(DynamicTypeNodeSetTest, LoadDiNodeSetAndRegisterTypes)
{
  ASSERT_GE(mNodeSets.size(), 2u);

  dynamic_types::AddressSpaceModelAccess access{*mAddressSpace};
  auto stats = dynamic_types::load_types_sync(access, *mRegistry);

  EXPECT_GT(stats.structureCount, 0u) << "Expected at least one structure type from DI";
  EXPECT_GT(stats.enumCount, 0u) << "Expected at least one enum type from DI";

  std::cout << "Registered " << stats.structureCount << " structure types, " << stats.enumCount
            << " enum types from DI NodeSet" << std::endl;
  std::cout << "Skipped " << stats.skippedAbstract << " abstract types, " << stats.failure_count()
            << " failures" << std::endl;

  if (stats.has_failures())
  {
    std::cout << "Registration failures (" << stats.failure_count() << "):" << std::endl;
    for (size_t i = 0; i < std::min(stats.failures.size(), size_t{10}); ++i)
    {
      std::cout << "  " << stats.failures[i].typeId.as_definition() << " "
                << static_cast<string_view>(stats.failures[i].typeName) << ": "
                << stats.failures[i].detail->summary << std::endl;
    }
  }
}

// =============================================================================
// Test: DI enum registration and DynamicEnumView usage
// =============================================================================

TEST_F(DynamicTypeNodeSetTest, DiEnumRegistration)
{
  dynamic_types::AddressSpaceModelAccess access{*mAddressSpace};
  auto stats = dynamic_types::load_types_sync(access, *mRegistry);
  ASSERT_GT(stats.enumCount, 0u);

  // Find any registered enum by iterating parsed DataType nodes.
  shared_ptr<const DynamicEnumTypeDescriptor> foundEnum;

  for (auto& nodeSet : mNodeSets)
  {
    for (const auto& [nodeId, nodePtr] : nodeSet->nodes())
    {
      auto dataType = dynamic_cast<const ns::DataType*>(nodePtr.get());
      if (!dataType || !dataType->definition().has_value())
      {
        continue;
      }

      // Try to look up this type as an enum in the registry by expanded ID.
      auto nsUri = nodeSet->namespace_uris().has_value() ? [&]() -> String
      {
        auto idx = dataType->node_id().namespace_index();
        if (idx == 0)
        {
          return String{"http://opcfoundation.org/UA/"};
        }
        auto uris = nodeSet->namespace_uris()->uris();
        auto adjustedIndex = static_cast<size_t>(idx - 1);
        if (adjustedIndex < uris.size())
        {
          return uris[adjustedIndex];
        }
        return {};
      }()
        : String{};

      NodeId idPart = dataType->node_id();
      idPart.namespace_index() = 0;
      ExpandedNodeId typeExpandedId{std::move(idPart), static_cast<string_view>(nsUri)};

      auto descriptor = mRegistry->find_enum(typeExpandedId);
      if (descriptor)
      {
        foundEnum = descriptor;
        break;
      }
    }
    if (foundEnum)
    {
      break;
    }
  }

  ASSERT_NE(foundEnum, nullptr) << "Expected to find at least one registered enum";

  auto& enumDef = foundEnum->definition();
  ASSERT_GT(enumDef.fields().size(), 0u)
    << "Enum '" << static_cast<string_view>(foundEnum->type_name()) << "' should have fields";

  auto firstFieldValue = enumDef.fields()[0].value();
  DynamicEnumView view(firstFieldValue, *foundEnum);

  EXPECT_EQ(view.value(), firstFieldValue);
  EXPECT_FALSE(view.value_name().empty()) << "Expected a name for value " << firstFieldValue;

  std::cout << "Enum: " << static_cast<string_view>(foundEnum->type_name())
            << ", first value: " << view.to_string() << std::endl;
}

// =============================================================================
// Test: DI structure round-trip encode/decode
// =============================================================================

TEST_F(DynamicTypeNodeSetTest, DiStructureRoundTrip)
{
  dynamic_types::AddressSpaceModelAccess access{*mAddressSpace};
  auto stats = dynamic_types::load_types_sync(access, *mRegistry);
  ASSERT_GT(stats.structureCount, 0u);

  auto limits = test_limits();

  // Collect every registered non-union structure descriptor reachable from the parsed NodeSets.
  // Sort by type name so selection is deterministic across platforms (the underlying NodeSet
  // storage is std::unordered_map, whose iteration order varies between stdlib/pointer widths).
  std::vector<shared_ptr<const DynamicStructureTypeDescriptor>> candidates;
  for (auto& nodeSet : mNodeSets)
  {
    for (const auto& [nodeId, nodePtr] : nodeSet->nodes())
    {
      auto dataType = dynamic_cast<const ns::DataType*>(nodePtr.get());
      if (!dataType || !dataType->definition().has_value())
      {
        continue;
      }

      auto nsUri = nodeSet->namespace_uris().has_value() ? [&]() -> String
      {
        auto idx = dataType->node_id().namespace_index();
        if (idx == 0)
        {
          return String{"http://opcfoundation.org/UA/"};
        }
        auto uris = nodeSet->namespace_uris()->uris();
        auto adjustedIndex = static_cast<size_t>(idx - 1);
        if (adjustedIndex < uris.size())
        {
          return uris[adjustedIndex];
        }
        return {};
      }()
        : String{};

      NodeId idPart = dataType->node_id();
      idPart.namespace_index() = 0;
      ExpandedNodeId typeExpandedId{std::move(idPart), static_cast<string_view>(nsUri)};

      auto descriptor = mRegistry->find_structure(typeExpandedId);
      if (!descriptor || descriptor->field_count() == 0 ||
          descriptor->definition().structure_type() == StructureType::Union)
      {
        continue;
      }
      candidates.push_back(descriptor);
    }
  }

  std::sort(candidates.begin(),
    candidates.end(),
    [](const auto& lhs, const auto& rhs)
    { return static_cast<string_view>(lhs->type_name()) < static_cast<string_view>(rhs->type_name()); });

  // A candidate is round-trippable only if it has no directly-encoded field the dynamic codec
  // rejects: DiagnosticInfo at the top level (scalar or array) is unsupported. Fields that are
  // arrays-of-structure are left empty by the round-trip below, so they are safe regardless of
  // what their element type contains.
  auto isRoundTrippable = [](const DynamicStructureTypeDescriptor& descriptor)
  {
    for (size_t fi = 0; fi < descriptor.field_count(); ++fi)
    {
      if (descriptor.field_built_in_type(fi) == BuiltInTypeId::DiagnosticInfo)
      {
        return false;
      }
    }
    return true;
  };

  // Prefer structures where all fields are scalar primitives (so the verify loop below asserts
  // real values). Fall back to any round-trippable structure.
  auto isAllScalarPrimitive = [](const DynamicStructureTypeDescriptor& descriptor)
  {
    const auto& defFields = descriptor.definition().fields();
    for (size_t fi = 0; fi < descriptor.field_count(); ++fi)
    {
      auto bt = descriptor.field_built_in_type(fi);
      if (bt == BuiltInTypeId::ExtensionObject || bt == BuiltInTypeId::DiagnosticInfo ||
          bt == BuiltInTypeId::Variant)
      {
        return false;
      }
      if (fi < defFields.size() && defFields[fi].value_rank() != -1)
      {
        return false;
      }
    }
    return true;
  };

  shared_ptr<const DynamicStructureTypeDescriptor> foundDescriptor;
  for (const auto& candidate : candidates)
  {
    if (isAllScalarPrimitive(*candidate))
    {
      foundDescriptor = candidate;
      break;
    }
  }
  if (!foundDescriptor)
  {
    for (const auto& candidate : candidates)
    {
      if (isRoundTrippable(*candidate))
      {
        foundDescriptor = candidate;
        break;
      }
    }
  }

  ASSERT_NE(foundDescriptor, nullptr)
    << "Expected to find at least one registered structure for round-trip test";

  std::cout << "Round-trip testing structure: " << static_cast<string_view>(foundDescriptor->type_name())
            << " with " << foundDescriptor->field_count() << " fields" << std::endl;

  // Create a DynamicStructure from the descriptor the registry shares.
  auto inputStructure = std::make_unique<DynamicStructure>(foundDescriptor);

  // Set fields to non-default values where the built-in type is straightforward
  for (size_t i = 0; i < foundDescriptor->field_count(); ++i)
  {
    auto builtInType = foundDescriptor->field_built_in_type(i);
    switch (builtInType)
    {
    case BuiltInTypeId::String:
      inputStructure->field(i) = Variant{String{"TestValue"}};
      break;
    case BuiltInTypeId::Int32:
      inputStructure->field(i) = Variant{int32_t{42}};
      break;
    case BuiltInTypeId::UInt32:
      inputStructure->field(i) = Variant{uint32_t{100}};
      break;
    case BuiltInTypeId::Boolean:
      inputStructure->field(i) = Variant{true};
      break;
    case BuiltInTypeId::Double:
      inputStructure->field(i) = Variant{double{3.14}};
      break;
    case BuiltInTypeId::Int16:
      inputStructure->field(i) = Variant{int16_t{7}};
      break;
    case BuiltInTypeId::UInt16:
      inputStructure->field(i) = Variant{uint16_t{8}};
      break;
    case BuiltInTypeId::Int64:
      inputStructure->field(i) = Variant{int64_t{999}};
      break;
    case BuiltInTypeId::UInt64:
      inputStructure->field(i) = Variant{uint64_t{1000}};
      break;
    case BuiltInTypeId::Byte:
      inputStructure->field(i) = Variant{uint8_t{0xAB}};
      break;
    case BuiltInTypeId::Float:
      inputStructure->field(i) = Variant{float{1.5f}};
      break;
    default:
      break;
    }
  }

  // Encode
  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  inputStructure->encode(test_stack_limit(), enc);

  // Decode - use make_resolver with namespace lookup since registry contains non-NS0 types
  stream.seek_from_start(0);
  auto& nsArray = mAddressSpace->namespace_array();
  auto nsLookup = [&nsArray](string_view uri) -> std::optional<uint16_t>
  {
    try
    {
      return nsArray.get_namespace_index(uri);
    }
    catch (...)
    {
      return std::nullopt;
    }
  };
  UaBinaryDecoder decoder{mRegistry->make_resolver(nsLookup), stream, test_limits()};

  auto outputStructure = std::make_unique<DynamicStructure>(foundDescriptor);
  Decoder dec(decoder);
  outputStructure->decode(test_stack_limit(), dec);

  // Verify field values match
  for (size_t i = 0; i < foundDescriptor->field_count(); ++i)
  {
    auto builtInType = foundDescriptor->field_built_in_type(i);
    auto fieldName = static_cast<string_view>(foundDescriptor->field(i).name());
    switch (builtInType)
    {
    case BuiltInTypeId::String:
      EXPECT_EQ(outputStructure->field(i).as<String>(), String{"TestValue"})
        << "Field " << fieldName << " mismatch";
      break;
    case BuiltInTypeId::Int32:
      EXPECT_EQ(outputStructure->field(i).as<int32_t>(), 42) << "Field " << fieldName << " mismatch";
      break;
    case BuiltInTypeId::UInt32:
      EXPECT_EQ(outputStructure->field(i).as<uint32_t>(), 100u) << "Field " << fieldName << " mismatch";
      break;
    case BuiltInTypeId::Boolean:
      EXPECT_EQ(outputStructure->field(i).as<bool>(), true) << "Field " << fieldName << " mismatch";
      break;
    case BuiltInTypeId::Double:
      EXPECT_DOUBLE_EQ(outputStructure->field(i).as<double>(), 3.14) << "Field " << fieldName << " mismatch";
      break;
    default:
      break;
    }
  }

  EXPECT_EQ(*inputStructure, *outputStructure);
}

// =============================================================================
// Test: Multiple NodeSets loaded with correct counts
// =============================================================================

TEST_F(DynamicTypeNodeSetTest, NodeSetStructure)
{
  ASSERT_GE(mNodeSets.size(), 2u);

  size_t totalDataTypes = 0;
  for (auto& nodeSet : mNodeSets)
  {
    for (const auto& [nodeId, nodePtr] : nodeSet->nodes())
    {
      if (dynamic_cast<const ns::DataType*>(nodePtr.get()))
      {
        ++totalDataTypes;
      }
    }
  }

  EXPECT_GT(totalDataTypes, 100u) << "Expected many DataType nodes from UA core + DI";
  std::cout << "Total DataType nodes across all NodeSets: " << totalDataTypes << std::endl;
}

// =============================================================================
// Test: The type loader skips NS0 (built-in) types and only registers companion types
// =============================================================================

TEST_F(DynamicTypeNodeSetTest, UaCoreTypesRegistration)
{
  ASSERT_GE(mNodeSets.size(), 2u);

  // Load only DI namespace types (non-NS0) using a filter that restricts to the DI namespace.
  // The loader always skips NS0 types by design (they are built-in).
  auto diNamespaceIndex =
    mAddressSpace->namespace_array().get_namespace_index("http://opcfoundation.org/UA/DI/");
  ASSERT_NE(diNamespaceIndex, 0u) << "DI namespace should be registered";

  dynamic_types::AddressSpaceModelAccess access{*mAddressSpace};
  auto stats = dynamic_types::load_types_sync(access,
    *mRegistry,
    [diNamespaceIndex](const dynamic_types::DiscoveredType& discovered)
    { return discovered.node_id().namespace_index() == diNamespaceIndex; });

  // Only DI namespace types should be registered; NS0 types are dependencies, not targets.
  EXPECT_GT(stats.structureCount + stats.enumCount, 0u) << "Expected DI types to be registered";
  EXPECT_FALSE(stats.has_failures()) << "Expected no registration failures";

  std::cout << "DI namespace (filtered): " << stats.structureCount << " structures, " << stats.enumCount
            << " enums, " << stats.dependencyCount << " dependencies" << std::endl;
}

// =============================================================================
// AddressSpaceModelAccess: dedicated read/browse coverage against a real address
// space (previously exercised only indirectly through the type loader).
// =============================================================================

TEST_F(DynamicTypeNodeSetTest, AddressSpaceModelAccessReadsAttributesAndBrowses)
{
  dynamic_types::AddressSpaceModelAccess access{*mAddressSpace};
  const NodeId structureType{0, static_cast<uint32_t>(DataTypeId::Structure)};

  // read_async: BrowseName + IsAbstract of the Structure base DataType (i=22).
  std::vector<ReadValueId> reads;
  {
    ReadValueId browseNameRead;
    browseNameRead.node_id() = structureType;
    browseNameRead.attribute_id() = static_cast<uint32_t>(AttributeId::BrowseName);
    reads.push_back(browseNameRead);

    ReadValueId isAbstractRead;
    isAbstractRead.node_id() = structureType;
    isAbstractRead.attribute_id() = static_cast<uint32_t>(AttributeId::IsAbstract);
    reads.push_back(isAbstractRead);
  }

  std::promise<Result<std::vector<DataValue>>> readPromise;
  auto readFuture = readPromise.get_future();
  access.read_async(reads,
    [&readPromise](Result<std::vector<DataValue>> result) mutable
    { readPromise.set_value(std::move(result)); });
  auto readResult = readFuture.get();
  ASSERT_TRUE(readResult.is_good());
  ASSERT_EQ(readResult.value().size(), 2u);
  EXPECT_EQ(static_cast<string_view>(readResult.value()[0].value().as<QualifiedName>().name()), "Structure");
  EXPECT_TRUE(readResult.value()[1].value().as<bool>()) << "Structure is an abstract DataType";

  // browse_async: forward HasSubtype references of Structure -> it has concrete subtypes.
  std::vector<BrowseDescription> browses;
  {
    BrowseDescription bd;
    bd.node_id() = structureType;
    bd.browse_direction() = BrowseDirection::Forward;
    bd.reference_type_id() = NodeId{ReferenceTypeId::HasSubtype};
    browses.push_back(bd);
  }

  std::promise<Result<std::vector<BrowseResult>>> browsePromise;
  auto browseFuture = browsePromise.get_future();
  access.browse_async(browses,
    [&browsePromise](Result<std::vector<BrowseResult>> result) mutable
    { browsePromise.set_value(std::move(result)); });
  auto browseResult = browseFuture.get();
  ASSERT_TRUE(browseResult.is_good());
  ASSERT_EQ(browseResult.value().size(), 1u);
  EXPECT_GT(browseResult.value()[0].references().size(), 0u) << "Structure should have subtypes";
}

// =============================================================================
// Amendment A: register_address_space_types_sync bridges the address space's
// discovered structure types into a decode factory.
// =============================================================================

TEST_F(DynamicTypeNodeSetTest, RegisterAddressSpaceTypesBridgesFactory)
{
  // A fresh decode factory seeded only with the generated NS0 types.
  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);

  auto stats = dynamic_types::register_address_space_types_sync(*mAddressSpace, factory);
  EXPECT_GT(stats.structureCount, 0u) << "DI defines custom structure types to register";
  EXPECT_FALSE(stats.has_failures()) << "unexpected failures: " << stats.failure_count();

  // The free function performs the same discovery as a direct loader run: the identical set of
  // structures and enums is discovered, and only the structures (which carry encodings) are
  // bridged into the factory. (An explicit before/after UnknownStructure -> DynamicStructure
  // decode assertion against a known encoding id lives in the integration suite.)
  DynamicTypeRegistry reference;
  dynamic_types::AddressSpaceModelAccess access{*mAddressSpace};
  auto referenceStats = dynamic_types::load_types_sync(access, reference);
  EXPECT_EQ(referenceStats.structureCount, stats.structureCount);
  EXPECT_EQ(referenceStats.enumCount, stats.enumCount);
}

// =============================================================================
// Regression: ASBrowseFlow must not recurse unbounded on a node with many refs
// =============================================================================
//
// Each forward reference triggers find_node_async to resolve the target's
// browse_name / node_class. find_node_async fires its callback through the
// strand post (default namespace is in-memory), so the process_next_ref ->
// on_target_resolved -> process_next_ref chain unwinds per iteration. This
// regression was originally caught as an ASan stack-overflow on
// DynamicTypeNodeSetTest.DiEnumRegistration before the dispatch->post sweep.
TEST_F(DynamicTypeNodeSetTest, BrowseManyReferencesDoesNotOverflowStack)
{
  constexpr std::size_t referenceCount = 1000;

  auto testNs = default_ns::Namespace::create("urn:test:browse-fanout", mThreadPool.get_executor());
  const auto testNsIndex = mAddressSpace->add_namespace_sync(testNs);

  const NodeId sourceId{testNsIndex, 1u};
  mAddressSpace->create_node_sync(sourceId, NodeClass::Object);
  auto sourceAccessor = mAddressSpace->find_node_sync(sourceId);

  for (std::size_t i = 0; i < referenceCount; ++i)
  {
    NodeId targetId{testNsIndex, static_cast<uint32_t>(1000 + i)};
    auto target = mAddressSpace->create_node_sync(targetId, NodeClass::Object);
    target.set_browse_name(QualifiedName{testNsIndex, "T"});
    sourceAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, targetId);
  }

  dynamic_types::AddressSpaceModelAccess access{*mAddressSpace};

  BrowseDescription bd;
  bd.node_id() = sourceId;
  bd.browse_direction() = BrowseDirection::Forward;
  bd.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  bd.include_subtypes() = false;
  bd.node_class_mask() = 0;
  bd.result_mask() = static_cast<uint32_t>(BrowseResultMask::BrowseName);

  std::promise<Result<std::vector<BrowseResult>>> done;
  auto future = done.get_future();
  access.browse_async({std::move(bd)},
    [&done](Result<std::vector<BrowseResult>> result) { done.set_value(std::move(result)); });

  ASSERT_EQ(future.wait_for(std::chrono::seconds(10)), std::future_status::ready);
  auto result = future.get();
  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(result.value().size(), 1u);
  EXPECT_EQ(result.value()[0].references().size(), referenceCount);
}
