// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 7 companion-spec integration tests - instantiation / read-write /
/// cross-namespace navigation rows (runtime, against the live DI NodeSet).
///
/// Row 7: object-type instantiation - assert the server-generated subtree lands
///        in a spec-compliant namespace index (NEVER NS0, Part 5 section 4.1) and the
///        generated typed handle attaches to it.
/// Row 8: variable-type instantiation + value read/write - instantiate a DI
///        VariableType and round-trip a written value.
/// Row 9: cross-namespace browse-path navigation - a path that starts in NS0
///        (ObjectsFolder) and steps into the DI namespace resolves to the
///        DI-namespace target. (Address-space-level equivalent of the
///        TranslateBrowsePaths service, which is exercised separately at the
///        server level.)

#include <boost/asio/thread_pool.hpp>
#include <future>
#include <memory>
#include <string>
#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_data_type_registration.h"
#include "ua_data_value.h"
#include "ua_encoding_limits.h"
#include "ua_default_namespace.h"
#include "ua_file_stream.h"
#include "ua_namespace_array.h"
#include "ua_nodeset_import.h"
#include "ua_node_accessor.h"
#include "ua_node_subtree.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_structure_factory.h"
#include "ua_variant.h"
#include "instantiation/ua_instantiation_service.h"

#include "ua_di_configurable_object.h"
#include "ua_di_objecttype_id.h"
#include "ua_di_software_update.h"
#include "ua_di_variabletype_id.h"
#include "ua_folder.h"

using namespace ua;

namespace
{
constexpr auto diUri = "http://opcfoundation.org/UA/DI/";

// Load NS0 + the DI NodeSet into a fresh AddressSpace via the dependency-aware
// public facade. DI's <RequiredModel> (NS0) is resolved to the NS0 stream so the
// whole closure loads in one pass; unknown structure values import opaquely.
// Returns the DI namespace index.
uint16_t load_ns0_and_di(AddressSpace& addressSpace, boost::asio::thread_pool& threadPool)
{
  StructureFactory factory;
  auto lookup = namespace_array_utils::get_index_lookup_function(addressSpace);
  const CodecNamespaceContext nsContext{std::move(lookup), {}, {}, {}};
  register_ua_data_types_with_factory(nsContext, &factory, &factory);

  NodeSetImportOptions options;
  options.namespaceFactory = [executor = threadPool.get_executor()](string_view uri) -> shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };
  options.structureResolver = factory.resolver();
  options.onUnknownStructure = NodeSetImportOptions::OnUnknownStructure::ImportOpaque;
  options.resolveRequiredModel = [](const ModelRef&) -> std::unique_ptr<Stream>
  {
    auto stream = std::make_unique<FileStream>("NodeSet2.xml");
    stream->open_for_read();
    return stream;
  };

  FileStream diStream{"Opc.Ua.Di.NodeSet2.xml"};
  diStream.open_for_read();
  auto importResult = try_import_nodeset_sync(addressSpace, diStream, options);
  EXPECT_TRUE(importResult.is_good()) << "DI import failed: " << importResult.status_code().value();

  return addressSpace.namespace_array().get_namespace_index(diUri);
}

NodeSubtreeResult instantiate_object(InstantiationService& inst, const NodeId& parent,
  const QualifiedName& browseName, const NodeId& typeDef, const InstantiationOptions& options)
{
  std::promise<NodeSubtreeResult> promise;
  auto future = promise.get_future();
  inst.instantiate_object_async(parent,
    browseName,
    typeDef,
    options,
    [&promise](NodeSubtreeResult r) { promise.set_value(std::move(r)); });
  return future.get();
}

NodeSubtreeResult instantiate_variable(InstantiationService& inst, const NodeId& parent,
  const QualifiedName& browseName, const NodeId& typeDef, const InstantiationOptions& options,
  const VariableInstantiationAttributes& attributes)
{
  std::promise<NodeSubtreeResult> promise;
  auto future = promise.get_future();
  inst.instantiate_variable_async(parent,
    browseName,
    typeDef,
    options,
    attributes,
    [&promise](NodeSubtreeResult r) { promise.set_value(std::move(r)); });
  return future.get();
}
}  // namespace

// Row 7 - instantiate a DI SoftwareUpdateType; NSI != 0; typed handle attaches.
TEST(DiInstanceTests, InstantiateSoftwareUpdateTypeLandsInNonZeroNamespace)
{
  boost::asio::thread_pool threadPool;
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto addressSpace = AddressSpace::create("uri:test:di-instance", threadPool.get_executor());
  const uint16_t diIndex = load_ns0_and_di(addressSpace, threadPool);
  ASSERT_NE(diIndex, 0) << "DI namespace must be allocated a non-zero index";

  InstantiationService inst{addressSpace};
  InstantiationOptions instOptions{};
  auto result = instantiate_object(inst,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{diIndex, "MySoftwareUpdate"},
    NodeId{diIndex, static_cast<uint32_t>(ua::di::ObjectTypeId::SoftwareUpdateType)},
    instOptions);
  ASSERT_TRUE(result.is_good()) << result.status_code().as_uint32();

  auto subtree = std::move(result).value();
  EXPECT_NE(subtree.root().namespace_index(), 0)
    << "instantiated DI SoftwareUpdateType must not live in NS0 (Part 5 section 4.1)";

  auto handleResult = ua::di::SoftwareUpdate::try_attach_sync(addressSpace, subtree.root());
  EXPECT_TRUE(handleResult.is_good())
    << "ua::di::SoftwareUpdate handle should attach: " << handleResult.status_code().as_uint32();

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Item 4 - NS0-owned typed child accessor exercised at runtime. DI's
// ConfigurableObjectType has a mandatory SupportedTypes child whose type
// definition is the NS0 FolderType (i=61), so the generated DI handle exposes it
// as a cross-spec ``::ua::Folder`` accessor. Instantiate the DI object, attach the
// DI handle, and call the NS0-typed child accessor - it must resolve the
// instantiated child to a valid NS0 Folder handle.
TEST(DiInstanceTests, ConfigurableObjectNs0TypedChildAccessorResolvesFolder)
{
  boost::asio::thread_pool threadPool;
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto addressSpace = AddressSpace::create("uri:test:di-ns0-child", threadPool.get_executor());
  const uint16_t diIndex = load_ns0_and_di(addressSpace, threadPool);
  ASSERT_NE(diIndex, 0);

  InstantiationService inst{addressSpace};
  InstantiationOptions instOptions{};
  auto result = instantiate_object(inst,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{diIndex, "MyConfigurableObject"},
    NodeId{diIndex, static_cast<uint32_t>(ua::di::ObjectTypeId::ConfigurableObjectType)},
    instOptions);
  ASSERT_TRUE(result.is_good()) << result.status_code().as_uint32();
  auto subtree = std::move(result).value();

  auto handleResult = ua::di::ConfigurableObject::try_attach_sync(addressSpace, subtree.root());
  ASSERT_TRUE(handleResult.is_good())
    << "ua::di::ConfigurableObject handle should attach: " << handleResult.status_code().as_uint32();
  auto configurable = std::move(handleResult).value();

  // The cross-spec (companion->NS0) typed child accessor resolves the mandatory
  // SupportedTypes child to an NS0 ::ua::Folder handle.
  auto folderResult = configurable.try_supported_types_sync();
  ASSERT_TRUE(folderResult.is_good())
    << "NS0-typed child accessor (::ua::Folder) must resolve the instantiated child: "
    << folderResult.status_code().as_uint32();
  ua::Folder supportedTypes = std::move(folderResult).value();

  // The resolved NS0 handle refers to the real instantiated child node (not NS0,
  // not null) - i.e. the cross-spec accessor returned a usable handle at runtime.
  EXPECT_FALSE(supportedTypes.node_id().is_null()) << "resolved NS0 Folder child must have a valid NodeId";
  EXPECT_NE(supportedTypes.node_id().namespace_index(), 0)
    << "the instantiated SupportedTypes child lives in the instance namespace, not NS0";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Row 8 - variable-type instantiation + value read/write round-trip.
TEST(DiInstanceTests, InstantiateDiVariableTypeAndRoundTripValue)
{
  boost::asio::thread_pool threadPool;
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto addressSpace = AddressSpace::create("uri:test:di-variable", threadPool.get_executor());
  const uint16_t diIndex = load_ns0_and_di(addressSpace, threadPool);
  ASSERT_NE(diIndex, 0);

  InstantiationService inst{addressSpace};
  InstantiationOptions instOptions{};
  VariableInstantiationAttributes attributes;

  auto result = instantiate_variable(inst,
    NodeId{ObjectId::ObjectsFolder},
    QualifiedName{diIndex, "MyLifetime"},
    NodeId{diIndex, static_cast<uint32_t>(ua::di::VariableTypeId::LifetimeVariableType)},
    instOptions,
    attributes);
  ASSERT_TRUE(result.is_good()) << result.status_code().as_uint32();

  auto subtree = std::move(result).value();
  EXPECT_NE(subtree.root().namespace_index(), 0) << "variable instance must not live in NS0";

  // Write a value to the instantiated DI variable and read it back.
  auto nodeResult = addressSpace.try_find_node_sync(subtree.root());
  ASSERT_TRUE(nodeResult.is_good());
  auto variable = nodeResult.value().as<VariableAccessor>();
  ASSERT_TRUE(variable);

  ASSERT_TRUE(variable->try_write_value_sync(DataValue{Variant{uint32_t{4242}}}).is_good());
  auto readBack = variable->try_read_value_sync();
  ASSERT_TRUE(readBack.is_good()) << readBack.status_code().as_uint32();
  EXPECT_EQ(readBack.value().value().as<uint32_t>(), 4242u);

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Row 9 - cross-namespace browse-path navigation: ObjectsFolder (NS0) -> the
// instantiated DI object resolves to a DI-namespace target.
TEST(DiInstanceTests, CrossNamespaceBrowsePathResolvesToDiTarget)
{
  boost::asio::thread_pool threadPool;
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  auto addressSpace = AddressSpace::create("uri:test:di-translate", threadPool.get_executor());
  const uint16_t diIndex = load_ns0_and_di(addressSpace, threadPool);
  ASSERT_NE(diIndex, 0);

  InstantiationService inst{addressSpace};
  InstantiationOptions instOptions{};
  const QualifiedName instanceName{diIndex, "MyDeviceObject"};
  auto result = instantiate_object(inst,
    NodeId{ObjectId::ObjectsFolder},
    instanceName,
    NodeId{diIndex, static_cast<uint32_t>(ua::di::ObjectTypeId::SoftwareUpdateType)},
    instOptions);
  ASSERT_TRUE(result.is_good()) << result.status_code().as_uint32();
  const NodeId expectedTarget = std::move(result).value().root();

  // Resolve the browse path Objects(NS0) --HasComponent--> {diIndex:MyDeviceObject}
  // by walking from the NS0 ObjectsFolder; the matching target must be the
  // DI-namespace instance (a path step that crosses the NS0->DI boundary).
  auto objectsFolder = addressSpace.try_find_node_sync(NodeId{ObjectId::ObjectsFolder});
  ASSERT_TRUE(objectsFolder.is_good());

  NodeId resolved;
  bool found = false;
  for (const auto& ref : objectsFolder.value().get_references_sync())
  {
    if (!ref.is_forward() || ref.is_remote())
      continue;
    if (ref.type_id() != NodeId{ReferenceTypeId::HasComponent})
      continue;
    const auto target = ref.target_id();
    if (!target.is_local())
      continue;
    auto child = addressSpace.try_find_node_sync(target.node_id());
    if (child.is_good() && child.value().get_browse_name() == instanceName)
    {
      resolved = target.node_id();
      found = true;
      break;
    }
  }

  ASSERT_TRUE(found) << "cross-namespace browse path Objects/"
                     << static_cast<std::string_view>(instanceName.name()) << " did not resolve";
  EXPECT_EQ(resolved, expectedTarget);
  EXPECT_EQ(resolved.namespace_index(), expectedTarget.namespace_index());
  EXPECT_NE(resolved.namespace_index(), 0) << "resolved DI target must be in the DI namespace";

  ::ua::test_utils::drain_with_timeout(threadPool);
}
