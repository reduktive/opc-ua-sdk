// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <set>
#include <string>

#include "ua_datatype_id.h"
#include "ua_file_stream.h"
#include "ua_node_accessor.h"
#include "ua_structure_factory.h"
#include "ua_data_type_registration.h"
#include "ua_namespace_array.h"
#include "instantiation/ua_instantiation_service.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

using namespace ua;
using namespace ua::xml::nodeset;
using namespace std::chrono_literals;

// Covers SVR-FILE-001 (coverage-audit retag).
// @relation(SVR-FILE-001, SVR-FILE-028, scope=function)
TEST(FileTypeInstantiationTests, InstantiatesMandatoryChildrenAndCleansUp)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());

  StructureFactory structureFactory;

  auto lookupFn = namespace_array_utils::get_index_lookup_function(addressSpace);
  const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
  register_ua_data_types_with_factory(nsConfig, &structureFactory, &structureFactory);

  FileStream inputStream{"NodeSet2.xml"};
  inputStream.open_for_read();
  auto nodeSets = Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});

  auto importer = ImportEngine::create(limits, addressSpace, nodeSets, {});
  importer->import_all_sync({}, {});

  InstantiationService inst{addressSpace};

  const NodeId parent{ObjectId::ObjectsFolder};
  const QualifiedName browseName{1, "MyFile"};
  const NodeId fileType{ObjectTypeId::FileType};

  InstantiationOptions options{};

  std::promise<NodeSubtreeResult> promise;
  auto future = promise.get_future();
  inst.instantiate_object_async(parent,
    browseName,
    fileType,
    options,
    [&promise](NodeSubtreeResult r) { promise.set_value(std::move(r)); });

  auto instResult = future.get();
  ASSERT_TRUE(instResult.is_good()) << instResult.status_code().as_uint32();

  auto subtree = std::move(instResult).value();
  // Verify that some well-known FileType mandatory children exist.
  static const std::set<std::string> expected{
    "Open",
    "Close",
    "Read",
    "Write",
    "GetPosition",
    "SetPosition",
    "Size",
  };

  auto rootResult = addressSpace.try_find_node_sync(subtree.root());
  ASSERT_TRUE(rootResult.is_good());

  const auto rootAcc = rootResult.value();
  std::set<std::string> found;
  for (const auto& ref : rootAcc.get_references_sync())
  {
    if (!ref.is_forward() || ref.is_remote())
    {
      continue;
    }
    const auto& refType = ref.type_id();
    const bool isHierarchical =
      (refType == NodeId{ReferenceTypeId::HasComponent}) || (refType == NodeId{ReferenceTypeId::HasProperty});
    if (!isHierarchical)
    {
      continue;
    }
    const auto target = ref.target_id();
    if (!target.is_local())
    {
      continue;
    }
    auto childResult = addressSpace.try_find_node_sync(target.node_id());
    if (childResult.is_good())
    {
      found.insert(std::string{childResult.value().get_browse_name().name()});
    }
  }

  for (const auto& e : expected)
  {
    EXPECT_TRUE(found.contains(e)) << "Missing mandatory child: " << e;
  }

  // Confirm cleanup: remove_async() fires a fire-and-forget cascade delete, so drain
  // the pool to let it complete before asserting the subtree is gone.
  auto rootId = subtree.root();
  subtree.remove_async();
  ::ua::test_utils::drain_with_timeout(threadPool);
  auto afterResult = addressSpace.try_find_node_sync(rootId);
  EXPECT_TRUE(afterResult.is_bad());
}

// Part 20 4.2.1: FileType declares Size, Writable, UserWritable and OpenCount as Mandatory
// Properties (ModellingRule i=78), each with a fixed DataType. An engine that materialises the
// Mandatory HasComponent Methods and only the Property it happens to need (Size) leaves a file
// Object that browses as a FileType but cannot answer whether it is writable or how many handles
// are open - the Mandatory set is all four, and each must carry its spec DataType, since a
// Property created with the generic BaseDataType is not the declared one.
// @verifies AC-SVR-FILE-001-MANDATORY-PROPERTIES
TEST(FileTypeInstantiationTests, FileObjectExposesTheFourMandatoryProperties)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto addressSpace = AddressSpace::create("uri:test", threadPool.get_executor());

  StructureFactory structureFactory;

  auto lookupFn = namespace_array_utils::get_index_lookup_function(addressSpace);
  const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
  register_ua_data_types_with_factory(nsConfig, &structureFactory, &structureFactory);

  FileStream inputStream{"NodeSet2.xml"};
  inputStream.open_for_read();
  auto nodeSets = Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});

  auto importer = ImportEngine::create(limits, addressSpace, nodeSets, {});
  importer->import_all_sync({}, {});

  InstantiationService inst{addressSpace};

  const NodeId parent{ObjectId::ObjectsFolder};
  const QualifiedName browseName{1, "MandatoryPropertyFile"};
  const NodeId fileType{ObjectTypeId::FileType};

  InstantiationOptions options{};

  std::promise<NodeSubtreeResult> promise;
  auto future = promise.get_future();
  inst.instantiate_object_async(parent,
    browseName,
    fileType,
    options,
    [&promise](NodeSubtreeResult r) { promise.set_value(std::move(r)); });

  auto instResult = future.get();
  ASSERT_TRUE(instResult.is_good()) << instResult.status_code().as_uint32();

  auto subtree = std::move(instResult).value();

  auto rootResult = addressSpace.try_find_node_sync(subtree.root());
  ASSERT_TRUE(rootResult.is_good());

  // Collect the HasProperty children only: the obligation is about Properties, so a child
  // materialised under HasComponent would not discharge it.
  const auto rootAcc = rootResult.value();
  std::map<std::string, NodeId> properties;
  for (const auto& ref : rootAcc.get_references_sync())
  {
    if (!ref.is_forward() || ref.is_remote())
    {
      continue;
    }
    if (ref.type_id() != NodeId{ReferenceTypeId::HasProperty})
    {
      continue;
    }
    const auto target = ref.target_id();
    if (!target.is_local())
    {
      continue;
    }
    auto childResult = addressSpace.try_find_node_sync(target.node_id());
    if (childResult.is_good())
    {
      properties.emplace(std::string{childResult.value().get_browse_name().name()}, target.node_id());
    }
  }

  ASSERT_FALSE(properties.empty()) << "the instantiated FileType Object exposes no Properties at all";

  // Every Mandatory Property, with the DataType Part 20 declares for it.
  const std::map<std::string, NodeId> mandatory{
    {"Size", NodeId{DataTypeId::UInt64}},
    {"Writable", NodeId{DataTypeId::Boolean}},
    {"UserWritable", NodeId{DataTypeId::Boolean}},
    {"OpenCount", NodeId{DataTypeId::UInt16}},
  };

  for (const auto& entry : mandatory)
  {
    const std::string& name = entry.first;
    ASSERT_TRUE(properties.contains(name)) << "Missing mandatory FileType Property: " << name;

    auto varResult = addressSpace.try_find_sync<VariableAccessor>(properties.at(name));
    ASSERT_TRUE(varResult.is_good()) << name << " is not a Variable node";
    EXPECT_EQ(varResult.value().get_data_type(), entry.second) << "Wrong DataType on Property: " << name;
  }

  subtree.remove_async();
  ::ua::test_utils::drain_with_timeout(threadPool);
}
