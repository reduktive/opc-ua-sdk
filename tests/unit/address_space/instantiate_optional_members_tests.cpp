// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for InstantiationService::instantiate_optional_members_async - the
/// reusable primitive that materialises selected non-mandatory members of a type
/// onto an EXISTING instance, assigning ids via a browse-name-keyed allocator.

#include <gtest/gtest.h>

#include <algorithm>

#include "test_utilities.h"

#include <atomic>
#include <future>
#include <map>
#include <optional>
#include <set>
#include <string>

#include "instantiation/ua_instantiation_service.h"
#include "ua_argument.h"
#include "ua_data_type_registration.h"
#include "ua_default_namespace.h"
#include "ua_file_stream.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_structure.h"
#include "ua_structure_factory.h"
#include "ua_variable_id.h"
#include <boost/asio/thread_pool.hpp>
#include <fmt/format.h>
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

using namespace ua;
using namespace ua::xml::nodeset;
using namespace std::chrono_literals;

namespace
{

void load_ns0(const EncodingLimits& limits, AddressSpace& addressSpace, StructureFactory& structureFactory)
{
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
}

/// Collect the local hierarchical forward children of a node, keyed by browse name.
std::map<std::string, NodeId> hierarchical_children(AddressSpace& addressSpace, const NodeId& parent)
{
  std::map<std::string, NodeId> out;
  auto parentResult = addressSpace.try_find_node_sync(parent);
  if (!parentResult)
    return out;
  for (const auto& ref : parentResult.value().get_references_sync())
  {
    if (!ref.is_forward() || ref.is_remote())
      continue;
    const auto& refType = ref.type_id();
    const bool isHierarchical = (refType == NodeId{ReferenceTypeId::HasComponent}) ||
                                (refType == NodeId{ReferenceTypeId::HasProperty}) ||
                                (refType == NodeId{ReferenceTypeId::HasOrderedComponent});
    if (!isHierarchical)
      continue;
    const auto target = ref.target_id();
    if (!target.is_local())
      continue;
    auto childResult = addressSpace.try_find_node_sync(target.node_id());
    if (childResult.is_good())
      out.emplace(std::string{childResult.value().get_browse_name().name()}, target.node_id());
  }
  return out;
}

VoidResult run_optional_members(InstantiationService& inst, const NodeId& instance,
  const NodeId& typeDefinition, InstantiationOptions options, OptionalChildFilter filter)
{
  options.optionalChildFilter = std::move(filter);
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  inst.instantiate_optional_members_async(
    instance, typeDefinition, options, [&promise](VoidResult r) { promise.set_value(std::move(r)); });
  return future.get();
}

}  // namespace

// Public API review D4 (API-D4.1, D4.2): the filter is the options' optionalChildFilter, and an unset one is
// refused - with no filter nothing would be added, so it can only be a mistake.
TEST(InstantiateOptionalMembersTests, AnUnsetFilterIsRefusedAndAddsNothing)
{
  boost::asio::thread_pool threadPool;
  auto addressSpace = AddressSpace::create("uri:test:optmembers", threadPool.get_executor());
  InstantiationService inst{addressSpace};
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  inst.instantiate_optional_members_async(NodeId{ObjectId::Server},
    NodeId{ObjectTypeId::ServerType},
    InstantiationOptions{},
    [&promise](VoidResult r) { promise.set_value(std::move(r)); });
  const VoidResult result = future.get();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "OptionalMembersFilterUnset");
}

// Materialising a selected optional member of a type onto an existing instance
// creates the member at the allocator-assigned id, copies its child subtree
// (the Method's InputArguments / OutputArguments with their Argument metadata),
// references it from the instance, and is idempotent on a second run.
TEST(InstantiateOptionalMembersTests, MaterialisesOptionalMethodWithArgumentSubtree)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto addressSpace = AddressSpace::create("uri:test:optmembers", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  InstantiationService inst{addressSpace};

  const NodeId serverConfigType{ObjectTypeId::ServerConfigurationType};

  // Use the real, NodeSet-imported ServerConfiguration instance (i=12637). It
  // carries all its mandatory children but NOT the Optional GetCertificates Method
  // - exactly the runtime situation the primitive must close. (Synthetic instances
  // from instantiate_object_async are not representative and may lack members.)
  const NodeId instanceId{0, static_cast<uint32_t>(ObjectId::ServerConfiguration)};

  {
    auto before = hierarchical_children(addressSpace, instanceId);
    ASSERT_FALSE(before.contains("GetCertificates"))
      << "GetCertificates should not be present on the imported ServerConfiguration instance";
  }

  // OPC-reserved instance ids (NodeIds.csv), assigned by browse name.
  const NodeId getCertificatesId{0, 32333u};
  const NodeId inputArgsId{0, 32334u};
  const NodeId outputArgsId{0, 32335u};

  InstantiationOptions options;
  options.nodeIdAllocator = [getCertificatesId, inputArgsId, outputArgsId](
                              uint16_t ns, const QualifiedName& browseName) -> NodeId
  {
    const auto name = browseName.name();
    if (name == "GetCertificates")
      return getCertificatesId;
    if (name == "InputArguments")
      return inputArgsId;
    if (name == "OutputArguments")
      return outputArgsId;
    static std::atomic<uint32_t> counter{800000};
    return NodeId{ns, counter.fetch_add(1)};
  };

  auto filter = [](const ChildFilterInfo& info)
  {
    return info.browseName.name() == "GetCertificates";
  };

  auto firstRun = run_optional_members(inst, instanceId, serverConfigType, options, filter);
  ASSERT_TRUE(firstRun.is_good()) << firstRun.status_code().as_uint32();

  // The Method now exists at the reserved id with a HasComponent edge from the instance.
  auto children = hierarchical_children(addressSpace, instanceId);
  ASSERT_TRUE(children.contains("GetCertificates")) << "GetCertificates was not materialised";
  EXPECT_EQ(children.at("GetCertificates"), getCertificatesId);

  auto methodResult = addressSpace.try_find_node_sync(getCertificatesId);
  ASSERT_TRUE(methodResult.is_good());
  EXPECT_EQ(methodResult.value().get_node_class(), NodeClass::Method);

  // The Method's InputArguments / OutputArguments subtree was copied (HasProperty children).
  auto argChildren = hierarchical_children(addressSpace, getCertificatesId);
  ASSERT_TRUE(argChildren.contains("InputArguments")) << "InputArguments not copied";
  ASSERT_TRUE(argChildren.contains("OutputArguments")) << "OutputArguments not copied";
  EXPECT_EQ(argChildren.at("InputArguments"), inputArgsId);
  EXPECT_EQ(argChildren.at("OutputArguments"), outputArgsId);

  // The Argument metadata Value attribute was carried onto the instance children.
  {
    auto inputResult = addressSpace.try_find_node_sync(inputArgsId);
    ASSERT_TRUE(inputResult.is_good());
    auto inputVar = inputResult.value().as<VariableAccessor>();
    ASSERT_TRUE(inputVar);
    // try_read_value_sync is a blocking bridge - safe here because the test runs
    // on the main thread (not the address-space executor). The async value-copy
    // step in the engine must have carried the declaration's Argument[] Value
    // onto the instance child; without it the value would be empty.
    auto value = inputVar->try_read_value_sync();
    ASSERT_TRUE(value.is_good()) << "InputArguments value should be readable";
    EXPECT_FALSE(value.value().value().empty())
      << "InputArguments must carry the copied Argument[] Value (async value-copy step)";
  }

  // Idempotent: a second run with the same allocator does not duplicate the member.
  auto secondRun = run_optional_members(inst, instanceId, serverConfigType, options, filter);
  ASSERT_TRUE(secondRun.is_good()) << secondRun.status_code().as_uint32();

  size_t getCertificatesCount = 0;
  {
    auto parentResult = addressSpace.try_find_node_sync(instanceId);
    ASSERT_TRUE(parentResult.is_good());
    for (const auto& ref : parentResult.value().get_references_sync())
    {
      if (!ref.is_forward() || ref.is_remote())
        continue;
      const auto target = ref.target_id();
      if (!target.is_local())
        continue;
      auto childResult = addressSpace.try_find_node_sync(target.node_id());
      if (childResult.is_good() && childResult.value().get_browse_name().name() == "GetCertificates")
        ++getCertificatesCount;
    }
  }
  EXPECT_EQ(getCertificatesCount, 1u) << "Second run must not duplicate the optional member";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A member that is not selected by the filter is not instantiated; a member that
// is already present on the instance is skipped (no error, no duplicate).
// @relation(AC-SVR-ADDRSP-092-PROPERTY-HAS-OWNER, scope=function)
TEST(InstantiateOptionalMembersTests, SkipsUnselectedAndPreExistingMembers)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto addressSpace = AddressSpace::create("uri:test:optmembers2", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  InstantiationService inst{addressSpace};

  const NodeId serverConfigType{ObjectTypeId::ServerConfigurationType};
  const NodeId instanceId{0, static_cast<uint32_t>(ObjectId::ServerConfiguration)};

  // A pre-existing mandatory member that must be skipped (not duplicated/re-created).
  const auto childrenBefore = hierarchical_children(addressSpace, instanceId);
  ASSERT_TRUE(childrenBefore.contains("UpdateCertificate"))
    << "imported ServerConfiguration should already carry UpdateCertificate";
  const NodeId updateCertIdBefore = childrenBefore.at("UpdateCertificate");

  // Select only SupportsTransactions - GetCertificates must remain absent.
  const NodeId supportsTxnId{0, 18663u};
  InstantiationOptions options;
  options.nodeIdAllocator = [supportsTxnId](uint16_t ns, const QualifiedName& browseName) -> NodeId
  {
    if (browseName.name() == "SupportsTransactions")
      return supportsTxnId;
    static std::atomic<uint32_t> counter{950000};
    return NodeId{ns, counter.fetch_add(1)};
  };

  auto filter = [](const ChildFilterInfo& info)
  {
    return info.browseName.name() == "SupportsTransactions";
  };

  auto run = run_optional_members(inst, instanceId, serverConfigType, options, filter);
  ASSERT_TRUE(run.is_good()) << run.status_code().as_uint32();

  auto children = hierarchical_children(addressSpace, instanceId);
  EXPECT_TRUE(children.contains("SupportsTransactions")) << "Selected optional must be materialised";
  EXPECT_EQ(children.at("SupportsTransactions"), supportsTxnId);

  const auto childReferences = addressSpace.find_node_sync(supportsTxnId).get_references_sync();
  EXPECT_TRUE(std::any_of(childReferences.begin(),
    childReferences.end(),
    [instanceId](const Reference& reference)
    {
      return !reference.is_forward() && !reference.is_remote() &&
             reference.type_id() == NodeId{ReferenceTypeId::HasProperty} &&
             reference.target_id().node_id() == instanceId;
    }))
    << "an instantiated Property must store the inverse HasProperty half naming its owner";
  EXPECT_FALSE(children.contains("GetCertificates")) << "Unselected optional must not be materialised";
  // Pre-existing mandatory member untouched (skipped, not re-created at a new id).
  ASSERT_TRUE(children.contains("UpdateCertificate"));
  EXPECT_EQ(children.at("UpdateCertificate"), updateCertIdBefore)
    << "Pre-existing member must be skipped, not re-created";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// NSI rule on the optional-members path: with NO allocator (so the default
// string-id fallback runs) and NO override, a member materialised onto an
// instance that lives in NSI 0 (ServerConfiguration, i=12637) lands in NSI 1,
// not NSI 0 - Part 5 section 4.1 forbids server-generated nodes in NSI 0.
TEST(InstantiateOptionalMembersTests, FallsBackToNsi1ForNsi0InstanceWithoutAllocator)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto addressSpace = AddressSpace::create("uri:test:optmembers:nsi0", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);

  InstantiationService inst{addressSpace};

  const NodeId serverConfigType{ObjectTypeId::ServerConfigurationType};
  const NodeId instanceId{0, static_cast<uint32_t>(ObjectId::ServerConfiguration)};
  ASSERT_EQ(instanceId.namespace_index(), 0u);

  // No allocator -> default string-id fallback uses the resolved NSI.
  InstantiationOptions options;
  auto filter = [](const ChildFilterInfo& info)
  {
    return info.browseName.name() == "GetCertificates";
  };

  auto run = run_optional_members(inst, instanceId, serverConfigType, options, filter);
  ASSERT_TRUE(run.is_good()) << run.status_code().as_uint32();

  auto children = hierarchical_children(addressSpace, instanceId);
  ASSERT_TRUE(children.contains("GetCertificates")) << "GetCertificates was not materialised";
  EXPECT_EQ(children.at("GetCertificates").namespace_index(), 1u)
    << "optional member on an NSI-0 instance must fall back to NSI 1, not NSI 0";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// NSI rule on the optional-members path: an explicit mTargetNamespaceIndex
// override places the materialised member NodeIds (default fallback, no
// allocator) in that namespace regardless of the instance's own NSI.
TEST(InstantiateOptionalMembersTests, HonoursTargetNamespaceOverrideWithoutAllocator)
{
  boost::asio::thread_pool threadPool;
  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto addressSpace = AddressSpace::create("uri:test:optmembers:override", threadPool.get_executor());
  StructureFactory structureFactory;
  load_ns0(limits, addressSpace, structureFactory);
  // NSI 0 (NS0) + NSI 1 (applicationUri) exist; register up to NSI 4 so the
  // override target is backed.
  for (uint16_t index = 2; index <= 4; ++index)
    addressSpace.add_namespace_sync(
      default_ns::Namespace::create(fmt::format("uri://opt-ns-{}", index), threadPool.get_executor()));

  InstantiationService inst{addressSpace};

  const NodeId serverConfigType{ObjectTypeId::ServerConfigurationType};
  const NodeId instanceId{0, static_cast<uint32_t>(ObjectId::ServerConfiguration)};

  InstantiationOptions options;
  options.targetNamespaceIndex = 4;
  auto filter = [](const ChildFilterInfo& info)
  {
    return info.browseName.name() == "GetCertificates";
  };

  auto run = run_optional_members(inst, instanceId, serverConfigType, options, filter);
  ASSERT_TRUE(run.is_good()) << run.status_code().as_uint32();

  auto children = hierarchical_children(addressSpace, instanceId);
  ASSERT_TRUE(children.contains("GetCertificates")) << "GetCertificates was not materialised";
  const NodeId getCertificatesId = children.at("GetCertificates");
  EXPECT_EQ(getCertificatesId.namespace_index(), 4u) << "override must place the member in NSI 4";

  // The member's own subtree (InputArguments / OutputArguments) propagates the override.
  auto argChildren = hierarchical_children(addressSpace, getCertificatesId);
  ASSERT_TRUE(argChildren.contains("OutputArguments"));
  EXPECT_EQ(argChildren.at("OutputArguments").namespace_index(), 4u)
    << "override propagates to the member's copied subtree";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 9 section 5.12 requires every type-level HasCondition Reference to survive instantiation;
// inheritance must not drop it, and a ConditionType target is shared rather than copied per instance.
// @relation(AC-SVR-AC-073-HASCONDITION-SURVIVES-INSTANTIATION, scope=function)
// @relation(AC-SVR-AC-074-HASCONDITION-TYPE-TARGET-SHARED, scope=function)
TEST(InstantiateOptionalMembersTests, ReplicatesInheritedHasConditionWithoutCopyingItsTarget)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("uri:test:has-condition", threadPool.get_executor());
  const NodeId baseType{1, uint32_t{9800}};
  const NodeId derivedType{1, uint32_t{9801}};
  const NodeId conditionType{1, uint32_t{9802}};
  const NodeId firstInstance{1, uint32_t{9803}};
  const NodeId secondInstance{1, uint32_t{9804}};

  auto base = addressSpace.create_node_sync(baseType, NodeClass::ObjectType);
  auto derived = addressSpace.create_node_sync(derivedType, NodeClass::ObjectType);
  addressSpace.create_node_sync(conditionType, NodeClass::ObjectType);
  addressSpace.create_node_sync(firstInstance, NodeClass::Object);
  addressSpace.create_node_sync(secondInstance, NodeClass::Object);
  base.add_reference_sync(NodeId{ReferenceTypeId::HasCondition}, conditionType);
  derived.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, baseType, /*isForward=*/false);

  InstantiationService instantiation{addressSpace};
  const auto rejectOptionalChild = [](const ChildFilterInfo&)
  {
    return false;
  };
  ASSERT_TRUE(run_optional_members(
    instantiation, firstInstance, derivedType, InstantiationOptions{}, rejectOptionalChild)
                .is_good());
  ASSERT_TRUE(run_optional_members(
    instantiation, secondInstance, derivedType, InstantiationOptions{}, rejectOptionalChild)
                .is_good());
  ASSERT_TRUE(run_optional_members(
    instantiation, firstInstance, derivedType, InstantiationOptions{}, rejectOptionalChild)
                .is_good())
    << "replication must be idempotent";

  const auto targets = [&addressSpace](const NodeId& instance)
  {
    std::vector<NodeId> result;
    for (const auto& reference : addressSpace.find_node_sync(instance).get_references_sync())
    {
      if (reference.is_forward() && !reference.is_remote() &&
          reference.type_id() == NodeId{ReferenceTypeId::HasCondition})
        result.push_back(reference.target_id().node_id());
    }
    return result;
  };
  EXPECT_EQ(targets(firstInstance), std::vector<NodeId>{conditionType});
  EXPECT_EQ(targets(secondInstance), std::vector<NodeId>{conditionType});

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// The reference-copy phase must not convert a missing instance into apparent success; the
// address-space lookup rich failure is part of the canonical async result.
// @relation(AC-SVR-AC-073-HASCONDITION-SURVIVES-INSTANTIATION, scope=function)
TEST(InstantiateOptionalMembersTests, HasConditionReplicationPreservesMissingInstanceDetail)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("uri:test:has-condition-error", threadPool.get_executor());
  const NodeId type{1, uint32_t{9810}};
  const NodeId conditionType{1, uint32_t{9811}};
  auto typeNode = addressSpace.create_node_sync(type, NodeClass::ObjectType);
  addressSpace.create_node_sync(conditionType, NodeClass::ObjectType);
  typeNode.add_reference_sync(NodeId{ReferenceTypeId::HasCondition}, conditionType);

  InstantiationService instantiation{addressSpace};
  const auto result = run_optional_members(instantiation,
    NodeId{1, uint32_t{9899}},
    type,
    InstantiationOptions{},
    [](const ChildFilterInfo&) { return false; });

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadNodeIdUnknown});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NodeNotFound");

  ::ua::test_utils::drain_with_timeout(threadPool);
}
