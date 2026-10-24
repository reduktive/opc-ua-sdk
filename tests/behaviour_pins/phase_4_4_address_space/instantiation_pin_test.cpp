// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.4a (instantiation service).
//
// authorising this file. IN pins exercise InstantiationService against a
// production AddressSpace + default_ns:
//
//   - instantiate_object_async - multi-step recursive walk (IN-A through IN-F)
//   - depth-budget exhaustion (IN-G)
//   - instantiate_variable_async - type-def attribute copy / override (IN-H/I)
//
// Most pins drive the production default_ns (parent + ObjectType + child
// declarations + HasModellingRule references created via the public
// AddressSpace API). IN-B uses a FakeAsyncNamespace to inject a staged
// failure mid-walk; IN-C deliberately points the parent NodeId at a
// non-existent node so find_node returns BadNodeIdUnknown.
//
// Forbidden tokens (per runbook section 4): no `_coro\b`, no `Task<`, no
// `await_callback`. The IN pins drive *_async only.

#include <atomic>
#include <future>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <fmt/format.h>

#include <gtest/gtest.h>

#include "fake_async_namespace.h"
#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_execution_limits.h"
#include "ua_expanded_node_id.h"
#include "instantiation/ua_instantiation_options.h"
#include "instantiation/ua_instantiation_service.h"
#include "instantiation/ua_node_subtree.h"
#include "ua_instantiation_options.h"
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
#include <boost/asio/thread_pool.hpp>
#include "ua_value_rank.h"

namespace ua::test::behaviour_pins
{
namespace
{

class InstantiationPin : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mAddressSpace = std::make_unique<AddressSpace>(
      AddressSpace::create(String{"urn:test:instantiation:pin"}, mPool->executor()));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    if (mPool)
    {
      mPool->stop();
    }
  }

  NodeAccessor create_real_node(const NodeId& id, NodeClass nodeClass)
  {
    std::promise<NodeAccessorResult> p;
    mAddressSpace->create_node_async(
      id, nodeClass, [&p](NodeAccessorResult r) { p.set_value(std::move(r)); });
    auto result = p.get_future().get();
    EXPECT_TRUE(result.is_good()) << "precondition: create_node_async failed; status 0x" << std::hex
                                  << result.status_code().as_uint32();
    return result.value();
  }

  // Allocate sequential NodeIds; capture the first allocation as the new
  // instance NodeId for rollback verification.
  NodeIdAllocator make_capturing_allocator(std::string prefix, std::shared_ptr<NodeId> firstAllocated)
  {
    auto counter = std::make_shared<std::atomic<int>>(0);
    return [prefix = std::move(prefix), counter, firstAllocated](uint16_t ns, const QualifiedName&)
    {
      const int n = counter->fetch_add(1);
      NodeId id{ns, fmt::format("{}-{}", prefix, n)};
      if (n == 0 && firstAllocated)
      {
        *firstAllocated = id;
      }
      return id;
    };
  }

  // Helper: drive instantiate_object_async synchronously via promise.
  NodeSubtreeResult instantiate_object_blocking(InstantiationService& service, const NodeId& parent,
    const QualifiedName& browseName, const NodeId& typeDefinition, const InstantiationOptions& options)
  {
    std::promise<NodeSubtreeResult> p;
    service.instantiate_object_async(
      parent, browseName, typeDefinition, options, [&p](NodeSubtreeResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  NodeSubtreeResult instantiate_variable_blocking(InstantiationService& service, const NodeId& parent,
    const QualifiedName& browseName, const NodeId& typeDefinition, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes)
  {
    std::promise<NodeSubtreeResult> p;
    service.instantiate_variable_async(parent,
      browseName,
      typeDefinition,
      options,
      attributes,
      [&p](NodeSubtreeResult r) { p.set_value(std::move(r)); });
    return p.get_future().get();
  }

  // Returns the unique forward HasComponent target (resolved as accessor) of
  // `instance` - optional<NodeAccessor> nullopt if no such ref or > 1 found.
  std::optional<NodeAccessor> first_has_component_child(const NodeId& instanceId)
  {
    auto findResult = mAddressSpace->try_find_node_sync(instanceId);
    if (!findResult.is_good())
      return std::nullopt;
    auto refs = findResult.value().get_references_sync();
    for (const auto& ref : refs)
    {
      if (!ref.is_forward())
        continue;
      if (ref.type_id() != NodeId{ReferenceTypeId::HasComponent})
        continue;
      const auto target = ref.target_id();
      if (!target.is_local())
        continue;
      auto childResult = mAddressSpace->try_find_node_sync(target.node_id());
      if (childResult.is_good())
      {
        return childResult.value();
      }
    }
    return std::nullopt;
  }

  // Build an ObjectType T with one mandatory Variable child V. Returns
  // {typeDefId, declarationId}. The declaration's browse name is `childName`.
  struct ObjectTypeWithMandatoryVar
  {
    NodeId typeDef;
    NodeId declaration;
  };

  ObjectTypeWithMandatoryVar build_object_type_with_mandatory_var(
    std::string_view typeIdStr, std::string_view declIdStr, std::string_view childName, uint16_t ns = 1u)
  {
    NodeId typeId{ns, typeIdStr};
    NodeId declId{ns, declIdStr};
    auto typeAcc = create_real_node(typeId, NodeClass::ObjectType);
    auto declAcc = create_real_node(declId, NodeClass::Variable);
    declAcc.set_browse_name(QualifiedName{0u, childName});
    // copy_class_specific_attrs reads data_type, value_rank, access_level from
    // the declaration; these must be set explicitly because read_attribute on
    // an unset attribute returns an empty Variant which throws on as<>().
    auto declVar = declAcc.as<VariableAccessor>();
    declVar->set_data_type(NodeId{DataTypeId::Int32});
    declVar->set_value_rank(ValueRank{ValueRank::scalar});
    declVar->set_access_level(AccessLevelType{0u});
    typeAcc.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{declId},
      /*isForward=*/true);
    declAcc.add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
      ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}},
      /*isForward=*/true);
    return {typeId, declId};
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

}  // namespace

// ---------------------------------------------------------------------------
// IN-A - instantiate_object_async creates an instance + its mandatory children
//        and links the instance back to the parent via HasComponent.
// ---------------------------------------------------------------------------
//
// Bug this would catch: a regression in the recursive walk that fails to
// create mandatory children would yield an instance subtree without the
// required Variable child. Asserting (i) NodeSubtreeResult Good, (ii) the
// new instance is reachable, (iii) the parent's HasComponent target is the
// new instance, and (iv) the new instance has a Variable child with the
// declared browse name catches the regression.

TEST_F(InstantiationPin, InstantiateObjectSucceedsForMandatoryChild)
{
  const NodeId parentId{1u, std::string_view{"in-a:parent"}};
  create_real_node(parentId, NodeClass::Object);
  auto type = build_object_type_with_mandatory_var("in-a:T", "in-a:V-decl", "MyVar");

  InstantiationService service{*mAddressSpace};
  auto firstId = std::make_shared<NodeId>();
  InstantiationOptions options;
  options.nodeIdAllocator = make_capturing_allocator("in-a:inst", firstId);

  auto result =
    instantiate_object_blocking(service, parentId, QualifiedName{0u, "MyInstance"}, type.typeDef, options);
  ASSERT_TRUE(result.is_good()) << "instantiate_object_async returned bad: 0x" << std::hex
                                << result.status_code().as_uint32() << " detail="
                                << (result.shared_detail() ? result.shared_detail()->code : "null");
  auto subtree = std::move(result).value();
  const auto rootId = subtree.root();
  EXPECT_EQ(rootId, *firstId);

  // (ii) new instance is reachable.
  auto rootResult = mAddressSpace->try_find_node_sync(rootId);
  ASSERT_TRUE(rootResult.is_good());

  // (iii) parent has a HasComponent forward ref to the new instance.
  auto parentChild = first_has_component_child(parentId);
  ASSERT_TRUE(parentChild.has_value());
  EXPECT_EQ(parentChild->get_node_id(), rootId);

  // (iv) instance has a Variable child with browse name "MyVar".
  auto instanceChild = first_has_component_child(rootId);
  ASSERT_TRUE(instanceChild.has_value());
  const QualifiedName expectedChildName{0u, std::string_view{"MyVar"}};
  EXPECT_EQ(instanceChild->get_browse_name(), expectedChildName);
  EXPECT_EQ(instanceChild->get_node_class(), NodeClass::Variable);

  // Prevent RAII cleanup from removing the verified subtree before TearDown.
  subtree.release();
}

// ---------------------------------------------------------------------------
// IN-B - instantiate_object_async rolls back the new instance when a child
//        declaration's find_node returns bad mid-walk.
// ---------------------------------------------------------------------------
//
// Setup: T has HasComponent forward to `decl-V` in a fake namespace. The fake
// stages a bad find_node result, so the recursive walk fails in
// on_child_declaration_resolved -> fail_instantiate_children -> on_children_
// instantiated calls subtree.remove_now(true).
//
// Bug this would catch: a regression that drops the rollback (e.g. a missed
// `remove_now` call at ua_instantiation_service.cpp:1115 would leave the
// half-built instance in the AddressSpace) is caught by asserting
// find_node on the captured instance NodeId returns BadNodeIdUnknown.

TEST_F(InstantiationPin, InstantiateObjectRollsBackOnChildCreationFailure)
{
  auto fakeNs = FakeAsyncNamespace::create("urn:test:in-b:fake");
  const auto fakeIndex = mAddressSpace->add_namespace_sync(fakeNs);
  ASSERT_GT(fakeIndex, 0u);

  const NodeId parentId{1u, std::string_view{"in-b:parent"}};
  create_real_node(parentId, NodeClass::Object);

  // T in default_ns; HasComponent forward to fake-namespace declaration.
  const NodeId typeId{1u, std::string_view{"in-b:T"}};
  auto typeAcc = create_real_node(typeId, NodeClass::ObjectType);
  const NodeId fakeDeclId{fakeIndex, std::string_view{"in-b:V-decl"}};
  typeAcc.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{fakeDeclId},
    /*isForward=*/true);

  // Fake stages 1 bad find_node - the V-decl resolve.
  auto stagedDetail = make_error_detail("InBStub", "stubbed by IN-B", "FakeAsyncNamespace");
  std::shared_ptr<const ErrorDetail> stagedDetailPtr{std::move(stagedDetail)};
  fakeNs->set_next_find_node_result(NodeResult{StatusCode{Status::BadInternalError}, stagedDetailPtr});

  InstantiationService service{*mAddressSpace};
  auto firstId = std::make_shared<NodeId>();
  InstantiationOptions options;
  options.nodeIdAllocator = make_capturing_allocator("in-b:inst", firstId);

  auto result = instantiate_object_blocking(service, parentId, QualifiedName{0u, "MyInst"}, typeId, options);

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadInternalError);
  EXPECT_EQ(result.shared_detail(), stagedDetailPtr);

  // The rollback must remove the new instance.
  ASSERT_FALSE(firstId->is_null()) << "allocator was never invoked - flow exited too early";
  // Rollback deletes the partial subtree via an async fire-and-forget cascade; drain
  // so it completes before asserting the instance node is gone.
  ::ua::test_utils::drain_with_timeout(*mPool);
  auto findInstance = mAddressSpace->try_find_node_sync(*firstId);
  EXPECT_TRUE(findInstance.is_bad());
  EXPECT_EQ(findInstance.status_code(), Status::BadNodeIdUnknown)
    << "rollback should have removed the new instance NodeId";
}

// ---------------------------------------------------------------------------
// IN-C - instantiate_object_async rolls back the new instance when the
//        parent's find_node returns bad.
// ---------------------------------------------------------------------------
//
// Setup: parent NodeId points at a non-existent node - find_node returns
// BadNodeIdUnknown. The flow has already created the new instance (and added
// its HasTypeDefinition ref) before this fails; the on_parent_resolved path
// (ua_instantiation_service.cpp:1047-1052) calls subtree.remove_now(true).

TEST_F(InstantiationPin, InstantiateObjectRollsBackOnParentResolutionFailure)
{
  // Type setup (no parent created - parent NodeId resolves bad).
  auto type = build_object_type_with_mandatory_var("in-c:T", "in-c:V-decl", "MyVar");
  const NodeId nonExistentParentId{1u, std::string_view{"in-c:no-such-parent"}};

  InstantiationService service{*mAddressSpace};
  auto firstId = std::make_shared<NodeId>();
  InstantiationOptions options;
  options.nodeIdAllocator = make_capturing_allocator("in-c:inst", firstId);

  auto result = instantiate_object_blocking(
    service, nonExistentParentId, QualifiedName{0u, "MyInst"}, type.typeDef, options);

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);

  ASSERT_FALSE(firstId->is_null());
  // Rollback deletes the partial subtree via an async fire-and-forget cascade; drain
  // so it completes before asserting the instance node is gone.
  ::ua::test_utils::drain_with_timeout(*mPool);
  auto findInstance = mAddressSpace->try_find_node_sync(*firstId);
  EXPECT_TRUE(findInstance.is_bad());
  EXPECT_EQ(findInstance.status_code(), Status::BadNodeIdUnknown)
    << "rollback should have removed the new instance NodeId";
}

// ---------------------------------------------------------------------------
// IN-D - instantiate_object_async walks the HasSubtype chain, picking up the
//        base type's mandatory children.
// ---------------------------------------------------------------------------
//
// ChildType has no mandatory children of its own. BaseType has mandatory
// Variable BV. ChildType has HasSubtype inverse -> BaseType (i.e. Base is
// Child's supertype). After instantiation, the instance carries BV.

TEST_F(InstantiationPin, InstantiateChildrenWalksHasSubtypeChain)
{
  const NodeId parentId{1u, std::string_view{"in-d:parent"}};
  create_real_node(parentId, NodeClass::Object);

  const NodeId childTypeId{1u, std::string_view{"in-d:Child"}};
  const NodeId baseTypeId{1u, std::string_view{"in-d:Base"}};
  const NodeId bvDeclId{1u, std::string_view{"in-d:BV-decl"}};

  auto childTypeAcc = create_real_node(childTypeId, NodeClass::ObjectType);
  auto baseTypeAcc = create_real_node(baseTypeId, NodeClass::ObjectType);
  auto bvDeclAcc = create_real_node(bvDeclId, NodeClass::Variable);
  bvDeclAcc.set_browse_name(QualifiedName{0u, std::string_view{"BV"}});
  auto bvVar = bvDeclAcc.as<VariableAccessor>();
  bvVar->set_data_type(NodeId{DataTypeId::Int32});
  bvVar->set_value_rank(ValueRank{ValueRank::scalar});
  bvVar->set_access_level(AccessLevelType{0u});

  // BaseType --HasComponent forward--> BV declaration.
  baseTypeAcc.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{bvDeclId},
    /*isForward=*/true);
  // BV --HasModellingRule forward--> Mandatory.
  bvDeclAcc.add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
    ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}},
    /*isForward=*/true);
  // ChildType --HasSubtype inverse--> BaseType (Child is a subtype of Base).
  childTypeAcc.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype},
    ExpandedNodeId{baseTypeId},
    /*isForward=*/false);

  InstantiationService service{*mAddressSpace};
  auto firstId = std::make_shared<NodeId>();
  InstantiationOptions options;
  options.nodeIdAllocator = make_capturing_allocator("in-d:inst", firstId);

  auto result =
    instantiate_object_blocking(service, parentId, QualifiedName{0u, "MyInst"}, childTypeId, options);
  ASSERT_TRUE(result.is_good()) << "instantiate_object_async returned bad: 0x" << std::hex
                                << result.status_code().as_uint32();
  auto subtree = std::move(result).value();
  const auto rootId = subtree.root();

  auto instanceChild = first_has_component_child(rootId);
  ASSERT_TRUE(instanceChild.has_value())
    << "instance must carry the supertype's mandatory child via HasSubtype walk";
  const QualifiedName expectedChildName{0u, std::string_view{"BV"}};
  EXPECT_EQ(instanceChild->get_browse_name(), expectedChildName);
  EXPECT_EQ(instanceChild->get_node_class(), NodeClass::Variable);

  subtree.release();
}

// ---------------------------------------------------------------------------
// IN-E - instantiate_object_async skips creating a child whose browse name is
//        already present on the instance (existing-child check).
// ---------------------------------------------------------------------------
//
// Note on runbook variance: the runbook description ("the parent already has
// a child ...") doesn't match the implementation, which checks the new
// instance, not the parent. The implementation's existing-child check at
// :551-555 only hits when the instance already has a child with the
// matching browse name - which happens during the walk if T has TWO
// mandatory children that share a browse name. Iteration 1 creates the
// child; iteration 2 sees the freshly-added child and skips.
//
// Bug this would catch: a regression that always returns false from
// instance_child_named_async (or skips the check entirely)
// would create a duplicate child. Asserting exactly ONE HasComponent
// forward ref to a "MyVar"-named child catches that.

TEST_F(InstantiationPin, InstantiateChildrenSkipsExistingChildBrowseName)
{
  const NodeId parentId{1u, std::string_view{"in-e:parent"}};
  create_real_node(parentId, NodeClass::Object);

  const NodeId typeId{1u, std::string_view{"in-e:T"}};
  const NodeId v1DeclId{1u, std::string_view{"in-e:V1-decl"}};
  const NodeId v2DeclId{1u, std::string_view{"in-e:V2-decl"}};

  auto typeAcc = create_real_node(typeId, NodeClass::ObjectType);
  auto v1Acc = create_real_node(v1DeclId, NodeClass::Variable);
  auto v2Acc = create_real_node(v2DeclId, NodeClass::Variable);

  // BOTH declarations carry the same browse name - this is what triggers the
  // existing-child-skip path on iteration 2.
  v1Acc.set_browse_name(QualifiedName{0u, std::string_view{"MyVar"}});
  v2Acc.set_browse_name(QualifiedName{0u, std::string_view{"MyVar"}});
  for (auto* va : {&v1Acc, &v2Acc})
  {
    auto var = va->as<VariableAccessor>();
    var->set_data_type(NodeId{DataTypeId::Int32});
    var->set_value_rank(ValueRank{ValueRank::scalar});
    var->set_access_level(AccessLevelType{0u});
  }

  typeAcc.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{v1DeclId},
    /*isForward=*/true);
  typeAcc.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{v2DeclId},
    /*isForward=*/true);
  v1Acc.add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
    ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}},
    /*isForward=*/true);
  v2Acc.add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
    ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}},
    /*isForward=*/true);

  InstantiationService service{*mAddressSpace};
  InstantiationOptions options;

  auto result = instantiate_object_blocking(service, parentId, QualifiedName{0u, "MyInst"}, typeId, options);
  ASSERT_TRUE(result.is_good());
  auto subtree = std::move(result).value();
  const auto rootId = subtree.root();

  // Count HasComponent forward refs on the instance.
  auto rootResult = mAddressSpace->try_find_node_sync(rootId);
  ASSERT_TRUE(rootResult.is_good());
  std::size_t childCount = 0;
  for (const auto& ref : rootResult.value().get_references_sync())
  {
    if (ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasComponent})
    {
      ++childCount;
    }
  }
  EXPECT_EQ(childCount, 1u) << "second iteration must skip - existing-child check returned true";

  subtree.release();
}

// ---------------------------------------------------------------------------
// IN-F - instantiate_object_async honours the OptionalChildFilter.
// ---------------------------------------------------------------------------
//
// Drive instantiation twice: first with a filter that returns false (skip
// optional child), then with a filter that returns true (keep). Assert that
// the optional child is absent in run 1 and present in run 2.

TEST_F(InstantiationPin, InstantiateOptionalChildHonoursFilter)
{
  const NodeId parentId{1u, std::string_view{"in-f:parent"}};
  create_real_node(parentId, NodeClass::Object);

  const NodeId typeId{1u, std::string_view{"in-f:T"}};
  const NodeId optDeclId{1u, std::string_view{"in-f:Opt-decl"}};

  auto typeAcc = create_real_node(typeId, NodeClass::ObjectType);
  auto optAcc = create_real_node(optDeclId, NodeClass::Variable);
  optAcc.set_browse_name(QualifiedName{0u, std::string_view{"OptVar"}});
  auto optVar = optAcc.as<VariableAccessor>();
  optVar->set_data_type(NodeId{DataTypeId::Int32});
  optVar->set_value_rank(ValueRank{ValueRank::scalar});
  optVar->set_access_level(AccessLevelType{0u});

  typeAcc.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
    ExpandedNodeId{optDeclId},
    /*isForward=*/true);
  optAcc.add_reference_sync(NodeId{ReferenceTypeId::HasModellingRule},
    ExpandedNodeId{NodeId{ObjectId::ModellingRule_Optional}},
    /*isForward=*/true);

  InstantiationService service{*mAddressSpace};

  // Run 1: filter returns false - child should be skipped.
  {
    InstantiationOptions options;
    options.optionalChildFilter = [](const ChildFilterInfo&)
    {
      return false;
    };
    auto result = instantiate_object_blocking(service, parentId, QualifiedName{0u, "Inst1"}, typeId, options);
    ASSERT_TRUE(result.is_good());
    auto subtree = std::move(result).value();
    auto child = first_has_component_child(subtree.root());
    EXPECT_FALSE(child.has_value()) << "filter returned false - optional child must be skipped";
    subtree.release();
  }

  // Run 2: filter returns true - child must be present.
  {
    InstantiationOptions options;
    options.optionalChildFilter = [](const ChildFilterInfo&)
    {
      return true;
    };
    auto result = instantiate_object_blocking(service, parentId, QualifiedName{0u, "Inst2"}, typeId, options);
    ASSERT_TRUE(result.is_good());
    auto subtree = std::move(result).value();
    auto child = first_has_component_child(subtree.root());
    ASSERT_TRUE(child.has_value()) << "filter returned true - optional child must be present";
    const QualifiedName expectedChildName{0u, std::string_view{"OptVar"}};
    EXPECT_EQ(child->get_browse_name(), expectedChildName);
    subtree.release();
  }
}

// ---------------------------------------------------------------------------
// IN-G - instantiate_object_async returns BadEncodingLimitsExceeded when the
//        per-call DepthBudget is exhausted; the ErrorDetail's code is
//        "DepthBudgetExceeded" and mSource is "DepthBudget".
// ---------------------------------------------------------------------------
//
// DepthBudget::consume throws UaException{Status::BadEncodingLimitsExceeded,
// make_error_detail("DepthBudgetExceeded", "...", "DepthBudget")} when
// remaining < n (DepthBudget in ua_resource_budgets.h). The exception unwinds to
// instantiate_object_async's catch clause and is converted via
// ua::exception_to_status_code.
//
// With InstantiationDepthLimit=2, the flow's start consumes (remaining=1), then
// on_typedef_ref_added consumes (remaining=0), then on_parent_linked
// consumes (remaining=0 < 1) and throws.

TEST_F(InstantiationPin, InstantiateBudgetExhaustionReturnsBadEncodingLimitsExceeded)
{
  ExecutionLimits tightLimits;
  tightLimits.instantiationDepthLimit = 2;
  mAddressSpace->set_limits(tightLimits);

  const NodeId parentId{1u, std::string_view{"in-g:parent"}};
  create_real_node(parentId, NodeClass::Object);

  // Construct a deep mandatory chain (>=3 levels) per the runbook; even with
  // a single mandatory child, the budget exhausts during the per-step
  // consumes - but the deep chain documents the semantic intent.
  auto level1 = build_object_type_with_mandatory_var("in-g:T1", "in-g:T1-decl", "L1");
  auto level2 = build_object_type_with_mandatory_var("in-g:T2", "in-g:T2-decl", "L2");
  auto level3 = build_object_type_with_mandatory_var("in-g:T3", "in-g:T3-decl", "L3");
  // Wire the chain via HasTypeDefinition on the declaration nodes (the
  // recursive walk pulls children from the declaration's typedef).
  auto t1Decl = mAddressSpace->try_find_node_sync(level1.declaration).value();
  auto t2Decl = mAddressSpace->try_find_node_sync(level2.declaration).value();
  t1Decl.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
    ExpandedNodeId{level2.typeDef},
    /*isForward=*/true);
  t2Decl.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
    ExpandedNodeId{level3.typeDef},
    /*isForward=*/true);

  InstantiationService service{*mAddressSpace};
  InstantiationOptions options;

  auto result =
    instantiate_object_blocking(service, parentId, QualifiedName{0u, "MyInst"}, level1.typeDef, options);

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadEncodingLimitsExceeded);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "DepthBudgetExceeded");
  EXPECT_EQ(result.shared_detail()->source, "DepthBudget");
}

// ---------------------------------------------------------------------------
// IN-H - instantiate_variable_async copies data_type and value_rank from the
//        VariableType when no explicit attributes are supplied.
// ---------------------------------------------------------------------------

TEST_F(InstantiationPin, InstantiateVariablePopulatesAttributesFromTypeDef)
{
  const NodeId parentId{1u, std::string_view{"in-h:parent"}};
  create_real_node(parentId, NodeClass::Object);

  const NodeId vtId{1u, std::string_view{"in-h:VT"}};
  auto vtAcc = create_real_node(vtId, NodeClass::VariableType);
  auto vtTyped = vtAcc.as<VariableTypeAccessor>();
  ASSERT_TRUE(vtTyped.has_value());
  vtTyped->set_data_type(NodeId{DataTypeId::Int32});
  vtTyped->set_value_rank(ValueRank{ValueRank::scalar});

  InstantiationService service{*mAddressSpace};
  InstantiationOptions options;
  VariableInstantiationAttributes attrs;  // empty - copy-from-type-def path

  auto result =
    instantiate_variable_blocking(service, parentId, QualifiedName{0u, "MyVar"}, vtId, options, attrs);
  ASSERT_TRUE(result.is_good());
  auto subtree = std::move(result).value();
  const auto rootId = subtree.root();

  auto rootResult = mAddressSpace->try_find_node_sync(rootId);
  ASSERT_TRUE(rootResult.is_good());
  auto var = rootResult.value().as<VariableAccessor>();
  ASSERT_TRUE(var.has_value());
  EXPECT_EQ(var->get_data_type(), NodeId{DataTypeId::Int32});
  EXPECT_TRUE(var->get_value_rank().is_scalar());

  subtree.release();
}

// ---------------------------------------------------------------------------
// IN-I - instantiate_variable_async honours explicit attributes (overrides
//        the VariableType's data_type).
// ---------------------------------------------------------------------------

TEST_F(InstantiationPin, InstantiateVariableUsesProvidedAttributesWhenSet)
{
  const NodeId parentId{1u, std::string_view{"in-i:parent"}};
  create_real_node(parentId, NodeClass::Object);

  const NodeId vtId{1u, std::string_view{"in-i:VT"}};
  auto vtAcc = create_real_node(vtId, NodeClass::VariableType);
  auto vtTyped = vtAcc.as<VariableTypeAccessor>();
  ASSERT_TRUE(vtTyped.has_value());
  vtTyped->set_data_type(NodeId{DataTypeId::Int32});
  vtTyped->set_value_rank(ValueRank{ValueRank::scalar});

  InstantiationService service{*mAddressSpace};
  InstantiationOptions options;
  VariableInstantiationAttributes attrs;
  attrs.dataType = NodeId{DataTypeId::Float};  // explicit override

  auto result =
    instantiate_variable_blocking(service, parentId, QualifiedName{0u, "MyVar"}, vtId, options, attrs);
  ASSERT_TRUE(result.is_good());
  auto subtree = std::move(result).value();
  const auto rootId = subtree.root();

  auto rootResult = mAddressSpace->try_find_node_sync(rootId);
  ASSERT_TRUE(rootResult.is_good());
  auto var = rootResult.value().as<VariableAccessor>();
  ASSERT_TRUE(var.has_value());
  EXPECT_EQ(var->get_data_type(), NodeId{DataTypeId::Float});

  subtree.release();
}

// ---------------------------------------------------------------------------
// IN-SYM - the parent-link mirror half's direction follows the parent reference
//          type's Symmetric attribute: a symmetric type is mirrored FORWARD
//          (OPC 10000-3 section 5.3.2 - symmetric references are forward from both ends
//          and are never inverse, OPC 10000-4 section 5.8.2), an asymmetric type INVERSE.
// ---------------------------------------------------------------------------
//
// Bug this would catch: the engine previously hard-coded the mirror half as
// isForward=false for any parent reference type. For a symmetric type that
// yields a non-conformant inverse reference (it would surface on an INVERSE
// browse and be reported with the wrong isForward). Asserting that the mirror's
// is_forward() tracks the reference type's Symmetric attribute catches a
// regression back to the hard-coded direction.

TEST_F(InstantiationPin, ParentLinkMirrorDirectionFollowsReferenceTypeSymmetry)
{
  // Allocate two custom reference types: one symmetric, one asymmetric. (The bare
  // test namespace has no NS0 reference-type nodes, so the engine reads the
  // Symmetric attribute off these explicitly-created nodes.)
  const NodeId symRefType{1u, std::string_view{"in-sym:symmetric-ref"}};
  auto symRt = create_real_node(symRefType, NodeClass::ReferenceType).as<ReferenceTypeAccessor>();
  ASSERT_TRUE(symRt.has_value());
  symRt->set_symmetric(true);
  ASSERT_TRUE(symRt->get_symmetric()) << "precondition: symmetric flag did not persist";

  const NodeId asymRefType{1u, std::string_view{"in-sym:asymmetric-ref"}};
  auto asymRt = create_real_node(asymRefType, NodeClass::ReferenceType).as<ReferenceTypeAccessor>();
  ASSERT_TRUE(asymRt.has_value());
  asymRt->set_symmetric(false);

  auto type = build_object_type_with_mandatory_var("in-sym:T", "in-sym:V-decl", "MyVar");
  InstantiationService service{*mAddressSpace};

  // Instantiate under `parentId` with `parentRefType` as the parent link, then
  // return the is_forward() of the new instance's mirror reference back to the
  // parent (nullopt if no such reference is present).
  auto mirrorIsForward =
    [&](const NodeId& parentId, const NodeId& parentRefType, const std::string& prefix) -> std::optional<bool>
  {
    InstantiationOptions options;
    options.parentReferenceType = parentRefType;
    auto firstId = std::make_shared<NodeId>();
    options.nodeIdAllocator = make_capturing_allocator(prefix, firstId);
    auto result =
      instantiate_object_blocking(service, parentId, QualifiedName{0u, "MyInstance"}, type.typeDef, options);
    EXPECT_TRUE(result.is_good()) << "instantiate failed: 0x" << std::hex << result.status_code().as_uint32();
    if (!result.is_good())
      return std::nullopt;
    auto subtree = std::move(result).value();
    const auto rootId = subtree.root();
    subtree.release();
    auto findResult = mAddressSpace->try_find_node_sync(rootId);
    EXPECT_TRUE(findResult.is_good());
    if (!findResult.is_good())
      return std::nullopt;
    for (const auto& ref : findResult.value().get_references_sync())
    {
      const auto target = ref.target_id();
      if (ref.type_id() == parentRefType && target.is_local() && target.node_id() == parentId)
        return ref.is_forward();
    }
    return std::nullopt;
  };

  const NodeId symParent{1u, std::string_view{"in-sym:parent-sym"}};
  create_real_node(symParent, NodeClass::Object);
  const auto symMirror = mirrorIsForward(symParent, symRefType, "in-sym:sym-inst");
  ASSERT_TRUE(symMirror.has_value()) << "symmetric: no mirror reference to parent found";
  EXPECT_TRUE(*symMirror)
    << "a symmetric parent reference type must mirror as a FORWARD reference (section 5.3.2 / section 5.8.2)";

  const NodeId asymParent{1u, std::string_view{"in-sym:parent-asym"}};
  create_real_node(asymParent, NodeClass::Object);
  const auto asymMirror = mirrorIsForward(asymParent, asymRefType, "in-sym:asym-inst");
  ASSERT_TRUE(asymMirror.has_value()) << "asymmetric: no mirror reference to parent found";
  EXPECT_FALSE(*asymMirror) << "an asymmetric parent reference type must mirror as an INVERSE reference";
}

}  // namespace ua::test::behaviour_pins
