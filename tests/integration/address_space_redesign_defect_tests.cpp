// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The address-space defects the redesign fixes, observed by a client (address_space_1_0.md P0).
///
/// Each test was red until its fix landed, and carries `@pending` against its DEFECT until then
/// (the address-space redesign defect record). They run in CI and fail there by
/// decision D-15. Each has a control that passes today, so a red result is the defect and not the
/// fixture.
///
/// | Defect | Fixed in | What the client sees |
/// |---|---|---|
/// | SB-1 | NR-70 B8 (fixed) | a HasSubtype added from the supertype side is not browsable from the subtype |
/// | SB-2 | P5 (fixed) | a Mandatory child under Organizes is not created on an instance |
/// | SB-3 | phase 1 | TranslateBrowsePaths cannot follow a Reference that Browse returns |

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#include "compliance_helpers.h"
#include "instantiation/ua_instantiation_service.h"
#include "requests.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_default_namespace.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor.h"
#include "ua_reference.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_session_view_services.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// A namespace whose reference reads answer, for one source Node, a forward HasComponent Reference to a Node
/// the namespace holds, besides the References stored on the source, without that Reference being stored on
/// the source. Each query is answered with every Reference of its Node and no resume token.
class ExtraReferenceNamespace final : public default_ns::Namespace
{
public:
  ExtraReferenceNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void set_extra_reference(NodeId source, NodeId target)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mSource = std::move(source);
    mTarget = std::move(target);
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    NodeId source;
    NodeId target;
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      source = mSource;
      target = mTarget;
    }
    std::vector<ReferenceQuery> whole;
    std::vector<NodeId> named;
    whole.reserve(queries.size());
    named.reserve(queries.size());
    for (const auto& query : queries)
    {
      whole.push_back(ReferenceQuery{query.node, query.nodeId, query.direction, {}, 0, ByteString{}});
      named.push_back(query.nodeId);
    }
    default_ns::Namespace::read_references_async(request,
      whole,
      [complete = std::move(complete), named = std::move(named), source, target](
        BatchResult<NodeReferencesResult> read)
      {
        if (read.batchStatus.is_good() && read.items.size() == named.size())
        {
          for (size_t i = 0; i < named.size(); ++i)
          {
            if (named[i] != source || !read.items[i].is_good())
            {
              continue;
            }
            const auto& stored = read.items[i].value().references;
            std::vector<Reference> references(stored.begin(), stored.end());
            references.emplace_back(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{target}, true);
            read.items[i] =
              NodeReferencesResult{NodeReferences{References{std::move(references)}, ByteString{}}};
          }
        }
        if (complete)
        {
          complete(std::move(read));
        }
      });
  }

private:
  std::mutex mMutex;
  NodeId mSource;
  NodeId mTarget;
};

class AddressSpaceRedesignDefects : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    const NodeId hasSubtype{ReferenceTypeId::HasSubtype};
    const NodeId hasTypeDefinition{ReferenceTypeId::HasTypeDefinition};
    const NodeId hasModellingRule{ReferenceTypeId::HasModellingRule};

    // SB-1: two ObjectTypes, the subtype relation added from the supertype side.
    mSupertype = NodeId{mTestNamespaceIndex, uint32_t{6000}};
    mSubtype = NodeId{mTestNamespaceIndex, uint32_t{6001}};
    make_object_type(addressSpace, mSupertype, "RedesignSupertype", true);
    make_object_type(addressSpace, mSubtype, "RedesignSubtype", false);
    addressSpace.find_node_sync(mSupertype).add_reference_sync(hasSubtype, ExpandedNodeId{mSubtype});
    // The control: a subtype relation added from the subtype side, as an inverse.
    mControlSubtype = NodeId{mTestNamespaceIndex, uint32_t{6002}};
    make_object_type(addressSpace, mControlSubtype, "RedesignControlSubtype", false);
    addressSpace.find_node_sync(mControlSubtype)
      .add_reference_sync(hasSubtype, ExpandedNodeId{mSupertype}, /*isForward=*/false);

    // SB-2: an ObjectType with two Mandatory children, one under Organizes and one under HasComponent.
    const NodeId instanceType{mTestNamespaceIndex, uint32_t{6100}};
    make_object_type(addressSpace, instanceType, "RedesignInstanceType", true);
    for (const auto& [id, name, referenceType] :
      {std::tuple{uint32_t{6101}, "OrganizedChild", NodeId{ReferenceTypeId::Organizes}},
        std::tuple{uint32_t{6102}, "ComponentChild", NodeId{ReferenceTypeId::HasComponent}}})
    {
      const NodeId childId{mTestNamespaceIndex, id};
      auto child = addressSpace.create_node_sync(childId, NodeClass::Object);
      child.set_browse_name(QualifiedName{mTestNamespaceIndex, name});
      child.set_display_name(LocalizedText{"", name});
      child.add_reference_sync(hasTypeDefinition, ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}});
      child.add_reference_sync(hasModellingRule, ExpandedNodeId{NodeId{ObjectId::ModellingRule_Mandatory}});
      addressSpace.find_node_sync(instanceType).add_reference_sync(referenceType, ExpandedNodeId{childId});
    }
    std::promise<NodeSubtreeResult> instantiated;
    InstantiationService{addressSpace}.instantiate_object_async(NodeId{ObjectId::ObjectsFolder},
      QualifiedName{mTestNamespaceIndex, "RedesignInstance"},
      instanceType,
      InstantiationOptions{},
      [&instantiated](NodeSubtreeResult result) { instantiated.set_value(std::move(result)); });
    auto subtree = instantiated.get_future().get();
    ASSERT_TRUE(subtree.is_good()) << to_string(subtree.status_code());
    mInstance = subtree.value().root();
    subtree.value().release();

    // SB-3: a namespace whose reference reads show a child its stored References do not hold.
    mDelegateNamespace =
      std::make_shared<ExtraReferenceNamespace>("urn:test:redesign-sb3", mServer.thread_pool().executor());
    const auto delegateIndex = addressSpace.add_namespace_sync(mDelegateNamespace);
    mDelegateNamespace->set_namespace_defaults(test_namespace_role_permissions(), std::nullopt);
    mDelegateSource = NodeId{delegateIndex, uint32_t{1}};
    mDelegateTarget = NodeId{delegateIndex, uint32_t{2}};
    mDelegateTargetName = QualifiedName{delegateIndex, "DelegatedChild"};
    for (const auto& [id, name] :
      {std::pair{mDelegateSource, "DelegatedSource"}, std::pair{mDelegateTarget, "DelegatedChild"}})
    {
      auto node = addressSpace.create_node_sync(id, NodeClass::Object);
      node.set_browse_name(QualifiedName{delegateIndex, name});
      node.set_display_name(LocalizedText{"", name});
      node.add_reference_sync(hasTypeDefinition, ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}});
    }
    mDelegateNamespace->set_extra_reference(mDelegateSource, mDelegateTarget);
  }

  /// An ObjectType, linked to BaseObjectType from its own side when @p subtypeOfBase is set.
  void make_object_type(AddressSpace& addressSpace, const NodeId& id, const char* name, bool subtypeOfBase)
  {
    auto type = addressSpace.create_node_sync(id, NodeClass::ObjectType);
    type.set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    type.set_display_name(LocalizedText{"", name});
    if (subtypeOfBase)
    {
      type.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype},
        ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}},
        /*isForward=*/false);
    }
  }

  std::vector<ReferenceDescription> browse(
    const NodeId& node, BrowseDirection direction, const NodeId& referenceType)
  {
    auto response = mSession->view().browse_sync(
      BrowseRequestBuilder().browse(node).direction(direction).reference_type(referenceType).build());
    EXPECT_EQ(response.results().size(), 1u);
    if (response.results().empty())
    {
      return {};
    }
    EXPECT_TRUE(response.results()[0].status_code().is_good());
    const auto& references = response.results()[0].references();
    return {references.begin(), references.end()};
  }

  static bool names(const std::vector<ReferenceDescription>& references, const NodeId& target)
  {
    for (const auto& reference : references)
    {
      if (reference.node_id().node_id() == target)
      {
        return true;
      }
    }
    return false;
  }

  static bool names(const std::vector<ReferenceDescription>& references, const std::string& browseName)
  {
    for (const auto& reference : references)
    {
      if (reference.browse_name().name() == browseName)
      {
        return true;
      }
    }
    return false;
  }

  NodeId mSupertype;
  NodeId mSubtype;
  NodeId mControlSubtype;
  NodeId mInstance;
  shared_ptr<ExtraReferenceNamespace> mDelegateNamespace;
  NodeId mDelegateSource;
  NodeId mDelegateTarget;
  QualifiedName mDelegateTargetName;
};

}  // namespace

// SB-1. OPC UA References are bidirectional (Part 3 section 5.5.2 and its parallel clauses): a Server
// that holds a Reference from A to B also answers it from B as an inverse Reference. Adding HasSubtype
// on the supertype stores it on the supertype alone, so the subtype does not know its supertype. Fixed in NR-70
// B8: the address space adds the other half of a HasSubtype or HasEncoding Reference.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-A-REQUIRED-PAIR-IS-ADDED-AND-REMOVED-ON-BOTH-SIDES, scope=function)
TEST_F(AddressSpaceRedesignDefects, AReferenceAddedOnItsSourceIsBrowsableFromItsTarget)
{
  const auto inverse = browse(mSubtype, BrowseDirection::Inverse, NodeId{ReferenceTypeId::HasSubtype});
  EXPECT_TRUE(names(inverse, mSupertype))
    << "the subtype must answer the HasSubtype its supertype holds, as an inverse Reference";
}

// Control for SB-1: the same relation added on the subtype side is browsable from the subtype, so the
// test above fails for the side the Reference was added on, not for the Browse.
TEST_F(AddressSpaceRedesignDefects, AReferenceAddedOnItsTargetIsBrowsableFromItsTarget)
{
  const auto inverse = browse(mControlSubtype, BrowseDirection::Inverse, NodeId{ReferenceTypeId::HasSubtype});
  EXPECT_TRUE(names(inverse, mSupertype));
}

// SB-2, fixed in P5. Every forward hierarchical Reference from a type to an InstanceDeclaration with a
// ModellingRule declares a member (Part 3 section 6.2.1, 6.4.2); a Mandatory one exists on every instance.
// Instantiation followed only HasComponent, HasProperty and HasOrderedComponent, so the Organizes child was
// missing.
// @relation(AC-SVR-ADDRSP-084-INSTANCE-MINIMUM-COMPONENTS, scope=function)
TEST_F(AddressSpaceRedesignDefects, AMandatoryChildUnderOrganizesIsCreatedOnTheInstance)
{
  const auto children = browse(mInstance, BrowseDirection::Forward, NodeId{ReferenceTypeId::Organizes});
  EXPECT_TRUE(names(children, "OrganizedChild")) << "a Mandatory InstanceDeclaration under Organizes";
}

// Control for SB-2: the HasComponent child of the same type is created, so the instance exists and the
// fixture's ModellingRule is read.
TEST_F(AddressSpaceRedesignDefects, AMandatoryChildUnderHasComponentIsCreatedOnTheInstance)
{
  const auto children = browse(mInstance, BrowseDirection::Forward, NodeId{ReferenceTypeId::HasComponent});
  EXPECT_TRUE(names(children, "ComponentChild"));
}

// SB-3. A Node has one set of References (Part 3 section 4.3.4); Browse and TranslateBrowsePaths are two
// views of it, and both ask the namespace's read_references_async for them. A child the namespace's reference
// read returns, which the source's stored References do not hold, is browsable and is reached by a path.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-BROWSE-AND-TRANSLATE-READ-THE-SAME-REFERENCES, scope=function)
TEST_F(AddressSpaceRedesignDefects, TranslateBrowsePathsFollowsAReferenceBrowseReturns)
{
  auto response =
    mSession->view().translate_browse_paths_sync(translate_path(mDelegateSource, mDelegateTargetName));
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code().as_status(), Status::Good);
  ASSERT_EQ(response.results()[0].targets().size(), 1u);
  EXPECT_EQ(response.results()[0].targets()[0].target_id().node_id(), mDelegateTarget);
}

// Control for SB-3: Browse of the same source returns the child.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-BROWSE-AND-TRANSLATE-READ-THE-SAME-REFERENCES, scope=function)
TEST_F(AddressSpaceRedesignDefects, BrowseReturnsTheDelegatedReference)
{
  const auto children =
    browse(mDelegateSource, BrowseDirection::Forward, NodeId{ReferenceTypeId::HierarchicalReferences});
  EXPECT_TRUE(names(children, mDelegateTarget));
}
