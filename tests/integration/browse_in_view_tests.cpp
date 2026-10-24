// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 3 section 5.4: "All Nodes contained in a View shall be accessible starting from the View Node when
// browsing in the context of the View", and the View Node is the root for the Nodes in the View. A Browse in
// the context of a View therefore starts at its View Node whether or not anything added the View Node to the
// View's members (NR-16 rule 6), while a Node that is not a member is still refused with Bad_NodeNotInView.

#include "compliance_helpers.h"
#include "every_node_in_view_namespace.h"
#include "matchers.h"
#include "requests.h"

#include "ua_browse_direction.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_session_view_services.h"
#include "ua_status.h"
#include "ua_to_string.h"

#include <algorithm>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;

namespace
{

class BrowseInView : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();

    mViewId = NodeId{mTestNamespaceIndex, uint32_t{7500}};
    mMemberA = NodeId{mTestNamespaceIndex, uint32_t{7501}};
    mMemberB = NodeId{mTestNamespaceIndex, uint32_t{7502}};
    mNonMember = NodeId{mTestNamespaceIndex, uint32_t{7503}};

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    const std::pair<NodeId, const char*> objects[]{
      {mMemberA, "MemberA"}, {mMemberB, "MemberB"}, {mNonMember, "NotInTheView"}};
    for (const auto& [id, name] : objects)
    {
      auto node = addressSpace.create_node_sync(id, NodeClass::Object);
      node.set_browse_name(QualifiedName{mTestNamespaceIndex, name});
      node.set_display_name(LocalizedText{"", String{name}});
      node.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
      objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, id);
      node.add_reference_sync(NodeId{ReferenceTypeId::Organizes},
        ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
        /*isForward=*/false);
    }

    auto viewNode = addressSpace.create_node_sync(mViewId, NodeClass::View);
    viewNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "TwoObjectView"});
    viewNode.set_display_name(LocalizedText{"", "TwoObjectView"});
    addressSpace.find_node_sync(NodeId{ObjectId::ViewsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mViewId);
    viewNode.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mMemberA);
    viewNode.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mMemberB);

    // The two Objects are the View's members; the View Node is not added to them.
    auto view = viewNode.as<ViewAccessor>();
    ASSERT_TRUE(view.has_value());
    ASSERT_TRUE(view->try_add_node_to_view_sync(mMemberA).is_good());
    ASSERT_TRUE(view->try_add_node_to_view_sync(mMemberB).is_good());
  }

  NodeId mViewId;
  NodeId mMemberA;
  NodeId mMemberB;
  NodeId mNonMember;
};

std::string describe(const std::vector<NodeId>& nodes)
{
  std::string text;
  for (const auto& node : nodes)
    text += to_string(node) + " ";
  return text;
}

}  // namespace

// @relation(AC-SVR-ADDRSP-075-VIEW-NODE-IN-ITS-OWN-VIEW, scope=function)
TEST_F(BrowseInView, TheViewNodeIsInItsOwnView)
{
  auto response = mSession->view().browse_sync(BrowseRequestBuilder()
                                                 .view(mViewId)
                                                 .browse(mViewId)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                 .include_subtypes(false)
                                                 .browse(mNonMember)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                 .include_subtypes(false));

  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 2u);
  const auto& viewNode = response.results().payload()[0];
  EXPECT_EQ(viewNode.status_code().as_status(), Status::Good)
    << "browsing the View Node in the context of its own View was refused";
  std::vector<NodeId> targets;
  for (const auto& reference : viewNode.references().payload())
    targets.push_back(reference.node_id().node_id());
  EXPECT_EQ(targets.size(), 2u);
  EXPECT_NE(std::find(targets.begin(), targets.end(), mMemberA), targets.end());
  EXPECT_NE(std::find(targets.begin(), targets.end(), mMemberB), targets.end());

  EXPECT_EQ(response.results().payload()[1].status_code().as_status(), Status::BadNodeNotInView)
    << "a Node that is not a member of the View was browsed in its context";
}

// NR-16 rule 6 makes a View Node a member of its own View, and NR-41 applies the rule to the target of each
// Reference as well as to the starting Node. The fixture's View holds MemberA and MemberB and not its View
// Node. Browsed Inverse in the View's context, MemberA shows its Organizes Reference to the View Node, for
// the ReferenceType given exactly and for HierarchicalReferences with its subtypes. The Objects folder also
// organizes MemberA and is not a member: the control that the target filter still omits a non-member.
// @relation(AC-SVR-ADDRSP-075-REFERENCE-TO-VIEW-NODE-KEPT, scope=function)
TEST_F(BrowseInView, AReferenceToTheViewNodeIsKeptInItsOwnView)
{
  const NodeId organizes{ReferenceTypeId::Organizes};
  mServer.server().address_space().find_node_sync(mMemberA).add_reference_sync(
    organizes, ExpandedNodeId{mViewId}, /*isForward=*/false);

  auto response =
    mSession->view().browse_sync(BrowseRequestBuilder()
                                   .view(mViewId)
                                   .browse(mMemberA)
                                   .direction(BrowseDirection::Inverse)
                                   .reference_type(organizes)
                                   .include_subtypes(false)
                                   .browse(mMemberA)
                                   .direction(BrowseDirection::Inverse)
                                   .reference_type(NodeId{ReferenceTypeId::HierarchicalReferences})
                                   .include_subtypes(true));

  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 2u);
  const char* const referenceTypes[]{"Organizes", "HierarchicalReferences with its subtypes"};
  for (size_t i = 0; i < 2; ++i)
  {
    SCOPED_TRACE(referenceTypes[i]);
    const auto& result = response.results().payload()[i];
    EXPECT_EQ(result.status_code().as_status(), Status::Good);
    std::vector<NodeId> targets;
    for (const auto& reference : result.references().payload())
      targets.push_back(reference.node_id().node_id());
    EXPECT_EQ(targets.size(), 1u) << "exactly the Reference to the View Node was expected, got: "
                                  << describe(targets);
    if (targets.size() != 1u)
      continue;
    const auto& reference = result.references().payload().front();
    EXPECT_EQ(targets.front(), mViewId) << "the Reference kept is to " << describe(targets);
    EXPECT_EQ(reference.reference_type_id(), organizes);
    EXPECT_FALSE(reference.is_forward());
  }
}

// NR-16 rule 6: "A View Node is always a member of its own View". The exemption is for the View the request
// names, not for any View Node, so a View Node of another View is a member only if the View contains it, both
// as the Node to browse and as the target of a Reference. The second View's View Node is not among the
// fixture View's members and organizes MemberA, a member. Browsed in the fixture View's context, the second
// View's View Node is refused and shows no Reference; MemberA browsed forward in the same request is the
// control that the members are still browsed; MemberA browsed Inverse shows its Organizes Reference from the
// fixture View's View Node, kept by the exemption, and neither the one from the second View's View Node nor
// the one from the Objects folder, which is not a member. Each operation fails if its exemption is widened to
// every View Node.
// @relation(AC-SVR-ADDRSP-075-ANOTHER-VIEW-NODE-NOT-A-MEMBER, scope=function)
TEST_F(BrowseInView, AnotherViewsNodeIsNotInTheView)
{
  auto addressSpace = mServer.server().address_space();
  const NodeId otherViewId{mTestNamespaceIndex, uint32_t{7504}};
  auto otherView = addressSpace.create_node_sync(otherViewId, NodeClass::View);
  otherView.set_browse_name(QualifiedName{mTestNamespaceIndex, "AnotherView"});
  otherView.set_display_name(LocalizedText{"", "AnotherView"});
  addressSpace.find_node_sync(NodeId{ObjectId::ViewsFolder})
    .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, otherViewId);
  otherView.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mMemberA);
  auto memberA = addressSpace.find_node_sync(mMemberA);
  memberA.add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{mViewId}, /*isForward=*/false);
  memberA.add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{otherViewId}, /*isForward=*/false);

  auto response = mSession->view().browse_sync(BrowseRequestBuilder()
                                                 .view(mViewId)
                                                 .browse(otherViewId)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                 .include_subtypes(false)
                                                 .browse(mMemberA)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                 .include_subtypes(false)
                                                 .browse(mMemberA)
                                                 .direction(BrowseDirection::Inverse)
                                                 .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                 .include_subtypes(false));

  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 3u);
  const auto& otherViewResult = response.results().payload()[0];
  EXPECT_EQ(otherViewResult.status_code().as_status(), Status::BadNodeNotInView)
    << "another View's View Node was browsed in the context of a View that does not contain it";
  EXPECT_EQ(otherViewResult.references().size(), 0u);
  EXPECT_EQ(response.results().payload()[1].status_code().as_status(), Status::Good)
    << "a member of the View was not browsed in its context";
  const auto& inverseResult = response.results().payload()[2];
  EXPECT_EQ(inverseResult.status_code().as_status(), Status::Good);
  std::vector<NodeId> inverseTargets;
  for (const auto& reference : inverseResult.references().payload())
    inverseTargets.push_back(reference.node_id().node_id());
  EXPECT_EQ(inverseTargets, std::vector<NodeId>{mViewId})
    << "MemberA browsed Inverse in the View's context returned: " << describe(inverseTargets)
    << "; expected exactly the Reference from the View's own View Node, and not those from the second View's "
       "View Node or the Objects folder, which the View does not contain";
  if (inverseTargets.size() == 1u)
  {
    const auto& inverse = inverseResult.references().payload().front();
    EXPECT_EQ(inverse.reference_type_id(), NodeId{ReferenceTypeId::Organizes});
    EXPECT_FALSE(inverse.is_forward());
  }
}

// DL-36: a Browse in a View's context resolves a target given by namespace URI before checking it, leaves out
// a target in another Server, and answers Uncertain_NotAllNodesAvailable when the View's namespace cannot say
// whether a target is a member. The channel's security mode is None, on which the Server returns no
// diagnostics, so these arms observe status codes and References only.
namespace
{
// The targets of @p result's References, as returned.
std::vector<ExpandedNodeId> targets_of(const BrowseResult& result)
{
  std::vector<ExpandedNodeId> targets;
  for (const auto& reference : result.references().payload())
    targets.push_back(reference.node_id());
  return targets;
}

std::string describe(const std::vector<ExpandedNodeId>& targets)
{
  std::string text;
  for (const auto& target : targets)
    text += to_string(target) + " ";
  return text;
}
}  // namespace

// Part 4 section 7.30, Table 172: a local target's nodeId "shall contain the namespace index". A target given
// by namespace URI and the same target given by index are one Node, so DL-36 point 1 resolves the URI before
// any target check. MemberA holds Organizes References to MemberB, to the Node that is not in the View and to
// the View Node given by namespace URI, and to a further member given by index. MemberB and that member are
// members, the View Node is kept by its own View's rule, and the Node that is not in the View is the control
// that a target given by URI is still checked. Every Reference returned is in index form.
// @relation(AC-SVR-ADDRSP-075-URI-FORM-TARGET-CHECKED-AS-INDEX, scope=function)
TEST_F(BrowseInView, AUriFormTargetIsCheckedAsItsIndexForm)
{
  auto addressSpace = mServer.server().address_space();
  const std::string nsUri{"urn:test:compliance"};
  ASSERT_EQ(addressSpace.namespace_array().get_namespace_index(nsUri), mTestNamespaceIndex);
  const NodeId memberByIndex{mTestNamespaceIndex, uint32_t{7510}};
  auto member = addressSpace.create_node_sync(memberByIndex, NodeClass::Object);
  member.set_browse_name(QualifiedName{mTestNamespaceIndex, "MemberByIndex"});
  member.set_display_name(LocalizedText{"", "MemberByIndex"});
  auto view = addressSpace.find_node_sync(mViewId).as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(memberByIndex).is_good());

  const NodeId organizes{ReferenceTypeId::Organizes};
  auto memberA = addressSpace.find_node_sync(mMemberA);
  for (const auto& target : {mMemberB, mNonMember, mViewId})
  {
    memberA.add_reference_sync(organizes,
      ExpandedNodeId{NodeId{uint16_t{0}, target.identifier().get_numeric()}, nsUri},
      /*isForward=*/true);
  }
  memberA.add_reference_sync(organizes, ExpandedNodeId{memberByIndex}, /*isForward=*/true);

  auto response = mSession->view().browse_sync(BrowseRequestBuilder()
                                                 .view(mViewId)
                                                 .browse(mMemberA)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(organizes)
                                                 .include_subtypes(false));

  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 1u);
  const auto& result = response.results().payload()[0];
  EXPECT_EQ(result.status_code().as_status(), Status::Good);
  const auto targets = targets_of(result);
  EXPECT_EQ(targets.size(), 3u) << "returned: " << describe(targets);
  for (const auto& expected : {mMemberB, mViewId, memberByIndex})
  {
    EXPECT_NE(std::find(targets.begin(), targets.end(), ExpandedNodeId{expected}), targets.end())
      << "no Reference in index form to " << to_string(expected) << "; returned: " << describe(targets);
  }
  for (const auto& target : targets)
  {
    EXPECT_TRUE(target.namespace_uri().empty()) << to_string(target) << " is not in index form";
    EXPECT_EQ(target.server_index(), 0u) << to_string(target);
    EXPECT_FALSE(target.is_local() && target.node_id() == mNonMember)
      << "the Node that is not in the View was returned";
  }
}

// Part 3 section 4.3.4: a Reference's TargetNode may be in another Server's AddressSpace. Membership of a
// View is asked with a local NodeId, so no namespace can say a remote Node is a member, and DL-36 point 2
// leaves a Reference to one out in a View's context without asking: a limit of today's interface, which B2
// removes. The View belongs to a namespace that answers true for every NodeId (DL-39), so a filter that asked
// it with a remote target's local NodeId would keep that Reference. S holds Organizes References to M, to a
// remote target given by namespace URI and to a remote target given by namespace index. In the View's
// context only M is returned; with no View all three are, the control that the omission belongs to the
// View's context.
// @relation(AC-SVR-ADDRSP-075-REMOTE-TARGET-OMITTED-IN-VIEW, scope=function)
TEST_F(BrowseInView, ARemoteTargetIsOmittedInAView)
{
  auto addressSpace = mServer.server().address_space();
  auto permissive = ua::test::EveryNodeInViewNamespace::create(
    "urn:test:remote-target-view", mServer.thread_pool().executor());
  const uint16_t nsIndex = addressSpace.add_namespace_sync(permissive);
  permissive->set_namespace_defaults(test_namespace_role_permissions(), test_namespace_access_restrictions());
  const NodeId viewId{nsIndex, uint32_t{7800}};
  const NodeId s{nsIndex, uint32_t{7801}};
  const NodeId m{nsIndex, uint32_t{7802}};
  const NodeId organizes{ReferenceTypeId::Organizes};
  const ExpandedNodeId remoteByUri{
    NodeId{uint16_t{0}, std::string{"RemoteNode"}}, "urn:example:remote", uint32_t{1}};
  const ExpandedNodeId remoteByIndex{NodeId{uint16_t{2}, uint32_t{4242}}, uint32_t{1}};

  auto view = addressSpace.create_node_sync(viewId, NodeClass::View);
  view.set_browse_name(QualifiedName{nsIndex, "EveryNodeView"});
  view.set_display_name(LocalizedText{"", "EveryNodeView"});
  const std::pair<NodeId, const char*> objects[]{{s, "S"}, {m, "M"}};
  for (const auto& [id, name] : objects)
  {
    auto node = addressSpace.create_node_sync(id, NodeClass::Object);
    node.set_browse_name(QualifiedName{nsIndex, name});
    node.set_display_name(LocalizedText{"", String{name}});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
  }
  auto sNode = addressSpace.find_node_sync(s);
  sNode.add_reference_sync(organizes, ExpandedNodeId{m}, /*isForward=*/true);
  sNode.add_reference_sync(organizes, remoteByUri, /*isForward=*/true);
  sNode.add_reference_sync(organizes, remoteByIndex, /*isForward=*/true);

  auto inView = mSession->view().browse_sync(BrowseRequestBuilder()
                                               .view(viewId)
                                               .browse(s)
                                               .direction(BrowseDirection::Forward)
                                               .reference_type(organizes)
                                               .include_subtypes(false));
  auto noView = mSession->view().browse_sync(BrowseRequestBuilder()
                                               .browse(s)
                                               .direction(BrowseDirection::Forward)
                                               .reference_type(organizes)
                                               .include_subtypes(false));

  ASSERT_THAT(inView, ServiceResultIsGood());
  ASSERT_EQ(inView.results().size(), 1u);
  EXPECT_EQ(inView.results().payload()[0].status_code().as_status(), Status::Good);
  const auto inViewTargets = targets_of(inView.results().payload()[0]);
  EXPECT_EQ(inViewTargets, std::vector<ExpandedNodeId>{ExpandedNodeId{m}})
    << "in the View's context only the Reference to M is defined for the View; returned: "
    << describe(inViewTargets);

  ASSERT_THAT(noView, ServiceResultIsGood());
  ASSERT_EQ(noView.results().size(), 1u);
  EXPECT_EQ(noView.results().payload()[0].status_code().as_status(), Status::Good);
  const auto noViewTargets = targets_of(noView.results().payload()[0]);
  EXPECT_EQ(noViewTargets.size(), 3u) << "returned: " << describe(noViewTargets);
  EXPECT_NE(
    std::find_if(noViewTargets.begin(),
      noViewTargets.end(),
      [](const ExpandedNodeId& target)
      { return target.server_index() == 1u && std::string{target.namespace_uri()} == "urn:example:remote"; }),
    noViewTargets.end())
    << "with no View, the remote target given by URI was not returned; returned: " << describe(noViewTargets);
  EXPECT_NE(std::find_if(noViewTargets.begin(),
              noViewTargets.end(),
              [](const ExpandedNodeId& target)
              {
                return target.server_index() == 1u &&
                       target.node_id().identifier() == NodeId::Identifier{uint32_t{4242}};
              }),
    noViewTargets.end())
    << "with no View, the remote target given by index was not returned; returned: "
    << describe(noViewTargets);
}

// Part 4 section 5.8.2.4, Table 36 lists Bad_NodeIdInvalid for Browse. DL-36 point 1 keeps today's operation
// failure for a target whose namespace URI the Server does not hold, and makes the Browse in a View's context
// answer it as the Browse with no View does. The Browse with no View is the control.
// @relation(AC-SVR-ADDRSP-075-UNRESOLVABLE-URI-TARGET-FAILS-AS-WITHOUT-VIEW, scope=function)
TEST_F(BrowseInView, AnUnresolvableUriFormTargetFailsAsWithoutAView)
{
  const NodeId organizes{ReferenceTypeId::Organizes};
  auto memberA = mServer.server().address_space().find_node_sync(mMemberA);
  memberA.add_reference_sync(organizes, ExpandedNodeId{mMemberB}, /*isForward=*/true);
  memberA.add_reference_sync(organizes,
    ExpandedNodeId{NodeId{uint16_t{0}, uint32_t{4711}}, "urn:example:not-registered"},
    /*isForward=*/true);

  auto inView = mSession->view().browse_sync(BrowseRequestBuilder()
                                               .view(mViewId)
                                               .browse(mMemberA)
                                               .direction(BrowseDirection::Forward)
                                               .reference_type(organizes)
                                               .include_subtypes(false));
  auto noView = mSession->view().browse_sync(BrowseRequestBuilder()
                                               .browse(mMemberA)
                                               .direction(BrowseDirection::Forward)
                                               .reference_type(organizes)
                                               .include_subtypes(false));

  const std::pair<const char*, const BrowseResponse*> browses[]{
    {"in the View's context", &inView}, {"with no View", &noView}};
  for (const auto& [context, response] : browses)
  {
    SCOPED_TRACE(context);
    ASSERT_THAT(*response, ServiceResultIsGood());
    ASSERT_EQ(response->results().size(), 1u);
    const auto& result = response->results().payload()[0];
    EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdInvalid);
    EXPECT_EQ(result.references().size(), 0u) << "returned: " << describe(targets_of(result));
  }
}

// Part 4 section 5.8.2.4, Table 36: Uncertain_NotAllNodesAvailable, "Browse results may be incomplete because
// of the unavailability of a subsystem." DL-36 point 3: when the View's namespace answers Bad for a target,
// the Reference is left out and the operation answers Uncertain_NotAllNodesAvailable. The View belongs to a
// namespace that answers per NodeId as the test chooses. S1 holds M1, T1 and M2; S2 holds T2, M3 and T3. The
// members are the control that the other References are returned; U, browsed in the same request, is the
// control that the check of the Node to browse is unchanged: the namespace's Bad answer for U is the
// operation's status.
// @relation(AC-COMP-SVR-BROWSE-VIEW-TARGET-FILTER-01-TARGET-MEMBERSHIP-FAILURE-UNCERTAIN, scope=function)
TEST_F(BrowseInView, AFailedTargetMembershipAnswerIsUncertainNotAllNodesAvailable)
{
  auto addressSpace = mServer.server().address_space();
  // The answers are filled in once the namespace's index is known, before anything is browsed.
  auto answers = std::make_shared<std::vector<std::pair<NodeId, BoolResult>>>();
  auto scripted = ua::test::EveryNodeInViewNamespace::create("urn:test:failing-view-membership",
    mServer.thread_pool().executor(),
    [answers](const NodeId& nodeId)
    {
      for (const auto& [node, answer] : *answers)
      {
        if (node == nodeId)
          return answer;
      }
      return BoolResult{false};
    });
  const uint16_t nsIndex = addressSpace.add_namespace_sync(scripted);
  scripted->set_namespace_defaults(test_namespace_role_permissions(), test_namespace_access_restrictions());
  const NodeId viewId{nsIndex, uint32_t{7700}};
  const NodeId s1{nsIndex, uint32_t{7701}};
  const NodeId s2{nsIndex, uint32_t{7702}};
  const NodeId m1{nsIndex, uint32_t{7703}};
  const NodeId m2{nsIndex, uint32_t{7704}};
  const NodeId m3{nsIndex, uint32_t{7705}};
  const NodeId t1{nsIndex, uint32_t{7706}};
  const NodeId t2{nsIndex, uint32_t{7707}};
  const NodeId t3{nsIndex, uint32_t{7708}};
  const NodeId u{nsIndex, uint32_t{7709}};
  const NodeId organizes{ReferenceTypeId::Organizes};

  auto view = addressSpace.create_node_sync(viewId, NodeClass::View);
  view.set_browse_name(QualifiedName{nsIndex, "FailingView"});
  view.set_display_name(LocalizedText{"", "FailingView"});
  const std::pair<NodeId, const char*> objects[]{
    {s1, "S1"}, {s2, "S2"}, {m1, "M1"}, {m2, "M2"}, {m3, "M3"}, {t1, "T1"}, {t2, "T2"}, {t3, "T3"}, {u, "U"}};
  for (const auto& [id, name] : objects)
  {
    auto node = addressSpace.create_node_sync(id, NodeClass::Object);
    node.set_browse_name(QualifiedName{nsIndex, name});
    node.set_display_name(LocalizedText{"", String{name}});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
  }
  for (const auto& member : {s1, s2, m1, m2, m3})
    answers->emplace_back(member, BoolResult{true});
  for (const auto& target : {t1, t2, t3})
  {
    answers->emplace_back(target,
      BoolResult{StatusCode{Status::BadInternalError},
        ErrorDetail::build("ScriptedMembershipFailure",
          "The test's View cannot say whether this Node is a member",
          "TestView")});
  }
  answers->emplace_back(u,
    BoolResult{StatusCode{Status::BadResourceUnavailable},
      ErrorDetail::build("ScriptedUMembershipFailure",
        "The test's View cannot say whether this Node is a member",
        "TestView")});
  auto s1Node = addressSpace.find_node_sync(s1);
  for (const auto& target : {m1, t1, m2})
    s1Node.add_reference_sync(organizes, ExpandedNodeId{target}, /*isForward=*/true);
  auto s2Node = addressSpace.find_node_sync(s2);
  for (const auto& target : {t2, m3, t3})
    s2Node.add_reference_sync(organizes, ExpandedNodeId{target}, /*isForward=*/true);

  // Precondition: S2's References come in the order they were added, so T2's answer is the first to fail.
  auto order = mSession->view().browse_sync(BrowseRequestBuilder()
                                              .browse(s2)
                                              .direction(BrowseDirection::Forward)
                                              .reference_type(organizes)
                                              .include_subtypes(false));
  ASSERT_EQ(order.results().size(), 1u);
  ASSERT_EQ(targets_of(order.results().payload()[0]),
    (std::vector<ExpandedNodeId>{ExpandedNodeId{t2}, ExpandedNodeId{m3}, ExpandedNodeId{t3}}));

  auto response = mSession->view().browse_sync(BrowseRequestBuilder()
                                                 .view(viewId)
                                                 .browse(s1)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(organizes)
                                                 .include_subtypes(false)
                                                 .browse(s2)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(organizes)
                                                 .include_subtypes(false)
                                                 .browse(u)
                                                 .direction(BrowseDirection::Forward));

  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 3u);
  const auto& s1Result = response.results().payload()[0];
  EXPECT_EQ(s1Result.status_code().as_status(), Status::UncertainNotAllNodesAvailable) << "S1";
  EXPECT_EQ(targets_of(s1Result), (std::vector<ExpandedNodeId>{ExpandedNodeId{m1}, ExpandedNodeId{m2}}))
    << "S1 returned: " << describe(targets_of(s1Result));
  const auto& s2Result = response.results().payload()[1];
  EXPECT_EQ(s2Result.status_code().as_status(), Status::UncertainNotAllNodesAvailable) << "S2";
  EXPECT_EQ(targets_of(s2Result), std::vector<ExpandedNodeId>{ExpandedNodeId{m3}})
    << "S2 returned: " << describe(targets_of(s2Result));
  const auto& uResult = response.results().payload()[2];
  EXPECT_EQ(uResult.status_code().as_status(), Status::BadResourceUnavailable) << "U, the Node to browse";
  EXPECT_EQ(uResult.references().size(), 0u);
}

namespace
{
// The BrowseInView server, whose Sessions may each hold one Browse continuation point.
class BrowseInViewWithOneContinuationPoint : public BrowseInView
{
protected:
  void configure_server_config(ua::server::ServerConfig& cfg) override
  {
    BrowseInView::configure_server_config(cfg);
    cfg.server_capabilities().maxBrowseContinuationPoints = 1;
  }
};
}  // namespace

// Part 4 section 7.9: a Server that cannot hand out a continuation point for an operation that has References
// left answers it Bad_NoContinuationPoints. An Uncertain_NotAllNodesAvailable result has References left when
// it pages, so DL-43 answers it as a Good one: with its continuation point refused, it is
// Bad_NoContinuationPoints with no continuation point and, by DL-44, no References. The Session may hold one
// point. One Browse in the View's context, one Reference per Node, has two operations: S1 holds M1 and M2,
// and S2 holds T, M3 and M4, where the View's namespace cannot say whether T is a member, so S2's operation
// is Uncertain_NotAllNodesAvailable and pages. S1's operation takes the one point: the control that the
// limit, not the View, refuses S2's. S2 browsed alone first is the precondition that its operation is
// Uncertain_NotAllNodesAvailable and pages, so a Good S2, which the Session also refuses, cannot pass.
// @relation(AC-SVR-VIEW-CPT-005-REFUSED-POINT-OF-A-RESULT-NOT-BAD, scope=function)
TEST_F(BrowseInViewWithOneContinuationPoint,
  AnIncompleteResultWhoseContinuationPointIsRefusedIsBadNoContinuationPoints)
{
  auto addressSpace = mServer.server().address_space();
  // The answers are filled in once the namespace's index is known, before anything is browsed.
  auto answers = std::make_shared<std::vector<std::pair<NodeId, BoolResult>>>();
  auto scripted = ua::test::EveryNodeInViewNamespace::create("urn:test:continuation-point-limit-view",
    mServer.thread_pool().executor(),
    [answers](const NodeId& nodeId)
    {
      for (const auto& [node, answer] : *answers)
      {
        if (node == nodeId)
          return answer;
      }
      return BoolResult{false};
    });
  const uint16_t nsIndex = addressSpace.add_namespace_sync(scripted);
  scripted->set_namespace_defaults(test_namespace_role_permissions(), test_namespace_access_restrictions());
  const NodeId viewId{nsIndex, uint32_t{7900}};
  const NodeId s1{nsIndex, uint32_t{7901}};
  const NodeId s2{nsIndex, uint32_t{7902}};
  const NodeId m1{nsIndex, uint32_t{7903}};
  const NodeId m2{nsIndex, uint32_t{7904}};
  const NodeId m3{nsIndex, uint32_t{7905}};
  const NodeId m4{nsIndex, uint32_t{7906}};
  const NodeId t{nsIndex, uint32_t{7907}};
  const NodeId organizes{ReferenceTypeId::Organizes};

  auto view = addressSpace.create_node_sync(viewId, NodeClass::View);
  view.set_browse_name(QualifiedName{nsIndex, "OnePointView"});
  view.set_display_name(LocalizedText{"", "OnePointView"});
  const std::pair<NodeId, const char*> objects[]{
    {s1, "S1"}, {s2, "S2"}, {m1, "M1"}, {m2, "M2"}, {m3, "M3"}, {m4, "M4"}, {t, "T"}};
  for (const auto& [id, name] : objects)
  {
    auto node = addressSpace.create_node_sync(id, NodeClass::Object);
    node.set_browse_name(QualifiedName{nsIndex, name});
    node.set_display_name(LocalizedText{"", String{name}});
    node.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
  }
  for (const auto& member : {s1, s2, m1, m2, m3, m4})
    answers->emplace_back(member, BoolResult{true});
  answers->emplace_back(t,
    BoolResult{StatusCode{Status::BadInternalError},
      ErrorDetail::build("ScriptedMembershipFailure",
        "The test's View cannot say whether this Node is a member",
        "TestView")});
  auto s1Node = addressSpace.find_node_sync(s1);
  for (const auto& target : {m1, m2})
    s1Node.add_reference_sync(organizes, ExpandedNodeId{target}, /*isForward=*/true);
  auto s2Node = addressSpace.find_node_sync(s2);
  for (const auto& target : {t, m3, m4})
    s2Node.add_reference_sync(organizes, ExpandedNodeId{target}, /*isForward=*/true);

  // Precondition: browsed alone while the one continuation point is free, S2's operation is
  // Uncertain_NotAllNodesAvailable with the Reference to M3 and a continuation point. Its point is then
  // released, so the slot is free again for the Browse under test.
  auto alone = mSession->view().browse_sync(BrowseRequestBuilder()
                                              .view(viewId)
                                              .max_references_per_node(1)
                                              .browse(s2)
                                              .direction(BrowseDirection::Forward)
                                              .reference_type(organizes)
                                              .include_subtypes(false));
  ASSERT_THAT(alone, ServiceResultIsGood());
  ASSERT_EQ(alone.results().size(), 1u);
  const auto& aloneResult = alone.results().payload()[0];
  ASSERT_EQ(aloneResult.status_code().as_status(), Status::UncertainNotAllNodesAvailable)
    << "precondition: S2 browsed alone answered " << to_string(aloneResult.status_code());
  ASSERT_EQ(targets_of(aloneResult), std::vector<ExpandedNodeId>{ExpandedNodeId{m3}})
    << "precondition: S2 browsed alone returned " << describe(targets_of(aloneResult));
  ASSERT_FALSE(aloneResult.continuation_point().empty())
    << "precondition: S2 browsed alone has no continuation point";
  auto released =
    mSession->view().browse_next_sync(browse_next(aloneResult.continuation_point(), /*release=*/true));
  // A release answers empty results and diagnosticInfos (OPC 10000-4 Table 37); the Browse below finds the
  // slot free only if the point was released.
  ASSERT_THAT(released, ServiceResultIsGood());
  ASSERT_TRUE(released.results().empty())
    << "precondition: the release answered " << released.results().size() << " results";

  auto response = mSession->view().browse_sync(BrowseRequestBuilder()
                                                 .view(viewId)
                                                 .max_references_per_node(1)
                                                 .browse(s1)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(organizes)
                                                 .include_subtypes(false)
                                                 .browse(s2)
                                                 .direction(BrowseDirection::Forward)
                                                 .reference_type(organizes)
                                                 .include_subtypes(false));

  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 2u);
  const auto& s1Result = response.results().payload()[0];
  EXPECT_EQ(s1Result.status_code().as_status(), Status::Good) << "S1";
  EXPECT_EQ(targets_of(s1Result), std::vector<ExpandedNodeId>{ExpandedNodeId{m1}})
    << "S1 returned: " << describe(targets_of(s1Result));
  EXPECT_FALSE(s1Result.continuation_point().empty())
    << "S1's operation did not keep the one continuation point";

  const auto& s2Result = response.results().payload()[1];
  EXPECT_EQ(s2Result.status_code().as_status(), Status::BadNoContinuationPoints)
    << "S2's incomplete result lost its continuation point and still answered "
    << to_string(s2Result.status_code());
  EXPECT_TRUE(s2Result.continuation_point().empty()) << "S2";
  EXPECT_TRUE(s2Result.references().empty())
    << "S2's refused result still returned " << describe(targets_of(s2Result));
}

// Part 3 section 5.4: "the Server Object defined in OPC 10000-5 shall never be part of any View". NR-41: the
// Browse service decides it by NodeId for every namespace, so a namespace whose View answers that every Node
// is a member, the Server Object included, still shows no View containing it. The other child of the
// Objects folder is the control that the View still shows its members.
// @relation(AC-SVR-EVT-ATTR-007-SERVER-OBJECT-NOT-IN-VIEW, scope=function)
TEST_F(BrowseInView, TheServerObjectIsInNoViewWhateverTheViewAnswers)
{
  auto addressSpace = mServer.server().address_space();
  auto permissive = ua::test::EveryNodeInViewNamespace::create(
    "urn:test:every-node-in-view", mServer.thread_pool().executor());
  const uint16_t permissiveIndex = addressSpace.add_namespace_sync(permissive);
  permissive->set_namespace_defaults(test_namespace_role_permissions(), test_namespace_access_restrictions());
  const NodeId permissiveView{permissiveIndex, uint32_t{7600}};
  const NodeId otherChild{permissiveIndex, uint32_t{7601}};
  const NodeId serverObject{ObjectId::Server};
  const NodeId objectsFolder{ObjectId::ObjectsFolder};

  auto child = addressSpace.create_node_sync(otherChild, NodeClass::Object);
  child.set_browse_name(QualifiedName{permissiveIndex, "OtherChild"});
  child.set_display_name(LocalizedText{"", "OtherChild"});
  child.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
  addressSpace.find_node_sync(objectsFolder)
    .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, otherChild);
  child.add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{objectsFolder}, /*isForward=*/false);

  auto viewNode = addressSpace.create_node_sync(permissiveView, NodeClass::View);
  viewNode.set_browse_name(QualifiedName{permissiveIndex, "EveryNodeView"});
  viewNode.set_display_name(LocalizedText{"", "EveryNodeView"});
  addressSpace.find_node_sync(NodeId{ObjectId::ViewsFolder})
    .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, permissiveView);
  auto view = viewNode.as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(objectsFolder).is_good());
  ASSERT_TRUE(view->try_add_node_to_view_sync(otherChild).is_good());

  auto response =
    mSession->view().browse_sync(BrowseRequestBuilder()
                                   .view(permissiveView)
                                   .browse(serverObject)
                                   .direction(BrowseDirection::Forward)
                                   .browse(objectsFolder)
                                   .direction(BrowseDirection::Forward)
                                   .reference_type(NodeId{ReferenceTypeId::HierarchicalReferences})
                                   .include_subtypes(true));
  ASSERT_THAT(response, ServiceResultIsGood());
  ASSERT_EQ(response.results().size(), 2u);
  EXPECT_EQ(response.results().payload()[0].status_code().as_status(), Status::BadNodeNotInView)
    << "the Server Object was browsed in the context of a View whose namespace claims it";
  EXPECT_EQ(response.results().payload()[1].status_code().as_status(), Status::Good);
  std::vector<NodeId> folderTargets;
  for (const auto& reference : response.results().payload()[1].references().payload())
    folderTargets.push_back(reference.node_id().node_id());
  auto continuation = response.results().payload()[1].continuation_point();
  for (int page = 0; page < 64 && !continuation.empty(); ++page)
  {
    auto next = mSession->view().browse_next_sync(browse_next(continuation));
    ASSERT_EQ(next.results().size(), 1u);
    for (const auto& reference : next.results().payload()[0].references().payload())
      folderTargets.push_back(reference.node_id().node_id());
    continuation = next.results().payload()[0].continuation_point();
  }
  EXPECT_NE(std::find(folderTargets.begin(), folderTargets.end(), otherChild), folderTargets.end())
    << "the View no longer shows its member; the Objects folder showed " << describe(folderTargets);
  EXPECT_EQ(std::find(folderTargets.begin(), folderTargets.end(), serverObject), folderTargets.end())
    << "a Browse in the View's context returned a Reference to the Server Object";

  // Every View under the Views folder, each in its own context.
  auto views = mSession->view().browse_sync(BrowseRequestBuilder()
                                              .browse(NodeId{ObjectId::ViewsFolder})
                                              .direction(BrowseDirection::Forward)
                                              .reference_type(NodeId{ReferenceTypeId::Organizes})
                                              .include_subtypes(true));
  ASSERT_THAT(views, ServiceResultIsGood());
  ASSERT_EQ(views.results().size(), 1u);
  std::vector<NodeId> viewIds;
  for (const auto& reference : views.results().payload()[0].references().payload())
    viewIds.push_back(reference.node_id().node_id());
  ASSERT_NE(std::find(viewIds.begin(), viewIds.end(), permissiveView), viewIds.end());
  ASSERT_NE(std::find(viewIds.begin(), viewIds.end(), mViewId), viewIds.end());
  for (const auto& viewId : viewIds)
  {
    auto inView =
      mSession->view().browse_sync(BrowseRequestBuilder()
                                     .view(viewId)
                                     .browse(serverObject)
                                     .direction(BrowseDirection::Forward)
                                     .browse(viewId)
                                     .direction(BrowseDirection::Forward)
                                     .reference_type(NodeId{ReferenceTypeId::HierarchicalReferences})
                                     .include_subtypes(true));
    ASSERT_THAT(inView, ServiceResultIsGood());
    ASSERT_EQ(inView.results().size(), 2u);
    EXPECT_EQ(inView.results().payload()[0].status_code().as_status(), Status::BadNodeNotInView)
      << "the View " << to_string(viewId) << " shows the Server Object";
    for (const auto& reference : inView.results().payload()[1].references().payload())
      EXPECT_NE(reference.node_id().node_id(), serverObject)
        << "the View " << to_string(viewId) << " has the Server Object below its View Node";
  }
}
