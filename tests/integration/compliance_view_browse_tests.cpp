// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 5: View Service Set - Browse, BrowseNext, ContinuationPoint, ReferenceDescription
///
/// Tests covering Part 4 View requirements (VIEW-BRW-*, VIEW-BNX-*, VIEW-CPT-*, VIEW-RFD-*).

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"

#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_browse_result_mask.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_datatype_id.h"
#include "ua_server_configuration.h"
#include "ua_timestamps_to_return.h"
#include "ua_view_description.h"

#include <queue>
#include <set>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// ===========================================================================
// Helpers
// ===========================================================================

/// Count references matching a predicate in a BrowseResult.
template<typename Pred>
static size_t count_refs(const BrowseResult& result, Pred pred)
{
  size_t count = 0;
  for (const auto& ref : result.references())
    if (pred(ref))
      ++count;
  return count;
}

/// Find a reference in a BrowseResult by target NodeId.
static const ReferenceDescription* find_ref_by_target(const BrowseResult& result, const NodeId& targetNodeId)
{
  for (const auto& ref : result.references())
  {
    if (ref.node_id().node_id() == targetNodeId)
      return &ref;
  }
  return nullptr;
}

// ===========================================================================
// ComplianceViewLimited: server with low CP and operation limits
// ===========================================================================

class ComplianceViewLimited : public ::testing::Test
{
protected:
  void SetUp() override
  {

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;

    server::ServerConfig serverCfg;
    serverCfg.server_capabilities().maxBrowseContinuationPoints = mMaxBrowseCPs;
    serverCfg.server_capabilities().operationLimits.maxNodesPerBrowse = mMaxNodesPerBrowse;
    if (mMaxReferencesPerNode)
      serverCfg.maxReferencesPerNode = mMaxReferencesPerNode;
    if (mMaxBrowsePathWalkReferences)
      serverCfg.maxBrowsePathWalkReferences = mMaxBrowsePathWalkReferences;
    if (mMaxReferencesPerBrowseRequest)
      serverCfg.maxReferencesPerBrowseRequest = mMaxReferencesPerBrowseRequest;

    server::CreateConfig createCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};

    auto logSink = test_log_sink();
    mServer.emplace(server::Server::create(mServerThreadPool.executor(),
      std::move(createCfg),
      server::ServerComponents{.crypto = ua::test_helpers::test_crypto(),
        .authenticator = std::make_shared<AnonymousAuthenticator>(),
        .roleConfiguration = RoleConfiguration::from_well_known_grants(
          {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}}),
        .logSink = logSink,
        .logLevel = LogLevel::Debug}));

    // Add test nodes before starting.
    add_test_nodes();

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListenerHandle = mServer->listen_sync(std::move(bind), {});

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, endpoint);

    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListenerHandle);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::test_utils::create_test_client_config(),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = logSink, .logLevel = LogLevel::Debug}));

    mChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceViewLimited"}));
    mSession->activate_sync();
  }

  void add_test_nodes()
  {
    auto addressSpace = mServer->address_space();
    mTestNamespace = default_ns::Namespace::create("urn:test:view-limited", mServerThreadPool.executor());
    mTestNamespaceIndex = addressSpace.add_namespace_sync(mTestNamespace);

    // This fixture stands up its own server instead of deriving from ComplianceBase, so the grant
    // ComplianceBase performs in its SetUp never runs here. A namespace that declares no permissions
    // publishes an ENGAGED, EMPTY default and refuses every undecorated node it owns, which surfaces as
    // BadUserAccessDenied on nodes this fixture itself just created. The helper skips any namespace that
    // already declares permissions, so it cannot grant away a subject under test.
    grant_fixture_namespace_permissions(addressSpace);

    // Parent folder with many children to force continuation points.
    mParentId = NodeId{mTestNamespaceIndex, uint32_t{5000}};
    auto parentNode = addressSpace.create_node_sync(mParentId, NodeClass::Object);
    auto parent = parentNode.as<ObjectAccessor>();
    ASSERT_TRUE(parent.has_value());
    parent->set_browse_name(QualifiedName{mTestNamespaceIndex, "CPTestParent"});
    parent->set_display_name(LocalizedText{"", "CPTestParent"});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mParentId);

    // Create children under parent.
    for (uint32_t i = 0; i < mChildCount; ++i)
    {
      auto childId = NodeId{mTestNamespaceIndex, uint32_t{5100 + i}};
      mChildIds.push_back(childId);
      auto childNode = addressSpace.create_node_sync(childId, NodeClass::Variable);
      auto childVar = childNode.as<VariableAccessor>();
      ASSERT_TRUE(childVar.has_value());
      auto name = "CPChild" + std::to_string(i);
      childVar->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
      childVar->set_display_name(LocalizedText{"", name});
      childVar->set_data_type(NodeId{DataTypeId::Int32});
      childVar->write_value_sync(int32_t{static_cast<int32_t>(i)});
      childVar->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
      parentNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, childId);
    }
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mClient.reset();
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");
  }

  uint16_t mMaxBrowseCPs{1};
  std::optional<uint32_t> mMaxNodesPerBrowse{2};
  // nullopt = leave the server default (10000); a derived fixture sets it to exercise the clamp.
  std::optional<uint32_t> mMaxReferencesPerNode{std::nullopt};
  // nullopt = leave the server default (1000000); a derived fixture sets it to exercise the request budget.
  std::optional<uint32_t> mMaxReferencesPerBrowseRequest{std::nullopt};
  // nullopt = leave the server default (100000); a derived fixture sets it to exercise the walk budget.
  std::optional<uint32_t> mMaxBrowsePathWalkReferences{std::nullopt};
  uint32_t mChildCount{5};

  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::optional<server::Server> mServer;
  server::ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;

  std::shared_ptr<default_ns::Namespace> mTestNamespace;
  uint16_t mTestNamespaceIndex{0};
  NodeId mParentId;
  std::vector<NodeId> mChildIds;
};

// ===========================================================================
// Browse tests (VIEW-BRW-*)
// ===========================================================================

// Requirement: SVR-VIEW-BRW-001 (SHALL)
// If a view is provided, the nodeId of the node to be browsed shall be included in that View.
// Spec: Part 4, section 5.8.2.2 (Table 34), line 2975
//
// We submit a Browse with a non-null ViewDescription whose viewId refers to a non-existent view.
// The server shall reject with BadViewIdUnknown (Table 35).
// @relation(SVR-VIEW-BRW-001, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BRW_001_ViewFilterEnforced)
{
  // Set a view that does not exist.
  auto result = mSession->view().try_browse_sync(
    BrowseRequestBuilder().browse(mTestFolderId).view(NodeId{mTestNamespaceIndex, uint32_t{99998}}));
  if (result.is_good())
  {
    // Service succeeded - check if the per-operation result rejects the view.
    // Or the service-level header has the error.
    auto serviceStatus = result.value().response_header().service_result();
    if (serviceStatus.is_good())
    {
      ASSERT_EQ(result.value().results().size(), 1u);
      EXPECT_THAT(result.value().results()[0], HasStatus(Status::BadViewIdUnknown))
        << "Non-existent view shall be rejected with BadViewIdUnknown";
    }
    else
    {
      EXPECT_EQ(serviceStatus, StatusCode{Status::BadViewIdUnknown})
        << "Non-existent view shall be rejected with BadViewIdUnknown";
    }
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadViewIdUnknown})
      << "Non-existent view shall be rejected with BadViewIdUnknown";
  }
}

// Requirement: SVR-VIEW-BRW-004 (SHALL implicit)
// Empty referenceTypeId -> all references returned.
// Spec: Part 4, section 5.8.2.2, lines 2985-2986
// @relation(SVR-VIEW-BRW-004, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BRW_004_NoRefTypeReturnsAll)
{
  // Browse TestFolder with no referenceTypeId filter and BrowseDirection::Both.
  // "All References" means both forward AND inverse references.
  auto resp = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(mTestFolderId).direction(BrowseDirection::Both));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  // TestFolder has:
  //   Forward: HasComponent -> TestMethod + 3 vars; Organizes -> 2 objects = 6
  //   Inverse: Organizes <- ObjectsFolder = at least 1
  // We must see both forward and inverse results to confirm "all references" are returned.
  bool hasForward = false, hasInverse = false;
  size_t hasComponentCount = 0, organizesCount = 0;
  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.is_forward())
    {
      hasForward = true;
      if (ref.reference_type_id() == NodeId{ReferenceTypeId::HasComponent})
        ++hasComponentCount;
      else if (ref.reference_type_id() == NodeId{ReferenceTypeId::Organizes})
        ++organizesCount;
    }
    else
    {
      hasInverse = true;
    }
  }
  EXPECT_TRUE(hasForward) << "No referenceTypeId filter should return forward references";
  EXPECT_TRUE(hasInverse) << "No referenceTypeId filter with Both direction should return inverse references";
  EXPECT_GE(hasComponentCount, 4u) << "Should include HasComponent references (TestMethod + 3 vars)";
  EXPECT_GE(organizesCount, 2u) << "Should include Organizes references (2 objects)";
}

// Requirement: SVR-VIEW-BRW-004 (SHALL implicit)
// No referenceTypeId -> includeSubtypes ignored.
// Spec: Part 4, section 5.8.2.2, lines 2985-2986
// @relation(SVR-VIEW-BRW-004, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BRW_004_IncludeSubtypesIgnoredWhenNoRefType)
{
  // Browse with empty refTypeId, includeSubtypes=false -> should still return all refs.
  auto resp1 =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).include_subtypes(false));
  ASSERT_EQ(resp1.results().size(), 1u);

  auto resp2 =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).include_subtypes(true));
  ASSERT_EQ(resp2.results().size(), 1u);

  // Both should return the same number of references.
  EXPECT_EQ(resp1.results()[0].references().size(), resp2.results()[0].references().size())
    << "includeSubtypes should be ignored when referenceTypeId is empty";
}

// Requirement: SVR-VIEW-BRW-005 (SHALL implicit)
// nodeClassMask=0 -> all NodeClasses returned.
// Spec: Part 4, section 5.8.2.2, line 3003
// @relation(SVR-VIEW-BRW-005, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BRW_005_NodeClassMaskZeroReturnsAll)
{
  // Browse TestFolder forward with mask=0 -> all classes.
  auto resp = mSession->view().browse_sync(browse(mTestFolderId));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  // Should include Method, Variable, and Object children.
  bool hasMethod = false, hasVariable = false, hasObject = false;
  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.node_class() == NodeClass::Method)
      hasMethod = true;
    else if (ref.node_class() == NodeClass::Variable)
      hasVariable = true;
    else if (ref.node_class() == NodeClass::Object)
      hasObject = true;
  }
  EXPECT_TRUE(hasMethod) << "mask=0 should include Method nodes";
  EXPECT_TRUE(hasVariable) << "mask=0 should include Variable nodes";
  EXPECT_TRUE(hasObject) << "mask=0 should include Object nodes";
}

// Requirement: SVR-VIEW-BRW-005 (SHALL implicit)
// Specific nodeClassMask -> only matching node classes.
// Spec: Part 4, section 5.8.2.2, line 3003
// @relation(SVR-VIEW-BRW-005, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BRW_005_NodeClassMaskFilters)
{
  // Browse TestFolder with mask = Variable only.
  uint32_t variableMask = static_cast<uint32_t>(NodeClass::Variable);
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).node_class_mask(variableMask));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  // All returned references should be Variable class only.
  for (const auto& ref : resp.results()[0].references())
  {
    EXPECT_EQ(ref.node_class(), NodeClass::Variable)
      << "Variable-only mask should not return " << to_string(ref.node_class());
  }
  // Should have at least the 3 BrowseChildVar nodes.
  EXPECT_GE(resp.results()[0].references().size(), 3u);
}

// Requirement: SVR-VIEW-BRW-006 (SHALL implicit)
// Results array size matches nodesToBrowse size.
// Spec: Part 4, section 5.8.2.2, lines 3020-3021
// @relation(SVR-VIEW-BRW-006, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BRW_006_ResultsSizeMatchesRequest)
{
  auto resp = mSession->view().browse_sync(BrowseRequestBuilder()
                                             .browse(mTestFolderId)
                                             .browse(NodeId{ObjectId::ObjectsFolder})
                                             .browse(mWritableVariableId));
  EXPECT_EQ(resp.results().size(), 3u);
}

// Requirement: SVR-VIEW-BRW-006 (SHALL implicit)
// Results order matches nodesToBrowse order.
// Spec: Part 4, section 5.8.2.2, lines 3020-3021
// @verifies CL-VIEW-004
// @relation(CL-VIEW-004, SVR-VIEW-BRW-006, scope=function)
// @relation(AC-SVR-VIEW-BRW-006-RESULTS-POSITIONAL, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BRW_006_ResultsOrderMatchesRequest)
{
  // Browse: TestFolder (has children), a non-existent node (should fail), ObjectsFolder.
  NodeId nonExistent{mTestNamespaceIndex, uint32_t{99999}};
  auto resp = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(mTestFolderId).browse(nonExistent).browse(NodeId{ObjectId::ObjectsFolder}));
  ASSERT_EQ(resp.results().size(), 3u);

  // First result: TestFolder should succeed and have children.
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_FALSE(resp.results()[0].references().empty());
  EXPECT_NE(find_ref_by_target(resp.results()[0], mTestMethodId), nullptr);
  EXPECT_EQ(find_ref_by_target(resp.results()[0], mTestFolderId), nullptr);

  // Second result: non-existent node should fail.
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadNodeIdUnknown));

  // Third result: ObjectsFolder should succeed.
  EXPECT_THAT(resp.results()[2], Good());
  EXPECT_FALSE(resp.results()[2].references().empty());
  EXPECT_NE(find_ref_by_target(resp.results()[2], mTestFolderId), nullptr);
  EXPECT_NE(find_ref_by_target(resp.results()[2], mWritableVariableId), nullptr);
}

// Requirement: SVR-VIEW-BRW-007 (SHALL implicit)
// No diagnostics requested -> empty diagnosticInfos.
// Spec: Part 4, section 5.8.2.2, lines 3025-3027
// @relation(SVR-VIEW-BRW-007, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BRW_007_DiagnosticsEmptyWhenNotRequested)
{
  // Default request header has no diagnostics requested.
  auto resp = mSession->view().browse_sync(browse(mTestFolderId));
  EXPECT_TRUE(resp.diagnostic_infos().empty()) << "diagnosticInfos should be empty when not requested";
}

// Functional: Browse Objects folder forward -> finds children.
TEST_F(ComplianceWithNodes, BrowseForward_ObjectsFolder)
{
  auto resp = mSession->view().browse_sync(browse(NodeId{ObjectId::ObjectsFolder}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_FALSE(resp.results()[0].references().empty()) << "ObjectsFolder should have forward references";
}

// Functional: Browse child node inverse -> finds parent.
TEST_F(ComplianceWithNodes, BrowseInverse_ChildToParent)
{
  // Browse TestFolder inverse -> should find ObjectsFolder as parent.
  auto resp = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(mTestFolderId).direction(BrowseDirection::Inverse));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  auto* parentRef = find_ref_by_target(resp.results()[0], NodeId{ObjectId::ObjectsFolder});
  EXPECT_NE(parentRef, nullptr) << "Inverse browse from TestFolder should find ObjectsFolder";
}

// Functional: BrowseDirection::Both returns forward and inverse refs.
TEST_F(ComplianceWithNodes, BrowseBothDirections)
{
  auto resp = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(mTestFolderId).direction(BrowseDirection::Both));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  bool hasForward = false, hasInverse = false;
  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.is_forward())
      hasForward = true;
    else
      hasInverse = true;
  }
  EXPECT_TRUE(hasForward) << "Both direction should include forward refs";
  EXPECT_TRUE(hasInverse) << "Both direction should include inverse refs";
}

// Functional: Filter by Organizes reference type.
TEST_F(ComplianceWithNodes, BrowseWithRefTypeFilter_Organizes)
{
  // Browse TestFolder forward, filter by Organizes only.
  auto resp = mSession->view().browse_sync(BrowseRequestBuilder()
                                             .browse(mTestFolderId)
                                             .reference_type(NodeId{ReferenceTypeId::Organizes})
                                             .include_subtypes(false));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  // All returned refs should be Organizes type.
  for (const auto& ref : resp.results()[0].references())
  {
    EXPECT_EQ(ref.reference_type_id(), NodeId{ReferenceTypeId::Organizes})
      << "Filter by Organizes should only return Organizes references";
  }
  // Should find the 2 BrowseChildObj nodes.
  EXPECT_GE(resp.results()[0].references().size(), 2u);
}

// Functional: includeSubtypes finds HierarchicalReferences subtypes.
TEST_F(ComplianceWithNodes, BrowseWithIncludeSubtypes)
{
  // Browse TestFolder with HierarchicalReferences + includeSubtypes=true.
  // Should find children via both HasComponent and Organizes (both are subtypes).
  auto resp = mSession->view().browse_sync(BrowseRequestBuilder()
                                             .browse(mTestFolderId)
                                             .reference_type(NodeId{ReferenceTypeId::HierarchicalReferences})
                                             .include_subtypes(true));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  // Should find all 6 children (1 method + 3 vars via HasComponent + 2 objects via Organizes).
  EXPECT_GE(resp.results()[0].references().size(), 6u)
    << "includeSubtypes=true on HierarchicalReferences should find all hierarchical children";
}

// Functional: includeSubtypes=false -> only exact type match.
TEST_F(ComplianceWithNodes, BrowseWithoutIncludeSubtypes)
{
  // Browse TestFolder with HierarchicalReferences + includeSubtypes=false.
  // HierarchicalReferences is abstract; no direct references of exactly this type should exist.
  auto resp = mSession->view().browse_sync(BrowseRequestBuilder()
                                             .browse(mTestFolderId)
                                             .reference_type(NodeId{ReferenceTypeId::HierarchicalReferences})
                                             .include_subtypes(false));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  // HierarchicalReferences is abstract - no concrete references of exactly that type should exist.
  // includeSubtypes=false means only exact type matches; abstract types have no instances.
  EXPECT_EQ(resp.results()[0].references().size(), 0u)
    << "includeSubtypes=false on abstract HierarchicalReferences should return zero results";
}

// Functional: Filter by Variable node class only.
TEST_F(ComplianceWithNodes, BrowseNodeClassMaskVariable)
{
  uint32_t variableMask = static_cast<uint32_t>(NodeClass::Variable);
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).node_class_mask(variableMask));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  for (const auto& ref : resp.results()[0].references())
  {
    EXPECT_EQ(ref.node_class(), NodeClass::Variable);
  }
}

// Functional: Filter by Object node class only.
TEST_F(ComplianceWithNodes, BrowseNodeClassMaskObject)
{
  uint32_t objectMask = static_cast<uint32_t>(NodeClass::Object);
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).node_class_mask(objectMask));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  for (const auto& ref : resp.results()[0].references())
  {
    EXPECT_EQ(ref.node_class(), NodeClass::Object);
  }
  // Should find the 2 BrowseChildObj nodes.
  EXPECT_GE(resp.results()[0].references().size(), 2u);
}

// Functional (negative): Browse non-existent node -> BadNodeIdUnknown.
// @verifies CL-VIEW-004
// @relation(CL-VIEW-004, SVR-VIEW-BRW-009, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, BrowseUnknownNode)
{
  NodeId nonExistent{mTestNamespaceIndex, uint32_t{99999}};
  auto resp = mSession->view().browse_sync(browse(nonExistent));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdUnknown));
}

// Functional (negative): Empty nodesToBrowse -> BadNothingToDo.
// Spec: Part 4, Table 177 - Common service-level result codes.
// @relation(SVR-VIEW-BRW-008, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, BrowseEmptyList)
{
  BrowseRequest req;
  // Leave nodes_to_browse empty.
  auto result = mSession->view().try_browse_sync(std::move(req));
  // BadNothingToDo shall be returned when the list is empty.
  // It may surface as a service-level fault or in the response header.
  if (result.is_good())
  {
    EXPECT_THAT(result.value(), ServiceResultIs(StatusCode{Status::BadNothingToDo}))
      << "Empty nodesToBrowse shall return BadNothingToDo";
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo})
      << "Empty nodesToBrowse shall return BadNothingToDo";
  }
}

// Functional (negative): Exceed MaxNodesPerBrowse -> BadTooManyOperations.
TEST_F(ComplianceViewLimited, BrowseTooManyOperations)
{
  // mMaxNodesPerBrowse = 2, send 3 nodes.
  auto result = mSession->view().try_browse_sync(
    BrowseRequestBuilder().browse(mParentId).browse(mParentId).browse(mParentId));
  if (result.is_good())
  {
    EXPECT_THAT(result.value(), ServiceResultIs(StatusCode{Status::BadTooManyOperations}));
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadTooManyOperations});
  }
}

// ===========================================================================
// BrowseNext tests (VIEW-BNX-*)
// ===========================================================================

// A BrowseNext with a malformed continuation point (not a 16-byte Guid) must be
// rejected with Bad_ContinuationPointInvalid and must NEVER crash the server.
// retrieve_continuation_points() decoded the CP Guid via from_ua_binary with no
// exception barrier, running in an async browse flow on a pool thread - so a single
// malformed BrowseNext threw Bad_DecodingError straight out to asio's thread
// function and std::terminate'd the whole server (found via UACTT View Minimum
// Continuation Point, which crashed the SUT mid-sweep).
TEST_F(ComplianceWithNodes, VIEW_BNX_MalformedContinuationPointRejectedNotCrash)
{
  ContinuationPoint badCp{std::vector<uint8_t>{1, 2, 3}};  // 3 bytes - not a 16-byte Guid
  auto result = mSession->view().try_browse_next_sync(browse_next(badCp, /*release=*/false));
  ASSERT_TRUE(result.is_good()) << "service-level result should be Good; the error is per-item";
  ASSERT_FALSE(result.value().results().empty());
  EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{Status::BadContinuationPointInvalid});

  // The server must still be serving after the malformed request.
  auto browseResp = mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId));
  EXPECT_THAT(browseResp, ServiceResultIsGood());
}

// Requirement: SVR-VIEW-BNX-001 (SHALL)
// BrowseNext shall be submitted on the same Session that was used to submit the Browse.
// Spec: Part 4, section 5.8.3.1, lines 3067-3068
// @relation(SVR-ATTR-CP-006, SVR-VIEW-BNX-001, SVR-VIEW-BNX-008, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BNX_001_SameSessionRequired)
{
  // Get a CP in the current session.
  auto browseResp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(1));
  ASSERT_EQ(browseResp.results().size(), 1u);
  ASSERT_FALSE(browseResp.results()[0].continuation_point().empty())
    << "Need a continuation point to test cross-session rejection";

  auto cp = browseResp.results()[0].continuation_point();

  // Open a second session on the same channel.
  auto session2 = mChannel->create_session_sync({.sessionName = "ComplianceTest2"});
  session2.activate_sync();

  // Try to use the CP from session 1 in session 2.
  auto nextResult = session2.view().try_browse_next_sync(browse_next(cp, /*release=*/false));
  if (nextResult.is_good())
  {
    ASSERT_EQ(nextResult.value().results().size(), 1u);
    EXPECT_THAT(nextResult.value().results()[0], HasStatus(Status::BadContinuationPointInvalid))
      << "CP from another session shall be rejected";
  }
  else
  {
    // Service-level rejection is also valid.
    EXPECT_EQ(nextResult.status_code(), StatusCode{Status::BadContinuationPointInvalid})
      << "CP from another session shall be rejected";
  }

  session2.close_sync();

  // Release the original CP in the correct session.
  mSession->view().browse_next_sync(browse_next(cp, /*release=*/true));
}

// Requirement: SVR-VIEW-BNX-002 (SHALL)
// releaseContinuationPoints=true -> CP released, results empty.
// Spec: Part 4, section 5.8.3.2, lines 3081-3083
// @relation(SVR-ATTR-CP-006, SVR-VIEW-BNX-002, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BNX_002_ReleaseContinuationPoints)
{
  // Browse TestFolder with maxResultsPerNode=1 to get a CP.
  auto browseResp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(1));
  ASSERT_EQ(browseResp.results().size(), 1u);
  EXPECT_THAT(browseResp.results()[0], Good());
  ASSERT_FALSE(browseResp.results()[0].continuation_point().empty())
    << "maxResultsPerNode=1 on TestFolder should produce a continuation point";

  // Release the CP.
  auto nextResp = mSession->view().browse_next_sync(
    browse_next(browseResp.results()[0].continuation_point(), /*release=*/true));
  EXPECT_TRUE(nextResp.response_header().service_result().is_good());
  EXPECT_TRUE(nextResp.results().empty());
  EXPECT_TRUE(nextResp.diagnostic_infos().empty());
}

// Requirement: SVR-VIEW-BNX-003 (SHALL)
// releaseContinuationPoints=false -> next batch of results.
// Spec: Part 4, section 5.8.3.2, lines 3084-3085
// @relation(SVR-ATTR-CP-006, SVR-VIEW-BNX-003, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BNX_003_ContinueReturnsNextBatch)
{
  // Browse TestFolder with maxResultsPerNode=1.
  auto browseResp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(1));
  ASSERT_EQ(browseResp.results().size(), 1u);
  ASSERT_EQ(browseResp.results()[0].references().size(), 1u);
  ASSERT_FALSE(browseResp.results()[0].continuation_point().empty());

  // Continue with the CP.
  auto nextResp = mSession->view().browse_next_sync(
    browse_next(browseResp.results()[0].continuation_point(), /*release=*/false));
  ASSERT_EQ(nextResp.results().size(), 1u);
  EXPECT_THAT(nextResp.results()[0], Good());
  EXPECT_FALSE(nextResp.results()[0].references().empty())
    << "Continue CP should return next batch of results";
}

// Regression (CTT View Minimum Continuation Point 01/05): a paged Browse followed by BrowseNext until
// the continuation point is exhausted must yield EVERY reference exactly once, in the same order as an
// unpaginated Browse - none skipped at a page boundary - for ANY maxReferencesPerNode.
//
// mTestFolderId carries an inverse Organizes reference (back to ObjectsFolder) interleaved among its
// forward references. A Forward browse filters that inverse reference out, so the namespace's
// offset-based page boundary no longer aligns with the maxReferencesPerNode cap: the cap falls in the
// MIDDLE of a namespace page. The service used to emit a continuation point carrying the namespace
// page-end token (which points past the unprocessed tail of that page), silently dropping
// maxReferencesPerNode-1 references at every page boundary - and dropping the whole tail when the cap
// fell on the last namespace page (empty token). The continuation point now buffers the unprocessed
// page tail and BrowseNext replays it before resuming the namespace token. The original F39 case
// (maxReferencesPerNode=1) never triggered this because a 1-reference page boundary always aligns;
// hence the sweep over page sizes 1..N+1 below.
TEST_F(ComplianceWithNodes, VIEW_BNX_PagedBrowseVisitsEveryReferenceExactlyOnce)
{
  // Unpaginated browse = the expected reference sequence.
  auto full = mSession->view().browse_sync(browse(mTestFolderId));
  ASSERT_EQ(full.results().size(), 1u);
  EXPECT_THAT(full.results()[0], Good());
  std::vector<NodeId> expected;
  for (const auto& ref : full.results()[0].references())
    expected.push_back(ref.node_id().node_id());
  ASSERT_GE(expected.size(), 3u) << "need several references to exercise pagination across pages";

  for (int32_t maxRefs = 1; maxRefs <= static_cast<int32_t>(expected.size()) + 1; ++maxRefs)
  {
    std::vector<NodeId> paged;
    auto collect = [&paged](const BrowseResult& result) -> ByteString
    {
      for (const auto& ref : result.references())
        paged.push_back(ref.node_id().node_id());
      return result.continuation_point();
    };

    auto resp = mSession->view().browse_sync(
      BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(maxRefs));
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], Good());
    EXPECT_LE(resp.results()[0].references().size(), static_cast<size_t>(maxRefs))
      << "maxReferencesPerNode=" << maxRefs << " must be honoured per page";
    ByteString cp = collect(resp.results()[0]);

    for (size_t guard = 0; !cp.empty() && guard < expected.size() + 5; ++guard)
    {
      auto next = mSession->view().browse_next_sync(browse_next(cp, /*release=*/false));
      ASSERT_EQ(next.results().size(), 1u);
      EXPECT_THAT(next.results()[0], Good());
      EXPECT_LE(next.results()[0].references().size(), static_cast<size_t>(maxRefs))
        << "maxReferencesPerNode=" << maxRefs << " must be honoured per BrowseNext page";
      cp = collect(next.results()[0]);
    }

    EXPECT_TRUE(cp.empty()) << "pagination must terminate at maxReferencesPerNode=" << maxRefs;
    EXPECT_EQ(paged, expected) << "paged Browse (maxReferencesPerNode=" << maxRefs
                               << ") must visit every reference exactly once, in browse order";
  }
}

// Requirement: SVR-VIEW-BNX-004 (SHALL)
// Client releases an unwanted continuation point; release arrays are empty.
// Spec: Part 4, section 5.8.3.2, lines 3086-3089
// @relation(SVR-VIEW-BNX-004, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BNX_004_ClientReleasesUnwantedCP)
{
  // Get a CP.
  auto browseResp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(1));
  ASSERT_EQ(browseResp.results().size(), 1u);
  ASSERT_FALSE(browseResp.results()[0].continuation_point().empty());

  // Release it immediately.
  auto nextResp = mSession->view().browse_next_sync(
    browse_next(browseResp.results()[0].continuation_point(), /*release=*/true));
  EXPECT_TRUE(nextResp.response_header().service_result().is_good());
  EXPECT_TRUE(nextResp.results().empty());
  EXPECT_TRUE(nextResp.diagnostic_infos().empty());
}

// Part 4 section 5.8.3.2 permits continuation points from separate origin responses in one
// BrowseNext request. Full unpaged controls establish the expected second reference for each source,
// making per-point order and independence observable through the public Session API.
// @relation(AC-SVR-VIEW-BNX-005-MIXED-RESPONSE-CONTINUATIONS, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BNX_005_MixesContinuationPointsFromSeparateBrowseResponses)
{
  const NodeId firstSource = mTestFolderId;
  const NodeId secondSource{ObjectId::ObjectsFolder};
  auto fullFirst = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(firstSource).direction(BrowseDirection::Forward));
  auto fullSecond = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(secondSource).direction(BrowseDirection::Forward));
  ASSERT_EQ(fullFirst.results().size(), 1u);
  ASSERT_EQ(fullSecond.results().size(), 1u);
  ASSERT_THAT(fullFirst.results()[0], Good());
  ASSERT_THAT(fullSecond.results()[0], Good());
  ASSERT_GE(fullFirst.results()[0].references().size(), 2u);
  ASSERT_GE(fullSecond.results()[0].references().size(), 2u);
  const auto expectedFirst = fullFirst.results()[0].references()[1].node_id().node_id();
  const auto expectedSecond = fullSecond.results()[0].references()[1].node_id().node_id();
  ASSERT_NE(expectedFirst, expectedSecond) << "the two source controls must make cross-wiring observable";

  auto firstPage = mSession->view().browse_sync(BrowseRequestBuilder()
                                                  .browse(firstSource)
                                                  .direction(BrowseDirection::Forward)
                                                  .max_references_per_node(1));
  auto secondPage = mSession->view().browse_sync(BrowseRequestBuilder()
                                                   .browse(secondSource)
                                                   .direction(BrowseDirection::Forward)
                                                   .max_references_per_node(1));
  ASSERT_EQ(firstPage.results().size(), 1u);
  ASSERT_EQ(secondPage.results().size(), 1u);
  ASSERT_THAT(firstPage.results()[0], Good());
  ASSERT_THAT(secondPage.results()[0], Good());
  ASSERT_EQ(firstPage.results()[0].references().size(), 1u);
  ASSERT_EQ(secondPage.results()[0].references().size(), 1u);
  ASSERT_EQ(firstPage.results()[0].references()[0].node_id().node_id(),
    fullFirst.results()[0].references()[0].node_id().node_id());
  ASSERT_EQ(secondPage.results()[0].references()[0].node_id().node_id(),
    fullSecond.results()[0].references()[0].node_id().node_id());
  ASSERT_FALSE(firstPage.results()[0].continuation_point().empty());
  ASSERT_FALSE(secondPage.results()[0].continuation_point().empty());
  ASSERT_NE(firstPage.results()[0].continuation_point(), secondPage.results()[0].continuation_point());

  BrowseNextRequest mixedRequest;
  mixedRequest.release_continuation_points() = false;
  mixedRequest.continuation_points().push_back(firstPage.results()[0].continuation_point());
  mixedRequest.continuation_points().push_back(secondPage.results()[0].continuation_point());
  auto mixedResponse = mSession->view().browse_next_sync(std::move(mixedRequest));
  ASSERT_EQ(mixedResponse.results().size(), 2u);
  ASSERT_THAT(mixedResponse.results()[0], Good());
  ASSERT_THAT(mixedResponse.results()[1], Good());
  ASSERT_EQ(mixedResponse.results()[0].references().size(), 1u);
  ASSERT_EQ(mixedResponse.results()[1].references().size(), 1u);
  EXPECT_EQ(mixedResponse.results()[0].references()[0].node_id().node_id(), expectedFirst);
  EXPECT_EQ(mixedResponse.results()[1].references()[0].node_id().node_id(), expectedSecond);

  BrowseNextRequest releaseRequest;
  releaseRequest.release_continuation_points() = true;
  for (const auto& result : mixedResponse.results())
  {
    if (!result.continuation_point().empty())
      releaseRequest.continuation_points().push_back(result.continuation_point());
  }
  if (!releaseRequest.continuation_points().empty())
  {
    auto releaseResponse = mSession->view().browse_next_sync(std::move(releaseRequest));
    EXPECT_TRUE(releaseResponse.response_header().service_result().is_good());
    EXPECT_TRUE(releaseResponse.results().empty());
    EXPECT_TRUE(releaseResponse.diagnostic_infos().empty());
  }
}

// Requirement: SVR-VIEW-BNX-006 (SHALL implicit)
// Results count matches continuationPoints count.
// Spec: Part 4, section 5.8.3.2, lines 3104-3105
// @relation(AC-SVR-VIEW-BNX-005-MIXED-RESPONSE-CONTINUATIONS, scope=function)
// @relation(SVR-VIEW-BNX-006, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_BNX_006_ResultsSizeMatchesCPs)
{
  // Get two CPs by browsing two nodes with maxResultsPerNode=1.
  auto browseResp = mSession->view().browse_sync(BrowseRequestBuilder()
                                                   .browse(mTestFolderId)
                                                   .browse(NodeId{ObjectId::ObjectsFolder})
                                                   .max_references_per_node(1));
  ASSERT_EQ(browseResp.results().size(), 2u);

  // Collect CPs.
  BrowseNextRequest nextReq;
  nextReq.release_continuation_points() = false;
  size_t cpCount = 0;
  for (const auto& result : browseResp.results())
  {
    ASSERT_FALSE(result.continuation_point().empty());
    nextReq.continuation_points().push_back(result.continuation_point());
    ++cpCount;
  }
  ASSERT_EQ(cpCount, 2u);

  auto nextResp = mSession->view().browse_next_sync(std::move(nextReq));
  ASSERT_EQ(nextResp.results().size(), cpCount);
  for (const auto& result : nextResp.results())
    EXPECT_THAT(result, Good());
}

// Functional (negative): Invalid continuation point -> BadContinuationPointInvalid.
// Per Part 4 Table 38, BadContinuationPointInvalid is an operation-level status code
// on the BrowseResult, not a service-level error.
// @verifies CL-VIEW-004
// @relation(SVR-ATTR-CP-006, CL-VIEW-004, SVR-VIEW-BNX-008, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, BrowseNextInvalidCP)
{
  // Fabricate an invalid CP.
  ByteString invalidCp;
  invalidCp.resize(16);
  for (size_t i = 0; i < 16; ++i)
    invalidCp[i] = static_cast<uint8_t>(i);
  auto result = mSession->view().try_browse_next_sync(browse_next(std::move(invalidCp), /*release=*/false));
  // The server should return a response (not a service fault) with per-operation status.
  ASSERT_THAT(result, Good())
    << "BrowseNext with invalid CP should return a response, not a service fault. Got: 0x" << std::hex
    << result.status_code().as_uint32();
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_THAT(result.value().results()[0], HasStatus(Status::BadContinuationPointInvalid));
}

// Functional (negative): Empty continuationPoints -> BadNothingToDo.
// @relation(SVR-VIEW-BNX-007, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, BrowseNextEmptyList)
{
  BrowseNextRequest nextReq;
  // Leave continuation_points empty.
  auto result = mSession->view().try_browse_next_sync(std::move(nextReq));
  if (result.is_good())
  {
    EXPECT_THAT(result.value(), ServiceResultIs(StatusCode{Status::BadNothingToDo}));
  }
  else
  {
    EXPECT_EQ(result.status_code(), StatusCode{Status::BadNothingToDo});
  }
}

// ===========================================================================
// ContinuationPoint tests (VIEW-CPT-*)
// ===========================================================================

// Requirement: SVR-VIEW-CPT-001 (SHALL)
// maxResultsPerNode limits results, returns CP.
// Spec: Part 4, section 7.9, lines 8385-8386
// Covers SVR-ATTR-CP-001 (coverage-audit retag).
// @relation(SVR-ATTR-CP-006, SVR-VIEW-CPT-001, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_CPT_001_MaxResultsPerNodeEnforced)
{
  // Browse TestFolder with maxResultsPerNode=2 (has 6 children).
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(2));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_LE(resp.results()[0].references().size(), 2u)
    << "Server should not return more than maxResultsPerNode references";
  EXPECT_FALSE(resp.results()[0].continuation_point().empty())
    << "With more refs than maxResultsPerNode, server should return a CP";

  // Clean up the CP.
  mSession->view().browse_next_sync(browse_next(resp.results()[0].continuation_point(), /*release=*/true));
}

// Requirement: SVR-VIEW-CPT-001 (SHALL)
// maxResultsPerNode=0 -> no limit, all results returned.
// Spec: Part 4, section 7.9, lines 8385-8386
// @relation(SVR-VIEW-CPT-001, scope=function)
TEST_F(ComplianceWithNodes, VIEW_CPT_001_MaxResultsPerNodeZeroUnlimited)
{
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(0));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  // Should return all 6 children (or more if server adds additional refs).
  EXPECT_GE(resp.results()[0].references().size(), 6u) << "maxResultsPerNode=0 should return all references";
  // No CP should be needed.
  EXPECT_TRUE(resp.results()[0].continuation_point().empty())
    << "All results returned -> no continuation point needed";
}

// Requirement: SVR-VIEW-CPT-002 (SHALL)
// Servers shall support at least one CP per session.
// Spec: Part 4, section 7.9, line 8388
// @relation(SVR-ATTR-CP-006, SVR-VIEW-CPT-002, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_CPT_002_AtLeastOneCPPerSession)
{
  // Browse with maxResultsPerNode=1 -> should get a CP.
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(1));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_FALSE(resp.results()[0].continuation_point().empty())
    << "Server must support at least one continuation point per session";

  // Continue the CP to verify it works.
  auto nextResp =
    mSession->view().browse_next_sync(browse_next(resp.results()[0].continuation_point(), /*release=*/false));
  ASSERT_EQ(nextResp.results().size(), 1u);
  EXPECT_THAT(nextResp.results()[0], Good());

  // Release any remaining CP.
  if (!nextResp.results()[0].continuation_point().empty())
  {
    mSession->view().browse_next_sync(
      browse_next(nextResp.results()[0].continuation_point(), /*release=*/true));
  }
}

// Requirement: SVR-VIEW-CPT-003 (SHALL)
// New request auto-frees CPs from prior requests.
// Spec: Part 4, section 7.9, lines 8391-8393
// @relation(SVR-VIEW-CPT-003, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceViewLimited, VIEW_CPT_003_AutoFreeOldCPs)
{
  // With mMaxBrowseCPs=1, browse to get a CP.
  auto resp1 =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mParentId).max_references_per_node(1));
  ASSERT_EQ(resp1.results().size(), 1u);
  EXPECT_THAT(resp1.results()[0], Good());

  ASSERT_FALSE(resp1.results()[0].continuation_point().empty())
    << "the server returned no continuation point for a node with more references than "
       "maxReferencesPerNode=1, so there is no CP to auto-free";

  auto oldCp = resp1.results()[0].continuation_point();

  // Issue another browse - server should auto-free the old CP.
  auto resp2 =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mParentId).max_references_per_node(1));
  ASSERT_EQ(resp2.results().size(), 1u);
  EXPECT_THAT(resp2.results()[0], Good());

  // Try to use the old CP - should fail with operation-level BadContinuationPointInvalid.
  // The spec requires auto-free, so the old CP is no longer valid.
  auto nextResult = mSession->view().try_browse_next_sync(browse_next(oldCp, /*release=*/false));
  // The server should return an operation-level result, not a service fault.
  ASSERT_THAT(nextResult, Good())
    << "BrowseNext with a freed CP should return a response (not a service fault). Got: 0x" << std::hex
    << nextResult.status_code().as_uint32();
  ASSERT_EQ(nextResult.value().results().size(), 1u);
  EXPECT_THAT(nextResult.value().results()[0], HasStatus(Status::BadContinuationPointInvalid))
    << "Old CP should be auto-freed when server needs it for a new request";

  // Clean up the new CP.
  if (!resp2.results()[0].continuation_point().empty())
  {
    mSession->view().browse_next_sync(browse_next(resp2.results()[0].continuation_point(), /*release=*/true));
  }
}

// Requirement: SVR-VIEW-CPT-005 (SHALL)
// Exceed max CPs -> BadNoContinuationPoints for remaining.
// Spec: Part 4, section 7.9, lines 8401-8403
// clang-format off
// @relation(SVR-ATTR-CP-005, SVR-ATTR-CP-006, SVR-VIEW-BRW-009, SVR-VIEW-CPT-005, SVR-VIEW-URG-002, scope=function)
// clang-format on
// @relation(AC-SVR-VIEW-CPT-005-NOCONTINUATIONPOINTS, scope=function)
TEST_F(ComplianceViewLimited, VIEW_CPT_005_BadNoContinuationPoints)
{
  // With mMaxBrowseCPs=1, browse 2 nodes each needing a CP.
  // First should succeed, second should get BadNoContinuationPoints.
  auto resp = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(mParentId).browse(mParentId).max_references_per_node(1));
  ASSERT_EQ(resp.results().size(), 2u);

  // First result should succeed with a CP.
  EXPECT_THAT(resp.results()[0], Good());

  ASSERT_FALSE(resp.results()[0].continuation_point().empty())
    << "the server returned no continuation point for the first node despite maxReferencesPerNode=1, so "
       "the continuation-point limit is never reached";

  // Second result should be BadNoContinuationPoints.
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadNoContinuationPoints));
  // A Bad result's References cannot be used (Part 4 Table 180), so the refused operation returns none
  // (DL-44).
  EXPECT_TRUE(resp.results()[1].references().empty())
    << "the operation refused a continuation point still returned " << resp.results()[1].references().size()
    << " References";

  // Clean up.
  mSession->view().browse_next_sync(browse_next(resp.results()[0].continuation_point(), /*release=*/true));
}

// Requirement: SVR-VIEW-CPT-006 (SHALL)
// Continuing prior CP never returns BadNoContinuationPoints.
// Spec: Part 4, section 7.9, lines 8408-8409
// Covers SVR-ATTR-CP-006 (coverage-audit retag).
// @relation(SVR-VIEW-CPT-006, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceViewLimited, VIEW_CPT_006_ContinueNeverReturnsBadNoCP)
{
  // Get a CP by browsing with maxResultsPerNode=1.
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mParentId).max_references_per_node(1));
  ASSERT_EQ(resp.results().size(), 1u);

  ASSERT_FALSE(resp.results()[0].continuation_point().empty())
    << "the server returned no continuation point despite maxReferencesPerNode=1, so there is none to "
       "continue";

  // Continue the CP - should never get BadNoContinuationPoints.
  auto cp = resp.results()[0].continuation_point();
  while (!cp.empty())
  {
    auto nextResp = mSession->view().browse_next_sync(browse_next(cp, /*release=*/false));
    ASSERT_EQ(nextResp.results().size(), 1u);
    EXPECT_NE(nextResp.results()[0].status_code(), StatusCode{Status::BadNoContinuationPoints})
      << "Continuing a prior CP must never return BadNoContinuationPoints";
    if (!nextResp.results()[0].status_code().is_good())
      break;
    cp = nextResp.results()[0].continuation_point();
  }
}

// ===========================================================================
// ReferenceDescription tests (VIEW-RFD-*)
// ===========================================================================

// Requirement: SVR-VIEW-RFD-001 (SHALL)
// Local target node uses namespace index (not URI).
// Spec: Part 4, section 7.30, lines 9581-9582
// @relation(SVR-VIEW-RFD-001, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_RFD_001_LocalNodeReturnsNamespaceIndex)
{
  // Browse TestFolder forward -> children are local nodes.
  auto resp = mSession->view().browse_sync(browse(mTestFolderId));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  for (const auto& ref : resp.results()[0].references())
  {
    // Local nodes: server_index should be 0 and namespace_uri should be empty.
    EXPECT_EQ(ref.node_id().server_index(), 0u) << "Local node should have server_index=0";
    EXPECT_TRUE(ref.node_id().namespace_uri().empty())
      << "Local node should use namespace index, not URI. Got URI: "
      << static_cast<string_view>(ref.node_id().namespace_uri());
  }
}

// Requirement: SVR-VIEW-RFD-002 (SHALL)
// Method/ReferenceType -> typeDefinition is null.
// Spec: Part 4, section 7.30, lines 9590-9591
// @relation(SVR-VIEW-RFD-002, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_RFD_002_NonObjectVariableTypeDefNull)
{
  // Browse TestFolder forward and find the Method child (TestMethod).
  auto resp = mSession->view().browse_sync(browse(mTestFolderId));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  const ReferenceDescription* methodRef = nullptr;
  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.node_class() == NodeClass::Method)
    {
      methodRef = &ref;
      break;
    }
  }
  ASSERT_NE(methodRef, nullptr) << "TestFolder should have a Method child";
  EXPECT_TRUE(methodRef->type_definition().node_id().is_null())
    << "Method node typeDefinition should be null NodeId";
}

// Requirement: SVR-VIEW-RFD-002 (SHALL)
// Object node -> typeDefinition is non-null.
// Spec: Part 4, section 7.30, lines 9590-9591
// @relation(SVR-VIEW-RFD-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_RFD_002_ObjectHasTypeDefinition)
{
  // Browse ObjectsFolder forward - Server object should have a typeDefinition.
  auto resp = mSession->view().browse_sync(browse(NodeId{ObjectId::ObjectsFolder}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  const ReferenceDescription* objectRef = nullptr;
  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.node_class() == NodeClass::Object && ref.node_id().node_id() == NodeId{ObjectId::Server})
    {
      objectRef = &ref;
      break;
    }
  }
  ASSERT_NE(objectRef, nullptr) << "ObjectsFolder should have Server object as child";
  EXPECT_FALSE(objectRef->type_definition().node_id().is_null())
    << "Object node typeDefinition should be non-null";
}

// Requirement: SVR-VIEW-RFD-002 (SHALL)
// Variable node -> typeDefinition is non-null.
// Spec: Part 4, section 7.30, lines 9590-9591
// @relation(SVR-VIEW-RFD-002, scope=function)
TEST_F(ComplianceWithNodes, VIEW_RFD_002_VariableHasTypeDefinition)
{
  // Browse Server node forward to find a Variable child (e.g., ServerStatus).
  auto resp = mSession->view().browse_sync(browse(NodeId{ObjectId::Server}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  const ReferenceDescription* variableRef = nullptr;
  for (const auto& ref : resp.results()[0].references())
  {
    if (ref.node_class() == NodeClass::Variable)
    {
      variableRef = &ref;
      break;
    }
  }
  ASSERT_NE(variableRef, nullptr) << "Server should have Variable children";
  EXPECT_FALSE(variableRef->type_definition().node_id().is_null())
    << "Variable node typeDefinition should be non-null";
}

// ===========================================================================
// Full iteration: Browse + BrowseNext collects all references
// ===========================================================================

// @relation(SVR-ATTR-CP-006, scope=function)
TEST_F(ComplianceWithNodes, BrowseAndBrowseNextCollectsAllReferences)
{
  // Browse TestFolder with maxResultsPerNode=2, then BrowseNext until done.
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mTestFolderId).max_references_per_node(2));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  std::vector<ReferenceDescription> allRefs;
  for (const auto& ref : resp.results()[0].references())
    allRefs.push_back(ref);

  auto cp = resp.results()[0].continuation_point();
  while (!cp.empty())
  {
    auto nextResp = mSession->view().browse_next_sync(browse_next(cp, /*release=*/false));
    ASSERT_EQ(nextResp.results().size(), 1u);
    EXPECT_THAT(nextResp.results()[0], Good());
    for (const auto& ref : nextResp.results()[0].references())
      allRefs.push_back(ref);
    cp = nextResp.results()[0].continuation_point();
  }

  // TestFolder has 6 forward children: TestMethod + 3 vars + 2 objects.
  EXPECT_GE(allRefs.size(), 6u) << "Browse + BrowseNext should collect all references";
}

// Covers VIEW-BROWSE (invalid direction) (CTT View Basic 2 / TranslateBrowsePath browse negatives)
// Part 4 section 5.8.2: an out-of-range browseDirection must yield a per-operation
// Bad_BrowseDirectionInvalid, not abort the channel.
// @verifies CL-VIEW-004
// @relation(CL-VIEW-004, scope=function)
TEST_F(ComplianceWithNodes, Mirror_Browse_InvalidDirection_ReturnsBadBrowseDirectionInvalid)
{
  auto result = mSession->view().try_browse_sync(
    BrowseRequestBuilder().browse(mTestFolderId).direction(static_cast<BrowseDirection>(99)));

  ASSERT_THAT(result, Good()) << "An invalid browseDirection must not abort the channel (UACTT F11)";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadBrowseDirectionInvalid));
}

// Covers VIEW-BROWSE (invalid referenceTypeId) (CTT View Basic 2 browse negatives)
// Part 4 section 5.8.2: a referenceTypeId that is not the NodeId of a ReferenceType node must yield a
// per-operation Bad_ReferenceTypeIdInvalid.
// @verifies CL-VIEW-004
// @relation(CL-VIEW-004, scope=function)
TEST_F(ComplianceWithNodes, Mirror_Browse_InvalidReferenceTypeId_ReturnsBadReferenceTypeIdInvalid)
{
  // mWritableVariableId resolves to a Variable, not a ReferenceType.
  auto result = mSession->view().try_browse_sync(
    BrowseRequestBuilder().browse(mTestFolderId).reference_type(mWritableVariableId));

  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceTypeIdInvalid));
}

// Covers VIEW-BROWSE (unknown view) (CTT View Basic 2 view negatives)
// Part 4 section 5.8.2.2: the ViewDescription is request-wide; an unknown viewId fails the whole Browse at
// the service level with Bad_ViewIdUnknown.
// @verifies CL-VIEW-006
// @relation(CL-VIEW-006, scope=function)
TEST_F(ComplianceWithNodes, Mirror_Browse_UnknownViewId_ServiceLevelBadViewIdUnknown)
{
  auto result = mSession->view().try_browse_sync(
    BrowseRequestBuilder().browse(mTestFolderId).view(NodeId{mTestNamespaceIndex, uint32_t{0xDEAD}}));

  // The server returns a service fault Bad_ViewIdUnknown (service-level), surfaced by the client as a
  // bad Result rather than a channel abort.
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadViewIdUnknown})
    << "Unknown viewId must fail the whole Browse at the service level (UACTT F17)";
}

// Covers VIEW-BRW (no dangling references) (CTT View Basic 2/018; BuildCacheMap "Unknown NodeIds")
// The NS0 import deliberately excludes the PubSub model. A node that is excluded from import must not
// remain as the target of a forward HasSubtype reference on an imported parent (e.g. BaseObjectType),
// or Browse returns a ReferenceDescription with NodeClass=0 / null BrowseName and the CTT reports
// "Address Model is broken". This pins the invariant across the whole imported NS0 address space:
// every forward reference into NS0 resolves to a real node. Walks all forward references from the
// Root folder (the same reachability the CTT's BuildCacheMap uses).
TEST_F(ComplianceWithNodes, Mirror_Browse_NoDanglingNs0References)
{
  auto addressSpace = mServer.server().address_space();
  std::queue<NodeId> pending;
  std::set<NodeId> visited;
  pending.push(NodeId{ObjectId::RootFolder});

  std::vector<std::string> dangling;
  while (!pending.empty())
  {
    auto id = pending.front();
    pending.pop();
    if (!visited.insert(id).second)
      continue;
    auto nodeResult = addressSpace.try_find_node_sync(id);
    if (nodeResult.is_bad())
      continue;
    auto refsResult = nodeResult.value().try_get_references_sync();
    if (refsResult.is_bad())
      continue;
    for (const auto& ref : refsResult.value())
    {
      if (!ref.is_forward())
        continue;
      auto targetId = ref.target_id().node_id();
      if (targetId.namespace_index() != 0)
        continue;  // only the imported NS0 must be self-consistent
      auto targetResult = addressSpace.try_find_node_sync(targetId);
      if (targetResult.is_bad() || targetResult.value().get_node_class() == NodeClass::Unspecified)
        dangling.push_back(to_string(targetId) + " (via " + to_string(ref.type_id()) + ")");
      else
        pending.push(targetId);
    }
  }

  EXPECT_TRUE(dangling.empty()) << "Found " << dangling.size()
                                << " dangling NS0 reference target(s); first = "
                                << (dangling.empty() ? std::string{} : dangling.front());
}

// ===========================================================================
// Stage-3c #3: per-node reference page-size ceiling clamps the 0 "no Client
// limit" sentinel so the continuation-point throttle always engages.
// ===========================================================================

class ComplianceViewRefCapped : public ComplianceViewLimited
{
protected:
  ComplianceViewRefCapped()
  {
    mMaxReferencesPerNode = 2;  // server ceiling below the parent's child count (5)
  }
};

// requestedMaxReferencesPerNode == 0 means "no Client-side limit" (OPC 10000-4 5.8.2). Left unclamped
// the server would return the node's entire reference list as one page with no continuation point,
// bypassing MaxBrowseContinuationPoints and emitting an unbounded array. The ceiling must clamp it so
// only `ceiling` references come back with a continuation point for the rest. Falsifiable: without the
// clamp all children return in one page and continuation_point() is empty.
TEST_F(ComplianceViewRefCapped, VIEW_REF_ZeroRequestClampedToServerCeiling)
{
  auto resp =
    mSession->view().browse_sync(BrowseRequestBuilder().browse(mParentId).max_references_per_node(0));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::Good));
  EXPECT_LE(resp.results()[0].references().size(), 2u)
    << "a 0 (no-limit) request must be clamped to the server ceiling";
  EXPECT_FALSE(resp.results()[0].continuation_point().empty())
    << "clamping must leave a continuation point so the client can page the remaining references";
}

class ComplianceViewRequestBudget : public ComplianceViewLimited
{
protected:
  ComplianceViewRequestBudget()
  {
    mMaxBrowseCPs = 2;  // one continuation point per operation below
    mMaxReferencesPerBrowseRequest = 2;  // the request-wide budget, at its floor of MaxNodesPerBrowse (2)
  }
};

// One Browse request naming the 5-child parent twice with no client limit shares the request budget of 2:
// each operation gets a page of one reference and a continuation point, so the response holds two
// references in all; the BrowseNext naming both points shares the same budget. Falsifiable: without the
// budget each operation returns every child as one page and no continuation point.
// @verifies AC-SVR-VIEW-BRW-002-A-BROWSE-REQUEST-SHARES-ONE-REFERENCE-BUDGET
TEST_F(ComplianceViewRequestBudget, RepeatedNodesShareTheRequestReferenceBudget)
{
  auto resp = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(mParentId).browse(mParentId).max_references_per_node(0));
  ASSERT_EQ(resp.results().size(), 2u);
  for (const auto& result : resp.results())
  {
    EXPECT_THAT(result, Good());
    EXPECT_EQ(result.references().size(), 1u) << "each operation's page is the budget split over two";
    EXPECT_FALSE(result.continuation_point().empty()) << "the rest of the children page through BrowseNext";
  }
  ASSERT_FALSE(resp.results()[0].continuation_point().empty());
  ASSERT_FALSE(resp.results()[1].continuation_point().empty());

  auto next = mSession->view().browse_next_sync(
    browse_next({resp.results()[0].continuation_point(), resp.results()[1].continuation_point()},
      /*release=*/false));
  ASSERT_EQ(next.results().size(), 2u);
  for (const auto& result : next.results())
  {
    EXPECT_THAT(result, Good());
    EXPECT_LE(result.references().size(), 1u) << "BrowseNext shares the same request budget";
  }
  for (const auto& result : next.results())
    if (!result.continuation_point().empty())
      mSession->view().browse_next_sync(browse_next(result.continuation_point(), /*release=*/true));
}

// ===========================================================================
// Stage-3c #2: per-operation references-examined budget for TranslateBrowsePaths
// terminates a walk that examines more references than allowed (CPU-amplification
// guard), with Bad_QueryTooComplex.
// ===========================================================================

class ComplianceViewWalkBudget : public ComplianceViewLimited
{
protected:
  ComplianceViewWalkBudget()
  {
    mMaxBrowsePathWalkReferences = 1;  // the parent has >1 reference, so any walk trips immediately
  }
};

// The walk fetches every reference of the start node and examines them in turn; the parent has 5
// HasComponent children (+ a HasTypeDefinition), so examining the 2nd reference exceeds the budget of
// 1. Falsifiable: without the budget the walk runs to completion and returns a matched target (or
// BadNoMatch), not BadQueryTooComplex.
TEST_F(ComplianceViewWalkBudget, VIEW_TBP_WalkReferenceBudgetEnforced)
{
  auto resp = mSession->view().translate_browse_paths_sync(
    translate_path(mParentId, QualifiedName{mTestNamespaceIndex, "CPChild4"}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadQueryTooComplex))
    << "a walk exceeding the per-operation references-examined budget must fail BadQueryTooComplex";
}

// ===========================================================================
// BrowseNext service-level validation
// ===========================================================================

// Part 4 section 5.8.3.4: BrowseNext fails at the SERVICE level - before any continuation point is
// dispatched - with Bad_NothingToDo for an empty continuationPoints array and with
// Bad_TooManyOperations for a batch larger than the MaxNodesPerBrowse operation limit. A plausible
// implementation carries Browse's two guards but not BrowseNext's: the empty list then comes back as
// an empty Good response, which is exactly what a client loop with a wrong termination condition
// produces and would spin on, and an over-long batch is answered per continuation point, so the
// operation limit the server advertises is not the limit it enforces.
// @verifies AC-SVR-VIEW-BNX-007-SERVICE-ERRORS
TEST_F(ComplianceViewLimited, BrowseNextRefusesEmptyListAndOverLimitBatchAtServiceLevel)
{
  // Conjunct 1 - empty continuationPoints.
  BrowseNextRequest emptyReq;
  // Leave continuation_points empty.
  auto emptyResult = mSession->view().try_browse_next_sync(std::move(emptyReq));
  if (emptyResult.is_good())
  {
    EXPECT_THAT(emptyResult.value(), ServiceResultIs(StatusCode{Status::BadNothingToDo}))
      << "an empty continuationPoints array shall fail the whole BrowseNext with BadNothingToDo";
    EXPECT_TRUE(emptyResult.value().results().empty())
      << "a service-level refusal shall not carry per-operation results";
  }
  else
  {
    EXPECT_EQ(emptyResult.status_code(), StatusCode{Status::BadNothingToDo})
      << "an empty continuationPoints array shall fail the whole BrowseNext with BadNothingToDo";
  }

  // Conjunct 2 - more continuation points than the MaxNodesPerBrowse operation limit (2 here).
  // The points themselves are well-formed 16-byte values that name nothing: the limit is checked
  // before any point is looked up, so a server that enforces it cannot reach per-operation
  // validation. Falsifiable - an unenforced limit yields a Good service result carrying three
  // BadContinuationPointInvalid operation results.
  ContinuationPoint cpA;
  ContinuationPoint cpB;
  ContinuationPoint cpC;
  cpA.resize(16);
  cpB.resize(16);
  cpC.resize(16);
  for (size_t i = 0; i < 16; ++i)
  {
    cpA[i] = static_cast<uint8_t>(i);
    cpB[i] = static_cast<uint8_t>(i + 16);
    cpC[i] = static_cast<uint8_t>(i + 32);
  }

  auto tooManyResult = mSession->view().try_browse_next_sync(
    browse_next({std::move(cpA), std::move(cpB), std::move(cpC)}, /*release=*/false));
  if (tooManyResult.is_good())
  {
    EXPECT_THAT(tooManyResult.value(), ServiceResultIs(StatusCode{Status::BadTooManyOperations}))
      << "a BrowseNext batch above MaxNodesPerBrowse shall fail the whole service with "
         "BadTooManyOperations";
    EXPECT_TRUE(tooManyResult.value().results().empty())
      << "a service-level refusal shall not carry per-operation results";
  }
  else
  {
    EXPECT_EQ(tooManyResult.status_code(), StatusCode{Status::BadTooManyOperations})
      << "a BrowseNext batch above MaxNodesPerBrowse shall fail the whole service with "
         "BadTooManyOperations";
  }
}

// ===========================================================================
// View membership of the browsed Node itself
// ===========================================================================

/// A real View Node whose membership set holds TestFolder's children but NOT TestFolder itself.
/// Browsing TestFolder under this View is therefore a browse of a Node outside the View whose
/// references are all inside it - so a server that only filters the targets returns a full,
/// plausible-looking result set, which is precisely the fall-back the obligation forbids.
class ComplianceViewMembership : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();

    mMemberViewId = NodeId{mTestNamespaceIndex, uint32_t{6100}};
    auto viewNode = addressSpace.create_node_sync(mMemberViewId, NodeClass::View);
    viewNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "ChildrenOnlyView"});
    viewNode.set_display_name(LocalizedText{"", "ChildrenOnlyView"});
    auto viewsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ViewsFolder});
    viewsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mMemberViewId);

    auto view = viewNode.as<ViewAccessor>();
    ASSERT_TRUE(view.has_value());
    // Members: TestFolder's children only. TestFolder is deliberately left out.
    for (const auto& id : mBrowseChildVariableIds)
      view->add_node_to_view_sync(id);
    for (const auto& id : mBrowseChildObjectIds)
      view->add_node_to_view_sync(id);
  }

  NodeId mMemberViewId;
};

// Part 4 section 5.8.2: when the request names a View, each nodesToBrowse[i].nodeId must be a member of
// that View; a Node outside it is rejected on that operation's result. A plausible implementation
// applies the View only to the references it returns - the reading that AC-SVR-VIEW-BRW-002
// describes - and lets the starting Node come from anywhere, which makes the View advisory: a
// client steps outside the boundary simply by asking for a Node it was never shown. Here every
// child of TestFolder is a View member while TestFolder is not, so that implementation answers Good
// with the children rather than refusing.
// @verifies AC-SVR-VIEW-BRW-001-NODE-IN-VIEW
TEST_F(ComplianceViewMembership, BrowsingANodeOutsideTheSuppliedViewIsRefused)
{
  // Precondition: the View resolves and its members are reachable through it, so a refusal below
  // cannot be the View itself being unusable.
  auto memberResult = mSession->view().try_browse_sync(
    BrowseRequestBuilder().browse(mBrowseChildObjectIds[0]).view(mMemberViewId));
  ASSERT_TRUE(memberResult.is_good()) << "browsing a View member must not fail at the service level";
  ASSERT_EQ(memberResult.value().results().size(), 1u);
  ASSERT_THAT(memberResult.value().results()[0], Good())
    << "precondition: a Node inside the View is browsable under it";

  auto result =
    mSession->view().try_browse_sync(BrowseRequestBuilder().browse(mTestFolderId).view(mMemberViewId));

  if (result.is_good())
  {
    ASSERT_EQ(result.value().results().size(), 1u);
    // Both conjuncts: the operation fails, and nothing of the address space leaks through it.
    EXPECT_TRUE(result.value().results()[0].status_code().is_bad())
      << "browsing a Node that is not a member of the supplied View must fail the operation, not "
         "fall back to the whole address space";
    EXPECT_TRUE(result.value().results()[0].references().empty())
      << "a Node outside the View must yield no references";
  }
  else
  {
    // A service-level refusal also discharges the obligation: no result and no references were
    // returned for a Node outside the View. The server must still be serving afterwards.
    EXPECT_NE(result.status_code(), StatusCode{Status::Good});
    auto stillServing = mSession->view().browse_sync(browse(mTestFolderId));
    ASSERT_EQ(stillServing.results().size(), 1u);
    EXPECT_THAT(stillServing.results()[0], Good())
      << "refusing an out-of-View browse must not disable the session";
  }
}

// ===========================================================================
// Symmetric references
// ===========================================================================

/// Two peer Objects joined by a custom symmetric ReferenceType. The relationship is recorded the way
/// this SDK records any two-ended relationship (compare TestFolder's inverse Organizes leg back to
/// the Objects folder): the forward leg on one node, the peer leg on the other. That makes the
/// Inverse assertions falsifiable - a server that simply replays the stored direction returns the
/// peer leg for an Inverse browse and hides it from a Forward one.
class ComplianceViewSymmetric : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});

    // Symmetric ReferenceType under NonHierarchicalReferences. Symmetric types carry no InverseName
    // (Part 3 section 5.3.3), so none is set.
    mSymmetricRefTypeId = NodeId{mTestNamespaceIndex, uint32_t{6000}};
    auto refTypeNode = addressSpace.create_node_sync(mSymmetricRefTypeId, NodeClass::ReferenceType);
    refTypeNode.set_browse_name(QualifiedName{mTestNamespaceIndex, "PeerOf"});
    refTypeNode.set_display_name(LocalizedText{"", "PeerOf"});
    auto refType = refTypeNode.as<ReferenceTypeAccessor>();
    ASSERT_TRUE(refType.has_value());
    refType->set_symmetric(true);
    ASSERT_TRUE(refType->get_symmetric()) << "precondition: the Symmetric attribute did not persist";
    auto nonHierarchical = addressSpace.find_node_sync(NodeId{ReferenceTypeId::NonHierarchicalReferences});
    // The address space adds the inverse half on the new ReferenceType (NR-70 B8).
    nonHierarchical.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, mSymmetricRefTypeId);

    // Peer A and peer B, each an Object organised under the Objects folder with the inverse leg
    // recorded so that an Inverse browse of either always has something to return.
    mPeerAId = NodeId{mTestNamespaceIndex, uint32_t{6001}};
    mPeerBId = NodeId{mTestNamespaceIndex, uint32_t{6002}};
    auto peerA = addressSpace.create_node_sync(mPeerAId, NodeClass::Object);
    auto peerB = addressSpace.create_node_sync(mPeerBId, NodeClass::Object);
    peerA.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    peerB.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    peerA.set_browse_name(QualifiedName{mTestNamespaceIndex, "SymmetricPeerA"});
    peerA.set_display_name(LocalizedText{"", "SymmetricPeerA"});
    peerB.set_browse_name(QualifiedName{mTestNamespaceIndex, "SymmetricPeerB"});
    peerB.set_display_name(LocalizedText{"", "SymmetricPeerB"});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mPeerAId);
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mPeerBId);
    peerA.add_reference_sync(
      NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}}, false);
    peerB.add_reference_sync(
      NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}}, false);

    // The symmetric relationship: forward leg on A, peer leg on B.
    peerA.add_reference_sync(mSymmetricRefTypeId, mPeerBId);
    peerB.add_reference_sync(mSymmetricRefTypeId, ExpandedNodeId{NodeId{mPeerAId}}, false);
  }

  NodeId mSymmetricRefTypeId;
  NodeId mPeerAId;
  NodeId mPeerBId;
};

// Requirement: SVR-VIEW-BRW-003 (SHALL implicit)
// Symmetric References are always considered to be in forward direction therefore the
// isForward flag is always set to TRUE and symmetric References are not returned if
// browseDirection is set to INVERSE.
// Spec: Part 4, section 5.8.2.2, lines 2981-2983
//
// The subject is the fixture's PeerOf Reference, so the precondition cannot be absent: NS0's only
// symmetric ReferenceType is the abstract References, which no Reference instantiates.
// @relation(SVR-VIEW-BRW-003, SVR-VIEW-URG-002, scope=function)
TEST_F(ComplianceViewSymmetric, VIEW_BRW_003_SymmetricRefsAlwaysForward)
{
  for (const NodeId& peer : {mPeerAId, mPeerBId})
  {
    auto findResp = mSession->view().browse_sync(BrowseRequestBuilder()
                                                   .browse(peer)
                                                   .direction(BrowseDirection::Both)
                                                   .reference_type(mSymmetricRefTypeId)
                                                   .include_subtypes(false));
    ASSERT_EQ(findResp.results().size(), 1u);
    ASSERT_FALSE(findResp.results()[0].references().empty())
      << "the symmetric Reference must be returned for a Both browse of " << to_string(peer);

    // A Both browse returns the symmetric Reference with isForward=true from either end.
    for (const auto& ref : findResp.results()[0].references())
    {
      EXPECT_TRUE(ref.is_forward())
        << "Symmetric reference should always have isForward=true regardless of browse direction";
    }
  }
}

// Requirement: SVR-VIEW-BRW-003 (SHALL implicit)
// Symmetric References are not returned if browseDirection is set to INVERSE.
// Spec: Part 4, section 5.8.2.2, lines 2981-2983
// @relation(SVR-VIEW-BRW-003, scope=function)
TEST_F(ComplianceViewSymmetric, VIEW_BRW_003_InverseBrowseExcludesSymmetric)
{
  // Control: the node carries the symmetric Reference, so an empty Inverse answer is a verdict.
  auto findResp = mSession->view().browse_sync(
    BrowseRequestBuilder().browse(mPeerAId).reference_type(mSymmetricRefTypeId).include_subtypes(false));
  ASSERT_EQ(findResp.results().size(), 1u);
  ASSERT_FALSE(findResp.results()[0].references().empty())
    << "the symmetric Reference must be returned for a Forward browse of the node that carries it";

  // Now browse the SAME node Inverse with the symmetric ref type filter.
  // Symmetric refs should NOT appear in inverse browse.
  auto inverseResp = mSession->view().browse_sync(BrowseRequestBuilder()
                                                    .browse(mPeerAId)
                                                    .direction(BrowseDirection::Inverse)
                                                    .reference_type(mSymmetricRefTypeId)
                                                    .include_subtypes(false));
  ASSERT_EQ(inverseResp.results().size(), 1u);
  EXPECT_THAT(inverseResp.results()[0], Good());

  // Symmetric references must not appear in inverse browse results.
  EXPECT_TRUE(inverseResp.results()[0].references().empty())
    << "Symmetric references shall not be returned when browseDirection is Inverse";
}

// Part 4 section 5.8.2.2: a symmetric Reference is always considered to be in the forward direction - the
// ReferenceDescription's isForward is TRUE for it - and it is not returned when browseDirection is
// INVERSE. The intuitive reading is the wrong one: a symmetric Reference looks like it should answer
// both directions, and an implementation that simply replays whichever direction it stored returns
// the peer's leg for an INVERSE browse (duplicating the Reference for any client that browses both
// directions in two calls) while hiding it from that peer's FORWARD browse. Both ends of the same
// symmetric Reference are exercised because both Nodes carry it.
// Browse resolves the stored edge's ReferenceType metadata before direction filtering. This fixture
// keeps both endpoint representations so a regression to replaying the stored per-Node flag fails in
// all three observable ways: missing from Forward, present in Inverse, and isForward FALSE in Both.
// @verifies AC-SVR-VIEW-BRW-003-SYMMETRIC-ALWAYS-FORWARD
TEST_F(ComplianceViewSymmetric, SymmetricReferenceIsForwardAtBothEndsAndNeverInverse)
{
  auto browseDir = [this](const NodeId& node, BrowseDirection dir)
  {
    return mSession->view().browse_sync(BrowseRequestBuilder().browse(node).direction(dir));
  };

  struct End
  {
    NodeId node;
    NodeId peer;
    const char* label;
  };

  const End ends[] = {
    End{mPeerAId, mPeerBId, "the Node holding the forward leg"},
    End{mPeerBId, mPeerAId, "the Node holding the peer leg"},
  };

  for (const auto& peerEnd : ends)
  {
    // Forward: returned, with isForward TRUE.
    auto forward = browseDir(peerEnd.node, BrowseDirection::Forward);
    ASSERT_EQ(forward.results().size(), 1u);
    ASSERT_THAT(forward.results()[0], Good());
    ASSERT_FALSE(forward.results()[0].references().empty())
      << peerEnd.label << ": a Forward browse must return references (HasTypeDefinition at least)";
    const auto* forwardRef = find_ref_by_target(forward.results()[0], peerEnd.peer);
    ASSERT_NE(forwardRef, nullptr) << peerEnd.label
                                   << ": a symmetric reference must be returned by a Forward browse";
    EXPECT_EQ(forwardRef->reference_type_id(), mSymmetricRefTypeId);
    EXPECT_TRUE(forwardRef->is_forward())
      << peerEnd.label << ": a symmetric reference must be reported with isForward=TRUE";

    // Both: returned, with isForward TRUE.
    auto both = browseDir(peerEnd.node, BrowseDirection::Both);
    ASSERT_EQ(both.results().size(), 1u);
    ASSERT_THAT(both.results()[0], Good());
    ASSERT_FALSE(both.results()[0].references().empty())
      << peerEnd.label << ": a Both browse must return references";
    const auto* bothRef = find_ref_by_target(both.results()[0], peerEnd.peer);
    ASSERT_NE(bothRef, nullptr) << peerEnd.label
                                << ": a symmetric reference must be returned by a Both browse";
    EXPECT_EQ(bothRef->reference_type_id(), mSymmetricRefTypeId);
    EXPECT_TRUE(bothRef->is_forward())
      << peerEnd.label << ": a symmetric reference must be reported with isForward=TRUE";

    // Inverse: not returned. The inverse Organizes leg back to the Objects folder keeps this
    // observation from passing merely because the result set is empty.
    auto inverse = browseDir(peerEnd.node, BrowseDirection::Inverse);
    ASSERT_EQ(inverse.results().size(), 1u);
    ASSERT_THAT(inverse.results()[0], Good());
    ASSERT_FALSE(inverse.results()[0].references().empty())
      << peerEnd.label << ": an Inverse browse must return the inverse Organizes leg";
    EXPECT_EQ(find_ref_by_target(inverse.results()[0], peerEnd.peer), nullptr)
      << peerEnd.label << ": a symmetric reference must not be returned for browseDirection Inverse";
    EXPECT_EQ(
      count_refs(inverse.results()[0],
        [this](const ReferenceDescription& ref) { return ref.reference_type_id() == mSymmetricRefTypeId; }),
      0u)
      << peerEnd.label << ": no reference of a symmetric type may appear in an Inverse browse";
  }
}

// Part 4 section 5.8.2: when the request names a View, the membership test applies to each
// nodesToBrowse[i].nodeId, and a Node outside the View is rejected on the operation result at that
// index - the ViewDescription is request-wide but its consequence is per operation. A plausible
// implementation resolves the View once, decides the request "has a valid View", and then serves
// every operation in it from the whole address space; the failure is invisible in a single-node
// request that happens to name a member, and equally invisible in one that names only non-members if
// the server answers at the service level. Mixing a member and a non-member in one request separates
// the two: the member operation is the control that proves the View is usable and the request was
// accepted, so the non-member operation's result is the only thing left that can carry the refusal.
// The non-member is browsed at index 1, between two members, so a server that rejects positionally
// cannot pass by rejecting the head or the tail of the batch.
// @verifies AC-SVR-VIEW-BRW-001-NODE-IN-VIEW
TEST_F(ComplianceViewMembership, NodesOutsideTheViewAreRejectedOnTheirOwnOperationResult)
{
  ASSERT_GE(mBrowseChildObjectIds.size(), 1u) << "fixture must supply an Object View member";
  ASSERT_GE(mBrowseChildVariableIds.size(), 1u) << "fixture must supply a Variable View member";

  auto result = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                   .browse(mBrowseChildObjectIds[0])
                                                   .browse(mTestFolderId)
                                                   .browse(mBrowseChildVariableIds[0])
                                                   .view(mMemberViewId));

  // Per SVR-VIEW-BRW-001 the rejection is carried "per the operation result on that index", so the
  // request as a whole must be accepted; failing the service would also refuse the two members.
  ASSERT_TRUE(result.is_good())
    << "a batch mixing View members with a non-member must be accepted at the service level; the "
       "non-member is refused on its own operation result";
  ASSERT_EQ(result.value().results().size(), 3u);

  // Controls: both View members are browsable under the View, so the middle refusal cannot be the
  // View being unresolvable or the request being rejected wholesale.
  EXPECT_THAT(result.value().results()[0], Good()) << "control: a Node inside the View is browsable under it";
  EXPECT_THAT(result.value().results()[2], Good()) << "control: a Node inside the View is browsable under it";

  // The obligation, at the index that carries it. Both conjuncts: the operation fails, and no part
  // of the address space is returned through it.
  EXPECT_TRUE(result.value().results()[1].status_code().is_bad())
    << "TestFolder is not a member of the supplied View, so its operation must fail rather than "
       "fall back to the whole address space";
  EXPECT_TRUE(result.value().results()[1].references().empty())
    << "a Node outside the View must yield no references on its operation result";
}

// Part 4 section 5.8.2.2: a symmetric Reference has one direction only - forward - so a Node holding it
// returns it exactly once, whichever browseDirection selects it, and never under INVERSE. A
// plausible implementation reaches the right answer for a single stored leg but not for the count:
// browsing BOTH is usually implemented as the forward pass followed by the inverse pass over the
// same reference list, and a symmetric Reference satisfies "is symmetric, therefore matches" in each
// pass, so it comes back twice - once claimed forward and once claimed inverse. A client that keys
// its cache on (source, referenceType, target) then sees the same relationship arrive with
// contradictory isForward values. Asserting over every occurrence rather than the first is what
// distinguishes the two implementations; a first-match lookup cannot see the duplicate at all.
// Both ends of the same symmetric Reference are exercised, because the stored leg sits on A.
// @verifies AC-SVR-VIEW-BRW-003-SYMMETRIC-ALWAYS-FORWARD
TEST_F(ComplianceViewSymmetric, SymmetricReferenceIsReturnedOnceAsForwardAndNeverUnderInverse)
{
  auto browseDir = [this](const NodeId& node, BrowseDirection dir)
  {
    return mSession->view().browse_sync(BrowseRequestBuilder().browse(node).direction(dir));
  };

  struct End
  {
    NodeId node;
    NodeId peer;
    const char* label;
  };

  const End ends[] = {
    End{mPeerAId, mPeerBId, "the Node holding the stored leg"},
    End{mPeerBId, mPeerAId, "the peer Node"},
  };

  for (const auto& peerEnd : ends)
  {
    auto isSymmetric = [this](const ReferenceDescription& ref)
    {
      return ref.reference_type_id() == mSymmetricRefTypeId;
    };
    auto isSymmetricForwardToPeer = [this, &peerEnd](const ReferenceDescription& ref)
    {
      return ref.reference_type_id() == mSymmetricRefTypeId && ref.is_forward() &&
             ref.node_id().node_id() == peerEnd.peer;
    };

    // Forward: exactly one occurrence, and it is the peer with isForward TRUE.
    auto forward = browseDir(peerEnd.node, BrowseDirection::Forward);
    ASSERT_EQ(forward.results().size(), 1u);
    ASSERT_THAT(forward.results()[0], Good());
    ASSERT_FALSE(forward.results()[0].references().empty())
      << peerEnd.label << ": a Forward browse must return references (HasTypeDefinition at least)";
    EXPECT_EQ(count_refs(forward.results()[0], isSymmetric), 1u)
      << peerEnd.label << ": a Forward browse must return the symmetric reference exactly once";
    EXPECT_EQ(count_refs(forward.results()[0], isSymmetricForwardToPeer), 1u)
      << peerEnd.label
      << ": the symmetric reference returned by a Forward browse must name the peer with "
         "isForward=TRUE";

    // Both: still exactly one occurrence - not one per direction pass - and still forward.
    auto both = browseDir(peerEnd.node, BrowseDirection::Both);
    ASSERT_EQ(both.results().size(), 1u);
    ASSERT_THAT(both.results()[0], Good());
    ASSERT_FALSE(both.results()[0].references().empty())
      << peerEnd.label << ": a Both browse must return references";
    EXPECT_EQ(count_refs(both.results()[0], isSymmetric), 1u)
      << peerEnd.label
      << ": a Both browse must return the symmetric reference exactly once, not once per direction";
    EXPECT_EQ(count_refs(both.results()[0], isSymmetricForwardToPeer), 1u)
      << peerEnd.label
      << ": the symmetric reference returned by a Both browse must name the peer with "
         "isForward=TRUE";

    // Inverse: zero occurrences. The inverse Organizes leg back to the Objects folder keeps this
    // from passing merely because the result set is empty.
    auto inverse = browseDir(peerEnd.node, BrowseDirection::Inverse);
    ASSERT_EQ(inverse.results().size(), 1u);
    ASSERT_THAT(inverse.results()[0], Good());
    ASSERT_FALSE(inverse.results()[0].references().empty())
      << peerEnd.label << ": an Inverse browse must return the inverse Organizes leg";
    EXPECT_EQ(count_refs(inverse.results()[0], isSymmetric), 0u)
      << peerEnd.label << ": a symmetric reference must not be returned for browseDirection Inverse";
  }
}
