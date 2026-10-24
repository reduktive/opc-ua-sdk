// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <future>

#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_default_namespace.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_translate_browse_paths_service.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"

#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;

namespace
{

/// Helper to build and execute a TranslateBrowsePaths request, returning the response.
TranslateBrowsePathsToNodeIdsResponse run_translate(shared_ptr<SessionInfo> sessionInfo,
  boost::asio::any_io_executor executor, TranslateBrowsePathsToNodeIdsRequest request)
{
  std::promise<Response> promise;
  auto future = promise.get_future();

  auto svc = TranslateBrowsePathsService::create(sessionInfo,
    {"en"},
    1,
    std::move(request),
    executor,
    [&](Response r) { promise.set_value(std::move(r)); });
  (void)svc;

  auto resp = future.get();
  auto* tr = dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(resp.second.get());
  EXPECT_NE(tr, nullptr);
  return std::move(*tr);
}

/// Build a single-element translate request.
TranslateBrowsePathsToNodeIdsRequest make_translate_request(const NodeId& startingNode,
  const NodeId& refTypeId, bool isInverse, bool includeSubtypes, const QualifiedName& targetName)
{
  TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().request_handle() = 1;

  BrowsePath bp;
  bp.starting_node() = startingNode;

  RelativePath rp;
  RelativePathElement el;
  el.reference_type_id() = refTypeId;
  el.is_inverse() = isInverse;
  el.include_subtypes() = includeSubtypes;
  el.target_name() = targetName;
  rp.elements().payload().push_back(std::move(el));
  bp.relative_path() = std::move(rp);

  req.browse_paths().payload().push_back(std::move(bp));
  return req;
}

}  // namespace

// @relation(SVR-VIEW-URG-002, scope=function)
TEST(TranslateBrowsePathsTests, ResolvesPathViaAddressSpace)
{
  boost::asio::thread_pool threadPool;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://plain-ns", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns);

  NodeId startId{2, 100};
  ns->create_node(startId, NodeClass::Object);

  NodeId targetId{2, 200};
  ns->create_node(targetId, NodeClass::Object);

  auto targetAccessor = server.address_space().find_node_sync(targetId);
  targetAccessor.set_browse_name(QualifiedName{2, "Child"});

  auto startAccessor = server.address_space().find_node_sync(startId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, targetId);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  auto req = make_translate_request(
    startId, NodeId{ReferenceTypeId::HasComponent}, false, true, QualifiedName{2, "Child"});

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(req));

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].status_code().is_good());
  ASSERT_EQ(response.results()[0].targets().size(), 1u);
  EXPECT_EQ(response.results()[0].targets()[0].target_id(), ExpandedNodeId{targetId});
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-AUTHZ-010-TRANSLATE-MATCHES-BROWSE, scope=function)
// @verifies AC-SVR-AUTHZ-010-TRANSLATE-MATCHES-BROWSE
TEST(TranslateBrowsePathsTests, DeniedTargetIsOmittedAndAllFilteredReturnsBadNoMatch)
{
  boost::asio::thread_pool threadPool;
  CreateConfig config{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};
  auto server = Server::create(threadPool.get_executor(),
    std::move(config),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto nameSpace = default_ns::Namespace::create("uri://translate-target-authz", threadPool.get_executor());
  server.address_space().add_namespace_sync(nameSpace);

  const NodeId startId{2, 110};
  const NodeId targetId{2, 210};
  nameSpace->create_node(startId, NodeClass::Object);
  nameSpace->create_node(targetId, NodeClass::Object);
  auto target = server.address_space().find_node_sync(targetId);
  target.set_browse_name(QualifiedName{2, "HiddenChild"});
  server.address_space().find_node_sync(startId).add_reference_sync(
    NodeId{ReferenceTypeId::HasComponent}, targetId);

  auto deniedPermissions = ua::test_helpers::all_permissions();
  deniedPermissions.reset(PermissionType::Bit::Browse);
  ua::test_helpers::set_test_node_permissions(target, deniedPermissions);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  auto request = [&]
  {
    return make_translate_request(
      startId, NodeId{ReferenceTypeId::HasComponent}, false, true, QualifiedName{2, "HiddenChild"});
  };

  auto denied = run_translate(sessionInfo, threadPool.get_executor(), request());
  ASSERT_EQ(denied.results().size(), 1u);
  EXPECT_EQ(denied.results()[0].status_code(), StatusCode{Status::BadNoMatch});
  EXPECT_TRUE(denied.results()[0].targets().empty());

  ua::test_helpers::set_test_node_permissions(target, ua::test_helpers::all_permissions());
  auto allowed = run_translate(sessionInfo, threadPool.get_executor(), request());
  ASSERT_EQ(allowed.results().size(), 1u);
  EXPECT_TRUE(allowed.results()[0].status_code().is_good());
  ASSERT_EQ(allowed.results()[0].targets().size(), 1u);
  EXPECT_EQ(allowed.results()[0].targets()[0].target_id(), ExpandedNodeId{targetId});

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TranslateBrowsePathsTests, DuplicateReferencesToSameTargetYieldSingleTarget)
{
  // A node reachable via more than one matching reference (here HasComponent AND Organizes to the
  // same child, matched by a null reference type that follows all references) is a single target:
  // the walk must dedup by NodeId and return one BrowsePathTarget, not two. Regression for UACTT
  // TranslateBrowsePath 004 (one relativePath element resolved to two targets where one was expected).
  boost::asio::thread_pool threadPool;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://plain-ns", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns);

  NodeId startId{2, 100};
  ns->create_node(startId, NodeClass::Object);

  NodeId targetId{2, 200};
  ns->create_node(targetId, NodeClass::Object);

  auto targetAccessor = server.address_space().find_node_sync(targetId);
  targetAccessor.set_browse_name(QualifiedName{2, "Child"});

  auto startAccessor = server.address_space().find_node_sync(startId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, targetId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, targetId);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  // Null reference type -> follows all references; both refs resolve to the same target node.
  auto req = make_translate_request(startId, NodeId{}, false, false, QualifiedName{2, "Child"});

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(req));

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].status_code().is_good());
  ASSERT_EQ(response.results()[0].targets().size(), 1u);
  EXPECT_EQ(response.results()[0].targets()[0].target_id(), ExpandedNodeId{targetId});
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(SVR-VIEW-TBP-009, SVR-VIEW-URG-002, scope=function)
TEST(TranslateBrowsePathsTests, NoMatchReturnsBadNoMatch)
{
  boost::asio::thread_pool threadPool;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://plain-ns", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns);

  NodeId startId{2, 100};
  ns->create_node(startId, NodeClass::Object);

  NodeId targetId{2, 200};
  ns->create_node(targetId, NodeClass::Object);

  auto targetAccessor = server.address_space().find_node_sync(targetId);
  targetAccessor.set_browse_name(QualifiedName{2, "WrongName"});

  auto startAccessor = server.address_space().find_node_sync(startId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, targetId);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  auto req = make_translate_request(
    startId, NodeId{ReferenceTypeId::HasComponent}, false, true, QualifiedName{2, "CorrectName"});

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(req));

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].targets().empty());
  EXPECT_EQ(response.results()[0].status_code(), Status::BadNoMatch);
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(SVR-VIEW-URG-002, scope=function)
TEST(TranslateBrowsePathsTests, MultiElementPathCrossesNamespaceBoundary)
{
  boost::asio::thread_pool threadPool;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns2 = default_ns::Namespace::create("uri://ns2", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns2);

  auto ns3 = default_ns::Namespace::create("uri://ns3", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns3);

  // Starting node in NS2.
  NodeId startId{2, 100};
  ns2->create_node(startId, NodeClass::Object);

  // Intermediate node in NS3.
  NodeId intermediateId{3, 50};
  ns3->create_node(intermediateId, NodeClass::Object);
  auto intermediateAccessor = server.address_space().find_node_sync(intermediateId);
  intermediateAccessor.set_browse_name(QualifiedName{3, "Intermediate"});

  // Reference from start to intermediate.
  auto startAccessor = server.address_space().find_node_sync(startId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, intermediateId);

  // Final target node in NS3.
  NodeId finalId{3, 99};
  ns3->create_node(finalId, NodeClass::Object);
  auto finalAccessor = server.address_space().find_node_sync(finalId);
  finalAccessor.set_browse_name(QualifiedName{3, "FinalTarget"});

  // Reference from intermediate to final.
  intermediateAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, finalId);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  // Two-element path: start -[Organizes]-> Intermediate -[HasComponent]-> FinalTarget
  TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().request_handle() = 1;

  BrowsePath bp;
  bp.starting_node() = startId;

  RelativePath rp;
  {
    RelativePathElement el;
    el.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    el.is_inverse() = false;
    el.include_subtypes() = true;
    el.target_name() = QualifiedName{3, "Intermediate"};
    rp.elements().payload().push_back(std::move(el));
  }
  {
    RelativePathElement el;
    el.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    el.is_inverse() = false;
    el.include_subtypes() = true;
    el.target_name() = QualifiedName{3, "FinalTarget"};
    rp.elements().payload().push_back(std::move(el));
  }
  bp.relative_path() = std::move(rp);
  req.browse_paths().payload().push_back(std::move(bp));

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(req));

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_TRUE(response.results()[0].status_code().is_good());
  ASSERT_EQ(response.results()[0].targets().size(), 1u);
  EXPECT_EQ(response.results()[0].targets()[0].target_id(), ExpandedNodeId{finalId});
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(SVR-VIEW-TBP-005, SVR-VIEW-URG-002, scope=function)
TEST(TranslateBrowsePathsTests, RemoteReferenceReturnsUncertain)
{
  boost::asio::thread_pool threadPool;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://plain-ns", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns);

  NodeId startId{2, 100};
  ns->create_node(startId, NodeClass::Object);

  // Add a remote reference (non-zero server index) directly in the address space.
  auto startAccessor = server.address_space().find_node_sync(startId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{NodeId{5, 999}, 1});

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  // Use a non-null target name - remote references bypass browse-name checks so any name matches.
  auto req = make_translate_request(
    startId, NodeId{ReferenceTypeId::HasComponent}, false, true, QualifiedName{0, "RemoteNode"});

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(req));

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code(), Status::UncertainReferenceOutOfServer);
  ASSERT_EQ(response.results()[0].targets().size(), 1u);
  EXPECT_EQ(response.results()[0].targets()[0].target_id(), (ExpandedNodeId{NodeId{5, 999}, 1}));
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.8.4.2 further restricts the generic RelativePath definition: the final element in a
// TranslateBrowsePathsToNodeIds request shall carry a targetName. Part 4 section 7.31's generic empty-name
// wildcard permission does not apply at this service boundary.
// @relation(AC-SVR-VIEW-TBP-003-TARGETNAME-REQUIRED, scope=function)
TEST(TranslateBrowsePathsTests, MissingFinalTargetNameReturnsRichBadBrowseNameInvalid)
{
  boost::asio::thread_pool threadPool;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://plain-ns", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns);

  NodeId startId{2, 100};
  ns->create_node(startId, NodeClass::Object);

  NodeId childId{2, 200};
  ns->create_node(childId, NodeClass::Object);
  auto childAccessor = server.address_space().find_node_sync(childId);
  childAccessor.set_browse_name(QualifiedName{2, "Child"});

  auto startAccessor = server.address_space().find_node_sync(startId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, childId);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  auto req =
    make_translate_request(startId, NodeId{ReferenceTypeId::HasComponent}, false, false, QualifiedName{});

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(req));

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::BadBrowseNameInvalid});
  ASSERT_NE(response.results()[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(response.results()[0].status_code().shared_detail()->code, "MissingBrowsePathTargetName");
  EXPECT_TRUE(response.results()[0].targets().empty());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(TranslateBrowsePathsTests, EmptyNonFinalTargetNameRemainsInvalid)
{
  boost::asio::thread_pool threadPool;
  CreateConfig config{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};
  auto server = Server::create(threadPool.get_executor(),
    std::move(config),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto nameSpace = default_ns::Namespace::create("uri://plain-ns", threadPool.get_executor());
  server.address_space().add_namespace_sync(nameSpace);
  const NodeId startId{2, 300};
  nameSpace->create_node(startId, NodeClass::Object);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  TranslateBrowsePathsToNodeIdsRequest request;
  BrowsePath path;
  path.starting_node() = startId;
  RelativePathElement emptyNonFinal;
  emptyNonFinal.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  emptyNonFinal.target_name() = QualifiedName{};
  path.relative_path().elements().push_back(std::move(emptyNonFinal));
  RelativePathElement namedFinal;
  namedFinal.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  namedFinal.target_name() = QualifiedName{2, "Child"};
  path.relative_path().elements().push_back(std::move(namedFinal));
  request.browse_paths().push_back(std::move(path));

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(request));

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::BadBrowseNameInvalid});
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.8.4.4 distinguishes malformed from merely unknown starting nodes, per operation. The
// valid sibling proves the structural screen does not reject or cancel the request as a whole.
// @relation(AC-SVR-VIEW-TBP-009-OPERATION-CODES, scope=function)
TEST(TranslateBrowsePathsTests, InvalidAndUnknownStartingNodesKeepDistinctRichStatuses)
{
  boost::asio::thread_pool threadPool;
  CreateConfig config{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};
  auto server = Server::create(threadPool.get_executor(),
    std::move(config),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto nameSpace = default_ns::Namespace::create("uri://plain-ns", threadPool.get_executor());
  server.address_space().add_namespace_sync(nameSpace);
  const NodeId startId{2, 500};
  const NodeId childId{2, 501};
  nameSpace->create_node(startId, NodeClass::Object);
  nameSpace->create_node(childId, NodeClass::Object);
  auto child = server.address_space().find_node_sync(childId);
  child.set_browse_name(QualifiedName{2, "Child"});
  server.address_space().find_node_sync(startId).add_reference_sync(
    NodeId{ReferenceTypeId::HasComponent}, childId);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  TranslateBrowsePathsToNodeIdsRequest request;
  request.request_header().request_handle() = 1;
  const auto appendPath = [&](const NodeId& startingNode)
  {
    auto single = make_translate_request(
      startingNode, NodeId{ReferenceTypeId::HasComponent}, false, true, QualifiedName{2, "Child"});
    request.browse_paths().payload().push_back(std::move(single.browse_paths().payload().front()));
  };
  appendPath(NodeId{});
  appendPath(NodeId{2, 99999});
  appendPath(startId);

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(request));

  ASSERT_EQ(response.results().size(), 3u);
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::BadNodeIdInvalid});
  ASSERT_NE(response.results()[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(response.results()[0].status_code().shared_detail()->code, "InvalidStartingNodeId");
  EXPECT_EQ(response.results()[1].status_code(), StatusCode{Status::BadNodeIdUnknown});
  EXPECT_TRUE(response.results()[2].status_code().is_good());
  ASSERT_EQ(response.results()[2].targets().size(), 1u);
  EXPECT_EQ(response.results()[2].targets()[0].target_id(), ExpandedNodeId{childId});

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Two paths of DIFFERENT depths in one request, sharing a starting node.
//
// Every path of a request is walked one relative-path element at a time, all paths together, so that
// the targets of an element can be resolved and authorized in one call each. That is what makes the
// attribution testable and worth testing: the shallow path retires while the deep one is still
// walking, and each element's answers have to reach the path that asked for them. A hop that
// credited a target to the wrong path, or that stopped the deep path when the shallow one ran out,
// would show up here and nowhere else.
TEST(TranslateBrowsePathsTests, PathsOfDifferentDepthsInOneRequestKeepTheirOwnTargets)
{
  boost::asio::thread_pool threadPool;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://two-paths-ns", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns);

  const NodeId startId{2, 100};
  const NodeId shallowId{2, 101};
  const NodeId level1Id{2, 102};
  const NodeId level2Id{2, 103};
  for (const auto& id : {startId, shallowId, level1Id, level2Id})
  {
    ns->create_node(id, NodeClass::Object);
  }

  auto addressSpace = server.address_space();
  const QualifiedName shallowName{2, "Shallow"};
  const QualifiedName level1Name{2, "Level1"};
  const QualifiedName level2Name{2, "Level2"};
  addressSpace.find_node_sync(shallowId).set_browse_name(shallowName);
  addressSpace.find_node_sync(level1Id).set_browse_name(level1Name);
  addressSpace.find_node_sync(level2Id).set_browse_name(level2Name);

  auto startAccessor = addressSpace.find_node_sync(startId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, shallowId);
  startAccessor.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, level1Id);
  addressSpace.find_node_sync(level1Id).add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, level2Id);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  const auto makeElement = [](const QualifiedName& targetName)
  {
    RelativePathElement element;
    element.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    element.is_inverse() = false;
    element.include_subtypes() = true;
    element.target_name() = targetName;
    return element;
  };

  TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().request_handle() = 1;

  BrowsePath shallowPath;
  shallowPath.starting_node() = startId;
  shallowPath.relative_path().elements().payload().push_back(makeElement(shallowName));
  req.browse_paths().payload().push_back(std::move(shallowPath));

  BrowsePath deepPath;
  deepPath.starting_node() = startId;
  deepPath.relative_path().elements().payload().push_back(makeElement(level1Name));
  deepPath.relative_path().elements().payload().push_back(makeElement(level2Name));
  req.browse_paths().payload().push_back(std::move(deepPath));

  auto response = run_translate(sessionInfo, threadPool.get_executor(), std::move(req));

  ASSERT_EQ(response.results().size(), 2u);

  EXPECT_TRUE(response.results()[0].status_code().is_good());
  ASSERT_EQ(response.results()[0].targets().size(), 1u);
  EXPECT_EQ(response.results()[0].targets()[0].target_id(), ExpandedNodeId{shallowId});

  EXPECT_TRUE(response.results()[1].status_code().is_good());
  ASSERT_EQ(response.results()[1].targets().size(), 1u);
  EXPECT_EQ(response.results()[1].targets()[0].target_id(), ExpandedNodeId{level2Id});

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// NOT COVERED HERE, and deliberately recorded rather than left unsaid: the rule that a reference
// read which FAILED after an out-of-server reference in the same relative-path element is the path's
// answer - `TranslateBrowsePathsService::apply_element_status`. Driving it needs one target of an
// element to resolve, answer its BrowseName and pass authorization, and then fail to produce its
// references. The default address space offers no way to produce that node from a test: the only
// lever is deletion, and a deleted node throws from `node_id()` and `browse_name()` as well, which
// fails the whole request instead of the one target. `default_ns::Namespace::attach_node` - which
// would let a test attach a node of its own type - is declared and never defined. The rule is
// implemented and reviewed; the test is owed, and owes a test interface first.

// A walk gives its strand back between relative-path elements, so the request's own timeout can run.
//
// Every collaborator on this path answers on the calling stack when the address space is local, and a
// completion that arrives on the strand it is already running on resumes inline. Without a yield the
// whole walk runs inside the single strand turn the request started in, the timeout timer - armed on
// that same strand - never gets a turn, and a client's timeoutHint is silently not honoured however
// long the walk takes.
//
// Falsifiable: delete the per-element yield and this request answers with a full
// TranslateBrowsePathsToNodeIds response instead of Bad_Timeout.
TEST(TranslateBrowsePathsTests, ALongWalkStillHonoursTheRequestTimeout)
{
  boost::asio::thread_pool threadPool;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://long-walk-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  // Two nodes referencing each other, so a path of any length walks without a large address space.
  const NodeId pingId{nsIndex, 100};
  const NodeId pongId{nsIndex, 101};
  ns->create_node(pingId, NodeClass::Object);
  ns->create_node(pongId, NodeClass::Object);

  auto addressSpace = server.address_space();
  const QualifiedName pingName{nsIndex, "Ping"};
  const QualifiedName pongName{nsIndex, "Pong"};
  addressSpace.find_node_sync(pingId).set_browse_name(pingName);
  addressSpace.find_node_sync(pongId).set_browse_name(pongName);
  addressSpace.find_node_sync(pingId).add_reference_sync(NodeId{ReferenceTypeId::Organizes}, pongId);
  addressSpace.find_node_sync(pongId).add_reference_sync(NodeId{ReferenceTypeId::Organizes}, pingId);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  constexpr size_t elements = 400;
  TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().request_handle() = 1;
  req.request_header().timeout_hint() = 1;
  BrowsePath path;
  path.starting_node() = pingId;
  for (size_t i = 0; i < elements; ++i)
  {
    RelativePathElement element;
    element.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    element.is_inverse() = false;
    element.include_subtypes() = true;
    element.target_name() = ((i % 2) == 0) ? pongName : pingName;
    path.relative_path().elements().payload().push_back(std::move(element));
  }
  req.browse_paths().payload().push_back(std::move(path));

  std::promise<Response> promise;
  auto svc = TranslateBrowsePathsService::create(sessionInfo,
    {"en"},
    1,
    std::move(req),
    threadPool.get_executor(),
    [&promise](Response r) { promise.set_value(std::move(r)); });
  (void)svc;

  auto future = promise.get_future();
  ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  auto response = future.get();

  auto* fault = dynamic_cast<ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "a walk that outlives its timeoutHint must answer with a service fault";
  EXPECT_EQ(fault->response_header().service_result(), Status::BadTimeout);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}
