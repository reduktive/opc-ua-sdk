// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <algorithm>
#include <chrono>
#include <future>

#include <fmt/core.h>
#include <gtest/gtest.h>
#include <boost/asio/io_context.hpp>
#include "ua_read_service.h"
#include "ua_default_object_node.h"
#include "ua_default_namespace.h"
#include "ua_server.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_timer.h"
#include "ua_browse_service.h"
#include "ua_attribute_id.h"
#include "ua_referencetype_id.h"
#include "ua_object_id.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"
#include "access_control_test_support.h"

#include "test_components.h"
#include "every_node_in_view_namespace.h"
#include "ua_diagnostic_bits.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

// @relation(SVR-VIEW-URG-002, scope=function)
TEST(BrowseServiceTests, BrowseASingleNode)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://my-namespace", threadPool.get_executor());
  server.address_space().add_namespace_sync(ns);

  NodeId nodeId{2, 123};
  ns->create_node(nodeId, NodeClass::Object);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  BrowseRequest browseRequest;
  browseRequest.nodes_to_browse().resize(1);
  browseRequest.nodes_to_browse()[0].node_id() = nodeId;
  browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;

  std::condition_variable cv;
  std::mutex mtx;
  bool done = false;
  StatusCode browseStatus;
  size_t resultCount = 0;

  std::vector<LocaleId> locales{"en"};

  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [&cv, &mtx, &done, &browseStatus, &resultCount](BrowseService::BrowseServiceResponse response)
    {
      auto& browseResponse = dynamic_cast<BrowseResponse&>(*response.response.second);
      resultCount = browseResponse.results().size();
      if (resultCount == 1)
      {
        browseStatus = browseResponse.results().payload().front().status_code();
      }
      {
        std::lock_guard lock(mtx);
        done = true;
      }
      cv.notify_all();
    });

  std::unique_lock<std::mutex> lock(mtx);
  cv.wait_for(lock, 3s, [&done] { return done; });

  ASSERT_TRUE(done) << "BrowseService did not complete within timeout";
  ASSERT_EQ(resultCount, 1u);
  EXPECT_TRUE(browseStatus.is_good());
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// P6d (interface refactor): Browse omits a reference whose LOCAL target the caller may not Browse
// (Part 3 section 4.8.3 + section 8.55 bit 0) - omission, not a per-reference error. Source has two forward
// references; Namespace policy denies Browse on exactly one target, which must vanish from the result
// while the other survives. Falsifiable: without the target-authz filter, both would be returned.
TEST(BrowseServiceTests, TargetTheCallerCannotBrowseIsOmitted)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://browse-filter-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  const NodeId source{nsIndex, 100};
  const NodeId allowed{nsIndex, 101};
  const NodeId denied{nsIndex, 102};
  ns->create_node(source, NodeClass::Object);
  ns->create_node(allowed, NodeClass::Object);
  ns->create_node(denied, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto sourceAccessor = addressSpace.try_find_node_sync(source);
  ASSERT_TRUE(sourceAccessor.is_good());
  sourceAccessor.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{allowed}, /*isForward=*/true);
  sourceAccessor.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{denied}, /*isForward=*/true);

  auto deniedAccessor = addressSpace.try_find_node_sync(denied);
  ASSERT_TRUE(deniedAccessor.is_good());
  ua::test_helpers::set_test_node_permissions(deniedAccessor.value(), PermissionType{});

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());

  BrowseRequest browseRequest;
  browseRequest.nodes_to_browse().resize(1);
  browseRequest.nodes_to_browse()[0].node_id() = source;
  browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;

  std::condition_variable cv;
  std::mutex mtx;
  bool done = false;
  size_t resultCount = 0;
  bool statusGood = false;
  bool hasAllowed = false;
  bool hasDenied = false;

  std::vector<LocaleId> locales{"en"};
  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [&, allowed, denied](BrowseService::BrowseServiceResponse response)
    {
      auto& browseResponse = dynamic_cast<BrowseResponse&>(*response.response.second);
      resultCount = browseResponse.results().size();
      if (resultCount == 1)
      {
        const auto& result0 = browseResponse.results().payload().front();
        statusGood = result0.status_code().is_good();
        for (const auto& reference : result0.references().payload())
        {
          const auto target = reference.node_id().node_id();
          if (target == allowed)
            hasAllowed = true;
          if (target == denied)
            hasDenied = true;
        }
      }
      {
        std::lock_guard lock(mtx);
        done = true;
      }
      cv.notify_all();
    });

  std::unique_lock<std::mutex> lock(mtx);
  cv.wait_for(lock, 3s, [&done] { return done; });

  ASSERT_TRUE(done) << "BrowseService did not complete within timeout";
  ASSERT_EQ(resultCount, 1u);
  EXPECT_TRUE(statusGood);
  EXPECT_TRUE(hasAllowed) << "the browseable target must be present";
  EXPECT_FALSE(hasDenied) << "the target the caller cannot Browse must be omitted from the result";
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 7.9: `requestedMaxReferencesPerNode` caps *every* response of that operation, not
// only the first, and whatever does not fit must be carried by a continuation point. A plausible
// implementation slices the first page to the client's maximum and then flushes the whole remainder
// on BrowseNext - which overruns exactly the buffer the client sized from the parameter, and drops
// the continuation point that would have paced the rest.
// @verifies AC-SVR-ATTR-CP-001-RESPECT-MAX-RESULTS
TEST(BrowseServiceTests, ContinuedBrowseReturnsNoMoreThanTheClientRequestedMaximum)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://browse-max-refs-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  // Five forward references behind a maximum of two: the first response is capped, and the
  // continuation still has three left - more than the maximum - so the cap must bind it too.
  const uint32_t maxReferencesPerNode = 2;
  const NodeId source{nsIndex, 300};
  ns->create_node(source, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto sourceAccessor = addressSpace.try_find_node_sync(source);
  ASSERT_TRUE(sourceAccessor.is_good());
  for (uint32_t i = 0; i < 5; ++i)
  {
    const NodeId target{nsIndex, 301 + i};
    ns->create_node(target, NodeClass::Object);
    sourceAccessor.value().try_add_reference_sync(
      NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{target}, /*isForward=*/true);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  std::vector<LocaleId> locales{"en"};

  // --- First Browse: establishes the cap and yields a continuation point ---
  BrowseRequest browseRequest;
  browseRequest.requested_max_references_per_node() = maxReferencesPerNode;
  browseRequest.nodes_to_browse().resize(1);
  browseRequest.nodes_to_browse()[0].node_id() = source;
  browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;

  std::condition_variable cv;
  std::mutex mtx;
  bool done = false;
  BrowseService::BrowseServiceResponse firstResponse;

  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [&cv, &mtx, &done, &firstResponse](BrowseService::BrowseServiceResponse response)
    {
      firstResponse = std::move(response);
      {
        std::lock_guard lock(mtx);
        done = true;
      }
      cv.notify_all();
    });

  {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait_for(lock, 3s, [&done] { return done; });
  }
  ASSERT_TRUE(done) << "BrowseService did not complete within timeout";

  auto* firstBrowseResponse = dynamic_cast<BrowseResponse*>(firstResponse.response.second.get());
  ASSERT_NE(firstBrowseResponse, nullptr);
  ASSERT_EQ(firstBrowseResponse->results().size(), 1u);
  const auto& firstResult = firstBrowseResponse->results().payload().front();
  ASSERT_TRUE(firstResult.status_code().is_good());
  const size_t firstReferenceCount = firstResult.references().size();
  ASSERT_GT(firstReferenceCount, 0u) << "the first Browse must return references to continue from";
  EXPECT_LE(firstReferenceCount, maxReferencesPerNode)
    << "the first response must not exceed requestedMaxReferencesPerNode";
  ASSERT_FALSE(firstResult.continuation_point().empty())
    << "references remain, so the first response must issue a continuation point";
  ASSERT_EQ(firstResponse.continuationPoints.size(), 1u);

  // --- BrowseNext: three references remain, still more than the maximum ---
  BrowseContinuationPoints continuationPoints;
  for (auto& cp : firstResponse.continuationPoints)
  {
    auto guid = cp.identifier();
    continuationPoints.emplace(guid, std::move(cp));
  }

  BrowseNextRequest browseNextRequest;
  browseNextRequest.release_continuation_points() = false;
  browseNextRequest.continuation_points().resize(1);
  browseNextRequest.continuation_points()[0] = firstResult.continuation_point();

  std::condition_variable cvNext;
  std::mutex mtxNext;
  bool doneNext = false;
  BrowseService::BrowseServiceResponse secondResponse;

  auto browseNextService = BrowseService::create(sessionInfo,
    locales,
    1,
    std::move(browseNextRequest),
    continuationPoints,
    threadPool.get_executor(),
    [&cvNext, &mtxNext, &doneNext, &secondResponse](BrowseService::BrowseServiceResponse response)
    {
      secondResponse = std::move(response);
      {
        std::lock_guard lock(mtxNext);
        doneNext = true;
      }
      cvNext.notify_all();
    });

  {
    std::unique_lock<std::mutex> lock(mtxNext);
    cvNext.wait_for(lock, 3s, [&doneNext] { return doneNext; });
  }
  ASSERT_TRUE(doneNext) << "BrowseNext did not complete within timeout";

  auto* nextResponse = dynamic_cast<BrowseNextResponse*>(secondResponse.response.second.get());
  ASSERT_NE(nextResponse, nullptr);
  ASSERT_EQ(nextResponse->results().size(), 1u);
  const auto& nextResult = nextResponse->results().payload().front();
  ASSERT_TRUE(nextResult.status_code().is_good()) << "continuing a live continuation point must succeed";
  const size_t nextReferenceCount = nextResult.references().size();
  ASSERT_GT(nextReferenceCount, 0u) << "the continuation must actually deliver the next slice";
  // Both conjuncts of the obligation: capped, and the rest is still paced by a continuation point.
  EXPECT_LE(nextReferenceCount, maxReferencesPerNode)
    << "a continued Browse must not return more than requestedMaxReferencesPerNode either";
  EXPECT_FALSE(nextResult.continuation_point().empty())
    << "references still remain after the continuation, so a further continuation point must be issued";
  EXPECT_EQ(secondResponse.continuationPoints.size(), 1u)
    << "the remainder must be retained server-side against the new continuation point";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// The page a Browse cuts at requestedMaxReferencesPerNode carries a continuation point whenever the
// node holds more matching references. Driven on the Objects folder - a namespace-0 node whose
// forward hierarchical references include one into another namespace, the shape every server's
// Objects folder has once an application adds its root folder - because the client_service_sets book
// example browses exactly that with a page size of 2 and was handed the cut page with no
// continuation point. The first Browse (no page limit) proves the premise: the node holds more
// references than the page. The service pages correctly (this arm is green); the example's folder
// sat in a namespace created without RolePermissions, which Browse hides from every Session.
// @verifies AC-SVR-VIEW-CPT-001-MAX-RESULTS-HONOURED
TEST(BrowseServiceTests, APageCutBelowTheObjectsFoldersHierarchicalReferencesCarriesAContinuationPoint)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto ns = default_ns::Namespace::create("uri://browse-objects-page", threadPool.get_executor());
  const uint16_t namespaceIndex = server.address_space().add_namespace_sync(ns);
  const NodeId plant{namespaceIndex, 900};
  ns->create_node(plant, NodeClass::Object);
  auto objects = server.address_space().try_find_node_sync(NodeId{ObjectId::ObjectsFolder});
  ASSERT_TRUE(objects.is_good());
  ASSERT_TRUE(
    objects.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{plant}, /*isForward=*/true)
      .is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  const std::vector<LocaleId> locales{"en"};
  auto browseObjects = [&](uint32_t maxReferencesPerNode, uint32_t requestId)
  {
    BrowseRequest request;
    request.requested_max_references_per_node() = maxReferencesPerNode;
    request.nodes_to_browse().resize(1);
    auto& description = request.nodes_to_browse()[0];
    description.node_id() = NodeId{ObjectId::ObjectsFolder};
    description.browse_direction() = BrowseDirection::Forward;
    description.reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
    description.include_subtypes() = true;
    description.node_class_mask() = 0;
    description.result_mask() = 0x3F;

    auto completion = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
    auto future = completion->get_future();
    [[maybe_unused]] auto service = BrowseService::create(sessionInfo,
      locales,
      requestId,
      std::move(request),
      threadPool.get_executor(),
      [completion](BrowseService::BrowseServiceResponse response)
      { completion->set_value(std::move(response)); });
    const auto waitStatus = future.wait_for(3s);
    EXPECT_EQ(waitStatus, std::future_status::ready) << "Browse did not complete within timeout";
    if (waitStatus != std::future_status::ready)
      return BrowseService::BrowseServiceResponse{};
    return future.get();
  };

  auto whole = browseObjects(0, 0);
  auto* wholeBrowse = dynamic_cast<BrowseResponse*>(whole.response.second.get());
  ASSERT_NE(wholeBrowse, nullptr);
  ASSERT_EQ(wholeBrowse->results().size(), 1u);
  ASSERT_TRUE(wholeBrowse->results()[0].status_code().is_good());
  ASSERT_GE(wholeBrowse->results()[0].references().size(), 3u)
    << "premise: the Objects folder holds more forward hierarchical references than the page below";

  auto page = browseObjects(2, 1);
  auto* pageBrowse = dynamic_cast<BrowseResponse*>(page.response.second.get());
  ASSERT_NE(pageBrowse, nullptr);
  ASSERT_EQ(pageBrowse->results().size(), 1u);
  ASSERT_TRUE(pageBrowse->results()[0].status_code().is_good());
  EXPECT_EQ(pageBrowse->results()[0].references().size(), 2u);
  EXPECT_FALSE(pageBrowse->results()[0].continuation_point().empty())
    << "the page was cut below the node's references and must carry a continuation point";
  EXPECT_EQ(page.continuationPoints.size(), 1u);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.8.3.2 permits one BrowseNext request to mix continuation points issued by
// different earlier responses. Distinct target ranges make a dropped, reordered, or cross-wired
// point observable instead of merely checking the result count.
// @relation(AC-SVR-VIEW-BNX-005-MIXED-RESPONSE-CONTINUATIONS, scope=function)
TEST(BrowseServiceTests, BrowseNextAdvancesContinuationPointsFromSeparateBrowseResponsesIndependently)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto ns =
    default_ns::Namespace::create("uri://browse-mixed-continuation-points", threadPool.get_executor());
  const uint16_t namespaceIndex = server.address_space().add_namespace_sync(ns);

  const NodeId firstSource{namespaceIndex, 410};
  const NodeId secondSource{namespaceIndex, 420};
  ns->create_node(firstSource, NodeClass::Object);
  ns->create_node(secondSource, NodeClass::Object);

  std::vector<NodeId> firstTargets;
  std::vector<NodeId> secondTargets;
  auto addressSpace = server.address_space();
  auto firstSourceResult = addressSpace.try_find_node_sync(firstSource);
  auto secondSourceResult = addressSpace.try_find_node_sync(secondSource);
  ASSERT_TRUE(firstSourceResult.is_good());
  ASSERT_TRUE(secondSourceResult.is_good());
  for (uint32_t offset = 0; offset < 3; ++offset)
  {
    firstTargets.emplace_back(namespaceIndex, 411 + offset);
    secondTargets.emplace_back(namespaceIndex, 421 + offset);
    ns->create_node(firstTargets.back(), NodeClass::Object);
    ns->create_node(secondTargets.back(), NodeClass::Object);
    ASSERT_TRUE(firstSourceResult.value()
                  .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes},
                    ExpandedNodeId{firstTargets.back()},
                    /*isForward=*/true)
                  .is_good());
    ASSERT_TRUE(secondSourceResult.value()
                  .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes},
                    ExpandedNodeId{secondTargets.back()},
                    /*isForward=*/true)
                  .is_good());
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  const std::vector<LocaleId> locales{"en"};
  auto issueBrowse = [&](const NodeId& source, uint32_t requestId)
  {
    BrowseRequest request;
    request.requested_max_references_per_node() = 1;
    request.nodes_to_browse().resize(1);
    request.nodes_to_browse()[0].node_id() = source;
    request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;

    auto completion = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
    auto future = completion->get_future();
    [[maybe_unused]] auto service = BrowseService::create(sessionInfo,
      locales,
      requestId,
      std::move(request),
      threadPool.get_executor(),
      [completion](BrowseService::BrowseServiceResponse response)
      { completion->set_value(std::move(response)); });
    const auto waitStatus = future.wait_for(3s);
    EXPECT_EQ(waitStatus, std::future_status::ready) << "Browse did not complete within timeout";
    if (waitStatus != std::future_status::ready)
      return BrowseService::BrowseServiceResponse{};
    return future.get();
  };

  auto firstResponse = issueBrowse(firstSource, 0);
  auto secondResponse = issueBrowse(secondSource, 1);
  auto* firstBrowse = dynamic_cast<BrowseResponse*>(firstResponse.response.second.get());
  auto* secondBrowse = dynamic_cast<BrowseResponse*>(secondResponse.response.second.get());
  ASSERT_NE(firstBrowse, nullptr);
  ASSERT_NE(secondBrowse, nullptr);
  ASSERT_EQ(firstBrowse->results().size(), 1u);
  ASSERT_EQ(secondBrowse->results().size(), 1u);
  ASSERT_TRUE(firstBrowse->results()[0].status_code().is_good());
  ASSERT_TRUE(secondBrowse->results()[0].status_code().is_good());
  ASSERT_EQ(firstBrowse->results()[0].references().size(), 1u);
  ASSERT_EQ(secondBrowse->results()[0].references().size(), 1u);
  ASSERT_FALSE(firstBrowse->results()[0].continuation_point().empty());
  ASSERT_FALSE(secondBrowse->results()[0].continuation_point().empty());
  EXPECT_NE(firstBrowse->results()[0].continuation_point(), secondBrowse->results()[0].continuation_point());
  ASSERT_EQ(firstResponse.continuationPoints.size(), 1u);
  ASSERT_EQ(secondResponse.continuationPoints.size(), 1u);

  BrowseContinuationPoints continuationPoints;
  for (auto& point : firstResponse.continuationPoints)
  {
    const auto identifier = point.identifier();
    ASSERT_TRUE(continuationPoints.emplace(identifier, std::move(point)).second);
  }
  for (auto& point : secondResponse.continuationPoints)
  {
    const auto identifier = point.identifier();
    ASSERT_TRUE(continuationPoints.emplace(identifier, std::move(point)).second);
  }

  BrowseNextRequest request;
  request.release_continuation_points() = false;
  request.continuation_points().push_back(firstBrowse->results()[0].continuation_point());
  request.continuation_points().push_back(secondBrowse->results()[0].continuation_point());

  auto completion = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
  auto future = completion->get_future();
  [[maybe_unused]] auto service = BrowseService::create(sessionInfo,
    locales,
    2,
    std::move(request),
    continuationPoints,
    threadPool.get_executor(),
    [completion](BrowseService::BrowseServiceResponse response)
    { completion->set_value(std::move(response)); });
  ASSERT_EQ(future.wait_for(3s), std::future_status::ready) << "BrowseNext did not complete within timeout";
  auto continuedResponse = future.get();
  auto* browseNext = dynamic_cast<BrowseNextResponse*>(continuedResponse.response.second.get());
  ASSERT_NE(browseNext, nullptr);
  ASSERT_EQ(browseNext->results().size(), 2u);

  const auto belongsTo = [](const NodeId& target, const std::vector<NodeId>& expected)
  {
    return std::ranges::find(expected, target) != expected.end();
  };
  for (size_t index = 0; index < 2; ++index)
  {
    ASSERT_TRUE(browseNext->results()[index].status_code().is_good()) << "continuation point index " << index;
    ASSERT_EQ(browseNext->results()[index].references().size(), 1u) << "continuation point index " << index;
  }
  const auto firstContinuedTarget = browseNext->results()[0].references()[0].node_id().node_id();
  const auto secondContinuedTarget = browseNext->results()[1].references()[0].node_id().node_id();
  EXPECT_TRUE(belongsTo(firstContinuedTarget, firstTargets));
  EXPECT_FALSE(belongsTo(firstContinuedTarget, secondTargets));
  EXPECT_TRUE(belongsTo(secondContinuedTarget, secondTargets));
  EXPECT_FALSE(belongsTo(secondContinuedTarget, firstTargets));

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.8.2: a Browse in a View context may only start from a Node contained in that
// View. The two operations below share one valid View: the member is the control, while the outside
// Node points at that member so a target-only View filter would return a plausible Good result.
// @relation(AC-SVR-VIEW-BRW-001-NODE-IN-VIEW, scope=function)
TEST(BrowseServiceTests, StartingNodeOutsideSuppliedViewReturnsRichBadNodeNotInView)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://browse-source-view-membership", threadPool.get_executor());
  const uint16_t namespaceIndex = server.address_space().add_namespace_sync(ns);
  const NodeId viewId{namespaceIndex, 390};
  const NodeId memberId{namespaceIndex, 391};
  const NodeId outsideId{namespaceIndex, 392};
  ns->create_node(viewId, NodeClass::View);
  ns->create_node(memberId, NodeClass::Object);
  ns->create_node(outsideId, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto viewResult = addressSpace.try_find_node_sync(viewId);
  ASSERT_TRUE(viewResult.is_good());
  auto view = viewResult.value().as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(memberId).is_good());

  auto outsideResult = addressSpace.try_find_node_sync(outsideId);
  ASSERT_TRUE(outsideResult.is_good());
  ASSERT_TRUE(outsideResult.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes},
                  ExpandedNodeId{memberId},
                  /*isForward=*/true)
                .is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  BrowseRequest browseRequest;
  browseRequest.view().view_id() = viewId;
  browseRequest.nodes_to_browse().resize(2);
  browseRequest.nodes_to_browse()[0].node_id() = memberId;
  browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Both;
  browseRequest.nodes_to_browse()[1].node_id() = outsideId;
  browseRequest.nodes_to_browse()[1].browse_direction() = BrowseDirection::Both;

  std::condition_variable completionCondition;
  std::mutex completionMutex;
  bool completed = false;
  BrowseService::BrowseServiceResponse serviceResponse;
  std::vector<LocaleId> locales{"en"};
  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [&completionCondition, &completionMutex, &completed, &serviceResponse](
      BrowseService::BrowseServiceResponse response)
    {
      serviceResponse = std::move(response);
      {
        std::lock_guard lock(completionMutex);
        completed = true;
      }
      completionCondition.notify_all();
    });

  {
    std::unique_lock lock(completionMutex);
    completionCondition.wait_for(lock, 3s, [&completed] { return completed; });
  }

  ASSERT_TRUE(completed) << "BrowseService did not complete within timeout";
  auto* response = dynamic_cast<BrowseResponse*>(serviceResponse.response.second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_TRUE(response->results()[0].status_code().is_good())
    << "control: the member Node must remain browsable in the supplied View";
  const auto& outsideBrowse = response->results()[1];
  EXPECT_EQ(outsideBrowse.status_code(), StatusCode{Status::BadNodeNotInView});
  ASSERT_NE(outsideBrowse.status_code().shared_detail(), nullptr)
    << "the per-operation status must retain the ErrorDetail in its single rich StatusCode carrier";
  EXPECT_EQ(outsideBrowse.status_code().shared_detail()->code, "NodeNotInView");
  EXPECT_TRUE(outsideBrowse.references().empty())
    << "a rejected source Node must not leak references from the whole address space";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 3 section 5.4: every Node contained in a View shall be accessible starting from the View Node
// when browsing in the context of that View. Browsing is the only way to enumerate a View, so a
// member reachable by NodeId but not by browsing is invisible to any client that did not already
// know it was there. A plausible implementation applies the View filter to the direct references of
// the View Node only, or lets the membership test drop a member found deeper in the hierarchy, and
// then silently hides part of the View.
// @verifies AC-SVR-ADDRSP-075-VIEW-MEMBERS-REACHABLE
TEST(BrowseServiceTests, EveryViewMemberIsReachableByBrowsingFromTheViewNode)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://view-members-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  // View graph: View -> directMemberA -> nestedMemberC, and View -> directMemberB. All three
  // objects are logical members of the View; the nested one is only reachable by continuing the
  // browse past the View Node's own references.
  const NodeId viewId{nsIndex, 400};
  const NodeId directMemberA{nsIndex, 401};
  const NodeId directMemberB{nsIndex, 402};
  const NodeId nestedMemberC{nsIndex, 403};

  ns->create_node(viewId, NodeClass::View);
  ns->create_node(directMemberA, NodeClass::Object);
  ns->create_node(directMemberB, NodeClass::Object);
  ns->create_node(nestedMemberC, NodeClass::Object);

  auto addressSpace = server.address_space();

  auto viewNodeResult = addressSpace.try_find_node_sync(viewId);
  ASSERT_TRUE(viewNodeResult.is_good());
  viewNodeResult.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{directMemberA}, /*isForward=*/true);
  viewNodeResult.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{directMemberB}, /*isForward=*/true);

  auto memberAResult = addressSpace.try_find_node_sync(directMemberA);
  ASSERT_TRUE(memberAResult.is_good());
  memberAResult.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{nestedMemberC}, /*isForward=*/true);

  // The logical membership set of the View. The View Node is entered as a member of itself so that
  // a source-in-View gate on the browsed Node cannot confound the reachability question asked here.
  auto viewAccessor = viewNodeResult.value().as<ViewAccessor>();
  ASSERT_TRUE(viewAccessor.has_value());
  ASSERT_TRUE(viewAccessor->try_add_node_to_view_sync(viewId).is_good());
  ASSERT_TRUE(viewAccessor->try_add_node_to_view_sync(directMemberA).is_good());
  ASSERT_TRUE(viewAccessor->try_add_node_to_view_sync(directMemberB).is_good());
  ASSERT_TRUE(viewAccessor->try_add_node_to_view_sync(nestedMemberC).is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  std::vector<LocaleId> locales{"en"};

  bool everyBrowseCompleted = true;
  bool everyBrowseGood = true;

  // One Browse in the context of the View, returning the targets it exposes.
  auto browseInViewContext = [&](const NodeId& startNode)
  {
    struct BrowseCapture
    {
      std::mutex mutex;
      std::condition_variable ready;
      bool done{false};
      bool statusGood{false};
      std::vector<NodeId> targets;
    };

    BrowseRequest browseRequest;
    browseRequest.view().view_id() = viewId;
    browseRequest.nodes_to_browse().resize(1);
    browseRequest.nodes_to_browse()[0].node_id() = startNode;
    browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;

    auto capture = std::make_shared<BrowseCapture>();

    auto browseService = BrowseService::create(sessionInfo,
      locales,
      0,
      std::move(browseRequest),
      threadPool.get_executor(),
      [capture](BrowseService::BrowseServiceResponse response)
      {
        const std::lock_guard lock(capture->mutex);
        auto& browseResponse = dynamic_cast<BrowseResponse&>(*response.response.second);
        if (browseResponse.results().size() == 1)
        {
          const auto& result0 = browseResponse.results().payload().front();
          capture->statusGood = result0.status_code().is_good();
          for (const auto& reference : result0.references().payload())
          {
            capture->targets.push_back(reference.node_id().node_id());
          }
        }
        capture->done = true;
        capture->ready.notify_all();
      });

    bool completed = false;
    bool statusGood = false;
    std::vector<NodeId> targets;
    {
      std::unique_lock<std::mutex> lock(capture->mutex);
      completed = capture->ready.wait_for(lock, 3s, [&capture] { return capture->done; });
      statusGood = capture->statusGood;
      targets = capture->targets;
    }
    EXPECT_TRUE(completed) << "BrowseService did not complete within timeout";
    EXPECT_TRUE(statusGood) << "browsing a View member in the View's context must succeed";
    if (!completed)
      everyBrowseCompleted = false;
    if (!statusGood)
      everyBrowseGood = false;
    return targets;
  };

  auto contains = [](const std::vector<NodeId>& haystack, const NodeId& needle)
  {
    for (const auto& entry : haystack)
    {
      if (entry == needle)
        return true;
    }
    return false;
  };

  // Walk the View from the View Node, following only what browsing in the View's context exposes.
  std::vector<NodeId> reached;
  std::vector<NodeId> visited;
  std::vector<NodeId> frontier{viewId};
  size_t viewNodeReferenceCount = 0;
  bool measuredViewNode = false;

  while (!frontier.empty())
  {
    const NodeId current = frontier.front();
    frontier.erase(frontier.begin());
    if (contains(visited, current))
      continue;
    visited.push_back(current);

    auto targets = browseInViewContext(current);
    if (!measuredViewNode)
    {
      viewNodeReferenceCount = targets.size();
      measuredViewNode = true;
    }
    for (const auto& target : targets)
    {
      if (!contains(reached, target))
        reached.push_back(target);
      frontier.push_back(target);
    }
  }

  ASSERT_TRUE(everyBrowseCompleted) << "a browse in the View's context did not complete";
  ASSERT_GT(viewNodeReferenceCount, 0u)
    << "browsing the View Node in its own context must expose the View's contents";
  EXPECT_TRUE(everyBrowseGood);
  EXPECT_TRUE(contains(reached, directMemberA))
    << "a direct member of the View must be reachable by browsing from the View Node";
  EXPECT_TRUE(contains(reached, directMemberB))
    << "a direct member of the View must be reachable by browsing from the View Node";
  EXPECT_TRUE(contains(reached, nestedMemberC))
    << "a nested member of the View must be reachable by browsing from the View Node - the View must "
       "not hide it";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 3 section 5.4: the View Node is the root for the Nodes in the View, and every member is accessible
// starting from it when browsing in the View's context. NR-16 rule 6: a View Node is always a member of its
// own View, so neither a namespace nor an application adds it. The View here has only its two Objects as
// members; the non-member operation in the same request shows the membership check still refuses.
// @relation(AC-SVR-ADDRSP-075-VIEW-NODE-IN-ITS-OWN-VIEW, scope=function)
TEST(ViewMembership, TheViewNodeIsAMemberOfItsOwnView)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://view-node-membership-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId viewId{nsIndex, 410};
  const NodeId memberA{nsIndex, 411};
  const NodeId memberB{nsIndex, 412};
  const NodeId nonMember{nsIndex, 413};
  ns->create_node(viewId, NodeClass::View);
  ns->create_node(memberA, NodeClass::Object);
  ns->create_node(memberB, NodeClass::Object);
  ns->create_node(nonMember, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto viewNode = addressSpace.try_find_node_sync(viewId);
  ASSERT_TRUE(viewNode.is_good());
  ASSERT_TRUE(viewNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{memberA}, true)
                .is_good());
  ASSERT_TRUE(viewNode.value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{memberB}, true)
                .is_good());
  auto view = viewNode.value().as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(memberA).is_good());
  ASSERT_TRUE(view->try_add_node_to_view_sync(memberB).is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  std::vector<LocaleId> locales{"en"};

  BrowseRequest browseRequest;
  browseRequest.view().view_id() = viewId;
  browseRequest.nodes_to_browse().resize(2);
  browseRequest.nodes_to_browse()[0].node_id() = viewId;
  browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
  browseRequest.nodes_to_browse()[1].node_id() = nonMember;
  browseRequest.nodes_to_browse()[1].browse_direction() = BrowseDirection::Forward;

  struct BrowseCapture
  {
    std::mutex mutex;
    std::condition_variable ready;
    bool done{false};
    std::vector<Status> statuses;
    std::vector<NodeId> viewNodeTargets;
  };

  auto capture = std::make_shared<BrowseCapture>();
  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [capture](BrowseService::BrowseServiceResponse response)
    {
      const std::lock_guard lock(capture->mutex);
      auto& browseResponse = dynamic_cast<BrowseResponse&>(*response.response.second);
      for (const auto& result : browseResponse.results().payload())
      {
        capture->statuses.push_back(result.status_code().as_status());
      }
      if (!browseResponse.results().payload().empty())
      {
        for (const auto& reference : browseResponse.results().payload().front().references().payload())
        {
          capture->viewNodeTargets.push_back(reference.node_id().node_id());
        }
      }
      capture->done = true;
      capture->ready.notify_all();
    });

  std::unique_lock<std::mutex> lock(capture->mutex);
  ASSERT_TRUE(capture->ready.wait_for(lock, 3s, [&capture] { return capture->done; }))
    << "BrowseService did not complete within timeout";
  ASSERT_EQ(capture->statuses.size(), 2u);
  EXPECT_EQ(capture->statuses[0], Status::Good)
    << "browsing the View Node in the context of its own View was refused";
  EXPECT_EQ(capture->statuses[1], Status::BadNodeNotInView)
    << "a Node that is not a member of the View was browsed in its context";
  EXPECT_EQ(capture->viewNodeTargets.size(), 2u);
  EXPECT_NE(std::find(capture->viewNodeTargets.begin(), capture->viewNodeTargets.end(), memberA),
    capture->viewNodeTargets.end());
  EXPECT_NE(std::find(capture->viewNodeTargets.begin(), capture->viewNodeTargets.end(), memberB),
    capture->viewNodeTargets.end());
  lock.unlock();

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

namespace
{
// What one Browse operation of the View-membership arms answered.
struct ViewBrowseOutcome
{
  Status status{Status::Good};
  std::vector<ReferenceDescription> references;
};

// Browses @p operations in one request in the context of @p viewId and returns one outcome per operation,
// or an empty vector when the service does not answer within three seconds.
std::vector<ViewBrowseOutcome> browse_in_view_context(const shared_ptr<SessionInfoStub>& sessionInfo,
  boost::asio::thread_pool& threadPool, const NodeId& viewId,
  const std::vector<BrowseDescription>& operations)
{
  BrowseRequest browseRequest;
  browseRequest.view().view_id() = viewId;
  browseRequest.nodes_to_browse().resize(operations.size());
  for (size_t i = 0; i < operations.size(); ++i)
    browseRequest.nodes_to_browse()[i] = operations[i];

  struct BrowseCapture
  {
    std::mutex mutex;
    std::condition_variable ready;
    bool done{false};
    std::vector<ViewBrowseOutcome> outcomes;
  };

  auto capture = std::make_shared<BrowseCapture>();
  std::vector<LocaleId> locales{"en"};
  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [capture](BrowseService::BrowseServiceResponse response)
    {
      const std::lock_guard lock(capture->mutex);
      auto& browseResponse = dynamic_cast<BrowseResponse&>(*response.response.second);
      for (const auto& result : browseResponse.results().payload())
      {
        ViewBrowseOutcome outcome{.status = result.status_code().as_status()};
        for (const auto& reference : result.references().payload())
          outcome.references.push_back(reference);
        capture->outcomes.push_back(std::move(outcome));
      }
      capture->done = true;
      capture->ready.notify_all();
    });

  std::unique_lock<std::mutex> lock(capture->mutex);
  if (!capture->ready.wait_for(lock, 3s, [&capture] { return capture->done; }))
    return {};
  return capture->outcomes;
}

// An operation of a Browse request that follows @p referenceType from @p node in @p direction and returns
// every field of each Reference.
BrowseDescription view_browse_operation(
  const NodeId& node, BrowseDirection direction, const NodeId& referenceType, bool includeSubtypes)
{
  BrowseDescription description;
  description.node_id() = node;
  description.browse_direction() = direction;
  description.reference_type_id() = referenceType;
  description.include_subtypes() = includeSubtypes;
  description.node_class_mask() = 0;
  description.result_mask() = 0x3F;
  return description;
}
}  // namespace

// Part 3 section 5.4: every Node in a View is accessible starting from the View Node when browsing in the
// context of the View. NR-16 rule 6 makes a View Node a member of its own View, and NR-41 applies the rule to
// the target of each Reference as well as to the starting Node. V's members are O1 and O2 and not its View
// Node. Browsed Inverse in V's context, O1 shows its Organizes Reference to V's View Node, for the
// ReferenceType given exactly and for HierarchicalReferences with its subtypes. The Objects folder also
// organizes O1 and is not a member of V: the control that the target filter still omits a non-member.
// @relation(AC-SVR-ADDRSP-075-REFERENCE-TO-VIEW-NODE-KEPT, scope=function)
TEST(ViewMembership, AReferenceToTheViewNodeIsKeptInItsOwnView)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://reference-to-view-node-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId viewId{nsIndex, 430};
  const NodeId o1{nsIndex, 431};
  const NodeId o2{nsIndex, 432};
  const NodeId objectsFolder{ObjectId::ObjectsFolder};
  const NodeId organizes{ReferenceTypeId::Organizes};
  ns->create_node(viewId, NodeClass::View);
  ns->create_node(o1, NodeClass::Object);
  ns->create_node(o2, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto viewNode = addressSpace.try_find_node_sync(viewId);
  auto o1Node = addressSpace.try_find_node_sync(o1);
  auto folderNode = addressSpace.try_find_node_sync(objectsFolder);
  ASSERT_TRUE(viewNode.is_good());
  ASSERT_TRUE(o1Node.is_good());
  ASSERT_TRUE(folderNode.is_good());
  ASSERT_TRUE(viewNode.value().try_add_reference_sync(organizes, ExpandedNodeId{o1}, true).is_good());
  ASSERT_TRUE(viewNode.value().try_add_reference_sync(organizes, ExpandedNodeId{o2}, true).is_good());
  ASSERT_TRUE(o1Node.value().try_add_reference_sync(organizes, ExpandedNodeId{viewId}, false).is_good());
  ASSERT_TRUE(folderNode.value().try_add_reference_sync(organizes, ExpandedNodeId{o1}, true).is_good());
  ASSERT_TRUE(
    o1Node.value().try_add_reference_sync(organizes, ExpandedNodeId{objectsFolder}, false).is_good());
  auto view = viewNode.value().as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(o1).is_good());
  ASSERT_TRUE(view->try_add_node_to_view_sync(o2).is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  const auto outcomes = browse_in_view_context(sessionInfo,
    threadPool,
    viewId,
    {view_browse_operation(o1, BrowseDirection::Inverse, organizes, false),
      view_browse_operation(
        o1, BrowseDirection::Inverse, NodeId{ReferenceTypeId::HierarchicalReferences}, true)});

  ASSERT_EQ(outcomes.size(), 2u) << "BrowseService did not answer both operations within the timeout";
  const char* const referenceTypes[]{"Organizes", "HierarchicalReferences with its subtypes"};
  for (size_t i = 0; i < outcomes.size(); ++i)
  {
    SCOPED_TRACE(referenceTypes[i]);
    EXPECT_EQ(outcomes[i].status, Status::Good);
    EXPECT_EQ(outcomes[i].references.size(), 1u)
      << "exactly the Reference to the View Node, and not the one from the Objects folder";
    if (outcomes[i].references.size() != 1u)
      continue;
    const auto& reference = outcomes[i].references.front();
    EXPECT_EQ(reference.node_id().node_id(), viewId)
      << "the Reference kept is not the one to the View's View Node";
    EXPECT_EQ(reference.reference_type_id(), organizes);
    EXPECT_FALSE(reference.is_forward());
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 3 section 5.4 makes the View Node the root of its View. NR-16 rule 6: "A View Node is always a member
// of its own View". The exemption is for the View the request names, not for any View Node, so a View Node of
// another View is a member only if the View contains it, both as the Node to browse and as the target of a
// Reference. V2's View Node is not among V's members and organizes O1, a member of V. Browsed in V's context,
// V2's View Node is refused and shows no Reference; O1 browsed forward in the same request is the control
// that the members are still browsed; O1 browsed Inverse shows its Organizes Reference from V's View Node,
// kept by the exemption, and not the one from V2's View Node. Each operation fails if its exemption is
// widened to every View Node.
// @relation(AC-SVR-ADDRSP-075-ANOTHER-VIEW-NODE-NOT-A-MEMBER, scope=function)
TEST(ViewMembership, AnotherViewsNodeIsNotAMemberOfTheView)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://another-view-node-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId viewId{nsIndex, 440};
  const NodeId o1{nsIndex, 441};
  const NodeId o2{nsIndex, 442};
  const NodeId otherViewId{nsIndex, 443};
  const NodeId organizes{ReferenceTypeId::Organizes};
  ns->create_node(viewId, NodeClass::View);
  ns->create_node(o1, NodeClass::Object);
  ns->create_node(o2, NodeClass::Object);
  ns->create_node(otherViewId, NodeClass::View);

  auto addressSpace = server.address_space();
  auto viewNode = addressSpace.try_find_node_sync(viewId);
  auto otherViewNode = addressSpace.try_find_node_sync(otherViewId);
  ASSERT_TRUE(viewNode.is_good());
  ASSERT_TRUE(otherViewNode.is_good());
  ASSERT_TRUE(viewNode.value().try_add_reference_sync(organizes, ExpandedNodeId{o1}, true).is_good());
  ASSERT_TRUE(viewNode.value().try_add_reference_sync(organizes, ExpandedNodeId{o2}, true).is_good());
  ASSERT_TRUE(otherViewNode.value().try_add_reference_sync(organizes, ExpandedNodeId{o1}, true).is_good());
  auto o1Node = addressSpace.try_find_node_sync(o1);
  ASSERT_TRUE(o1Node.is_good());
  ASSERT_TRUE(o1Node.value().try_add_reference_sync(organizes, ExpandedNodeId{viewId}, false).is_good());
  ASSERT_TRUE(o1Node.value().try_add_reference_sync(organizes, ExpandedNodeId{otherViewId}, false).is_good());
  auto view = viewNode.value().as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(o1).is_good());
  ASSERT_TRUE(view->try_add_node_to_view_sync(o2).is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  const auto outcomes = browse_in_view_context(sessionInfo,
    threadPool,
    viewId,
    {view_browse_operation(otherViewId, BrowseDirection::Forward, organizes, false),
      view_browse_operation(o1, BrowseDirection::Forward, organizes, false),
      view_browse_operation(o1, BrowseDirection::Inverse, organizes, false)});

  ASSERT_EQ(outcomes.size(), 3u) << "BrowseService did not answer the three operations within the timeout";
  EXPECT_EQ(outcomes[0].status, Status::BadNodeNotInView)
    << "another View's View Node was browsed in the context of a View that does not contain it";
  EXPECT_TRUE(outcomes[0].references.empty())
    << "the refused operation returned " << outcomes[0].references.size() << " References";
  EXPECT_EQ(outcomes[1].status, Status::Good) << "a member of the View was not browsed in its context";
  EXPECT_EQ(outcomes[2].status, Status::Good);
  ASSERT_EQ(outcomes[2].references.size(), 1u) << "O1 browsed Inverse in V's context must show exactly its "
                                                  "Organizes Reference from V's View Node, and not "
                                                  "the one from V2's View Node, which V does not contain";
  const auto& inverse = outcomes[2].references.front();
  EXPECT_EQ(inverse.node_id().node_id(), viewId) << "the Reference shown is not the one to V's View Node";
  EXPECT_EQ(inverse.reference_type_id(), organizes);
  EXPECT_FALSE(inverse.is_forward());

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// DL-36: a Browse in a View's context resolves a target given by namespace URI before checking it, leaves out
// a target in another Server, and answers Uncertain_NotAllNodesAvailable when the View's namespace cannot say
// whether a target is a member.
namespace
{
// What one Browse operation answered, with the operation's DiagnosticInfo as the Client would read it.
struct DiagnosedBrowseOutcome
{
  StatusCode status;
  std::vector<ReferenceDescription> references;
  std::string symbolicId;
  std::string additionalInfo;
};

// Browses @p operations in one request with operation-level diagnostics, in the context of @p viewId (a null
// NodeId for no View). Returns one outcome per operation, or an empty vector when the service does not answer
// within three seconds. The session must have had enable_operation_diagnostics() called.
std::vector<DiagnosedBrowseOutcome> browse_with_diagnostics(const shared_ptr<SessionInfoStub>& sessionInfo,
  boost::asio::thread_pool& threadPool, const NodeId& viewId,
  const std::vector<BrowseDescription>& operations)
{
  BrowseRequest browseRequest;
  browseRequest.request_header().return_diagnostics() = diag::operationLevelMask;
  browseRequest.view().view_id() = viewId;
  browseRequest.nodes_to_browse().resize(operations.size());
  for (size_t i = 0; i < operations.size(); ++i)
    browseRequest.nodes_to_browse()[i] = operations[i];

  struct BrowseCapture
  {
    std::mutex mutex;
    std::condition_variable ready;
    bool done{false};
    std::vector<DiagnosedBrowseOutcome> outcomes;
  };

  auto capture = std::make_shared<BrowseCapture>();
  std::vector<LocaleId> locales{"en"};
  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [capture](BrowseService::BrowseServiceResponse response)
    {
      const std::lock_guard lock(capture->mutex);
      auto& browseResponse = dynamic_cast<BrowseResponse&>(*response.response.second);
      const auto& strings = browseResponse.response_header().string_table();
      const auto& diagnostics = browseResponse.diagnostic_infos().payload();
      size_t index = 0;
      for (const auto& result : browseResponse.results().payload())
      {
        DiagnosedBrowseOutcome outcome{.status = result.status_code()};
        for (const auto& reference : result.references().payload())
          outcome.references.push_back(reference);
        if (index < diagnostics.size())
        {
          const auto symbolic = diagnostics[index].symbolic_id();
          if (symbolic.has_value() && *symbolic >= 0 && static_cast<size_t>(*symbolic) < strings.size())
            outcome.symbolicId = std::string{strings[static_cast<size_t>(*symbolic)]};
          if (diagnostics[index].additional_info().has_value())
            outcome.additionalInfo = std::string{*diagnostics[index].additional_info()};
        }
        capture->outcomes.push_back(std::move(outcome));
        ++index;
      }
      capture->done = true;
      capture->ready.notify_all();
    });

  std::unique_lock<std::mutex> lock(capture->mutex);
  if (!capture->ready.wait_for(lock, 3s, [&capture] { return capture->done; }))
    return {};
  return capture->outcomes;
}

// The targets of @p references, as returned.
std::vector<ExpandedNodeId> targets_of(const std::vector<ReferenceDescription>& references)
{
  std::vector<ExpandedNodeId> targets;
  for (const auto& reference : references)
    targets.push_back(reference.node_id());
  return targets;
}

// The ErrorDetail code a StatusCode carries, or an empty string.
std::string detail_code(const StatusCode& status)
{
  return status.shared_detail() ? std::string{status.shared_detail()->code} : std::string{};
}

// A server with the default namespace "uri://<name>" registered; its index is stored in @p nsIndex.
ua::server::Server create_server_with_namespace(
  boost::asio::thread_pool& threadPool, const std::shared_ptr<default_ns::Namespace>& ns, uint16_t& nsIndex)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  nsIndex = server.address_space().add_namespace_sync(ns);
  return server;
}
}  // namespace

// Part 4 section 5.8.2.2, Table 34: in a View's context only the References defined for that View are
// returned; Part 4 section 7.30, Table 172: a local target's nodeId "shall contain the namespace index". A
// target given by namespace URI and the same target given by index are one Node, so DL-36 point 1 resolves
// the URI before any target check. S holds Organizes References to M, N and V's View Node given by namespace
// URI, and to M2 given by index. M and M2 are members, V's View Node is kept by F8's rule, and N is not a
// member: the control that a target given by URI is still checked. Every Reference returned is in index form.
// @relation(AC-SVR-ADDRSP-075-URI-FORM-TARGET-CHECKED-AS-INDEX, scope=function)
TEST(ViewMembership, AUriFormTargetIsCheckedAsItsIndexForm)
{
  boost::asio::thread_pool threadPool;
  const std::string nsUri{"uri://uri-form-target-ns"};
  auto ns = default_ns::Namespace::create(nsUri, threadPool.get_executor());
  uint16_t nsIndex = 0;
  auto server = create_server_with_namespace(threadPool, ns, nsIndex);
  const NodeId viewId{nsIndex, 450};
  const NodeId s{nsIndex, 451};
  const NodeId m{nsIndex, 452};
  const NodeId m2{nsIndex, 453};
  const NodeId n{nsIndex, 454};
  const NodeId organizes{ReferenceTypeId::Organizes};
  ns->create_node(viewId, NodeClass::View);
  for (const auto& id : {s, m, m2, n})
    ns->create_node(id, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto viewNode = addressSpace.try_find_node_sync(viewId);
  auto sNode = addressSpace.try_find_node_sync(s);
  ASSERT_TRUE(viewNode.is_good());
  ASSERT_TRUE(sNode.is_good());
  ASSERT_TRUE(viewNode.value().try_add_reference_sync(organizes, ExpandedNodeId{s}, true).is_good());
  const ExpandedNodeId byUri[]{ExpandedNodeId{NodeId{uint16_t{0}, uint32_t{452}}, nsUri},
    ExpandedNodeId{NodeId{uint16_t{0}, uint32_t{454}}, nsUri},
    ExpandedNodeId{NodeId{uint16_t{0}, uint32_t{450}}, nsUri}};
  for (const auto& target : byUri)
    ASSERT_TRUE(sNode.value().try_add_reference_sync(organizes, target, true).is_good()) << to_string(target);
  ASSERT_TRUE(sNode.value().try_add_reference_sync(organizes, ExpandedNodeId{m2}, true).is_good());
  auto view = viewNode.value().as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  for (const auto& member : {s, m, m2})
    ASSERT_TRUE(view->try_add_node_to_view_sync(member).is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  const auto outcomes = browse_in_view_context(
    sessionInfo, threadPool, viewId, {view_browse_operation(s, BrowseDirection::Forward, organizes, false)});

  ASSERT_EQ(outcomes.size(), 1u) << "BrowseService did not answer within the timeout";
  EXPECT_EQ(outcomes[0].status, Status::Good);
  const auto targets = targets_of(outcomes[0].references);
  EXPECT_EQ(targets.size(), 3u) << "expected the References to M, to V's View Node and to M2";
  for (const auto& expected : {m, viewId, m2})
  {
    EXPECT_NE(std::find(targets.begin(), targets.end(), ExpandedNodeId{expected}), targets.end())
      << "no Reference in index form to " << to_string(expected);
  }
  for (const auto& target : targets)
  {
    EXPECT_TRUE(target.namespace_uri().empty()) << to_string(target) << " is not in index form";
    EXPECT_EQ(target.server_index(), 0u) << to_string(target);
    EXPECT_FALSE(target.is_local() && target.node_id() == n) << "the non-member N was returned";
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 3 section 4.3.4: a Reference's TargetNode may be in another Server's AddressSpace. Membership of a
// View is asked with a local NodeId (Node::is_node_in_view_async), so no namespace can say a remote Node is a
// member, and DL-36 point 2 leaves a Reference to one out in a View's context without asking: a limit of
// today's interface, which B2 removes. V's namespace answers true for every NodeId (DL-39), so a filter that
// asked it with a remote target's local NodeId would keep that Reference. S holds Organizes References to M,
// to a remote target given by namespace URI and to a remote target given by namespace index. In V's context
// only M is returned; with no View all three are, the control that the omission belongs to the View's
// context.
// @relation(AC-SVR-ADDRSP-075-REMOTE-TARGET-OMITTED-IN-VIEW, scope=function)
TEST(ViewMembership, ARemoteTargetIsOmittedInAView)
{
  boost::asio::thread_pool threadPool;
  auto ns = ua::test::EveryNodeInViewNamespace::create("uri://remote-target-ns", threadPool.get_executor());
  uint16_t nsIndex = 0;
  auto server = create_server_with_namespace(threadPool, ns, nsIndex);
  const NodeId viewId{nsIndex, 460};
  const NodeId s{nsIndex, 461};
  const NodeId m{nsIndex, 462};
  const NodeId organizes{ReferenceTypeId::Organizes};
  const ExpandedNodeId remoteByUri{
    NodeId{uint16_t{0}, std::string{"RemoteNode"}}, "urn:example:remote", uint32_t{1}};
  const ExpandedNodeId remoteByIndex{NodeId{uint16_t{2}, uint32_t{4242}}, uint32_t{1}};
  ns->create_node(viewId, NodeClass::View);
  ns->create_node(s, NodeClass::Object);
  ns->create_node(m, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto viewNode = addressSpace.try_find_node_sync(viewId);
  auto sNode = addressSpace.try_find_node_sync(s);
  ASSERT_TRUE(viewNode.is_good());
  ASSERT_TRUE(sNode.is_good());
  ASSERT_NO_THROW(sNode.value().add_reference_sync(organizes, ExpandedNodeId{m}, true));
  ASSERT_NO_THROW(sNode.value().add_reference_sync(organizes, remoteByUri, true));
  ASSERT_NO_THROW(sNode.value().add_reference_sync(organizes, remoteByIndex, true));

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  const auto inView = browse_in_view_context(
    sessionInfo, threadPool, viewId, {view_browse_operation(s, BrowseDirection::Forward, organizes, false)});
  const auto noView = browse_in_view_context(sessionInfo,
    threadPool,
    NodeId{},
    {view_browse_operation(s, BrowseDirection::Forward, organizes, false)});

  ASSERT_EQ(inView.size(), 1u) << "BrowseService did not answer the Browse in V's context within the timeout";
  EXPECT_EQ(inView[0].status, Status::Good);
  const auto inViewTargets = targets_of(inView[0].references);
  ASSERT_EQ(inViewTargets.size(), 1u) << "in V's context only the Reference to M is defined for the View";
  EXPECT_EQ(inViewTargets.front(), ExpandedNodeId{m});

  ASSERT_EQ(noView.size(), 1u) << "BrowseService did not answer the Browse with no View within the timeout";
  EXPECT_EQ(noView[0].status, Status::Good);
  const auto noViewTargets = targets_of(noView[0].references);
  EXPECT_EQ(noViewTargets.size(), 3u);
  const auto byUri = std::find_if(noViewTargets.begin(),
    noViewTargets.end(),
    [](const ExpandedNodeId& target)
    { return target.server_index() == 1u && std::string{target.namespace_uri()} == "urn:example:remote"; });
  EXPECT_NE(byUri, noViewTargets.end()) << "with no View, the remote target given by URI was not returned";
  const auto byIndex = std::find_if(noViewTargets.begin(),
    noViewTargets.end(),
    [](const ExpandedNodeId& target)
    {
      return target.server_index() == 1u &&
             target.node_id().identifier() == NodeId::Identifier{uint32_t{4242}};
    });
  EXPECT_NE(byIndex, noViewTargets.end())
    << "with no View, the remote target given by index was not returned";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.8.2.4, Table 36 lists Bad_NodeIdInvalid for Browse. DL-36 point 1 keeps today's operation
// failure for a target whose namespace URI the Server does not hold, Bad_NodeIdInvalid with the ErrorDetail
// InvalidReferenceTarget naming the URI, and makes the Browse in a View's context answer it as the Browse
// with no View does. The Browse with no View is the control.
// @relation(AC-SVR-ADDRSP-075-UNRESOLVABLE-URI-TARGET-FAILS-AS-WITHOUT-VIEW, scope=function)
TEST(ViewMembership, AnUnresolvableUriFormTargetFailsAsWithoutAView)
{
  boost::asio::thread_pool threadPool;
  auto ns = default_ns::Namespace::create("uri://unresolvable-uri-target-ns", threadPool.get_executor());
  uint16_t nsIndex = 0;
  auto server = create_server_with_namespace(threadPool, ns, nsIndex);
  const NodeId viewId{nsIndex, 470};
  const NodeId s{nsIndex, 471};
  const NodeId m{nsIndex, 472};
  const NodeId organizes{ReferenceTypeId::Organizes};
  const std::string unregistered{"urn:example:not-registered"};
  ns->create_node(viewId, NodeClass::View);
  ns->create_node(s, NodeClass::Object);
  ns->create_node(m, NodeClass::Object);

  auto addressSpace = server.address_space();
  auto viewNode = addressSpace.try_find_node_sync(viewId);
  auto sNode = addressSpace.try_find_node_sync(s);
  ASSERT_TRUE(viewNode.is_good());
  ASSERT_TRUE(sNode.is_good());
  ASSERT_NO_THROW(sNode.value().add_reference_sync(organizes, ExpandedNodeId{m}, true));
  ASSERT_NO_THROW(sNode.value().add_reference_sync(
    organizes, ExpandedNodeId{NodeId{uint16_t{0}, uint32_t{4711}}, unregistered}, true));
  auto view = viewNode.value().as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(s).is_good());
  ASSERT_TRUE(view->try_add_node_to_view_sync(m).is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  sessionInfo->enable_operation_diagnostics();
  const auto inView = browse_with_diagnostics(
    sessionInfo, threadPool, viewId, {view_browse_operation(s, BrowseDirection::Forward, organizes, false)});
  const auto noView = browse_with_diagnostics(sessionInfo,
    threadPool,
    NodeId{},
    {view_browse_operation(s, BrowseDirection::Forward, organizes, false)});

  const std::pair<const char*, const std::vector<DiagnosedBrowseOutcome>*> browses[]{
    {"in V's context", &inView}, {"with no View", &noView}};
  for (const auto& [context, outcomes] : browses)
  {
    SCOPED_TRACE(context);
    ASSERT_EQ(outcomes->size(), 1u) << "BrowseService did not answer within the timeout";
    const auto& outcome = outcomes->front();
    EXPECT_EQ(outcome.status.as_status(), Status::BadNodeIdInvalid);
    EXPECT_TRUE(outcome.references.empty()) << outcome.references.size() << " References returned";
    EXPECT_EQ(outcome.symbolicId, "InvalidReferenceTarget");
    EXPECT_NE(outcome.additionalInfo.find("\"namespace.uri\",\"" + unregistered + "\""), std::string::npos)
      << "additional info: " << outcome.additionalInfo;
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.8.2.4, Table 36: Uncertain_NotAllNodesAvailable, "Browse results may be incomplete because
// of the unavailability of a subsystem." When the View's namespace answers Bad for a target, whether the
// Reference belongs to the View is unknown; DL-36 point 3 leaves it out and answers
// Uncertain_NotAllNodesAvailable, and the first failing answer's ErrorDetail is the one reported, in the
// status and in the operation's diagnostics. The View answers per NodeId as the test chooses. S1 holds M1, T1
// and M2; S2 holds T2, M3 and T3, T2 first. The members are the control that the other References are
// returned. U, browsed in the same request, is the control that the check of the Node to browse is unchanged:
// the namespace's Bad answer for U is the operation's status.
// @relation(AC-COMP-SVR-BROWSE-VIEW-TARGET-FILTER-01-TARGET-MEMBERSHIP-FAILURE-UNCERTAIN, scope=function)
TEST(ViewMembership, AFailedTargetMembershipAnswerIsUncertainNotAllNodesAvailable)
{
  boost::asio::thread_pool threadPool;
  // The answers are filled in once the namespace's index is known, before anything is browsed.
  auto answers = std::make_shared<std::vector<std::pair<NodeId, BoolResult>>>();
  auto ns = ua::test::EveryNodeInViewNamespace::create("uri://failing-view-membership-ns",
    threadPool.get_executor(),
    [answers](const NodeId& nodeId)
    {
      for (const auto& [scripted, answer] : *answers)
      {
        if (scripted == nodeId)
          return answer;
      }
      return BoolResult{false};
    });
  uint16_t nsIndex = 0;
  auto server = create_server_with_namespace(threadPool, ns, nsIndex);
  const NodeId viewId{nsIndex, 480};
  const NodeId s1{nsIndex, 481};
  const NodeId s2{nsIndex, 482};
  const NodeId m1{nsIndex, 483};
  const NodeId m2{nsIndex, 484};
  const NodeId m3{nsIndex, 485};
  const NodeId t1{nsIndex, 486};
  const NodeId t2{nsIndex, 487};
  const NodeId t3{nsIndex, 488};
  const NodeId u{nsIndex, 489};
  const NodeId organizes{ReferenceTypeId::Organizes};
  ns->create_node(viewId, NodeClass::View);
  for (const auto& id : {s1, s2, m1, m2, m3, t1, t2, t3, u})
    ns->create_node(id, NodeClass::Object);
  for (const auto& member : {s1, s2, m1, m2, m3})
    answers->emplace_back(member, BoolResult{true});
  const std::pair<NodeId, const char*> failing[]{{t1, "ScriptedT1MembershipFailure"},
    {t2, "ScriptedT2MembershipFailure"},
    {t3, "ScriptedT3MembershipFailure"}};
  for (const auto& [id, code] : failing)
  {
    answers->emplace_back(id,
      BoolResult{StatusCode{Status::BadInternalError},
        ErrorDetail::build(code, "The test's View cannot say whether this Node is a member", "TestView")});
  }
  answers->emplace_back(u,
    BoolResult{StatusCode{Status::BadResourceUnavailable},
      ErrorDetail::build("ScriptedUMembershipFailure",
        "The test's View cannot say whether this Node is a member",
        "TestView")});

  auto addressSpace = server.address_space();
  auto s1Node = addressSpace.try_find_node_sync(s1);
  auto s2Node = addressSpace.try_find_node_sync(s2);
  ASSERT_TRUE(s1Node.is_good());
  ASSERT_TRUE(s2Node.is_good());
  for (const auto& target : {m1, t1, m2})
    ASSERT_TRUE(s1Node.value().try_add_reference_sync(organizes, ExpandedNodeId{target}, true).is_good());
  for (const auto& target : {t2, m3, t3})
    ASSERT_TRUE(s2Node.value().try_add_reference_sync(organizes, ExpandedNodeId{target}, true).is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  sessionInfo->enable_operation_diagnostics();

  // Precondition: S2's References come in the order they were added, so T2's answer is the first to fail.
  const auto order = browse_in_view_context(sessionInfo,
    threadPool,
    NodeId{},
    {view_browse_operation(s2, BrowseDirection::Forward, organizes, false)});
  ASSERT_EQ(order.size(), 1u);
  const auto s2Targets = targets_of(order[0].references);
  const auto t2At = std::find(s2Targets.begin(), s2Targets.end(), ExpandedNodeId{t2});
  const auto t3At = std::find(s2Targets.begin(), s2Targets.end(), ExpandedNodeId{t3});
  ASSERT_TRUE(t2At != s2Targets.end() && t3At != s2Targets.end() && t2At < t3At)
    << "with no View, S2 does not return T2 before T3, so the first failing answer is not T2's";

  const auto outcomes = browse_with_diagnostics(sessionInfo,
    threadPool,
    viewId,
    {view_browse_operation(s1, BrowseDirection::Forward, organizes, false),
      view_browse_operation(s2, BrowseDirection::Forward, organizes, false),
      view_browse_operation(u, BrowseDirection::Forward, NodeId{}, false)});
  ASSERT_EQ(outcomes.size(), 3u) << "BrowseService did not answer the three operations within the timeout";

  {
    SCOPED_TRACE("S1: M1, T1, M2");
    EXPECT_EQ(outcomes[0].status.as_status(), Status::UncertainNotAllNodesAvailable);
    const auto targets = targets_of(outcomes[0].references);
    EXPECT_EQ(targets, (std::vector<ExpandedNodeId>{ExpandedNodeId{m1}, ExpandedNodeId{m2}}))
      << targets.size() << " References returned";
    EXPECT_EQ(outcomes[0].symbolicId, "ScriptedT1MembershipFailure");
  }
  {
    SCOPED_TRACE("S2: T2, M3, T3");
    EXPECT_EQ(outcomes[1].status.as_status(), Status::UncertainNotAllNodesAvailable);
    const auto targets = targets_of(outcomes[1].references);
    EXPECT_EQ(targets, (std::vector<ExpandedNodeId>{ExpandedNodeId{m3}}))
      << targets.size() << " References returned";
    EXPECT_EQ(detail_code(outcomes[1].status), "ScriptedT2MembershipFailure")
      << "the status does not carry the first failing answer's ErrorDetail";
    EXPECT_EQ(outcomes[1].symbolicId, "ScriptedT2MembershipFailure")
      << "the diagnostics do not carry the first failing answer's ErrorDetail";
  }
  {
    SCOPED_TRACE("U, the Node to browse");
    EXPECT_EQ(outcomes[2].status.as_status(), Status::BadResourceUnavailable);
    EXPECT_EQ(outcomes[2].symbolicId, "ScriptedUMembershipFailure");
    EXPECT_TRUE(outcomes[2].references.empty());
  }

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.8.2.4, Table 36: Uncertain_NotAllNodesAvailable, "Browse results may be incomplete because
// of the unavailability of a subsystem." A membership answer whose status is Uncertain carries no value, so
// whether the target is in the View is unknown, as for a Bad answer (DL-39): the Reference is left out and
// the operation answers Uncertain_NotAllNodesAvailable with that answer's ErrorDetail. The View answers per
// NodeId as the test chooses: S, M1 and M2 are members, and T4's answer is Uncertain. M1 and M2 are the
// control that the other References are returned.
// @relation(AC-COMP-SVR-BROWSE-VIEW-TARGET-FILTER-01-UNCERTAIN-MEMBERSHIP-ANSWER-UNKNOWN, scope=function)
TEST(ViewMembership, AnUncertainTargetMembershipAnswerLeavesTheReferenceOut)
{
  boost::asio::thread_pool threadPool;
  // The answers are filled in once the namespace's index is known, before anything is browsed.
  auto answers = std::make_shared<std::vector<std::pair<NodeId, BoolResult>>>();
  auto ns = ua::test::EveryNodeInViewNamespace::create("uri://uncertain-view-membership-ns",
    threadPool.get_executor(),
    [answers](const NodeId& nodeId)
    {
      for (const auto& [scripted, answer] : *answers)
      {
        if (scripted == nodeId)
          return answer;
      }
      return BoolResult{false};
    });
  uint16_t nsIndex = 0;
  auto server = create_server_with_namespace(threadPool, ns, nsIndex);
  const NodeId viewId{nsIndex, 490};
  const NodeId s{nsIndex, 491};
  const NodeId m1{nsIndex, 492};
  const NodeId t4{nsIndex, 493};
  const NodeId m2{nsIndex, 494};
  const NodeId organizes{ReferenceTypeId::Organizes};
  ns->create_node(viewId, NodeClass::View);
  for (const auto& id : {s, m1, t4, m2})
    ns->create_node(id, NodeClass::Object);
  for (const auto& member : {s, m1, m2})
    answers->emplace_back(member, BoolResult{true});
  answers->emplace_back(t4,
    BoolResult{StatusCode{Status::Uncertain},
      ErrorDetail::build("ScriptedT4MembershipUncertain",
        "The test's View is not sure whether this Node is a member",
        "TestView")});

  auto addressSpace = server.address_space();
  auto sNode = addressSpace.try_find_node_sync(s);
  ASSERT_TRUE(sNode.is_good());
  for (const auto& target : {m1, t4, m2})
    ASSERT_TRUE(sNode.value().try_add_reference_sync(organizes, ExpandedNodeId{target}, true).is_good());

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  sessionInfo->enable_operation_diagnostics();
  const auto outcomes = browse_with_diagnostics(
    sessionInfo, threadPool, viewId, {view_browse_operation(s, BrowseDirection::Forward, organizes, false)});

  ASSERT_EQ(outcomes.size(), 1u) << "BrowseService did not answer within the timeout";
  EXPECT_EQ(outcomes[0].status.as_status(), Status::UncertainNotAllNodesAvailable);
  const auto targets = targets_of(outcomes[0].references);
  EXPECT_EQ(targets, (std::vector<ExpandedNodeId>{ExpandedNodeId{m1}, ExpandedNodeId{m2}}))
    << targets.size() << " References returned";
  EXPECT_EQ(detail_code(outcomes[0].status), "ScriptedT4MembershipUncertain")
    << "the status does not carry the Uncertain answer's ErrorDetail";
  EXPECT_EQ(outcomes[0].symbolicId, "ScriptedT4MembershipUncertain")
    << "the diagnostics do not carry the Uncertain answer's ErrorDetail";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 3 section 5.4: "the Server Object defined in OPC 10000-5 shall never be part of any View". NR-41: the
// Browse service decides it by NodeId, whatever the namespace holding the View answers. The View here
// belongs to a namespace that answers every membership question true, the Server Object included. Browsed in
// that View's context, the Server Object is refused, and the Objects folder shows its other child and not
// the Server Object; the other child is the control that the View still shows its members.
// @relation(AC-SVR-EVT-ATTR-007-SERVER-OBJECT-NOT-IN-VIEW, scope=function)
TEST(ViewMembership, TheServerObjectIsInNoViewWhateverTheViewAnswers)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns =
    ua::test::EveryNodeInViewNamespace::create("uri://every-node-in-view-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId viewId{nsIndex, 420};
  const NodeId otherChild{nsIndex, 421};
  const NodeId serverObject{ObjectId::Server};
  const NodeId objectsFolder{ObjectId::ObjectsFolder};
  ns->create_node(viewId, NodeClass::View);
  ns->create_node(otherChild, NodeClass::Object);

  auto addressSpace = server.address_space();
  ASSERT_TRUE(addressSpace.try_find_node_sync(objectsFolder)
                .value()
                .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{otherChild}, true)
                .is_good());
  auto view = addressSpace.try_find_node_sync(viewId).value().as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(objectsFolder).is_good());
  ASSERT_TRUE(view->try_add_node_to_view_sync(otherChild).is_good());
  // Asked of the View's namespace itself: the address space answers the Server Object not a member without
  // asking the namespace (NR-41), so only the namespace's own member shows what it would answer.
  auto asked = std::make_shared<std::promise<BatchResult<BoolResult>>>();
  auto namespaceAnswer = asked->get_future();
  const std::vector<ExpandedNodeId> candidates{ExpandedNodeId{serverObject}};
  ns->view_contains_async(RequestInfo{},
    viewId,
    candidates,
    [asked](BatchResult<BoolResult> answer) { asked->set_value(std::move(answer)); });
  ASSERT_EQ(namespaceAnswer.wait_for(5s), std::future_status::ready) << "the View's namespace did not answer";
  const auto contains = namespaceAnswer.get();
  ASSERT_TRUE(contains.batchStatus.is_good() && contains.items.size() == 1U && contains.items[0].is_good() &&
              contains.items[0].value())
    << "the View's namespace must answer that the Server Object is in the View, or nothing is tested";

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  sessionInfo->enable_operation_diagnostics();
  std::vector<LocaleId> locales{"en"};

  BrowseRequest browseRequest;
  browseRequest.request_header().return_diagnostics() = diag::operationLevelMask;
  browseRequest.view().view_id() = viewId;
  browseRequest.nodes_to_browse().resize(2);
  browseRequest.nodes_to_browse()[0].node_id() = serverObject;
  browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
  browseRequest.nodes_to_browse()[1].node_id() = objectsFolder;
  browseRequest.nodes_to_browse()[1].browse_direction() = BrowseDirection::Forward;
  browseRequest.nodes_to_browse()[1].reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
  browseRequest.nodes_to_browse()[1].include_subtypes() = true;

  struct BrowseCapture
  {
    std::mutex mutex;
    std::condition_variable ready;
    bool done{false};
    std::vector<Status> statuses;
    std::vector<std::string> symbolicIds;
    std::vector<NodeId> folderTargets;
  };

  auto capture = std::make_shared<BrowseCapture>();
  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [capture](BrowseService::BrowseServiceResponse response)
    {
      const std::lock_guard lock(capture->mutex);
      auto& browseResponse = dynamic_cast<BrowseResponse&>(*response.response.second);
      for (const auto& result : browseResponse.results().payload())
        capture->statuses.push_back(result.status_code().as_status());
      const auto& strings = browseResponse.response_header().string_table();
      for (const auto& diagnostic : browseResponse.diagnostic_infos().payload())
      {
        const auto symbolic = diagnostic.symbolic_id();
        capture->symbolicIds.push_back(symbolic.has_value() && static_cast<size_t>(*symbolic) < strings.size()
                                         ? std::string{strings[static_cast<size_t>(*symbolic)]}
                                         : std::string{});
      }
      if (browseResponse.results().size() == 2)
      {
        for (const auto& reference : browseResponse.results().payload()[1].references().payload())
          capture->folderTargets.push_back(reference.node_id().node_id());
      }
      capture->done = true;
      capture->ready.notify_all();
    });

  std::unique_lock<std::mutex> lock(capture->mutex);
  ASSERT_TRUE(capture->ready.wait_for(lock, 3s, [&capture] { return capture->done; }))
    << "BrowseService did not complete within timeout";
  ASSERT_EQ(capture->statuses.size(), 2u);
  EXPECT_EQ(capture->statuses[0], Status::BadNodeNotInView)
    << "the Server Object was browsed in the context of a View";
  ASSERT_FALSE(capture->symbolicIds.empty()) << "the refusal carries no diagnostic";
  EXPECT_EQ(capture->symbolicIds[0], "ServerObjectInNoView");
  EXPECT_EQ(capture->statuses[1], Status::Good);
  EXPECT_NE(std::find(capture->folderTargets.begin(), capture->folderTargets.end(), otherChild),
    capture->folderTargets.end())
    << "the View no longer shows its member";
  EXPECT_EQ(std::find(capture->folderTargets.begin(), capture->folderTargets.end(), serverObject),
    capture->folderTargets.end())
    << "a Browse in the View's context returned a Reference to the Server Object";
  lock.unlock();

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// SVC-12: the per-node ceiling bounds one operation; a request that names the same high-fan-in node
// several times multiplied it. The whole-request budget is split over the operations and the
// continuation-point path pages the rest, so the response never carries more than the budget.
// @verifies AC-SVR-VIEW-BRW-002-A-BROWSE-REQUEST-SHARES-ONE-REFERENCE-BUDGET
TEST(BrowseServiceTests, RepeatedHighFanInNodesShareTheRequestBudget)
{
  boost::asio::thread_pool threadPool;
  ua::server::ServerConfig serverConfig;
  serverConfig.maxReferencesPerBrowseRequest = 6;  // three operations -> two references each
  serverConfig.server_capabilities().operationLimits.maxNodesPerBrowse = 3;  // validate(): budget >= nodes
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://browse-request-budget-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId source{nsIndex, 400};
  ns->create_node(source, NodeClass::Object);
  auto addressSpace = server.address_space();
  auto sourceAccessor = addressSpace.try_find_node_sync(source);
  ASSERT_TRUE(sourceAccessor.is_good());
  for (uint32_t i = 0; i < 5; ++i)
  {
    const NodeId target{nsIndex, 401 + i};
    ns->create_node(target, NodeClass::Object);
    sourceAccessor.value().try_add_reference_sync(
      NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{target}, /*isForward=*/true);
  }
  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  std::vector<LocaleId> locales{"en"};

  BrowseRequest browseRequest;
  browseRequest.requested_max_references_per_node() = 0;  // "no client limit": the budget decides
  browseRequest.nodes_to_browse().resize(3);
  for (auto& node : browseRequest.nodes_to_browse())
  {
    node.node_id() = source;
    node.browse_direction() = BrowseDirection::Forward;
  }

  std::condition_variable cv;
  std::mutex mtx;
  bool done = false;
  BrowseService::BrowseServiceResponse response;
  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [&](BrowseService::BrowseServiceResponse r)
    {
      response = std::move(r);
      {
        std::lock_guard lock(mtx);
        done = true;
      }
      cv.notify_all();
    });
  {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait_for(lock, 3s, [&done] { return done; });
  }
  ASSERT_TRUE(done) << "BrowseService did not complete within timeout";

  auto* browseResponse = dynamic_cast<BrowseResponse*>(response.response.second.get());
  ASSERT_NE(browseResponse, nullptr);
  ASSERT_EQ(browseResponse->results().size(), 3u);
  size_t returned = 0;
  for (const auto& result : browseResponse->results().payload())
  {
    ASSERT_TRUE(result.status_code().is_good());
    EXPECT_EQ(result.references().size(), 2u) << "each operation gets exactly its share of the budget";
    EXPECT_FALSE(result.continuation_point().empty()) << "the rest is paged, not dropped";
    returned += result.references().size();
  }
  EXPECT_EQ(returned, 6u) << "the response carries exactly the request budget";
  EXPECT_EQ(response.continuationPoints.size(), 3u);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// SVC-12: BrowseNext shares the request budget over its continuation points as Browse does over its
// operations, so a client cannot collect one continuation point per request and then replay them all
// in one BrowseNext for MaxBrowseContinuationPoints x MaxReferencesPerNode references.
// @verifies AC-SVR-VIEW-BRW-002-A-BROWSE-REQUEST-SHARES-ONE-REFERENCE-BUDGET
TEST(BrowseServiceTests, BrowseNextSharesTheRequestBudgetAcrossContinuationPoints)
{
  boost::asio::thread_pool threadPool;
  ua::server::ServerConfig serverConfig;
  serverConfig.maxReferencesPerBrowseRequest = 3;  // three continuation points -> one reference each
  serverConfig.server_capabilities().operationLimits.maxNodesPerBrowse = 3;  // validate(): budget >= nodes
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = default_ns::Namespace::create("uri://browse-next-budget-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId source{nsIndex, 500};
  ns->create_node(source, NodeClass::Object);
  auto addressSpace = server.address_space();
  auto sourceAccessor = addressSpace.try_find_node_sync(source);
  ASSERT_TRUE(sourceAccessor.is_good());
  for (uint32_t i = 0; i < 5; ++i)
  {
    const NodeId target{nsIndex, 501 + i};
    ns->create_node(target, NodeClass::Object);
    sourceAccessor.value().try_add_reference_sync(
      NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{target}, /*isForward=*/true);
  }
  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  std::vector<LocaleId> locales{"en"};

  const auto waitFor = [&](auto&& start) -> BrowseService::BrowseServiceResponse
  {
    std::condition_variable cv;
    std::mutex mtx;
    bool done = false;
    BrowseService::BrowseServiceResponse response;
    auto service = start(
      [&](BrowseService::BrowseServiceResponse r)
      {
        response = std::move(r);
        // Notified under the lock: waitFor returns, destroying cv, as soon as it sees done.
        std::lock_guard lock(mtx);
        done = true;
        cv.notify_all();
      });
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait_for(lock, 3s, [&done] { return done; });
    EXPECT_TRUE(done) << "BrowseService did not complete within timeout";
    return response;
  };
  const auto runBrowse = [&](BrowseRequest request)
  {
    return waitFor(
      [&](auto sink)
      {
        return BrowseService::create(
          sessionInfo, locales, 0, std::move(request), threadPool.get_executor(), std::move(sink));
      });
  };
  const auto runNext = [&](BrowseNextRequest request, BrowseContinuationPoints& points)
  {
    return waitFor(
      [&](auto sink)
      {
        return BrowseService::create(
          sessionInfo, locales, 1, std::move(request), points, threadPool.get_executor(), std::move(sink));
      });
  };

  // Three separate single-operation Browses, each of which keeps its budget (3 per request) and so
  // leaves a continuation point behind (5 references, page 3).
  BrowseContinuationPoints continuationPoints;
  BrowseNextRequest next;
  next.release_continuation_points() = false;
  for (int i = 0; i < 3; ++i)
  {
    BrowseRequest browseRequest;
    browseRequest.requested_max_references_per_node() = 0;
    browseRequest.nodes_to_browse().resize(1);
    browseRequest.nodes_to_browse()[0].node_id() = source;
    browseRequest.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
    auto response = runBrowse(std::move(browseRequest));
    auto* browseResponse = dynamic_cast<BrowseResponse*>(response.response.second.get());
    ASSERT_NE(browseResponse, nullptr);
    ASSERT_EQ(browseResponse->results().size(), 1u);
    const auto& result = browseResponse->results().payload().front();
    ASSERT_TRUE(result.status_code().is_good());
    EXPECT_EQ(result.references().size(), 3u) << "one operation: the whole budget is its page";
    ASSERT_FALSE(result.continuation_point().empty());
    next.continuation_points().push_back(result.continuation_point());
    for (auto& cp : response.continuationPoints)
    {
      auto guid = cp.identifier();
      continuationPoints.emplace(guid, std::move(cp));
    }
  }
  ASSERT_EQ(continuationPoints.size(), 3u);

  // One BrowseNext naming all three: each point gets a third of the budget, not the page it was made with.
  auto response = runNext(std::move(next), continuationPoints);
  auto* nextResponse = dynamic_cast<BrowseNextResponse*>(response.response.second.get());
  ASSERT_NE(nextResponse, nullptr);
  ASSERT_EQ(nextResponse->results().size(), 3u);
  size_t returned = 0;
  for (const auto& result : nextResponse->results().payload())
  {
    ASSERT_TRUE(result.status_code().is_good());
    EXPECT_EQ(result.references().size(), 1u)
      << "each continuation point gets exactly its share of the budget";
    returned += result.references().size();
  }
  EXPECT_EQ(returned, 3u) << "the BrowseNext response carries exactly the request budget";
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Control for the budget: with the budget disabled (nullopt) the same three operations return every
// reference and no continuation point, so the arm above cannot be an artefact of the fixture.
// @verifies AC-SVR-VIEW-BRW-002-A-BROWSE-REQUEST-SHARES-ONE-REFERENCE-BUDGET
TEST(BrowseServiceTests, ADisabledRequestBudgetLeavesEveryOperationItsFullPage)
{
  boost::asio::thread_pool threadPool;
  ua::server::ServerConfig serverConfig;
  serverConfig.maxReferencesPerBrowseRequest = std::nullopt;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = std::move(serverConfig)};
  auto server = ua::server::Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto ns = default_ns::Namespace::create("uri://browse-no-budget-ns", threadPool.get_executor());
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId source{nsIndex, 600};
  ns->create_node(source, NodeClass::Object);
  auto addressSpace = server.address_space();
  auto sourceAccessor = addressSpace.try_find_node_sync(source);
  ASSERT_TRUE(sourceAccessor.is_good());
  for (uint32_t i = 0; i < 5; ++i)
  {
    const NodeId target{nsIndex, 601 + i};
    ns->create_node(target, NodeClass::Object);
    sourceAccessor.value().try_add_reference_sync(
      NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{target}, /*isForward=*/true);
  }
  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  std::vector<LocaleId> locales{"en"};
  BrowseRequest browseRequest;
  browseRequest.requested_max_references_per_node() = 0;
  browseRequest.nodes_to_browse().resize(3);
  for (auto& node : browseRequest.nodes_to_browse())
  {
    node.node_id() = source;
    node.browse_direction() = BrowseDirection::Forward;
  }
  std::condition_variable cv;
  std::mutex mtx;
  bool done = false;
  BrowseService::BrowseServiceResponse response;
  auto browseService = BrowseService::create(sessionInfo,
    locales,
    0,
    std::move(browseRequest),
    threadPool.get_executor(),
    [&](BrowseService::BrowseServiceResponse r)
    {
      response = std::move(r);
      {
        std::lock_guard lock(mtx);
        done = true;
      }
      cv.notify_all();
    });
  {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait_for(lock, 3s, [&done] { return done; });
  }
  ASSERT_TRUE(done);
  auto* browseResponse = dynamic_cast<BrowseResponse*>(response.response.second.get());
  ASSERT_NE(browseResponse, nullptr);
  ASSERT_EQ(browseResponse->results().size(), 3u);
  for (const auto& result : browseResponse->results().payload())
  {
    ASSERT_TRUE(result.status_code().is_good());
    EXPECT_EQ(result.references().size(), 5u);
    EXPECT_TRUE(result.continuation_point().empty());
  }
  ::ua::test_utils::drain_with_timeout(threadPool);
}
