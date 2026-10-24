// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Browse and BrowseNext at the partial-result deadline (public_api_1_0_design.md item 10, API-10.2 to
// API-10.5, and D11). The namespace under test holds every read of its sources' References until the test
// releases it, so which items are finished at the deadline is decided by the test, not by timing.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_service.h"
#include "ua_continuation_points.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include "batch_recording_namespace.h"
#include "every_node_in_view_namespace.h"
#include "stubs.h"
#include "access_control_test_support.h"
#include "test_components.h"
#include "test_utilities.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

/// A server with one gated namespace (index 2) and one plain in-memory namespace (index 3). The gated
/// namespace holds every read of the References of its sources 2:1, 2:2 and 2:3 until the test releases it.
/// 2:1 and 2:2 each hold one forward HasComponent Reference, and 2:3 two, to Objects whose BrowseName is
/// "Released".
struct Fixture
{
  std::atomic<size_t> completions{0};
  boost::asio::thread_pool threadPool{4};
  shared_ptr<ua::test::BatchRecordingNamespace> gated;
  shared_ptr<default_ns::Namespace> plain;
  shared_ptr<SessionInfoStub> sessionInfo;
  std::vector<LocaleId> locales{"en"};

  explicit Fixture(double fraction, uint16_t maxContinuationPoints = 10)
  {
    ServerConfig serverConfiguration;
    serverConfiguration.partialResultDeadlineFraction = fraction;
    serverConfiguration.server_capabilities().maxBrowseContinuationPoints = maxContinuationPoints;
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = serverConfiguration};
    auto server = Server::create(
      threadPool.get_executor(), std::move(cfg), ServerComponents{.crypto = ua::test_helpers::test_crypto()});

    gated = make_shared<ua::test::BatchRecordingNamespace>("uri://gated-browse", threadPool.get_executor());
    server.address_space().add_namespace_sync(gated);
    plain = default_ns::Namespace::create("uri://plain-browse", threadPool.get_executor());
    server.address_space().add_namespace_sync(plain);
    plain->create_node(NodeId{3, 1}, NodeClass::Object);
    auto addressSpace = server.address_space();
    const std::vector<std::pair<NodeId, std::vector<NodeId>>> sources{{NodeId{2, 1}, {NodeId{2, 101}}},
      {NodeId{2, 2}, {NodeId{2, 102}}},
      {NodeId{2, 3}, {NodeId{2, 103}, NodeId{2, 104}}}};
    for (const auto& [source, targets] : sources)
    {
      auto sourceNode = addressSpace.create_node_sync(source, NodeClass::Object);
      for (const auto& target : targets)
      {
        auto targetNode = addressSpace.create_node_sync(target, NodeClass::Object);
        targetNode.set_browse_name(QualifiedName{0, "Released"});
        sourceNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{target}, true);
        targetNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{source}, false);
      }
    }
    gated->hold_reference_reads_of({NodeId{2, 1}, NodeId{2, 2}, NodeId{2, 3}});

    sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
  }

  /// Waits until @p count reads of the sources' References have been held.
  bool wait_for_reads(size_t count, std::chrono::milliseconds limit = 2000ms)
  {
    return gated->wait_for_held_reference_reads(count, limit);
  }

  /// Answers every held read with the source's References.
  void release_reads()
  {
    gated->release_held_reference_reads();
  }

  /// The gated namespace answers every read at once from now on.
  void answer_at_once()
  {
    gated->hold_reference_reads_of({});
  }

  ~Fixture()
  {
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  Fixture(const Fixture&) = delete;
  Fixture& operator=(const Fixture&) = delete;

  /// Runs a Browse of @p nodes with @p timeoutHint and waits for its response.
  std::optional<BrowseService::BrowseServiceResponse> browse(std::vector<NodeId> nodes, uint32_t timeoutHint,
    std::chrono::milliseconds limit = 3000ms, uint32_t maxReferencesPerNode = 0)
  {
    BrowseRequest request;
    request.request_header().timeout_hint() = timeoutHint;
    request.requested_max_references_per_node() = maxReferencesPerNode;
    request.nodes_to_browse().resize(nodes.size());
    for (size_t i = 0; i < nodes.size(); ++i)
    {
      request.nodes_to_browse()[i].node_id() = nodes[i];
      request.nodes_to_browse()[i].browse_direction() = BrowseDirection::Both;
      // Every field of each ReferenceDescription, the BrowseName the tests read included.
      request.nodes_to_browse()[i].result_mask() = 0x3f;
    }
    auto done = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
    auto future = done->get_future();
    services.push_back(BrowseService::create(sessionInfo,
      locales,
      1,
      std::move(request),
      threadPool.get_executor(),
      [done, &completions = completions](BrowseService::BrowseServiceResponse response)
      {
        ++completions;
        done->set_value(std::move(response));
      }));
    if (future.wait_for(limit) != std::future_status::ready)
    {
      return std::nullopt;
    }
    return future.get();
  }

  /// Runs a BrowseNext with @p continuationPoints (taken from @p store) and waits for its response.
  std::optional<BrowseService::BrowseServiceResponse> browse_next(std::vector<ByteString> continuationPoints,
    BrowseContinuationPoints& store, uint32_t timeoutHint, bool release = false,
    std::chrono::milliseconds limit = 3000ms)
  {
    BrowseNextRequest request;
    request.request_header().timeout_hint() = timeoutHint;
    request.release_continuation_points() = release;
    request.continuation_points().resize(continuationPoints.size());
    for (size_t i = 0; i < continuationPoints.size(); ++i)
    {
      request.continuation_points()[i] = continuationPoints[i];
    }
    auto done = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
    auto future = done->get_future();
    services.push_back(BrowseService::create(sessionInfo,
      locales,
      2,
      std::move(request),
      store,
      threadPool.get_executor(),
      [done, &completions = completions](BrowseService::BrowseServiceResponse response)
      {
        ++completions;
        done->set_value(std::move(response));
      }));
    if (future.wait_for(limit) != std::future_status::ready)
    {
      return std::nullopt;
    }
    return future.get();
  }

  /// The continuation points a response handed out, as the Session would store them.
  static BrowseContinuationPoints store_of(BrowseService::BrowseServiceResponse& response)
  {
    BrowseContinuationPoints store;
    for (auto& continuationPoint : response.continuationPoints)
    {
      auto identifier = continuationPoint.identifier();
      store.emplace(identifier, std::move(continuationPoint));
    }
    response.continuationPoints.clear();
    return store;
  }

  std::vector<shared_ptr<BrowseService>> services;
};

const BrowseResponse& as_browse(const BrowseService::BrowseServiceResponse& response)
{
  auto* browse = dynamic_cast<BrowseResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  if (browse == nullptr)
  {
    throw std::runtime_error("not a BrowseResponse");
  }
  return *browse;
}

const BrowseNextResponse& as_browse_next(const BrowseService::BrowseServiceResponse& response)
{
  auto* next = dynamic_cast<BrowseNextResponse*>(std::get<shared_ptr<Structure>>(response.response).get());
  if (next == nullptr)
  {
    throw std::runtime_error("not a BrowseNextResponse");
  }
  return *next;
}

}  // namespace

// At the deadline, a finished item keeps its result and an unfinished one is answered Good with no
// references and a continuation point; the request does not fail. The operation keeps running, and a
// BrowseNext with that point returns what it produced.
// @relation(AC-SVR-PARTIAL-RESULTS-001-PAUSE-AND-RESUME, scope=function)
TEST(BrowsePartialResultsTests, UnfinishedItemIsAnsweredWithAContinuationPointThatReturnsItsResult)
{
  Fixture fixture{0.1};  // deadline at 100 ms of a 1000 ms hint

  const auto started = std::chrono::steady_clock::now();
  auto first = fixture.browse({NodeId{2, 1}, NodeId{3, 1}}, 1000);
  const auto answeredAt = std::chrono::steady_clock::now();
  ASSERT_TRUE(first.has_value()) << "the request must be answered at its partial-result deadline";
  const auto& response = as_browse(*first);
  ASSERT_EQ(response.results().size(), 2u);
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(response.results()[0].references().empty());
  EXPECT_FALSE(response.results()[0].continuation_point().empty()) << "the unfinished item gets a point";
  EXPECT_EQ(response.results()[1].status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(response.results()[1].continuation_point().empty()) << "the finished item keeps its result";
  ASSERT_EQ(first->continuationPoints.size(), 1u);

  ASSERT_TRUE(fixture.wait_for_reads(1));
  const auto answerBy = fixture.gated->held_reference_read_request(0).answerBy;
  ASSERT_TRUE(answerBy.has_value());
  EXPECT_GE(*answerBy, started + 100ms);
  EXPECT_GE(answeredAt, *answerBy) << "the response must wait until its partial-result deadline";
  fixture.release_reads();

  auto store = Fixture::store_of(*first);
  auto next = fixture.browse_next({response.results()[0].continuation_point()}, store, 1000);
  ASSERT_TRUE(next.has_value());
  const auto& nextResponse = as_browse_next(*next);
  ASSERT_EQ(nextResponse.results().size(), 1u);
  EXPECT_EQ(nextResponse.results()[0].status_code(), StatusCode{Status::Good});
  ASSERT_EQ(nextResponse.results()[0].references().size(), 1u);
  EXPECT_EQ(nextResponse.results()[0].references()[0].browse_name(), (QualifiedName{0, "Released"}));
  EXPECT_TRUE(nextResponse.results()[0].continuation_point().empty());
}

// Control for the test above: with the namespace answering at once, nothing is paused.
// @relation(AC-SVR-PARTIAL-RESULTS-001-PAUSE-AND-RESUME, scope=function)
TEST(BrowsePartialResultsTests, ItemsFinishedBeforeTheDeadlineGetNoContinuationPoint)
{
  Fixture fixture{0.1};
  fixture.answer_at_once();

  auto first = fixture.browse({NodeId{2, 1}, NodeId{3, 1}}, 1000);
  ASSERT_TRUE(first.has_value());
  const auto& response = as_browse(*first);
  ASSERT_EQ(response.results().size(), 2u);
  ASSERT_EQ(response.results()[0].references().size(), 1u);
  EXPECT_TRUE(response.results()[0].continuation_point().empty());
  EXPECT_TRUE(first->continuationPoints.empty());
}

// A BrowseNext whose own deadline comes before the paused operation finishes returns no references and
// a new continuation point, which then returns the operation's result.
// @relation(AC-SVR-PARTIAL-RESULTS-001-WAIT-AGAIN, scope=function)
TEST(BrowsePartialResultsTests, BrowseNextReachingItsDeadlineFirstReturnsANewContinuationPoint)
{
  Fixture fixture{0.1};

  auto first = fixture.browse({NodeId{2, 1}}, 1000);
  ASSERT_TRUE(first.has_value());
  const auto firstPoint = as_browse(*first).results()[0].continuation_point();
  ASSERT_FALSE(firstPoint.empty());
  auto store = Fixture::store_of(*first);

  auto second = fixture.browse_next({firstPoint}, store, 1000);
  ASSERT_TRUE(second.has_value());
  const auto& secondResponse = as_browse_next(*second);
  ASSERT_EQ(secondResponse.results().size(), 1u);
  EXPECT_EQ(secondResponse.results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_TRUE(secondResponse.results()[0].references().empty());
  const auto secondPoint = secondResponse.results()[0].continuation_point();
  ASSERT_FALSE(secondPoint.empty());
  EXPECT_NE(secondPoint, firstPoint);
  ASSERT_EQ(second->continuationPoints.size(), 1u);

  ASSERT_TRUE(fixture.wait_for_reads(1));
  fixture.release_reads();

  auto secondStore = Fixture::store_of(*second);
  auto third = fixture.browse_next({secondPoint}, secondStore, 1000);
  ASSERT_TRUE(third.has_value());
  const auto& thirdResponse = as_browse_next(*third);
  ASSERT_EQ(thirdResponse.results()[0].references().size(), 1u);
  EXPECT_EQ(thirdResponse.results()[0].references()[0].browse_name(), (QualifiedName{0, "Released"}));
}

// Releasing the continuation point that owns a running reference read sets the cancellation flag of the
// read's RequestInfo; the read's late answer is then discarded without effect.
// @relation(AC-SVR-PARTIAL-RESULTS-001-RELEASE-STOPS-WORK, scope=function)
TEST(BrowsePartialResultsTests, ReleasingThePausedContinuationPointSetsTheCallsCancellationFlag)
{
  Fixture fixture{0.1};

  auto first = fixture.browse({NodeId{2, 1}}, 1000);
  ASSERT_TRUE(first.has_value());
  const auto point = as_browse(*first).results()[0].continuation_point();
  ASSERT_TRUE(fixture.wait_for_reads(1));
  const auto flag = fixture.gated->held_reference_read_request(0).cancelled;
  ASSERT_NE(flag, nullptr);
  EXPECT_FALSE(flag->load()) << "answering at the deadline must not stop the operation";

  auto store = Fixture::store_of(*first);
  auto released = fixture.browse_next({point}, store, 1000, /*release=*/true);
  ASSERT_TRUE(released.has_value());
  EXPECT_TRUE(as_browse_next(*released).response_header().service_result().is_good());
  EXPECT_TRUE(as_browse_next(*released).results().empty());
  EXPECT_TRUE(as_browse_next(*released).diagnostic_infos().empty());
  fixture.services.clear();  // the BrowseNext service holds the released point until it goes
  const auto until = std::chrono::steady_clock::now() + 1000ms;
  while (!flag->load() && std::chrono::steady_clock::now() < until)
  {
    std::this_thread::sleep_for(5ms);
  }
  EXPECT_TRUE(flag->load()) << "releasing the point must tell the running call to stop";

  EXPECT_TRUE(store.empty());
  auto resumed = fixture.browse_next({point}, store, 1000);
  ASSERT_TRUE(resumed.has_value());
  ASSERT_EQ(as_browse_next(*resumed).results().size(), 1u);
  EXPECT_EQ(
    as_browse_next(*resumed).results()[0].status_code(), StatusCode{Status::BadContinuationPointInvalid});
  ASSERT_EQ(fixture.completions.load(), 3u);

  ASSERT_EQ(fixture.gated->release_held_reference_reads(), 1u);
  fixture.services.clear();
  fixture.sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(fixture.threadPool);

  EXPECT_EQ(fixture.completions.load(), 3u) << "a late namespace answer must not complete a service again";
  EXPECT_TRUE(flag->load());
  EXPECT_TRUE(store.empty());
  EXPECT_TRUE(first->continuationPoints.empty());
  EXPECT_TRUE(as_browse(*first).results()[0].references().empty());
  EXPECT_TRUE(released->continuationPoints.empty());
  EXPECT_TRUE(as_browse_next(*released).results().empty());
  EXPECT_TRUE(resumed->continuationPoints.empty());
  EXPECT_EQ(
    as_browse_next(*resumed).results()[0].status_code(), StatusCode{Status::BadContinuationPointInvalid});
}

// Control: a point the client keeps does not set the flag.
// @relation(AC-SVR-PARTIAL-RESULTS-001-RELEASE-STOPS-WORK, scope=function)
TEST(BrowsePartialResultsTests, AKeptContinuationPointLeavesTheCallRunning)
{
  Fixture fixture{0.1};

  auto first = fixture.browse({NodeId{2, 1}}, 1000);
  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(fixture.wait_for_reads(1));
  const auto flag = fixture.gated->held_reference_read_request(0).cancelled;
  auto store = Fixture::store_of(*first);
  fixture.services.clear();
  EXPECT_FALSE(flag->load());
  const auto point = as_browse(*first).results()[0].continuation_point();
  ASSERT_EQ(fixture.gated->release_held_reference_reads(), 1u);
  auto resumed = fixture.browse_next({point}, store, 0);
  ASSERT_TRUE(resumed.has_value());
  const auto& response = as_browse_next(*resumed);
  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::Good});
  ASSERT_EQ(response.results()[0].references().size(), 1u);
  EXPECT_EQ(response.results()[0].references()[0].browse_name(), (QualifiedName{0, "Released"}));
  EXPECT_TRUE(response.results()[0].continuation_point().empty());
  EXPECT_TRUE(resumed->continuationPoints.empty());
  fixture.services.clear();
  fixture.sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(fixture.threadPool);
  EXPECT_EQ(fixture.completions.load(), 2u);
}

// With no continuation point left for it, a running Browse item is awaited until the timeoutHint and
// then answered Bad_NoContinuationPoints on its own (OPC 10000-4 section 7.9); the item that did get a
// point keeps it.
// @relation(AC-SVR-PARTIAL-RESULTS-001-NO-CONTINUATION-POINT, scope=function)
TEST(BrowsePartialResultsTests, AnItemWithNoContinuationPointLeftIsAnsweredBadNoContinuationPointsAtTheHint)
{
  Fixture fixture{0.25, /*maxContinuationPoints=*/1};  // deadline at 100 ms of a 400 ms hint

  const auto started = std::chrono::steady_clock::now();
  auto first = fixture.browse({NodeId{2, 1}, NodeId{2, 2}}, 400);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  ASSERT_TRUE(first.has_value());
  const auto& response = as_browse(*first);
  ASSERT_EQ(response.results().size(), 2u);
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_FALSE(response.results()[0].continuation_point().empty());
  EXPECT_EQ(response.results()[1].status_code(), StatusCode{Status::BadNoContinuationPoints});
  EXPECT_TRUE(response.results()[1].continuation_point().empty());
  EXPECT_GE(elapsed, 400ms) << "the item without a point is awaited until the timeoutHint";
  ASSERT_TRUE(fixture.wait_for_reads(1));
  fixture.release_reads();
}

// Control: the item awaiting a point that finishes before the timeoutHint is answered with its
// references, and the response is sent as soon as it has.
// @relation(AC-SVR-PARTIAL-RESULTS-001-NO-CONTINUATION-POINT, scope=function)
TEST(BrowsePartialResultsTests, AnItemAwaitingAContinuationPointThatFinishesInTimeKeepsItsResult)
{
  Fixture fixture{0.25, /*maxContinuationPoints=*/1};

  std::thread releaser{[&fixture]
    {
      if (fixture.wait_for_reads(1))
      {
        std::this_thread::sleep_for(150ms);  // after the 100 ms deadline, well before the 400 ms hint
        fixture.release_reads();
      }
    }};
  const auto started = std::chrono::steady_clock::now();
  auto first = fixture.browse({NodeId{2, 1}, NodeId{2, 2}}, 400);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  releaser.join();
  ASSERT_TRUE(first.has_value());
  const auto& response = as_browse(*first);
  ASSERT_EQ(response.results().size(), 2u);
  EXPECT_EQ(response.results()[0].status_code(), StatusCode{Status::Good});
  EXPECT_FALSE(response.results()[0].continuation_point().empty()) << "the first item took the one point";
  EXPECT_EQ(response.results()[1].status_code(), StatusCode{Status::Good});
  EXPECT_EQ(response.results()[1].references().size(), 1u);
  EXPECT_TRUE(response.results()[1].continuation_point().empty());
  EXPECT_LT(elapsed, 380ms) << "answered when the awaited item finished, not at the timeoutHint";
}

// API-10.2: the namespace's reference read is told the partial-result deadline, as its RequestInfo's
// answerBy; a request with timeoutHint 0 has none.
// @relation(AC-SVR-PARTIAL-RESULTS-001-DEADLINE-REACHES-NAMESPACE, scope=function)
TEST(BrowsePartialResultsTests, TheReferenceReadIsToldThePartialResultDeadline)
{
  Fixture held{0.5};
  const auto before = std::chrono::steady_clock::now();
  std::thread releaser{[&held]
    {
      if (held.wait_for_reads(1))
      {
        held.release_reads();
      }
    }};
  auto response = held.browse({NodeId{2, 1}}, 1000);
  releaser.join();
  ASSERT_TRUE(response.has_value());
  ASSERT_EQ(held.gated->held_reference_read_count(), 1u) << "the reference read of 2:1 was not made";
  const auto answerBy = held.gated->held_reference_read_request(0).answerBy;
  ASSERT_TRUE(answerBy.has_value()) << "the reference read carries no answerBy";
  EXPECT_GE(*answerBy, before + 450ms);
  EXPECT_LE(*answerBy, before + 600ms);

  Fixture noHint{0.5};
  std::thread releaseNoHint{[&noHint]
    {
      if (noHint.wait_for_reads(1))
      {
        noHint.release_reads();
      }
    }};
  auto noHintResponse = noHint.browse({NodeId{2, 1}}, 0);
  releaseNoHint.join();
  ASSERT_TRUE(noHintResponse.has_value());
  ASSERT_EQ(noHint.gated->held_reference_read_count(), 1u) << "the reference read of 2:1 was not made";
  EXPECT_FALSE(noHint.gated->held_reference_read_request(0).answerBy.has_value());
}

// timeoutHint 0 asks for no timeout: nothing is answered early, so an operation slower than any deadline
// still returns its result in the first response.
// @relation(AC-SVR-PARTIAL-RESULTS-001-NO-HINT, scope=function)
TEST(BrowsePartialResultsTests, ARequestWithTimeoutHintZeroIsNeverAnsweredEarly)
{
  Fixture fixture{0.1};
  std::thread releaser{[&fixture]
    {
      if (fixture.wait_for_reads(1))
      {
        std::this_thread::sleep_for(300ms);
        fixture.release_reads();
      }
    }};
  auto first = fixture.browse({NodeId{2, 1}}, 0);
  releaser.join();
  ASSERT_TRUE(first.has_value());
  const auto& response = as_browse(*first);
  ASSERT_EQ(response.results()[0].references().size(), 1u);
  EXPECT_TRUE(response.results()[0].continuation_point().empty());
}

// D11: a namespace continuing a browse through BrowseNext receives, in its reference read's RequestInfo, a
// cancellation flag, and cancelling the BrowseNext sets it. 2:3 holds two References and the namespace pages
// at the query's maxReferences, so a Browse with requestedMaxReferencesPerNode 1 hands out a continuation
// point holding the namespace's resume token, and the BrowseNext reads 2:3 again.
// @relation(AC-SVR-PARTIAL-RESULTS-005-BROWSE-NEXT-FLAG, scope=function)
TEST(BrowsePartialResultsTests, BrowseNextReferenceReadCarriesACancellationFlagThatCancelSets)
{
  Fixture fixture{0.5};
  fixture.gated->page_references_by_max_references();
  std::thread releaser{[&fixture]
    {
      if (fixture.wait_for_reads(1))
      {
        fixture.release_reads();
      }
    }};
  auto first = fixture.browse({NodeId{2, 3}}, 0, 3000ms, 1);
  releaser.join();
  ASSERT_TRUE(first.has_value());
  const auto point = as_browse(*first).results()[0].continuation_point();
  ASSERT_FALSE(point.empty());
  auto store = Fixture::store_of(*first);

  BrowseNextRequest request;
  request.continuation_points().resize(1);
  request.continuation_points()[0] = point;
  auto done = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
  auto future = done->get_future();
  auto service = BrowseService::create(fixture.sessionInfo,
    fixture.locales,
    3,
    std::move(request),
    store,
    fixture.threadPool.get_executor(),
    [done](BrowseService::BrowseServiceResponse response) { done->set_value(std::move(response)); });
  ASSERT_TRUE(fixture.wait_for_reads(2));
  const auto flag = fixture.gated->held_reference_read_request(1).cancelled;
  ASSERT_NE(flag, nullptr) << "BrowseNext must hand the reference read a cancellation flag";
  EXPECT_FALSE(flag->load());

  service->cancel();
  ASSERT_EQ(future.wait_for(2000ms), std::future_status::ready);
  EXPECT_TRUE(flag->load());
  fixture.release_reads();
}

// A BrowseNext that delivers a paused operation's result authorizes it again first, as every continuation
// is: once Browse on the Node is withdrawn, the stored references are not returned, and the item is
// answered with the status a fresh Browse of that Node gets.
// @relation(AC-SVR-PARTIAL-RESULTS-001-WAIT-REAUTHORIZED, scope=function)
TEST(BrowsePartialResultsTests, AContinuationIsAuthorizedAgainBeforeItsStoredResultIsReturned)
{
  Fixture fixture{0.1};
  auto first = fixture.browse({NodeId{2, 1}}, 1000);
  ASSERT_TRUE(first.has_value());
  const auto point = as_browse(*first).results()[0].continuation_point();
  ASSERT_FALSE(point.empty());
  ASSERT_TRUE(fixture.wait_for_reads(1));
  fixture.release_reads();

  // Withdraw Browse on the source Node from every role the test session holds.
  std::vector<RolePermissionType> none;
  for (const auto& role :
    {ua::test_helpers::test_access_role_id(), NodeId{ObjectId::WellKnownRole_SecurityAdmin}})
  {
    RolePermissionType permission;
    permission.role_id() = role;
    permission.permissions() = PermissionType{};
    none.push_back(std::move(permission));
  }
  auto node = fixture.sessionInfo->address_space().find_node_sync(NodeId{2, 1});
  node.set_role_permissions(none);

  fixture.answer_at_once();
  auto fresh = fixture.browse({NodeId{2, 1}}, 1000);
  ASSERT_TRUE(fresh.has_value());
  const auto refusal = as_browse(*fresh).results()[0].status_code();
  ASSERT_TRUE(refusal.is_bad()) << "the fixture must actually withdraw Browse";

  auto store = Fixture::store_of(*first);
  auto next = fixture.browse_next({point}, store, 1000);
  ASSERT_TRUE(next.has_value());
  const auto& nextResponse = as_browse_next(*next);
  ASSERT_EQ(nextResponse.results().size(), 1u);
  EXPECT_EQ(nextResponse.results()[0].status_code(), refusal);
  EXPECT_TRUE(nextResponse.results()[0].references().empty());
  EXPECT_TRUE(nextResponse.results()[0].continuation_point().empty());
}

// DL-36: a Browse in a View's context answers Uncertain_NotAllNodesAvailable, with the References it could
// decide and possibly a continuation point, when the View's namespace cannot say whether a target is a
// member.
namespace
{
/// A membership question the View's namespace holds until the test answers it.
struct HeldMembershipQuestion
{
  std::mutex mutex;
  std::condition_variable asked;
  std::function<void(BoolResult)> answer;

  /// Waits until the held question has been asked.
  bool wait_until_asked(std::chrono::milliseconds limit = 2000ms)
  {
    std::unique_lock<std::mutex> lock(mutex);
    return asked.wait_for(lock, limit, [this] { return static_cast<bool>(answer); });
  }

  /// Answers the held question with @p result, once; nothing when it was not asked or is answered.
  void release(BoolResult result)
  {
    std::function<void(BoolResult)> held;
    {
      const std::lock_guard<std::mutex> lock(mutex);
      held = std::exchange(answer, {});
    }
    if (held)
    {
      held(std::move(result));
    }
  }
};

/// What the BrowseNext continuing the paused operation answered for its one item.
struct ContinuedOutcome
{
  NodeId m1;
  StatusCode status;
  std::vector<ExpandedNodeId> targets;
  bool continuationPoint{false};
};

/// AC-SVR-PARTIAL-RESULTS-001-WAIT-REAUTHORIZED-UNCERTAIN-OUTCOME's stimulus. In a View whose namespace
/// answers T's membership only when released, browses S with requestedMaxReferencesPerNode 1; S holds
/// Organizes References to T, M1 and M2, in that order. The Browse is answered at the partial-result deadline
/// with a continuation point P; T's membership is then answered Bad, so the operation finishes
/// Uncertain_NotAllNodesAvailable with the Reference to M1 and a continuation point of its own. Browse on S
/// is withdrawn from every role the Session holds when @p withdrawBrowse, and P is continued by a BrowseNext.
void continue_incomplete_paused_outcome(bool withdrawBrowse, ContinuedOutcome& continued)
{
  Fixture fixture{0.1};  // deadline at 100 ms of a 1000 ms hint
  auto held = std::make_shared<HeldMembershipQuestion>();
  auto heldNode = std::make_shared<NodeId>();
  auto members = std::make_shared<std::vector<NodeId>>();
  auto ns = ua::test::EveryNodeInViewNamespace::create_deferred("uri://held-view-membership",
    fixture.threadPool.get_executor(),
    [held, heldNode, members](const NodeId& nodeId, std::function<void(BoolResult)> answer)
    {
      if (nodeId == *heldNode)
      {
        const std::lock_guard<std::mutex> lock(held->mutex);
        held->answer = std::move(answer);
        held->asked.notify_all();
        return;
      }
      answer(BoolResult{std::find(members->begin(), members->end(), nodeId) != members->end()});
    });
  auto addressSpace = fixture.sessionInfo->address_space();
  const uint16_t nsIndex = addressSpace.add_namespace_sync(ns);
  // The Session's access was configured for the namespaces it was created with; this one is granted as they
  // are.
  ua::test_helpers::grant_namespace_to_test_client(
    addressSpace, nsIndex, {ua::test_helpers::test_access_role_id()});
  const NodeId viewId{nsIndex, 1};
  const NodeId s{nsIndex, 2};
  const NodeId t{nsIndex, 3};
  const NodeId m1{nsIndex, 4};
  const NodeId m2{nsIndex, 5};
  const NodeId organizes{ReferenceTypeId::Organizes};
  *heldNode = t;
  *members = {s, m1, m2};
  continued.m1 = m1;
  ns->create_node(viewId, NodeClass::View);
  for (const auto& id : {s, t, m1, m2})
    ns->create_node(id, NodeClass::Object);
  auto source = addressSpace.find_node_sync(s);
  for (const auto& target : {t, m1, m2})
    ASSERT_TRUE(source.try_add_reference_sync(organizes, ExpandedNodeId{target}, true).is_good());

  BrowseRequest request;
  request.request_header().timeout_hint() = 1000;
  request.view().view_id() = viewId;
  request.requested_max_references_per_node() = 1;
  request.nodes_to_browse().resize(1);
  request.nodes_to_browse()[0].node_id() = s;
  request.nodes_to_browse()[0].browse_direction() = BrowseDirection::Forward;
  request.nodes_to_browse()[0].reference_type_id() = organizes;
  request.nodes_to_browse()[0].include_subtypes() = false;
  auto done = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
  auto future = done->get_future();
  fixture.services.push_back(BrowseService::create(fixture.sessionInfo,
    fixture.locales,
    1,
    std::move(request),
    fixture.threadPool.get_executor(),
    [done](BrowseService::BrowseServiceResponse response) { done->set_value(std::move(response)); }));
  const bool answered = future.wait_for(3000ms) == std::future_status::ready;
  if (!answered)
  {
    held->release(BoolResult{StatusCode{Status::BadInternalError}});
  }
  ASSERT_TRUE(answered) << "the Browse must be answered at its partial-result deadline";
  auto first = future.get();
  const auto& paused = as_browse(first);
  ASSERT_EQ(paused.results().size(), 1u);
  const auto point = paused.results()[0].continuation_point();
  if (point.empty())
  {
    held->release(BoolResult{StatusCode{Status::BadInternalError}});
  }
  ASSERT_FALSE(point.empty()) << "S's operation was not paused with a continuation point; it answered "
                              << to_string(paused.results()[0].status_code()) << " with "
                              << paused.results()[0].references().size() << " References";
  ASSERT_TRUE(held->wait_until_asked()) << "T's membership was never asked";

  held->release(BoolResult{StatusCode{Status::BadInternalError},
    ErrorDetail::build(
      "ScriptedTMembershipFailure", "The test's View cannot say whether this Node is a member", "TestView")});

  if (withdrawBrowse)
  {
    std::vector<RolePermissionType> none;
    for (const auto& role :
      {ua::test_helpers::test_access_role_id(), NodeId{ObjectId::WellKnownRole_SecurityAdmin}})
    {
      RolePermissionType permission;
      permission.role_id() = role;
      permission.permissions() = PermissionType{};
      none.push_back(std::move(permission));
    }
    addressSpace.find_node_sync(s).set_role_permissions(none);
  }

  auto store = Fixture::store_of(first);
  auto next = fixture.browse_next({point}, store, 0);
  ASSERT_TRUE(next.has_value()) << "the BrowseNext was not answered";
  const auto& nextResponse = as_browse_next(*next);
  ASSERT_EQ(nextResponse.results().size(), 1u);
  const auto& result = nextResponse.results()[0];
  continued.status = result.status_code();
  for (const auto& reference : result.references())
    continued.targets.push_back(reference.node_id());
  continued.continuationPoint = !result.continuation_point().empty();
}
}  // namespace

// OPC 10000-4 section 6.2.1 and SVR-AUTHZ-010: a continuation is authorized again, as a fresh request is.
// Part 4 section 5.8.2.4, Table 36: Uncertain_NotAllNodesAvailable, "Browse results may be incomplete because
// of the unavailability of a subsystem.", is an outcome that carries References and may carry a
// continuation point, so a BrowseNext that waited on a paused operation with that outcome authorizes it
// again as it does a Good one (DL-39 (b)). The operation is paused by the View's late membership answer for
// T. With Browse on S withdrawn, the BrowseNext answers the access control's denial with nothing else; the
// control, with Browse still granted, is answered the operation's own outcome.
// @relation(AC-SVR-PARTIAL-RESULTS-001-WAIT-REAUTHORIZED-UNCERTAIN-OUTCOME, scope=function)
TEST(BrowsePartialResultsTests, AContinuationOfAnIncompletePausedOutcomeIsAuthorizedAgain)
{
  {
    SCOPED_TRACE("Browse on S withdrawn");
    ContinuedOutcome withdrawn;
    ASSERT_NO_FATAL_FAILURE(continue_incomplete_paused_outcome(true, withdrawn));
    EXPECT_EQ(withdrawn.status.as_status(), Status::BadUserAccessDenied)
      << "the continuation was not authorized again";
    EXPECT_TRUE(withdrawn.targets.empty()) << withdrawn.targets.size() << " References returned";
    EXPECT_FALSE(withdrawn.continuationPoint);
  }
  {
    SCOPED_TRACE("control: Browse on S granted");
    ContinuedOutcome granted;
    ASSERT_NO_FATAL_FAILURE(continue_incomplete_paused_outcome(false, granted));
    EXPECT_EQ(granted.status.as_status(), Status::UncertainNotAllNodesAvailable);
    EXPECT_EQ(granted.targets, std::vector<ExpandedNodeId>{ExpandedNodeId{granted.m1}})
      << granted.targets.size() << " References returned; expected the Reference to M1 alone";
    EXPECT_TRUE(granted.continuationPoint) << "the operation's own continuation point was not returned";
  }
}
