// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How TranslateBrowsePaths calls the namespaces that hold the Nodes its paths walk: per path element one
// read_references_async per namespace for the distinct Nodes the paths have reached, each query carrying the
// element's direction and ReferenceType as hints; a paged answer followed within the element and a resume
// token left open released; and every lookup, permissions call and reference read carrying the request.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ua_address_space.h"
#include "ua_browse_direction.h"
#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_byte_string.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_to_string.h"
#include "ua_translate_browse_paths_service.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include <boost/asio/thread_pool.hpp>

#include "batch_recording_namespace.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;
using Call = BatchRecordingNamespace::Call;

namespace
{

struct TranslateOutcome
{
  bool answered{false};
  StatusCode serviceResult;
  std::optional<TranslateBrowsePathsToNodeIdsResponse> response;
};

// A server with the given namespaces registered, and a Session on it.
struct FlowHarness
{
  ~FlowHarness()
  {
    sent.clear();
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool;
  shared_ptr<SessionInfoStub> sessionInfo;
  // The services @ref send started, held until the harness ends.
  std::vector<shared_ptr<TranslateBrowsePathsService>> sent;

  std::vector<uint16_t> setup(
    const std::vector<shared_ptr<ua::Namespace>>& namespaces, ServerConfig serverConfig = ServerConfig{})
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfig)};
    auto server = Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    std::vector<uint16_t> indexes;
    for (const auto& nameSpace : namespaces)
    {
      indexes.push_back(server.address_space().add_namespace_sync(nameSpace));
    }
    sessionInfo = make_shared<SessionInfoStub>(std::move(server), threadPool.get_executor());
    return indexes;
  }

  // A Node of @p nodeClass with the BrowseName @p name in its own namespace.
  NodeId create(const NodeId& nodeId, const std::string& name, NodeClass nodeClass = NodeClass::Object)
  {
    auto created = sessionInfo->address_space().try_create_node_sync(nodeId, nodeClass);
    EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
    if (created.is_good())
    {
      created.value().set_browse_name(QualifiedName{nodeId.namespace_index(), name});
    }
    return nodeId;
  }

  // A Reference of @p type from @p source to @p target: the forward half held by the source and the inverse
  // half held by the target.
  void link(const NodeId& source, ReferenceTypeId type, const NodeId& target)
  {
    auto addressSpace = sessionInfo->address_space();
    auto from = addressSpace.try_find_node_sync(source);
    auto to = addressSpace.try_find_node_sync(target);
    ASSERT_TRUE(from.is_good()) << source.as_definition();
    ASSERT_TRUE(to.is_good()) << target.as_definition();
    EXPECT_TRUE(from.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{target}, true).is_good())
      << source.as_definition() << " to " << target.as_definition();
    EXPECT_TRUE(to.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{source}, false).is_good())
      << target.as_definition() << " from " << source.as_definition();
  }

  TranslateOutcome translate(TranslateBrowsePathsToNodeIdsRequest request)
  {
    auto promise = std::make_shared<std::promise<TranslateOutcome>>();
    auto future = promise->get_future();
    auto service = TranslateBrowsePathsService::create(sessionInfo,
      {"en"},
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise](Response response)
      {
        TranslateOutcome outcome;
        outcome.answered = true;
        if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* translated =
                   dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get()))
        {
          outcome.serviceResult = translated->response_header().service_result();
          outcome.response = std::move(*translated);
        }
        promise->set_value(std::move(outcome));
      });
    if (future.wait_for(10s) != std::future_status::ready)
    {
      ADD_FAILURE() << "TranslateBrowsePaths did not complete";
      return {};
    }
    return future.get();
  }

  // Sends @p request without waiting: the future is ready when the response arrives.
  std::future<TranslateOutcome> send(TranslateBrowsePathsToNodeIdsRequest request)
  {
    auto promise = std::make_shared<std::promise<TranslateOutcome>>();
    auto future = promise->get_future();
    sent.push_back(TranslateBrowsePathsService::create(sessionInfo,
      {"en"},
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise](Response response)
      {
        TranslateOutcome outcome;
        outcome.answered = true;
        if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* translated =
                   dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get()))
        {
          outcome.serviceResult = translated->response_header().service_result();
          outcome.response = std::move(*translated);
        }
        promise->set_value(std::move(outcome));
      }));
    return future;
  }
};

// One element of a relative path.
struct Step
{
  NodeId referenceType;
  bool inverse{false};
  bool includeSubtypes{true};
  QualifiedName name;
};

Step forward_step(ReferenceTypeId type, QualifiedName name)
{
  return Step{
    .referenceType = NodeId{type}, .inverse = false, .includeSubtypes = true, .name = std::move(name)};
}

BrowsePath path_of(const NodeId& start, const std::vector<Step>& steps)
{
  BrowsePath path;
  path.starting_node() = start;
  for (const auto& step : steps)
  {
    RelativePathElement element;
    element.reference_type_id() = step.referenceType;
    element.is_inverse() = step.inverse;
    element.include_subtypes() = step.includeSubtypes;
    element.target_name() = step.name;
    path.relative_path().elements().payload().push_back(std::move(element));
  }
  return path;
}

TranslateBrowsePathsToNodeIdsRequest request_of(std::vector<BrowsePath> paths, uint32_t timeoutHint = 0)
{
  TranslateBrowsePathsToNodeIdsRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = timeoutHint;
  for (auto& path : paths)
  {
    request.browse_paths().payload().push_back(std::move(path));
  }
  return request;
}

std::vector<NodeId> sorted(std::vector<NodeId> nodeIds)
{
  std::sort(nodeIds.begin(), nodeIds.end());
  return nodeIds;
}

// The local NodeIds of @p result's targets, sorted.
std::vector<NodeId> targets_of(const BrowsePathResult& result)
{
  std::vector<NodeId> targets;
  for (const auto& target : result.targets())
  {
    targets.push_back(target.target_id().node_id());
  }
  return sorted(std::move(targets));
}

std::string describe(const std::vector<Call>& calls)
{
  std::string text;
  for (const auto& call : calls)
  {
    text += "\n  call";
    for (const auto& nodeId : call.nodeIds)
    {
      text += " " + nodeId.as_definition();
    }
  }
  return text;
}

std::string text_of(const ByteString& token)
{
  return std::string{reinterpret_cast<const char*>(token.data()), token.size()};
}

// Every query of every read_references_async call @p nameSpace received, in order.
std::vector<BatchRecordingNamespace::ReferenceQueryRecord> queries_of(
  const BatchRecordingNamespace& nameSpace)
{
  std::vector<BatchRecordingNamespace::ReferenceQueryRecord> queries;
  for (const auto& call : nameSpace.calls(Member::ReadReferences))
  {
    queries.insert(queries.end(), call.referenceQueries.begin(), call.referenceQueries.end());
  }
  return queries;
}

// Each recorded call carries a request whose deadline lies between @p from and @p to and whose cancellation
// flag is not set.
void expect_each_carries_the_request(const std::vector<Call>& calls,
  std::chrono::steady_clock::time_point from, std::chrono::steady_clock::time_point to, const char* kind)
{
  EXPECT_FALSE(calls.empty()) << kind << ": no call was made";
  for (std::size_t k = 0; k < calls.size(); ++k)
  {
    const auto& call = calls[k];
    EXPECT_TRUE(call.hasRequest) << kind << " " << k << ": the call took no RequestInfo";
    EXPECT_GE(call.deadline, from) << kind << " " << k << ": the deadline is before T0 + 4.5 s";
    EXPECT_LE(call.deadline, to) << kind << " " << k << ": the deadline is after T0 + 5.5 s";
    EXPECT_FALSE(call.cancelled) << kind << " " << k << ": the cancellation flag is set";
  }
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-ONE-REFERENCE-READ-PER-NAMESPACE-PER-ELEMENT, scope=function)
TEST(TranslateFlow, OneReferenceReadPerNamespacePerRound)
{
  FlowHarness harness;
  auto r1 =
    make_shared<BatchRecordingNamespace>("urn:test:translate-flow:r1", harness.threadPool.get_executor());
  auto r2 =
    make_shared<BatchRecordingNamespace>("urn:test:translate-flow:r2", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r1, r2});
  const uint16_t i1 = indexes.at(0);
  const uint16_t i2 = indexes.at(1);
  const NodeId s = harness.create(NodeId{i1, 100u}, "S");
  const NodeId m = harness.create(NodeId{i1, 101u}, "M");
  const NodeId a1 = harness.create(NodeId{i2, 200u}, "A");
  const NodeId a2 = harness.create(NodeId{i2, 201u}, "A");
  const NodeId t1 = harness.create(NodeId{i2, 300u}, "T", NodeClass::Variable);
  const NodeId t2 = harness.create(NodeId{i2, 301u}, "T", NodeClass::Variable);
  harness.link(s, ReferenceTypeId::HasComponent, m);
  harness.link(m, ReferenceTypeId::HasComponent, a1);
  harness.link(m, ReferenceTypeId::HasComponent, a2);
  harness.link(a1, ReferenceTypeId::HasProperty, t1);
  harness.link(a2, ReferenceTypeId::HasProperty, t2);
  r1->reset();
  r2->reset();

  const QualifiedName nameM{i1, "M"};
  const QualifiedName nameA{i2, "A"};
  const QualifiedName nameT{i2, "T"};
  const auto outcome = harness.translate(request_of({path_of(s,
                                                       {forward_step(ReferenceTypeId::HasComponent, nameM),
                                                         forward_step(ReferenceTypeId::HasComponent, nameA),
                                                         forward_step(ReferenceTypeId::HasProperty, nameT)}),
    path_of(s,
      {forward_step(ReferenceTypeId::HasComponent, nameM),
        forward_step(ReferenceTypeId::HasComponent, nameA)})}));

  const auto readsR1 = r1->calls(Member::ReadReferences);
  EXPECT_EQ(readsR1.size(), 2U) << "R1's read_references_async calls:" << describe(readsR1);
  if (readsR1.size() == 2U)
  {
    EXPECT_EQ(readsR1[0].nodeIds, std::vector<NodeId>{s}) << "R1's first call names S only";
    EXPECT_EQ(readsR1[1].nodeIds, std::vector<NodeId>{m}) << "R1's second call names M only";
  }
  const auto readsR2 = r2->calls(Member::ReadReferences);
  EXPECT_EQ(readsR2.size(), 1U) << "R2's read_references_async calls:" << describe(readsR2);
  if (readsR2.size() == 1U)
  {
    EXPECT_EQ(sorted(readsR2[0].nodeIds), sorted({a1, a2})) << "R2's call names A1 and A2";
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(outcome.response->results()[0].status_code().as_status(), Status::Good) << "the path M/A/T";
  EXPECT_EQ(targets_of(outcome.response->results()[0]), sorted({t1, t2})) << "the path M/A/T";
  EXPECT_EQ(outcome.response->results()[1].status_code().as_status(), Status::Good) << "the path M/A";
  EXPECT_EQ(targets_of(outcome.response->results()[1]), sorted({a1, a2})) << "the path M/A";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-THE-REFERENCE-READS-CARRY-THE-ELEMENTS-DIRECTION-AND-HINT, scope=function)
TEST(TranslateFlow, ReferenceReadsCarryTheElementsDirectionAndHint)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:direction-and-hint", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId p = harness.create(NodeId{index, 100u}, "P");
  const NodeId c = harness.create(NodeId{index, 101u}, "C");
  const NodeId d = harness.create(NodeId{index, 102u}, "D");
  harness.link(p, ReferenceTypeId::HasComponent, c);
  harness.link(c, ReferenceTypeId::Organizes, d);
  r->reset();

  const Step inverseHasComponent{.referenceType = NodeId{ReferenceTypeId::HasComponent},
    .inverse = true,
    .includeSubtypes = true,
    .name = QualifiedName{index, "P"}};
  const Step anyForward{
    .referenceType = NodeId{}, .inverse = false, .includeSubtypes = true, .name = QualifiedName{index, "C"}};
  const auto outcome =
    harness.translate(request_of({path_of(c, {inverseHasComponent}), path_of(p, {anyForward})}));

  const auto queries = queries_of(*r);
  const auto queryOf = [&queries](const NodeId& nodeId)
  {
    std::optional<BatchRecordingNamespace::ReferenceQueryRecord> found;
    std::size_t count = 0;
    for (const auto& query : queries)
    {
      if (query.nodeId == nodeId)
      {
        found = query;
        ++count;
      }
    }
    EXPECT_EQ(count, 1U) << "queries naming " << nodeId.as_definition();
    return found;
  };
  if (const auto forC = queryOf(c))
  {
    EXPECT_EQ(forC->direction, BrowseDirection::Inverse) << "C's query, read for an inverse element";
    EXPECT_EQ(forC->referenceTypeHint, std::vector<NodeId>{NodeId{ReferenceTypeId::HasComponent}})
      << "C's query, read for a HasComponent element";
  }
  if (const auto forP = queryOf(p))
  {
    EXPECT_EQ(forP->direction, BrowseDirection::Forward) << "P's query, read for a forward element";
    EXPECT_TRUE(forP->referenceTypeHint.empty()) << "P's query, read for an element naming no ReferenceType";
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(outcome.response->results()[0].status_code().as_status(), Status::Good)
    << "the inverse path from C";
  EXPECT_EQ(targets_of(outcome.response->results()[0]), std::vector<NodeId>{p}) << "the inverse path from C";
  EXPECT_EQ(outcome.response->results()[1].status_code().as_status(), Status::Good)
    << "the null-type path from P";
  EXPECT_EQ(targets_of(outcome.response->results()[1]), std::vector<NodeId>{c})
    << "the null-type path from P";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-THE-NAMESPACE-CALLS-CARRY-THE-REQUEST, scope=function)
TEST(TranslateFlow, EveryNamespaceCallCarriesTheRequest)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:request", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  const NodeId t = harness.create(NodeId{index, 101u}, "T");
  harness.link(s, ReferenceTypeId::HasComponent, t);
  r->decline_single_lookups();
  r->decline_immediate_permissions();
  r->reset();

  const auto sent = std::chrono::steady_clock::now();
  const auto outcome = harness.translate(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})})}, 5000));

  const auto from = sent + 4500ms;
  const auto to = sent + 5500ms;
  expect_each_carries_the_request(r->calls(Member::BatchedLookup), from, to, "batched lookup");
  expect_each_carries_the_request(
    r->calls(Member::PermissionsAsyncForRequest), from, to, "permissions call taking a RequestInfo");
  expect_each_carries_the_request(r->calls(Member::ReadReferences), from, to, "read_references_async");

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  EXPECT_EQ(outcome.response->results()[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(targets_of(outcome.response->results()[0]), std::vector<NodeId>{t});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-A-SUBTYPE-REFERENCE-IS-FOLLOWED-WHEN-THE-NAMESPACE-APPLIES-THE-HINT, scope=function)
TEST(TranslateFlow, ASubtypeReferenceIsFollowedWhenTheNamespaceAppliesTheHint)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:subtype", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  const NodeId t = harness.create(NodeId{index, 101u}, "T");
  harness.link(s, ReferenceTypeId::HasOrderedComponent, t);
  r->apply_reference_hints();
  r->reset();

  const auto outcome = harness.translate(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})})}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  EXPECT_EQ(outcome.response->results()[0].status_code().as_status(), Status::Good)
    << "a HasOrderedComponent Reference under a HasComponent element with subtypes";
  EXPECT_EQ(targets_of(outcome.response->results()[0]), std::vector<NodeId>{t});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-A-WIDE-ELEMENT-IS-ONE-CALL-OF-EACH-KIND-PER-NAMESPACE, scope=function)
// @relation(AC-COMP-RESOLUTION-ROUND-TRIP-COST-01-COST-IS-PER-REQUEST-NOT-PER-NODE, scope=function)
TEST(TranslateFlow, AWideElementIsOneCallOfEachKindPerNamespace)
{
  constexpr uint32_t width = 40;
  FlowHarness harness;
  auto r1 = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:wide:r1", harness.threadPool.get_executor());
  auto r2 = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:wide:r2", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.server_capabilities().operationLimits.maxNodesPerRead = std::nullopt;
  serverConfig.server_capabilities().operationLimits.maxNodesPerBrowse = std::nullopt;
  // The per-request Browse budget needs a MaxNodesPerBrowse; it does not bound TranslateBrowsePaths.
  serverConfig.maxReferencesPerBrowseRequest = std::nullopt;
  const auto indexes = harness.setup({r1, r2}, std::move(serverConfig));
  const uint16_t i1 = indexes.at(0);
  const uint16_t i2 = indexes.at(1);
  const NodeId s = harness.create(NodeId{i1, 100u}, "S");
  std::vector<NodeId> as;
  std::vector<NodeId> ts;
  for (uint32_t i = 0; i < width; ++i)
  {
    as.push_back(harness.create(NodeId{i2, 1000u + i}, "A"));
    ts.push_back(harness.create(NodeId{i2, 2000u + i}, "T", NodeClass::Variable));
    harness.link(s, ReferenceTypeId::HasComponent, as.back());
    harness.link(as.back(), ReferenceTypeId::HasProperty, ts.back());
  }
  for (const auto& nameSpace : {r1, r2})
  {
    nameSpace->decline_single_lookups();
    nameSpace->decline_immediate_permissions();
    nameSpace->reset();
  }

  const auto outcome = harness.translate(request_of({path_of(s,
    {forward_step(ReferenceTypeId::HasComponent, QualifiedName{i2, "A"}),
      forward_step(ReferenceTypeId::HasProperty, QualifiedName{i2, "T"})})}));

  const auto reads = r2->calls(Member::ReadReferences);
  EXPECT_EQ(reads.size(), 1U) << "R2's read_references_async calls:" << describe(reads);
  if (reads.size() == 1U)
  {
    EXPECT_EQ(sorted(reads[0].nodeIds), sorted(as)) << "R2's reference read names A1 to A40";
  }
  const auto lookups = r2->calls(Member::BatchedLookup);
  EXPECT_EQ(lookups.size(), 2U) << "R2's batched lookups:" << describe(lookups);
  if (lookups.size() == 2U)
  {
    EXPECT_EQ(sorted(lookups[0].nodeIds), sorted(as)) << "R2's first batched lookup names A1 to A40";
    EXPECT_EQ(sorted(lookups[1].nodeIds), sorted(ts)) << "R2's second batched lookup names T1 to T40";
  }
  const auto permissions = r2->calls(Member::PermissionsAsyncForRequest);
  EXPECT_EQ(permissions.size(), 2U) << "R2's permissions calls taking a RequestInfo:"
                                    << describe(permissions);
  if (permissions.size() == 2U)
  {
    EXPECT_EQ(sorted(permissions[0].nodeIds), sorted(as)) << "R2's first permissions call names A1 to A40";
    EXPECT_EQ(sorted(permissions[1].nodeIds), sorted(ts)) << "R2's second permissions call names T1 to T40";
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  EXPECT_EQ(outcome.response->results()[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(targets_of(outcome.response->results()[0]), sorted(ts));
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-A-PAGED-ANSWER-IS-FOLLOWED-WITHIN-THE-ELEMENT, scope=function)
TEST(TranslateFlow, APagedAnswerIsFollowedWithinTheElement)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:translate-flow:paged", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  const NodeId x = harness.create(NodeId{index, 101u}, "X");
  const NodeId t = harness.create(NodeId{index, 102u}, "T");
  harness.link(s, ReferenceTypeId::Organizes, x);
  harness.link(s, ReferenceTypeId::HasComponent, t);
  r->page_references(1);
  r->reset();

  const auto outcome = harness.translate(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})})}));

  std::vector<BatchRecordingNamespace::ReferenceQueryRecord> ofS;
  for (const auto& query : queries_of(*r))
  {
    if (query.nodeId == s)
    {
      ofS.push_back(query);
    }
  }
  EXPECT_EQ(ofS.size(), 2U) << "read_references_async queries naming S";
  if (ofS.size() == 2U)
  {
    EXPECT_TRUE(ofS[0].resumeToken.empty()) << "the first query carried a resume token";
    EXPECT_FALSE(ofS[0].answeredToken.empty()) << "the first answer gave no resume token";
    EXPECT_EQ(ofS[1].resumeToken, ofS[0].answeredToken)
      << "the second query carried \"" << text_of(ofS[1].resumeToken) << "\", the first answer's token is \""
      << text_of(ofS[0].answeredToken) << "\"";
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  EXPECT_EQ(outcome.response->results()[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(targets_of(outcome.response->results()[0]), std::vector<NodeId>{t});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-AN-ABANDONED-RESUME-TOKEN-IS-RELEASED, scope=function)
TEST(TranslateFlow, AnAbandonedResumeTokenIsReleased)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:abandoned", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.maxBrowsePathWalkReferences = 1;
  const uint16_t index = harness.setup({r}, std::move(serverConfig)).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  for (uint32_t i = 1; i <= 3; ++i)
  {
    harness.link(
      s, ReferenceTypeId::Organizes, harness.create(NodeId{index, 100u + i}, "O" + std::to_string(i)));
  }
  r->page_references(1);
  r->reset();

  const auto outcome = harness.translate(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})})}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& result = outcome.response->results()[0];
  EXPECT_EQ(result.status_code().as_status(), Status::BadQueryTooComplex);
  ASSERT_NE(result.status_code().shared_detail(), nullptr) << "the path's status names no ErrorDetail";
  EXPECT_EQ(result.status_code().shared_detail()->code, "BrowsePathWalkTooComplex");

  // The release may follow the answer; it is given a moment to arrive.
  const auto until = std::chrono::steady_clock::now() + 1s;
  while (r->count(Member::ReleaseResumeToken) == 0 && std::chrono::steady_clock::now() < until)
  {
    std::this_thread::sleep_for(10ms);
  }

  const auto reads = r->calls(Member::ReadReferences);
  ASSERT_GE(reads.size(), 2U) << "read_references_async calls:" << describe(reads);
  ASSERT_EQ(reads[1].referenceQueries.size(), 1U) << "the second call's queries";
  const ByteString secondAnswer = reads[1].referenceQueries[0].answeredToken;
  ASSERT_FALSE(secondAnswer.empty()) << "R gave no resume token in its answer to the second call";

  const auto releases = r->calls(Member::ReleaseResumeToken);
  EXPECT_EQ(releases.size(), 1U) << "release_resume_token calls";
  if (releases.size() == 1U)
  {
    EXPECT_EQ(releases[0].token, secondAnswer)
      << "released \"" << text_of(releases[0].token) << "\", the second answer's token is \""
      << text_of(secondAnswer) << "\"";
  }
  for (std::size_t k = 2; k < reads.size(); ++k)
  {
    for (const auto& query : reads[k].referenceQueries)
    {
      EXPECT_NE(query.resumeToken, secondAnswer)
        << "call " << k + 1 << " carried the second answer's token \"" << text_of(secondAnswer) << "\"";
    }
  }
}

// Both halves of a symmetric Reference are forward (OPC 10000-3 5.3.2): from the Node that holds the half
// stored as inverse, a forward element follows it and an inverse element does not, as Browse reports it. The
// control is the same paths over a non-symmetric type, whose inverse half only an inverse element follows.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-27-A-SYMMETRIC-REFERENCE-STORED-AS-INVERSE-IS-FOLLOWED-AS-FORWARD, scope=function)
TEST(TranslateFlow, ASymmetricReferenceStoredAsInverseIsFollowedAsForward)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:symmetric", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  auto addressSpace = harness.sessionInfo->address_space();
  const NodeId symmetricType{index, 900u};
  const NodeId oneWayType{index, 901u};
  for (const auto& [typeId, symmetric] : {std::pair{symmetricType, true}, std::pair{oneWayType, false}})
  {
    auto type = addressSpace.try_create_sync<ReferenceTypeAccessor>(typeId, NodeClass::ReferenceType);
    ASSERT_TRUE(type.is_good()) << to_string(type.status_code());
    type.value().set_browse_name(QualifiedName{index, symmetric ? "Twin" : "Feeds"});
    type.value().set_symmetric(symmetric);
    if (!symmetric)
    {
      type.value().set_inverse_name(LocalizedText{"", "FedBy"});
    }
    ASSERT_TRUE(type.value()
                  .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype},
                    ExpandedNodeId{NodeId{ReferenceTypeId::NonHierarchicalReferences}},
                    false)
                  .is_good());
  }
  const NodeId a = harness.create(NodeId{index, 100u}, "A");
  const NodeId b = harness.create(NodeId{index, 101u}, "B");
  for (const auto& typeId : {symmetricType, oneWayType})
  {
    auto from = addressSpace.try_find_node_sync(a);
    auto to = addressSpace.try_find_node_sync(b);
    ASSERT_TRUE(from.is_good() && to.is_good());
    ASSERT_TRUE(from.value().try_add_reference_sync(typeId, ExpandedNodeId{b}, true).is_good());
    ASSERT_TRUE(to.value().try_add_reference_sync(typeId, ExpandedNodeId{a}, false).is_good());
  }
  const auto step = [index](const NodeId& type, bool inverse)
  {
    return Step{
      .referenceType = type, .inverse = inverse, .includeSubtypes = false, .name = QualifiedName{index, "A"}};
  };

  const auto outcome = harness.translate(request_of({path_of(b, {step(symmetricType, false)}),
    path_of(b, {step(symmetricType, true)}),
    path_of(b, {step(oneWayType, false)}),
    path_of(b, {step(oneWayType, true)})}));

  ASSERT_TRUE(outcome.answered);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 4U);
  const auto& results = outcome.response->results();
  EXPECT_EQ(targets_of(results[0]), std::vector<NodeId>{a}) << "a forward element over the symmetric type";
  EXPECT_EQ(results[1].status_code().as_status(), Status::BadNoMatch)
    << "an inverse element over the symmetric type";
  EXPECT_EQ(results[2].status_code().as_status(), Status::BadNoMatch)
    << "a forward element over the one-way type";
  EXPECT_EQ(targets_of(results[3]), std::vector<NodeId>{a}) << "an inverse element over the one-way type";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-A-URI-FORM-TARGET-IS-FOLLOWED-AS-ITS-INDEX-FORM, scope=function)
TEST(TranslateFlow, AUriFormTargetIsFollowedAsItsIndexForm)
{
  constexpr const char* uri = "urn:test:translate-flow:uri-form";
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(uri, harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  const NodeId t = harness.create(NodeId{index, 101u}, "T");
  const NodeId u = harness.create(NodeId{index, 102u}, "U");
  {
    auto addressSpace = harness.sessionInfo->address_space();
    auto from = addressSpace.try_find_node_sync(s);
    auto to = addressSpace.try_find_node_sync(t);
    ASSERT_TRUE(from.is_good());
    ASSERT_TRUE(to.is_good());
    // The forward half names T by R's namespace URI and no index; T holds the inverse half.
    ASSERT_TRUE(from.value()
                  .try_add_reference_sync(
                    NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{NodeId{0, 101u}, uri}, true)
                  .is_good());
    ASSERT_TRUE(to.value()
                  .try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{s}, false)
                  .is_good());
  }
  harness.link(s, ReferenceTypeId::HasComponent, u);
  r->reset();

  const auto outcome = harness.translate(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})}),
      path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "U"})})}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);

  const auto& toT = outcome.response->results()[0];
  EXPECT_EQ(toT.status_code().as_status(), Status::Good)
    << "the path to T, given by namespace URI, answered " << to_string(toT.status_code());
  EXPECT_EQ(toT.targets().size(), 1U) << "the path to T's targets";
  if (toT.targets().size() == 1U)
  {
    const auto& target = toT.targets()[0];
    EXPECT_EQ(target.target_id().node_id(), t) << "T's target is not T's NodeId in index form";
    EXPECT_TRUE(target.target_id().namespace_uri().empty()) << "T's target carries a namespace URI";
    EXPECT_EQ(target.target_id().server_index(), 0U);
    EXPECT_EQ(target.remaining_path_index(), std::numeric_limits<uint32_t>::max());
  }

  const auto& toU = outcome.response->results()[1];
  EXPECT_EQ(toU.status_code().as_status(), Status::Good) << "the path to U, given by namespace index";
  EXPECT_EQ(targets_of(toU), std::vector<NodeId>{u}) << "the path to U";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-A-TOKEN-ANSWERED-AFTER-THE-REQUEST-ENDED-IS-RELEASED, scope=function)
TEST(TranslateFlow, ATokenAnsweredAfterTheRequestEndedIsReleased)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:late-token", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  harness.link(s, ReferenceTypeId::Organizes, harness.create(NodeId{index, 101u}, "O1"));
  harness.link(s, ReferenceTypeId::Organizes, harness.create(NodeId{index, 102u}, "O2"));
  r->page_references(1);
  r->hold_reference_reads_of({s});
  r->reset();

  const auto outcome = harness.translate(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})})}, 500));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::BadTimeout)
    << "the request answered " << to_string(outcome.serviceResult);
  const std::size_t readsAtResponse = r->count(Member::ReadReferences);
  EXPECT_EQ(r->release_held_reference_reads(), 1U) << "held read_references_async calls released";

  // What follows the released answer - the release, or a further read - is given a moment to arrive, and a
  // further moment for anything after it.
  const auto until = std::chrono::steady_clock::now() + 2s;
  while (r->count(Member::ReleaseResumeToken) == 0 && r->count(Member::ReadReferences) == readsAtResponse &&
         std::chrono::steady_clock::now() < until)
  {
    std::this_thread::sleep_for(10ms);
  }
  std::this_thread::sleep_for(200ms);

  const auto reads = r->calls(Member::ReadReferences);
  const auto releases = r->calls(Member::ReleaseResumeToken);
  // Nothing is left held when the test ends.
  r->hold_reference_reads_of({});
  r->release_held_reference_reads();

  ASSERT_EQ(readsAtResponse, 1U) << "read_references_async calls when the response arrived:"
                                 << describe(reads);
  ASSERT_FALSE(reads.empty());
  ASSERT_EQ(reads[0].referenceQueries.size(), 1U) << "the held call's queries";
  const ByteString released = reads[0].referenceQueries[0].answeredToken;
  ASSERT_FALSE(released.empty()) << "the released answer gave no resume token";
  EXPECT_EQ(releases.size(), 1U) << "release_resume_token calls";
  if (releases.size() == 1U)
  {
    EXPECT_EQ(releases[0].token, released)
      << "released \"" << text_of(releases[0].token) << "\", the released answer's token is \""
      << text_of(released) << "\"";
  }
  EXPECT_EQ(reads.size(), readsAtResponse)
    << "R received read_references_async calls after the release:" << describe(reads);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-PAGING-THAT-DOES-NOT-END-FAILS-THE-READ, scope=function)
TEST(TranslateFlow, PagingThatDoesNotEndFailsTheRead)
{
  // The arm bounds its own wait: a read that never ends is a failure here, not a stuck run.
  constexpr std::size_t roundBound = 1024;
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:paging-without-end", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  const NodeId u = harness.create(NodeId{index, 101u}, "U");
  const NodeId t = harness.create(NodeId{index, 102u}, "T");
  harness.link(u, ReferenceTypeId::HasComponent, t);
  r->page_without_end_of({s});
  r->reset();

  auto response = harness.send(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})}),
      path_of(u, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})})}));

  // Waits for the response for at most 20 s, and gives up early once R has been asked well past the bound.
  const auto until = std::chrono::steady_clock::now() + 20s;
  bool answered = false;
  while (std::chrono::steady_clock::now() < until)
  {
    if (response.wait_for(10ms) == std::future_status::ready)
    {
      answered = true;
      break;
    }
    if (r->count(Member::ReadReferences) > roundBound + 100)
    {
      break;
    }
  }
  const std::size_t readsWhenWaitEnded = r->count(Member::ReadReferences);
  // Stops the answers without end, so that a read still paging ends and nothing outlives the test.
  r->page_without_end_of({});
  ASSERT_TRUE(answered) << "no response; R had received " << readsWhenWaitEnded
                        << " read_references_async calls when the wait ended";
  const auto outcome = response.get();

  // The release may follow the answer; it is given a moment to arrive.
  const auto releaseBy = std::chrono::steady_clock::now() + 1s;
  while (r->count(Member::ReleaseResumeToken) == 0 && std::chrono::steady_clock::now() < releaseBy)
  {
    std::this_thread::sleep_for(10ms);
  }

  std::vector<BatchRecordingNamespace::ReferenceQueryRecord> ofS;
  for (const auto& query : queries_of(*r))
  {
    if (query.nodeId == s)
    {
      ofS.push_back(query);
    }
  }
  EXPECT_LE(ofS.size(), roundBound) << "read_references_async queries naming S";
  const auto releases = r->calls(Member::ReleaseResumeToken);
  EXPECT_EQ(releases.size(), 1U) << "release_resume_token calls";
  if (releases.size() == 1U && !ofS.empty())
  {
    EXPECT_EQ(releases[0].token, ofS.back().answeredToken)
      << "released \"" << text_of(releases[0].token) << "\", the last token R gave for S is \""
      << text_of(ofS.back().answeredToken) << "\"";
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  const auto& fromS = outcome.response->results()[0];
  EXPECT_EQ(fromS.status_code().as_status(), Status::BadInternalError)
    << "the path from S answered " << to_string(fromS.status_code());
  EXPECT_NE(fromS.status_code().shared_detail(), nullptr) << "the path from S names no ErrorDetail";
  if (fromS.status_code().shared_detail() != nullptr)
  {
    EXPECT_EQ(fromS.status_code().shared_detail()->code, "NamespacePagingDidNotEnd");
  }
  const auto& fromU = outcome.response->results()[1];
  EXPECT_EQ(fromU.status_code().as_status(), Status::Good) << "the path from U";
  EXPECT_EQ(targets_of(fromU), std::vector<NodeId>{t}) << "the path from U";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-07-AN-ELEMENT-READ-IN-MORE-THAN-1024-PAGES-IS-FOLLOWED, scope=function)
TEST(TranslateFlow, AnElementReadInMoreThan1024PagesIsFollowed)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:many-pages", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.maxBrowsePathWalkReferences = std::nullopt;
  const uint16_t index = harness.setup({r}, std::move(serverConfig)).at(0);
  const NodeId s = harness.create(NodeId{index, 1u}, "S");
  NodeId t;
  for (uint32_t i = 1; i <= 1100; ++i)
  {
    // Only the last added is named T.
    t = harness.create(NodeId{index, 1000u + i}, i == 1100 ? "T" : "O");
    harness.link(s, ReferenceTypeId::HasComponent, t);
  }
  r->page_references(1);
  r->reset();

  auto response = harness.send(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "T"})})}));

  // The arm bounds its own wait: an element that is never followed fails here.
  ASSERT_EQ(response.wait_for(30s), std::future_status::ready)
    << "no response within 30 s; R had received " << r->count(Member::ReadReferences)
    << " read_references_async calls";
  const auto outcome = response.get();
  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& result = outcome.response->results()[0];
  EXPECT_EQ(result.status_code().as_status(), Status::Good)
    << "the path answered " << to_string(result.status_code()) << " ("
    << (result.status_code().shared_detail() ? result.status_code().shared_detail()->code : std::string{})
    << ")";
  EXPECT_EQ(targets_of(result), std::vector<NodeId>{t});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-24-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-OPERATION, scope=function)
TEST(TranslateFlow, ATargetWhoseLookupIsAnsweredUncertainIsSkipped)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:translate-flow:uncertain", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  const NodeId x = harness.create(NodeId{index, 101u}, "X");
  const NodeId y = harness.create(NodeId{index, 102u}, "X");
  harness.link(s, ReferenceTypeId::HasComponent, x);
  harness.link(s, ReferenceTypeId::HasComponent, y);
  r->decline_single_lookups();
  r->answer_lookup_of(y, StatusCode{Status::UncertainNoCommunicationLastUsableValue});
  r->reset();

  const auto outcome = harness.translate(
    request_of({path_of(s, {forward_step(ReferenceTypeId::HasComponent, QualifiedName{index, "X"})})}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  const auto& result = outcome.response->results()[0];
  EXPECT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code());
  ASSERT_EQ(result.targets().size(), 1U);
  EXPECT_EQ(result.targets()[0].target_id().node_id(), x);
}
