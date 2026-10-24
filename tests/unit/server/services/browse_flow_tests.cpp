// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How Browse and BrowseNext call the namespaces that hold the Nodes they browse: in rounds of one
// read_references_async per namespace, each query carrying the Browse's direction, hint, page size and resume
// token; one View membership call per round; TypeDefinitions read with one hinted call per target namespace;
// every call carrying the request; resume tokens passed back; References beyond maxReferences kept for
// BrowseNext; and an answer without a value taken as the operation's status.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "ua_address_space.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_service.h"
#include "ua_byte_string.h"
#include "ua_continuation_points.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_guid.h"
#include "ua_log_sink_implementations.h"
#include "ua_logger.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_to_string.h"
#include "ua_variabletype_id.h"
#include <boost/asio/thread_pool.hpp>

#include "access_control_test_support.h"
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
using QueryRecord = BatchRecordingNamespace::ReferenceQueryRecord;

namespace
{

// Every ResultMask bit (OPC 10000-4 Table 34).
constexpr uint32_t everyResultMaskBit = 0x3f;

struct BrowseOutcome
{
  bool answered{false};
  StatusCode serviceResult;
  std::vector<BrowseResult> results;
  std::size_t diagnosticInfos{0};

  // The continuation points the response handed out, as the Session would store them.
  BrowseContinuationPoints store;
};

// A server with the given namespaces registered, and a Session on it.
struct BrowseHarness
{
  ~BrowseHarness()
  {
    services.clear();
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
    if (!logPath.empty())
    {
      std::error_code error;
      std::filesystem::remove(logPath, error);
    }
  }

  std::filesystem::path logPath;
  boost::asio::thread_pool threadPool{4};
  shared_ptr<SessionInfoStub> sessionInfo;
  std::vector<shared_ptr<BrowseService>> services;
  std::vector<LocaleId> locales{"en"};

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

  // The forward HasTypeDefinition Reference of @p instance to @p type, held by the instance only.
  void type(const NodeId& instance, const NodeId& typeDefinition)
  {
    auto node = sessionInfo->address_space().try_find_node_sync(instance);
    ASSERT_TRUE(node.is_good()) << instance.as_definition();
    EXPECT_TRUE(node.value()
                  .try_add_reference_sync(
                    NodeId{ReferenceTypeId::HasTypeDefinition}, ExpandedNodeId{typeDefinition}, true)
                  .is_good())
      << instance.as_definition();
  }

  BrowseOutcome browse(BrowseRequest request)
  {
    auto promise = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
    auto future = promise->get_future();
    services.push_back(BrowseService::create(sessionInfo,
      locales,
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise](BrowseService::BrowseServiceResponse response) { promise->set_value(std::move(response)); }));
    return outcome_of(future);
  }

  BrowseOutcome browse_next(std::vector<ByteString> points, BrowseContinuationPoints& store,
    bool release = false, uint32_t timeoutHint = 0, std::chrono::milliseconds limit = 10s,
    uint32_t returnDiagnostics = 0)
  {
    BrowseNextRequest request;
    request.request_header().timeout_hint() = timeoutHint;
    request.request_header().return_diagnostics() = returnDiagnostics;
    request.release_continuation_points() = release;
    for (auto& point : points)
    {
      request.continuation_points().push_back(std::move(point));
    }
    auto promise = std::make_shared<std::promise<BrowseService::BrowseServiceResponse>>();
    auto future = promise->get_future();
    services.push_back(BrowseService::create(sessionInfo,
      locales,
      2,
      std::move(request),
      store,
      threadPool.get_executor(),
      [promise](BrowseService::BrowseServiceResponse response) { promise->set_value(std::move(response)); }));
    return outcome_of(future, limit);
  }

private:
  static BrowseOutcome outcome_of(
    std::future<BrowseService::BrowseServiceResponse>& future, std::chrono::milliseconds limit = 10s)
  {
    BrowseOutcome outcome;
    if (future.wait_for(limit) != std::future_status::ready)
    {
      ADD_FAILURE() << "the request was not answered";
      return outcome;
    }
    auto response = future.get();
    outcome.answered = true;
    const auto& body = std::get<shared_ptr<Structure>>(response.response);
    if (auto* fault = dynamic_cast<ServiceFault*>(body.get()))
    {
      outcome.serviceResult = fault->response_header().service_result();
    }
    else if (auto* browsed = dynamic_cast<BrowseResponse*>(body.get()))
    {
      outcome.serviceResult = browsed->response_header().service_result();
      outcome.results.assign(browsed->results().begin(), browsed->results().end());
      outcome.diagnosticInfos = browsed->diagnostic_infos().size();
    }
    else if (auto* next = dynamic_cast<BrowseNextResponse*>(body.get()))
    {
      outcome.serviceResult = next->response_header().service_result();
      outcome.results.assign(next->results().begin(), next->results().end());
      outcome.diagnosticInfos = next->diagnostic_infos().size();
    }
    for (auto& point : response.continuationPoints)
    {
      auto identifier = point.identifier();
      outcome.store.emplace(identifier, std::move(point));
    }
    return outcome;
  }
};

BrowseDescription description_of(const NodeId& source, BrowseDirection direction = BrowseDirection::Forward,
  uint32_t resultMask = everyResultMaskBit)
{
  BrowseDescription description;
  description.node_id() = source;
  description.browse_direction() = direction;
  description.reference_type_id() = NodeId{};
  description.include_subtypes() = true;
  description.result_mask() = resultMask;
  return description;
}

BrowseRequest request_of(std::vector<BrowseDescription> descriptions, uint32_t maxReferencesPerNode = 0,
  uint32_t timeoutHint = 0, const NodeId& view = NodeId{})
{
  BrowseRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = timeoutHint;
  request.view().view_id() = view;
  request.requested_max_references_per_node() = maxReferencesPerNode;
  for (auto& description : descriptions)
  {
    request.nodes_to_browse().push_back(std::move(description));
  }
  return request;
}

std::vector<NodeId> targets_of(const BrowseResult& result)
{
  std::vector<NodeId> targets;
  for (const auto& reference : result.references())
  {
    targets.push_back(reference.node_id().node_id());
  }
  return targets;
}

std::string describe(const std::vector<NodeId>& nodeIds)
{
  std::string text;
  for (const auto& nodeId : nodeIds)
  {
    text += " " + nodeId.as_definition();
  }
  return text;
}

std::string describe(const std::vector<Call>& calls)
{
  std::string text;
  for (const auto& call : calls)
  {
    text += "\n  call" + describe(call.nodeIds);
  }
  return text;
}

std::string text_of(const ByteString& token)
{
  return std::string{reinterpret_cast<const char*>(token.data()), token.size()};
}

// Every read_references_async query @p nameSpace received naming @p nodeId, in order.
std::vector<QueryRecord> queries_naming(const BatchRecordingNamespace& nameSpace, const NodeId& nodeId)
{
  std::vector<QueryRecord> queries;
  for (const auto& call : nameSpace.calls(Member::ReadReferences))
  {
    for (const auto& query : call.referenceQueries)
    {
      if (query.nodeId == nodeId)
      {
        queries.push_back(query);
      }
    }
  }
  return queries;
}

// The recorded calls of @p member that name @p nodeId.
std::vector<Call> calls_naming(const BatchRecordingNamespace& nameSpace, Member member, const NodeId& nodeId)
{
  std::vector<Call> named;
  for (const auto& call : nameSpace.calls(member))
  {
    if (std::find(call.nodeIds.begin(), call.nodeIds.end(), nodeId) != call.nodeIds.end())
    {
      named.push_back(call);
    }
  }
  return named;
}

// The ErrorDetail code @p status carries; empty for none.
std::string detail_code(const StatusCode& status)
{
  return status.shared_detail() ? status.shared_detail()->code : std::string{};
}

// Each recorded call carries a request whose deadline lies in [deadlineFrom, deadlineTo], whose answerBy lies
// in [answerByFrom, answerByTo], and whose cancellation flag is not set.
void expect_each_carries_the_request(
  const std::vector<Call>& calls, std::chrono::steady_clock::time_point sent, const char* kind)
{
  EXPECT_FALSE(calls.empty()) << kind << ": no call was made";
  for (std::size_t k = 0; k < calls.size(); ++k)
  {
    const auto& call = calls[k];
    EXPECT_TRUE(call.hasRequest) << kind << " " << k << ": the call took no RequestInfo";
    EXPECT_GE(call.deadline, sent + 1800ms) << kind << " " << k << ": the deadline is before T0 + 1.8 s";
    EXPECT_LE(call.deadline, sent + 2200ms) << kind << " " << k << ": the deadline is after T0 + 2.2 s";
    EXPECT_TRUE(call.answerBy.has_value()) << kind << " " << k << ": the call carries no answerBy";
    if (call.answerBy.has_value())
    {
      EXPECT_GE(*call.answerBy, sent + 800ms) << kind << " " << k << ": the answerBy is before T0 + 0.8 s";
      EXPECT_LE(*call.answerBy, sent + 1200ms) << kind << " " << k << ": the answerBy is after T0 + 1.2 s";
    }
    EXPECT_FALSE(call.cancelled) << kind << " " << k << ": the cancellation flag is set";
  }
}

// A Browse of S, whose five forward HasComponent References name T1 to T5 in that order, with
// requestedMaxReferencesPerNode 2, then a BrowseNext of the continuation point each of the first two answers
// returns. How A answers is set before.
struct FivePages
{
  std::vector<NodeId> targets;
  NodeId s;
  std::vector<BrowseOutcome> outcomes;
};

void browse_five_in_pages(
  BrowseHarness& harness, BatchRecordingNamespace& a, uint16_t index, FivePages& pages)
{
  pages.s = harness.create(NodeId{index, 100u}, "S");
  for (uint32_t i = 1; i <= 5; ++i)
  {
    pages.targets.push_back(harness.create(NodeId{index, 100u + i}, "T" + std::to_string(i)));
    harness.link(pages.s, ReferenceTypeId::HasComponent, pages.targets.back());
  }
  a.reset();

  pages.outcomes.push_back(harness.browse(request_of({description_of(pages.s)}, 2)));
  for (int k = 0; k < 2; ++k)
  {
    auto& last = pages.outcomes.back();
    ASSERT_TRUE(last.answered);
    ASSERT_EQ(last.results.size(), 1U);
    const auto point = last.results[0].continuation_point();
    ASSERT_FALSE(point.empty()) << "page " << k + 1 << " handed out no continuation point; it answered "
                                << to_string(last.results[0].status_code()) << " with"
                                << describe(targets_of(last.results[0]));
    auto store = std::move(last.store);
    pages.outcomes.push_back(harness.browse_next({point}, store));
  }
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-ONE-REFERENCE-READ-PER-NAMESPACE-PER-ROUND, scope=function)
TEST(BrowseFlow, OneReferenceReadPerNamespacePerRound)
{
  BrowseHarness harness;
  auto a = make_shared<BatchRecordingNamespace>("urn:test:browse-flow:a", harness.threadPool.get_executor());
  auto b = make_shared<BatchRecordingNamespace>("urn:test:browse-flow:b", harness.threadPool.get_executor());
  const auto indexes = harness.setup({a, b});

  // In each namespace three sources, each holding, in this order: HasComponent to X1, Organizes from U1,
  // HasComponent to X2, Organizes from U2.
  struct Layout
  {
    std::vector<NodeId> sources;
    NodeId x1;
    NodeId x2;
  };

  std::vector<Layout> layouts;
  for (const uint16_t index : indexes)
  {
    Layout layout;
    layout.x1 = harness.create(NodeId{index, 201u}, "X1");
    layout.x2 = harness.create(NodeId{index, 202u}, "X2");
    const NodeId u1 = harness.create(NodeId{index, 301u}, "U1");
    const NodeId u2 = harness.create(NodeId{index, 302u}, "U2");
    for (uint32_t i = 1; i <= 3; ++i)
    {
      const NodeId source = harness.create(NodeId{index, 100u + i}, "S" + std::to_string(i));
      harness.link(source, ReferenceTypeId::HasComponent, layout.x1);
      harness.link(u1, ReferenceTypeId::Organizes, source);
      harness.link(source, ReferenceTypeId::HasComponent, layout.x2);
      harness.link(u2, ReferenceTypeId::Organizes, source);
      layout.sources.push_back(source);
    }
    layouts.push_back(std::move(layout));
  }
  for (const auto& nameSpace : {a, b})
  {
    nameSpace->decline_single_lookups();
    nameSpace->decline_immediate_permissions();
    nameSpace->page_references_by_max_references();
    nameSpace->reset();
  }

  std::vector<BrowseDescription> descriptions;
  for (std::size_t i = 0; i < 3; ++i)
  {
    descriptions.push_back(description_of(layouts[0].sources[i], BrowseDirection::Forward, 0));
    descriptions.push_back(description_of(layouts[1].sources[i], BrowseDirection::Forward, 0));
  }
  const auto outcome = harness.browse(request_of(std::move(descriptions), 2));

  const std::vector<std::pair<const char*, const BatchRecordingNamespace*>> named{
    {"A", a.get()}, {"B", b.get()}};
  for (std::size_t n = 0; n < named.size(); ++n)
  {
    const auto& [name, nameSpace] = named[n];
    const auto& sources = layouts[n].sources;
    const auto reads = nameSpace->calls(Member::ReadReferences);
    EXPECT_EQ(reads.size(), 2U) << name << "'s read_references_async calls:" << describe(reads);
    for (std::size_t k = 0; k < reads.size() && k < 2; ++k)
    {
      EXPECT_EQ(reads[k].nodeIds, sources)
        << name << "'s call " << k + 1 << " names" << describe(reads[k].nodeIds);
      for (const auto& query : reads[k].referenceQueries)
      {
        EXPECT_EQ(query.maxReferences, 2U)
          << name << "'s call " << k + 1 << ", query naming " << query.nodeId.as_definition();
      }
    }
    if (reads.size() == 2U && reads[0].referenceQueries.size() == reads[1].referenceQueries.size())
    {
      for (std::size_t q = 0; q < reads[1].referenceQueries.size(); ++q)
      {
        EXPECT_EQ(reads[1].referenceQueries[q].resumeToken, reads[0].referenceQueries[q].answeredToken)
          << name << "'s second call, query " << q + 1 << ", carried \""
          << text_of(reads[1].referenceQueries[q].resumeToken) << "\"; the first answer gave \""
          << text_of(reads[0].referenceQueries[q].answeredToken) << "\"";
      }
    }

    std::size_t lookupsOfTargets = 0;
    for (const auto& call : nameSpace->calls(Member::BatchedLookup))
    {
      if (std::any_of(call.nodeIds.begin(),
            call.nodeIds.end(),
            [&](const NodeId& id) { return id == layouts[n].x1 || id == layouts[n].x2; }))
      {
        ++lookupsOfTargets;
      }
    }
    EXPECT_LE(lookupsOfTargets, 2U) << name << "'s batched lookups naming targets";
    std::size_t permissionsOfTargets = 0;
    for (const auto& call : nameSpace->calls(Member::PermissionsAsyncForRequest))
    {
      if (std::any_of(call.nodeIds.begin(),
            call.nodeIds.end(),
            [&](const NodeId& id) { return id == layouts[n].x1 || id == layouts[n].x2; }))
      {
        ++permissionsOfTargets;
      }
    }
    EXPECT_LE(permissionsOfTargets, 2U) << name << "'s permissions calls taking a RequestInfo naming targets";
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 6U);
  for (std::size_t i = 0; i < 6; ++i)
  {
    const auto& layout = layouts[i % 2];
    const auto& result = outcome.results[i];
    EXPECT_EQ(result.status_code().as_status(), Status::Good) << "source " << i;
    EXPECT_EQ(targets_of(result), (std::vector<NodeId>{layout.x1, layout.x2})) << "source " << i;
    EXPECT_FALSE(result.continuation_point().empty()) << "source " << i;
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-TYPEDEFINITIONS-ARE-ONE-HINTED-READ-PER-NAMESPACE, scope=function)
TEST(BrowseFlow, TypeDefinitionsUseTheHasTypeDefinitionHint)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:typed:a", harness.threadPool.get_executor());
  auto b =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:typed:b", harness.threadPool.get_executor());
  const auto indexes = harness.setup({a, b});
  const NodeId s = harness.create(NodeId{indexes.at(0), 100u}, "S");
  const NodeId o1 = harness.create(NodeId{indexes.at(1), 201u}, "O1");
  const NodeId o2 = harness.create(NodeId{indexes.at(1), 202u}, "O2");
  const NodeId v = harness.create(NodeId{indexes.at(1), 203u}, "V", NodeClass::Variable);
  harness.type(o1, NodeId{ObjectTypeId::FolderType});
  harness.type(o2, NodeId{ObjectTypeId::BaseObjectType});
  harness.type(v, NodeId{VariableTypeId::BaseDataVariableType});
  for (const auto& target : {o1, o2, v})
  {
    harness.link(s, ReferenceTypeId::HasComponent, target);
  }
  a->reset();
  b->reset();

  const auto outcome = harness.browse(request_of({description_of(s)}));

  const std::vector<NodeId> hint{NodeId{ReferenceTypeId::HasTypeDefinition}};
  std::vector<Call> hinted;
  for (const auto& call : b->calls(Member::ReadReferences))
  {
    if (!call.referenceQueries.empty() &&
        std::all_of(call.referenceQueries.begin(),
          call.referenceQueries.end(),
          [&hint](const QueryRecord& query) { return query.referenceTypeHint == hint; }))
    {
      hinted.push_back(call);
    }
  }
  EXPECT_EQ(hinted.size(), 1U) << "B's read_references_async calls hinted with HasTypeDefinition:"
                               << describe(hinted)
                               << "\nB's calls:" << describe(b->calls(Member::ReadReferences));
  if (hinted.size() == 1U)
  {
    std::vector<NodeId> named = hinted[0].nodeIds;
    std::sort(named.begin(), named.end());
    std::vector<NodeId> expected{o1, o2, v};
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(named, expected) << "the hinted call names" << describe(hinted[0].nodeIds);
    for (const auto& query : hinted[0].referenceQueries)
    {
      EXPECT_EQ(query.direction, BrowseDirection::Forward)
        << "the query naming " << query.nodeId.as_definition();
    }
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 1U);
  const auto& result = outcome.results[0];
  EXPECT_EQ(result.status_code().as_status(), Status::Good);
  ASSERT_EQ(result.references().size(), 3U) << describe(targets_of(result));
  const std::vector<std::pair<NodeId, NodeId>> typed{{o1, NodeId{ObjectTypeId::FolderType}},
    {o2, NodeId{ObjectTypeId::BaseObjectType}},
    {v, NodeId{VariableTypeId::BaseDataVariableType}}};
  for (std::size_t i = 0; i < typed.size(); ++i)
  {
    EXPECT_EQ(result.references()[i].node_id().node_id(), typed[i].first) << "Reference " << i;
    EXPECT_EQ(result.references()[i].type_definition().node_id(), typed[i].second)
      << "the TypeDefinition of " << typed[i].first.as_definition();
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-ONE-VIEW-MEMBERSHIP-CALL-PER-ROUND, scope=function)
TEST(BrowseFlow, OneViewMembershipCallPerRound)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:view", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  const NodeId view = harness.create(NodeId{index, 1u}, "V", NodeClass::View);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  const NodeId m1 = harness.create(NodeId{index, 201u}, "M1");
  const NodeId n1 = harness.create(NodeId{index, 301u}, "N1");
  const NodeId m2 = harness.create(NodeId{index, 202u}, "M2");
  const NodeId n2 = harness.create(NodeId{index, 302u}, "N2");
  for (const auto& target : {m1, n1, m2, n2})
  {
    harness.link(s, ReferenceTypeId::HasComponent, target);
  }
  const std::vector<NodeId> members{s, m1, m2};
  a->answer_view_membership([members](const NodeId&, const NodeId& candidate)
    { return std::find(members.begin(), members.end(), candidate) != members.end(); });
  a->reset();

  const auto outcome = harness.browse(request_of({description_of(s)}, 0, 0, view));

  const auto asked = a->calls(Member::ViewContains);
  std::string askedText;
  std::vector<std::vector<NodeId>> candidates;
  for (const auto& call : asked)
  {
    std::vector<NodeId> named;
    for (const auto& candidate : call.candidates)
    {
      named.push_back(candidate.node_id());
    }
    askedText += "\n  call" + describe(named);
    candidates.push_back(std::move(named));
  }
  EXPECT_EQ(asked.size(), 2U) << "view_contains_async calls:" << askedText;
  if (asked.size() == 2U)
  {
    EXPECT_EQ(candidates[0], std::vector<NodeId>{s}) << "the first call names S only";
    EXPECT_EQ(candidates[1], (std::vector<NodeId>{m1, n1, m2, n2})) << "the second call names the targets";
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 1U);
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(targets_of(outcome.results[0]), (std::vector<NodeId>{m1, m2}));
}

// The View membership of a page's targets is asked in calls of at most maxNodesPerBrowse candidates, each
// after the previous has answered (NR-31 rule 5); the control is the Browse result, the same as with one
// call.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-VIEW-MEMBERSHIP-CALLS-ARE-SPLIT-BY-MAX-NODES-PER-BROWSE, scope=function)
TEST(BrowseFlow, ViewMembershipCallsAreSplitByMaxNodesPerBrowse)
{
  BrowseHarness harness;
  auto a = make_shared<BatchRecordingNamespace>(
    "urn:test:browse-flow:view-split", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.server_capabilities().operationLimits.maxNodesPerBrowse = 2;
  const uint16_t index = harness.setup({a}, std::move(serverConfig)).at(0);
  const NodeId view = harness.create(NodeId{index, 1u}, "V", NodeClass::View);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  std::vector<NodeId> targets;
  for (uint32_t i = 0; i < 5; ++i)
  {
    targets.push_back(harness.create(NodeId{index, 200u + i}, "T" + std::to_string(i)));
    harness.link(s, ReferenceTypeId::HasComponent, targets.back());
  }
  const std::vector<NodeId> members{s, targets[0], targets[2], targets[4]};
  a->answer_view_membership([members](const NodeId&, const NodeId& candidate)
    { return std::find(members.begin(), members.end(), candidate) != members.end(); });
  a->reset();

  const auto outcome = harness.browse(request_of({description_of(s)}, 0, 0, view));

  std::size_t asked = 0;
  for (const auto& call : a->calls(Member::ViewContains))
  {
    EXPECT_LE(call.candidates.size(), 2U) << "a view_contains_async call named more than maxNodesPerBrowse";
    asked += call.candidates.size();
  }
  EXPECT_EQ(asked, 6U) << "S, then the five targets, each asked once";
  ASSERT_TRUE(outcome.answered);
  ASSERT_EQ(outcome.results.size(), 1U);
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(targets_of(outcome.results[0]), (std::vector<NodeId>{targets[0], targets[2], targets[4]}));
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-THE-NAMESPACE-CALLS-CARRY-THE-REQUEST, scope=function)
TEST(BrowseFlow, EveryNamespaceCallCarriesTheRequest)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:request", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.partialResultDeadlineFraction = 0.5;
  const uint16_t index = harness.setup({a}, std::move(serverConfig)).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  const NodeId t = harness.create(NodeId{index, 101u}, "T");
  harness.link(s, ReferenceTypeId::HasComponent, t);
  a->decline_single_lookups();
  a->decline_immediate_permissions();
  a->reset();

  const auto sent = std::chrono::steady_clock::now();
  const auto outcome = harness.browse(request_of({description_of(s, BrowseDirection::Forward, 0)}, 0, 2000));

  expect_each_carries_the_request(a->calls(Member::BatchedLookup), sent, "batched lookup");
  expect_each_carries_the_request(
    a->calls(Member::PermissionsAsyncForRequest), sent, "permissions call taking a RequestInfo");
  expect_each_carries_the_request(a->calls(Member::ReadReferences), sent, "read_references_async");

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 1U);
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(targets_of(outcome.results[0]), std::vector<NodeId>{t});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-RESUMED-PAUSED-OPERATIONS-ARE-ONE-LOOKUP-AND-ONE-AUTHORIZATION, scope=function)
TEST(BrowseFlow, ResumedPausedOperationsAreOneLookupAndOneAuthorization)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:resumed", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.partialResultDeadlineFraction = 0.25;
  const uint16_t index = harness.setup({a}, std::move(serverConfig)).at(0);
  const NodeId s1 = harness.create(NodeId{index, 101u}, "S1");
  const NodeId s2 = harness.create(NodeId{index, 102u}, "S2");
  const NodeId t1 = harness.create(NodeId{index, 201u}, "T1");
  const NodeId t2 = harness.create(NodeId{index, 202u}, "T2");
  harness.link(s1, ReferenceTypeId::HasComponent, t1);
  harness.link(s2, ReferenceTypeId::HasComponent, t2);
  a->decline_single_lookups();
  a->decline_immediate_permissions();
  a->hold_reference_reads_of({s1, s2});
  a->reset();

  auto first = harness.browse(request_of({description_of(s1), description_of(s2)}, 0, 2000));
  a->hold_reference_reads_of({});
  const std::size_t released = a->release_held_reference_reads();
  ASSERT_TRUE(first.answered);
  ASSERT_EQ(first.results.size(), 2U);
  std::vector<ByteString> points;
  for (std::size_t i = 0; i < 2; ++i)
  {
    ASSERT_EQ(first.results[i].status_code().as_status(), Status::Good) << "source " << i + 1;
    ASSERT_FALSE(first.results[i].continuation_point().empty())
      << "source " << i + 1 << " was not paused with a continuation point (" << released << " reads held)";
    points.push_back(first.results[i].continuation_point());
  }
  a->reset();

  auto next = harness.browse_next(points, first.store);

  const auto lookups = calls_naming(*a, Member::BatchedLookup, s1);
  const auto lookupsOfS2 = calls_naming(*a, Member::BatchedLookup, s2);
  EXPECT_EQ(lookups.size(), 1U) << "batched lookups naming S1:" << describe(lookups);
  EXPECT_EQ(lookupsOfS2.size(), 1U) << "batched lookups naming S2:" << describe(lookupsOfS2);
  if (lookups.size() == 1U)
  {
    EXPECT_NE(std::find(lookups[0].nodeIds.begin(), lookups[0].nodeIds.end(), s2), lookups[0].nodeIds.end())
      << "the lookup naming S1 does not name S2";
  }
  const auto permissions = calls_naming(*a, Member::PermissionsAsyncForRequest, s1);
  const auto permissionsOfS2 = calls_naming(*a, Member::PermissionsAsyncForRequest, s2);
  EXPECT_EQ(permissions.size(), 1U) << "permissions calls taking a RequestInfo naming S1:"
                                    << describe(permissions);
  EXPECT_EQ(permissionsOfS2.size(), 1U)
    << "permissions calls taking a RequestInfo naming S2:" << describe(permissionsOfS2);
  if (permissions.size() == 1U)
  {
    EXPECT_NE(std::find(permissions[0].nodeIds.begin(), permissions[0].nodeIds.end(), s2),
      permissions[0].nodeIds.end())
      << "the permissions call naming S1 does not name S2";
  }

  ASSERT_TRUE(next.answered);
  EXPECT_EQ(next.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(next.results.size(), 2U);
  EXPECT_EQ(next.results[0].status_code().as_status(), Status::Good)
    << to_string(next.results[0].status_code());
  EXPECT_EQ(targets_of(next.results[0]), std::vector<NodeId>{t1});
  EXPECT_EQ(next.results[1].status_code().as_status(), Status::Good)
    << to_string(next.results[1].status_code());
  EXPECT_EQ(targets_of(next.results[1]), std::vector<NodeId>{t2});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-10-BROWSENEXT-PASSES-THE-RESUME-TOKEN-BACK, scope=function)
TEST(BrowseFlow, BrowseNextPassesTheResumeTokenBack)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:resume", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  a->page_references_by_max_references();
  FivePages pages;
  ASSERT_NO_FATAL_FAILURE(browse_five_in_pages(harness, *a, index, pages));

  const auto& t = pages.targets;
  const std::vector<std::vector<NodeId>> expected{{t[0], t[1]}, {t[2], t[3]}, {t[4]}};
  ASSERT_EQ(pages.outcomes.size(), 3U);
  for (std::size_t k = 0; k < 3; ++k)
  {
    ASSERT_TRUE(pages.outcomes[k].answered) << "page " << k + 1;
    ASSERT_EQ(pages.outcomes[k].results.size(), 1U) << "page " << k + 1;
    const auto& result = pages.outcomes[k].results[0];
    EXPECT_EQ(result.status_code().as_status(), Status::Good) << "page " << k + 1;
    EXPECT_EQ(targets_of(result), expected[k]) << "page " << k + 1;
    EXPECT_EQ(result.continuation_point().empty(), k == 2) << "page " << k + 1 << "'s continuation point";
  }

  const auto queries = queries_naming(*a, pages.s);
  ASSERT_EQ(queries.size(), 3U) << "read_references_async queries naming S";
  EXPECT_TRUE(queries[0].resumeToken.empty())
    << "the first query carried \"" << text_of(queries[0].resumeToken) << "\"";
  ASSERT_FALSE(queries[0].answeredToken.empty()) << "A's first answer gave no resume token";
  ASSERT_FALSE(queries[1].answeredToken.empty()) << "A's second answer gave no resume token";
  EXPECT_EQ(queries[1].resumeToken, queries[0].answeredToken)
    << "the second query carried \"" << text_of(queries[1].resumeToken) << "\"; the first answer gave \""
    << text_of(queries[0].answeredToken) << "\"";
  EXPECT_EQ(queries[2].resumeToken, queries[1].answeredToken)
    << "the third query carried \"" << text_of(queries[2].resumeToken) << "\"; the second answer gave \""
    << text_of(queries[1].answeredToken) << "\"";
  EXPECT_EQ(a->count(Member::ReleaseResumeToken), 0U) << "release_resume_token calls";
}

// A paused operation's late reference read answers with a resume token, which the continuation point waiting
// for it owns: a BrowseNext passes it back on the next read, and releasing the point releases it once,
// whichever of the release and the late answer comes first.
// @relation(AC-SVR-PARTIAL-RESULTS-001-A-LATE-RESUME-TOKEN-IS-PASSED-BACK-OR-RELEASED-ONCE, scope=function)
TEST(BrowseFlow, APausedOperationsLateResumeTokenIsPassedBackOrReleasedOnce)
{
  for (const bool release : {false, true})
  {
    SCOPED_TRACE(release ? "the point is released" : "the point is continued");
    BrowseHarness harness;
    auto a = make_shared<BatchRecordingNamespace>(
      "urn:test:browse-flow:late-token", harness.threadPool.get_executor());
    ServerConfig serverConfig;
    serverConfig.partialResultDeadlineFraction = 0.25;
    const uint16_t index = harness.setup({a}, std::move(serverConfig)).at(0);
    a->page_references_by_max_references();
    const NodeId s = harness.create(NodeId{index, 100u}, "S");
    std::vector<NodeId> t;
    for (uint32_t i = 1; i <= 5; ++i)
    {
      t.push_back(harness.create(NodeId{index, 100u + i}, "T" + std::to_string(i)));
      harness.link(s, ReferenceTypeId::HasComponent, t.back());
    }
    a->hold_reference_reads_of({s});
    a->reset();

    auto first = harness.browse(request_of({description_of(s)}, 2, 2000));
    ASSERT_TRUE(first.answered);
    ASSERT_EQ(first.results.size(), 1U);
    ASSERT_EQ(first.results[0].status_code().as_status(), Status::Good);
    const ByteString point = first.results[0].continuation_point();
    ASSERT_FALSE(point.empty()) << "S was not paused with a continuation point";
    a->hold_reference_reads_of({});
    ASSERT_EQ(a->release_held_reference_reads(), 1U);

    auto store = std::move(first.store);
    auto next = harness.browse_next({point}, store, release);
    ASSERT_TRUE(next.answered);
    EXPECT_EQ(next.serviceResult.as_status(), Status::Good);
    const auto queries = queries_naming(*a, s);
    ASSERT_GE(queries.size(), 1U);
    ASSERT_FALSE(queries[0].answeredToken.empty()) << "the held read answered no resume token";
    if (release)
    {
      const auto deadline = std::chrono::steady_clock::now() + 2s;
      while (a->count(Member::ReleaseResumeToken) == 0 && std::chrono::steady_clock::now() < deadline)
      {
        std::this_thread::sleep_for(5ms);
      }
      // Time for a second release, were there one.
      std::this_thread::sleep_for(50ms);
      const auto released = a->calls(Member::ReleaseResumeToken);
      ASSERT_EQ(released.size(), 1U) << "release_resume_token calls";
      EXPECT_EQ(released[0].token, queries[0].answeredToken)
        << "released \"" << text_of(released[0].token) << "\"; the late answer gave \""
        << text_of(queries[0].answeredToken) << "\"";
      EXPECT_EQ(queries.size(), 1U) << "a released point read S again";
    }
    else
    {
      ASSERT_EQ(next.results.size(), 1U);
      EXPECT_EQ(targets_of(next.results[0]), (std::vector<NodeId>{t[0], t[1]}));
      const ByteString nextPoint = next.results[0].continuation_point();
      ASSERT_FALSE(nextPoint.empty()) << "the late page handed out no continuation point";
      auto nextStore = std::move(next.store);
      auto third = harness.browse_next({nextPoint}, nextStore);
      ASSERT_TRUE(third.answered);
      ASSERT_EQ(third.results.size(), 1U);
      EXPECT_EQ(targets_of(third.results[0]), (std::vector<NodeId>{t[2], t[3]}));
      const auto read = queries_naming(*a, s);
      ASSERT_EQ(read.size(), 2U) << "read_references_async queries naming S";
      EXPECT_EQ(read[1].resumeToken, read[0].answeredToken)
        << "the BrowseNext's read carried \"" << text_of(read[1].resumeToken) << "\"; the late answer gave \""
        << text_of(read[0].answeredToken) << "\"";
      EXPECT_EQ(a->count(Member::ReleaseResumeToken), 0U) << "release_resume_token calls";
    }
  }
}

// Two operations paused while their reference read is held; one point is released before the read answers.
// The next round reads only the operation still wanted, and releases the resume token the released one was
// given.
// @relation(AC-SVR-PARTIAL-RESULTS-001-A-RELEASED-OPERATION-IS-NOT-READ-AGAIN, scope=function)
TEST(BrowseFlow, APausedOperationWhosePointIsReleasedIsNotReadAgain)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:released", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.partialResultDeadlineFraction = 0.25;
  const uint16_t index = harness.setup({a}, std::move(serverConfig)).at(0);
  a->page_references(1);
  const NodeId s1 = harness.create(NodeId{index, 101u}, "S1");
  const NodeId s2 = harness.create(NodeId{index, 102u}, "S2");
  std::vector<NodeId> targetsOfS2;
  for (uint32_t i = 1; i <= 3; ++i)
  {
    harness.link(
      s1, ReferenceTypeId::HasComponent, harness.create(NodeId{index, 200u + i}, "A" + std::to_string(i)));
    targetsOfS2.push_back(harness.create(NodeId{index, 300u + i}, "B" + std::to_string(i)));
    harness.link(s2, ReferenceTypeId::HasComponent, targetsOfS2.back());
  }
  a->hold_reference_reads_of({s1, s2});
  a->reset();

  auto first = harness.browse(request_of({description_of(s1), description_of(s2)}, 0, 2000));
  ASSERT_TRUE(first.answered);
  ASSERT_EQ(first.results.size(), 2U);
  ASSERT_FALSE(first.results[0].continuation_point().empty())
    << "S1 was not paused with a continuation point";
  ASSERT_FALSE(first.results[1].continuation_point().empty())
    << "S2 was not paused with a continuation point";
  auto store = std::move(first.store);
  const auto released = harness.browse_next({first.results[0].continuation_point()}, store, true);
  ASSERT_TRUE(released.answered);
  EXPECT_EQ(released.serviceResult.as_status(), Status::Good);

  a->hold_reference_reads_of({});
  ASSERT_EQ(a->release_held_reference_reads(), 1U);
  auto kept = harness.browse_next({first.results[1].continuation_point()}, store);

  ASSERT_TRUE(kept.answered);
  ASSERT_EQ(kept.results.size(), 1U);
  EXPECT_EQ(kept.results[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(targets_of(kept.results[0]), targetsOfS2) << "S2, whose point was kept";
  const auto readsOfS1 = queries_naming(*a, s1);
  ASSERT_EQ(readsOfS1.size(), 1U) << "read_references_async queries naming S1";
  ASSERT_FALSE(readsOfS1[0].answeredToken.empty()) << "the held read gave S1 no resume token";
  EXPECT_EQ(queries_naming(*a, s2).size(), 3U) << "read_references_async queries naming S2";
  const auto releases = a->calls(Member::ReleaseResumeToken);
  ASSERT_EQ(releases.size(), 1U) << "release_resume_token calls";
  EXPECT_EQ(releases[0].token, readsOfS1[0].answeredToken);
}

// A BrowseNext that releases its points answers with empty results and diagnosticInfos (OPC 10000-4 5.9.3.2,
// Table 37), whatever the points it names: an unknown point, malformed bytes and a repeat add no result. It
// releases only the points it names, each point's resume token once, and resumes no operation.
// @relation(AC-SVR-VIEW-BNX-002-RELEASE-FREES, scope=function)
TEST(BrowseFlow, BrowseNextReleaseReturnsEmptyArraysAndRemovesOnlyNamedPoints)
{
  BrowseHarness harness;
  auto a = make_shared<BatchRecordingNamespace>(
    "urn:test:browse-flow:release-arrays", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  a->page_references_by_max_references();
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  for (uint32_t i = 1; i <= 3; ++i)
  {
    harness.link(
      s, ReferenceTypeId::HasComponent, harness.create(NodeId{index, 100u + i}, "T" + std::to_string(i)));
  }
  a->reset();

  auto first = harness.browse(request_of({description_of(s), description_of(s)}, 1));
  ASSERT_TRUE(first.answered);
  ASSERT_EQ(first.results.size(), 2U);
  const auto named = first.results[0].continuation_point();
  const auto untouched = first.results[1].continuation_point();
  ASSERT_FALSE(named.empty()) << "the first operation handed out no continuation point";
  ASSERT_FALSE(untouched.empty()) << "the second operation handed out no continuation point";
  ASSERT_NE(named, untouched);
  auto store = std::move(first.store);
  ASSERT_EQ(store.size(), 2U);
  const auto readsAfterBrowse = queries_naming(*a, s).size();

  const ByteString unknown(16, 0);
  const ByteString malformed{0x6e, 0x6f, 0x74};
  const auto released = harness.browse_next({named, unknown, malformed, named}, store, true, 0, 10s, 0x3ff);
  ASSERT_TRUE(released.answered);
  EXPECT_EQ(released.serviceResult.as_status(), Status::Good) << to_string(released.serviceResult);
  EXPECT_TRUE(released.results.empty()) << released.results.size() << " results";
  EXPECT_EQ(released.diagnosticInfos, 0U);
  EXPECT_TRUE(released.store.empty()) << "a release handed out continuation points";
  EXPECT_EQ(store.size(), 1U) << "the point not named must stay stored";
  EXPECT_EQ(a->count(Member::ReleaseResumeToken), 1U) << "release_resume_token calls";

  const auto continued = harness.browse_next({named}, store);
  ASSERT_TRUE(continued.answered);
  ASSERT_EQ(continued.results.size(), 1U);
  EXPECT_EQ(continued.results[0].status_code().as_status(), Status::BadContinuationPointInvalid)
    << "the released point was continued: " << to_string(continued.results[0].status_code());
  EXPECT_EQ(store.size(), 1U);

  const auto repeated = harness.browse_next({named}, store, true);
  ASSERT_TRUE(repeated.answered);
  EXPECT_TRUE(repeated.results.empty());
  EXPECT_EQ(repeated.diagnosticInfos, 0U);
  EXPECT_EQ(store.size(), 1U);

  const auto last = harness.browse_next({untouched}, store, true);
  ASSERT_TRUE(last.answered);
  EXPECT_TRUE(last.results.empty());
  EXPECT_EQ(last.diagnosticInfos, 0U);
  EXPECT_TRUE(store.empty());
  EXPECT_EQ(a->count(Member::ReleaseResumeToken), 2U) << "release_resume_token calls";
  EXPECT_EQ(queries_naming(*a, s).size(), readsAfterBrowse) << "a release resumed an operation";
}

// API-10.2 for BrowseNext: the reference read a BrowseNext makes to resume an operation is told the
// BrowseNext's own partial-result deadline, as its RequestInfo's answerBy, and its timeoutHint, as the
// deadline.
// @relation(AC-SVR-PARTIAL-RESULTS-001-DEADLINE-REACHES-NAMESPACE, scope=function)
TEST(BrowseFlow, BrowseNextsReferenceReadIsToldItsPartialResultDeadline)
{
  BrowseHarness harness;
  auto a = make_shared<BatchRecordingNamespace>(
    "urn:test:browse-flow:next-deadline", harness.threadPool.get_executor());
  ServerConfig serverConfig;
  serverConfig.partialResultDeadlineFraction = 0.5;
  const uint16_t index = harness.setup({a}, std::move(serverConfig)).at(0);
  a->page_references_by_max_references();
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  for (uint32_t i = 1; i <= 3; ++i)
  {
    harness.link(
      s, ReferenceTypeId::HasComponent, harness.create(NodeId{index, 100u + i}, "T" + std::to_string(i)));
  }
  for (const uint32_t timeoutHint : {1000u, 0u})
  {
    SCOPED_TRACE(timeoutHint);
    a->reset();
    auto first = harness.browse(request_of({description_of(s)}, 2));
    ASSERT_TRUE(first.answered);
    ASSERT_EQ(first.results.size(), 1U);
    const ByteString point = first.results[0].continuation_point();
    ASSERT_FALSE(point.empty()) << "the first page handed out no continuation point";
    a->reset();

    auto store = std::move(first.store);
    const auto sent = std::chrono::steady_clock::now();
    auto next = harness.browse_next({point}, store, false, timeoutHint);

    ASSERT_TRUE(next.answered);
    ASSERT_EQ(next.results.size(), 1U);
    EXPECT_EQ(next.results[0].status_code().as_status(), Status::Good);
    // The resume-token read and target TypeDefinition reads serve the same BrowseNext and must
    // receive its request deadlines.
    const auto reads = a->calls(Member::ReadReferences);
    ASSERT_FALSE(reads.empty()) << "the BrowseNext made no read_references_async call";
    EXPECT_TRUE(std::any_of(reads.begin(),
      reads.end(),
      [&s](const auto& read)
      { return std::find(read.nodeIds.begin(), read.nodeIds.end(), s) != read.nodeIds.end(); }))
      << "no read_references_async call of the BrowseNext names S";
    for (std::size_t k = 0; k < reads.size(); ++k)
    {
      ASSERT_TRUE(reads[k].hasRequest) << "call " << k;
      if (timeoutHint == 0)
      {
        EXPECT_FALSE(reads[k].answerBy.has_value()) << "zero-hint BrowseNext call " << k;
        EXPECT_EQ(reads[k].deadline, std::chrono::steady_clock::time_point::max()) << "call " << k;
      }
      else
      {
        ASSERT_TRUE(reads[k].answerBy.has_value())
          << "the BrowseNext's reference read " << k << " carries no answerBy";
        EXPECT_GE(*reads[k].answerBy, sent + 500ms) << "call " << k;
        EXPECT_LE(*reads[k].answerBy, sent + 600ms) << "call " << k;
        EXPECT_GE(reads[k].deadline, sent + 1000ms) << "call " << k;
        EXPECT_LE(reads[k].deadline, sent + 1100ms) << "call " << k;
      }
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-10-REFERENCES-BEYOND-MAXREFERENCES-ARE-KEPT-FOR-BROWSENEXT, scope=function)
// @relation(AC-SVR-AUTHZ-010-DELEGATE-BROWSE-REFERENCES-PASS-TARGET-AUTHORIZATION, scope=function)
TEST(BrowseFlow, ReferencesBeyondMaxReferencesAreKeptForBrowseNext)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:beyond", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  a->answer_every_reference();
  FivePages pages;
  ASSERT_NO_FATAL_FAILURE(browse_five_in_pages(harness, *a, index, pages));

  const auto& t = pages.targets;
  const std::vector<std::vector<NodeId>> expected{{t[0], t[1]}, {t[2], t[3]}, {t[4]}};
  ASSERT_EQ(pages.outcomes.size(), 3U);
  for (std::size_t k = 0; k < 3; ++k)
  {
    ASSERT_TRUE(pages.outcomes[k].answered) << "page " << k + 1;
    ASSERT_EQ(pages.outcomes[k].results.size(), 1U) << "page " << k + 1;
    const auto& result = pages.outcomes[k].results[0];
    EXPECT_EQ(result.status_code().as_status(), Status::Good) << "page " << k + 1;
    EXPECT_EQ(targets_of(result), expected[k]) << "page " << k + 1;
    EXPECT_EQ(result.continuation_point().empty(), k == 2) << "page " << k + 1 << "'s continuation point";
  }
  EXPECT_EQ(queries_naming(*a, pages.s).size(), 1U) << "read_references_async queries naming S";
}

// @relation(AC-SVR-AUTHZ-010-DELEGATE-BROWSE-REFERENCES-PASS-TARGET-AUTHORIZATION, scope=function)
// @relation(AC-SVR-AUTHZ-001-LOCAL-TARGET-LOOKUP-FAILS-CLOSED, scope=function)
TEST(BrowseFlow, LookupFailuresCannotAuthorizeLocalTargets)
{
  for (const std::string_view responseShape : {"item", "batch", "short", "empty"})
  {
    for (const auto failure : {Status::BadResourceUnavailable, Status::BadInternalError, Status::Uncertain})
    {
      if ((responseShape == "batch" && failure == Status::Uncertain) ||
          ((responseShape == "short" || responseShape == "empty") &&
            failure != Status::BadResourceUnavailable))
        continue;
      for (const bool resume : {false, true})
      {
        SCOPED_TRACE(responseShape);
        SCOPED_TRACE(static_cast<uint32_t>(failure));
        SCOPED_TRACE(resume ? "BrowseNext after an allowed page" : "fresh Browse");
        BrowseHarness harness;
        auto nameSpace = make_shared<BatchRecordingNamespace>(
          "urn:test:browse-flow:failed-target", harness.threadPool.get_executor());
        auto availableNamespace = make_shared<BatchRecordingNamespace>(
          "urn:test:browse-flow:available-target", harness.threadPool.get_executor());
        const auto indexes = harness.setup({nameSpace, availableNamespace});
        const auto index = indexes.at(0);
        const auto availableIndex = indexes.at(1);
        const auto source = harness.create(NodeId{index, 710u}, "Source");
        const auto allowedPrefix = harness.create(NodeId{availableIndex, 711u}, "AllowedPrefix");
        const auto allowedSuffix = harness.create(NodeId{availableIndex, 712u}, "AllowedSuffix");
        const auto firstProtected = harness.create(NodeId{index, 713u}, "FirstProtected");
        const auto secondProtected = harness.create(NodeId{index, 714u}, "SecondProtected");
        const NodeId dangling{availableIndex, 715u};
        const ExpandedNodeId remote{firstProtected, uint32_t{1}};
        // A reference to another server is returned with its namespace URI, since the index is local.
        const ExpandedNodeId remoteAsBrowsed{
          NodeId{0, uint32_t{713}}, "urn:test:browse-flow:failed-target", uint32_t{1}};
        harness.link(source, ReferenceTypeId::HasComponent, allowedPrefix);
        harness.link(source, ReferenceTypeId::HasComponent, firstProtected);
        harness.link(source, ReferenceTypeId::HasComponent, secondProtected);
        harness.link(source, ReferenceTypeId::HasComponent, allowedSuffix);
        auto sourceNode = harness.sessionInfo->address_space().find_node_sync(source);
        ASSERT_TRUE(
          sourceNode
            .try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{dangling}, true)
            .is_good());
        ASSERT_TRUE(
          sourceNode.try_add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, remote, true).is_good());
        auto firstProtectedNode = harness.sessionInfo->address_space().find_node_sync(firstProtected);
        auto secondProtectedNode = harness.sessionInfo->address_space().find_node_sync(secondProtected);
        const auto firstStoredNode = nameSpace->find_node(firstProtected, std::nullopt);
        const auto secondStoredNode = nameSpace->find_node(secondProtected, std::nullopt);
        ASSERT_TRUE(firstStoredNode.has_value());
        ASSERT_TRUE(secondStoredNode.has_value());
        ASSERT_TRUE(firstStoredNode->is_good());
        ASSERT_TRUE(secondStoredNode->is_good());
        nameSpace->answer_every_reference();
        nameSpace->decline_single_lookups();
        availableNamespace->answer_every_reference();
        harness.logPath = ua::test_utils::unique_temp_path("browse_lookup_failure", ".log");
        harness.sessionInfo->log = Logger{std::make_shared<FileLogSink>(harness.logPath.string(), false),
          std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace),
          "test.browse"};

        // The same source and references are visible before the lookup failure and permission revocation.
        // BrowseNext must authorize the retained references against their current state, not this page's.
        auto first = harness.browse(request_of({description_of(source)}, resume ? 1u : 0u));
        ASSERT_TRUE(first.answered);
        ASSERT_EQ(first.results.size(), 1u);
        ASSERT_EQ(first.results[0].status_code().as_status(), Status::Good);
        std::vector<ExpandedNodeId> beforeFailure;
        for (const auto& reference : first.results[0].references())
          beforeFailure.push_back(reference.node_id());
        const std::vector<ExpandedNodeId> allControls{ExpandedNodeId{allowedPrefix},
          ExpandedNodeId{firstProtected},
          ExpandedNodeId{secondProtected},
          ExpandedNodeId{allowedSuffix},
          ExpandedNodeId{dangling},
          remoteAsBrowsed};
        EXPECT_EQ(
          beforeFailure, resume ? std::vector<ExpandedNodeId>{ExpandedNodeId{allowedPrefix}} : allControls);
        const auto firstPoint = first.results[0].continuation_point();
        EXPECT_EQ(firstPoint.empty(), !resume);
        ASSERT_EQ(harness.sessionInfo->address_space().try_find_node_sync(dangling).status_code().as_status(),
          Status::BadNodeIdUnknown)
          << "the dangling control is definitively absent";

        ua::test_helpers::set_test_node_permissions(firstProtectedNode, PermissionType{});
        ua::test_helpers::set_test_node_permissions(secondProtectedNode, PermissionType{});
        const StatusCode lookupFailure{failure,
          ErrorDetail::build(
            "ProtectedTargetUnavailable", "Target lookup is unavailable", "test.protected-lookup")
            .context(ContextKeys::method, "lookup-round")
            .cause(StatusCode{Status::BadCommunicationError,
              ErrorDetail::build("UnderlyingStoreFailure", "The protected target store failed", "test.store")
                .context(ContextKeys::fieldName, "protected-backend")})};
        for (const auto& [nodeId, storedNode] : std::vector<std::pair<NodeId, shared_ptr<Node>>>{
               {firstProtected, firstStoredNode->value()}, {secondProtected, secondStoredNode->value()}})
        {
          if (responseShape == "item")
            nameSpace->answer_lookup_of(nodeId, lookupFailure);
          else if (responseShape == "batch")
            nameSpace->answer_lookup_of(nodeId, storedNode, lookupFailure);
          else
            nameSpace->answer_lookup_of(
              nodeId, storedNode, std::nullopt, responseShape == "short" ? std::size_t{1} : std::size_t{0});
        }
        nameSpace->reset();

        BrowseOutcome outcome;
        if (resume)
        {
          ASSERT_FALSE(firstPoint.empty());
          outcome = harness.browse_next({firstPoint}, first.store);
        }
        else
        {
          outcome = harness.browse(request_of({description_of(source)}));
        }
        std::vector<ExpandedNodeId> afterFailure;
        for (int page = 0; page < 8; ++page)
        {
          ASSERT_TRUE(outcome.answered);
          ASSERT_EQ(outcome.results.size(), 1u);
          EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
          EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::Good);
          for (const auto& reference : outcome.results[0].references())
            afterFailure.push_back(reference.node_id());
          const auto point = outcome.results[0].continuation_point();
          if (point.empty())
            break;
          auto store = std::move(outcome.store);
          outcome = harness.browse_next({point}, store);
        }
        EXPECT_TRUE(outcome.results[0].continuation_point().empty()) << "the finite reference list must end";
        std::vector<ExpandedNodeId> expected;
        if (!resume)
          expected.push_back(ExpandedNodeId{allowedPrefix});
        expected.push_back(ExpandedNodeId{allowedSuffix});
        expected.push_back(ExpandedNodeId{dangling});
        expected.push_back(remoteAsBrowsed);
        EXPECT_EQ(afterFailure, expected)
          << "failed local authorization dependencies must not hide allowed, dangling or remote controls";
        // BrowseNext here pages one Reference at a time, so each of its lookups names one target: only the
        // fresh Browse looks both protected targets up together, and only there is a one-item answer short.
        if (responseShape != "item" && !resume)
        {
          const auto batches = calls_naming(*nameSpace, Member::BatchedLookup, firstProtected);
          ASSERT_FALSE(batches.empty()) << "the scripted batch response was not exercised";
          EXPECT_TRUE(std::ranges::any_of(batches,
            [&secondProtected](const Call& call)
            { return std::ranges::find(call.nodeIds, secondProtected) != call.nodeIds.end(); }))
            << "short and batch failures must exercise the two-target lookup";
        }

        std::ifstream logFile{harness.logPath, std::ios::binary};
        const std::string logged{std::istreambuf_iterator<char>{logFile}, std::istreambuf_iterator<char>{}};
        if (responseShape == "short" && resume)
        {
          // A one-item answer to a one-target lookup is well formed; the permission revocation omits it.
        }
        else if (responseShape == "short" || responseShape == "empty")
        {
          EXPECT_NE(logged.find("NamespaceItemCountMismatch"), std::string::npos)
            << "malformed lookup results must be logged before their detail is discarded";
        }
        else
        {
          EXPECT_NE(logged.find(to_string(StatusCode{failure})), std::string::npos);
          EXPECT_NE(logged.find("ProtectedTargetUnavailable"), std::string::npos);
          EXPECT_NE(logged.find("test.protected-lookup"), std::string::npos);
          EXPECT_NE(logged.find("lookup-round"), std::string::npos);
          EXPECT_NE(logged.find("UnderlyingStoreFailure"), std::string::npos)
            << "the local log must preserve the original nested cause";
          EXPECT_NE(logged.find("protected-backend"), std::string::npos);
        }
      }
    }
  }
}

TEST(BrowseFlow, ReferencesToUnbrowsableTargetsAreOmitted)
{
  BrowseHarness harness;
  auto a = make_shared<BatchRecordingNamespace>(
    "urn:test:browse-flow:unbrowsable", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  const NodeId browsed = harness.create(NodeId{index, 700u}, "Browsed");
  const NodeId allowed = harness.create(NodeId{index, 701u}, "Allowed");
  const NodeId denied = harness.create(NodeId{index, 702u}, "Denied");
  harness.link(browsed, ReferenceTypeId::HasComponent, allowed);
  harness.link(browsed, ReferenceTypeId::HasComponent, denied);
  auto deniedNode = harness.sessionInfo->address_space().try_find_node_sync(denied);
  ASSERT_TRUE(deniedNode.is_good());
  ua::test_helpers::set_test_node_permissions(deniedNode.value(), PermissionType{});
  a->reset();

  const auto outcome = harness.browse(request_of({description_of(browsed)}));

  ASSERT_FALSE(queries_naming(*a, browsed).empty()) << "the References of 700 were not read";
  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 1U);
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(targets_of(outcome.results[0]), std::vector<NodeId>{allowed})
    << "the unbrowsable target is omitted";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-11-AN-ANSWER-WITHOUT-A-VALUE-IS-THE-OPERATIONS-STATUS, scope=function)
TEST(BrowseFlow, AnAnswerWithoutAValueIsTheOperationsStatus)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:uncertain", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  const NodeId s1 = harness.create(NodeId{index, 101u}, "S1");
  const NodeId s2 = harness.create(NodeId{index, 102u}, "S2");
  std::vector<NodeId> targetsOfS2;
  for (uint32_t i = 1; i <= 3; ++i)
  {
    harness.link(
      s1, ReferenceTypeId::HasComponent, harness.create(NodeId{index, 200u + i}, "A" + std::to_string(i)));
    targetsOfS2.push_back(harness.create(NodeId{index, 300u + i}, "B" + std::to_string(i)));
    harness.link(s2, ReferenceTypeId::HasComponent, targetsOfS2.back());
  }
  a->answer_lookup_of(s1,
    StatusCode{Status::Uncertain,
      ErrorDetail::build(
        "UncertainLookupSentinel", "The test's namespace cannot say what this Node is", "TestNamespace")});
  a->page_references(2);
  a->answer_reference_query_of(s2,
    2,
    StatusCode{Status::Uncertain,
      ErrorDetail::build("UncertainPageSentinel",
        "The test's namespace cannot read this page of References",
        "TestNamespace")});
  a->reset();

  const auto outcome = harness.browse(request_of({description_of(s1), description_of(s2)}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 2U);
  const auto& first = outcome.results[0];
  EXPECT_EQ(first.status_code().as_status(), Status::Uncertain)
    << "S1 answered " << to_string(first.status_code());
  EXPECT_EQ(detail_code(first.status_code()), "UncertainLookupSentinel");
  EXPECT_TRUE(first.references().empty()) << "S1 returned" << describe(targets_of(first));
  EXPECT_TRUE(first.continuation_point().empty()) << "S1 handed out a continuation point";

  const auto& second = outcome.results[1];
  EXPECT_EQ(second.status_code().as_status(), Status::Uncertain)
    << "S2 answered " << to_string(second.status_code());
  EXPECT_EQ(detail_code(second.status_code()), "UncertainPageSentinel");
  EXPECT_EQ(targets_of(second), (std::vector<NodeId>{targetsOfS2[0], targetsOfS2[1]}))
    << "S2 returned" << describe(targets_of(second));
  EXPECT_TRUE(second.continuation_point().empty()) << "S2 handed out a continuation point";
}

// Two operations of one request fail for different reasons, one at its source lookup and one at its first
// page of References; each slot carries its own status and its own ErrorDetail, not one shared across the
// request.
// @relation(AC-SVR-DIAG-010-PEROPERATION-DETAIL, scope=function)
TEST(BrowseFlow, EachFailedOperationCarriesItsOwnDetail)
{
  BrowseHarness harness;
  auto a = make_shared<BatchRecordingNamespace>(
    "urn:test:browse-flow:per-operation", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  const NodeId s1 = harness.create(NodeId{index, 101u}, "S1");
  const NodeId s2 = harness.create(NodeId{index, 102u}, "S2");
  for (uint32_t i = 1; i <= 2; ++i)
  {
    harness.link(
      s1, ReferenceTypeId::HasComponent, harness.create(NodeId{index, 200u + i}, "A" + std::to_string(i)));
    harness.link(
      s2, ReferenceTypeId::HasComponent, harness.create(NodeId{index, 300u + i}, "B" + std::to_string(i)));
  }
  a->answer_lookup_of(s1,
    StatusCode{Status::BadResourceUnavailable,
      ErrorDetail::build(
        "LookupFailedSentinel", "The test's namespace cannot look this Node up", "TestNamespace")});
  a->answer_reference_query_of(s2,
    1,
    StatusCode{Status::BadInternalError,
      ErrorDetail::build(
        "PageFailedSentinel", "The test's namespace cannot read this page of References", "TestNamespace")});
  a->reset();

  const auto outcome = harness.browse(request_of({description_of(s1), description_of(s2)}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 2U);
  const auto& first = outcome.results[0];
  EXPECT_EQ(first.status_code().as_status(), Status::BadResourceUnavailable)
    << "S1 answered " << to_string(first.status_code());
  EXPECT_EQ(detail_code(first.status_code()), "LookupFailedSentinel");
  EXPECT_TRUE(first.references().empty()) << "S1 returned" << describe(targets_of(first));
  EXPECT_TRUE(first.continuation_point().empty()) << "S1 handed out a continuation point";

  const auto& second = outcome.results[1];
  EXPECT_EQ(second.status_code().as_status(), Status::BadInternalError)
    << "S2 answered " << to_string(second.status_code());
  EXPECT_EQ(detail_code(second.status_code()), "PageFailedSentinel");
  EXPECT_TRUE(second.references().empty()) << "S2 returned" << describe(targets_of(second));
  EXPECT_TRUE(second.continuation_point().empty()) << "S2 handed out a continuation point";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-AN-UNKNOWN-VIEW-FAULTS-ONLY-WHEN-AN-OPERATION-REACHES-THE-VIEW-CHECK, scope=function)
TEST(BrowseFlow, AnUnknownViewFaultsOnlyWhenAnOperationReachesTheViewCheck)
{
  BrowseHarness harness;
  harness.setup({});
  // No namespace holds this NodeId.
  const NodeId view{0, uint32_t{987654321}};
  const NodeId objects{ObjectId::ObjectsFolder};

  const auto invalid =
    harness.browse(request_of({description_of(objects, static_cast<BrowseDirection>(7))}, 0, 0, view));
  const auto forward = harness.browse(request_of({description_of(objects)}, 0, 0, view));

  ASSERT_TRUE(invalid.answered);
  EXPECT_EQ(invalid.serviceResult.as_status(), Status::Good) << to_string(invalid.serviceResult);
  ASSERT_EQ(invalid.results.size(), 1U);
  EXPECT_EQ(invalid.results[0].status_code().as_status(), Status::BadBrowseDirectionInvalid)
    << to_string(invalid.results[0].status_code());

  ASSERT_TRUE(forward.answered);
  EXPECT_EQ(forward.serviceResult.as_status(), Status::BadViewIdUnknown) << to_string(forward.serviceResult);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-A-SOURCE-THE-SESSION-MAY-NOT-BROWSE-IS-NOT-READ, scope=function)
TEST(BrowseFlow, ASourceTheSessionMayNotBrowseIsNotRead)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:refused", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  const NodeId s1 = harness.create(NodeId{index, 101u}, "S1");
  const NodeId s2 = harness.create(NodeId{index, 102u}, "S2");
  const NodeId t1 = harness.create(NodeId{index, 201u}, "T1");
  const NodeId t2 = harness.create(NodeId{index, 202u}, "T2");
  harness.link(s1, ReferenceTypeId::HasComponent, t1);
  harness.link(s2, ReferenceTypeId::HasComponent, t2);
  a->decline_single_lookups();
  a->decline_immediate_permissions();
  // Every permission but Browse on S1; every permission, Browse included, on the other Nodes.
  auto withoutBrowse = ua::test_helpers::all_permissions();
  withoutBrowse.reset(PermissionType::Bit::Browse);
  a->grant(s1, withoutBrowse);
  a->reset();

  const auto outcome = harness.browse(request_of({description_of(s1), description_of(s2)}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 2U);
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::BadUserAccessDenied)
    << to_string(outcome.results[0].status_code());
  EXPECT_TRUE(outcome.results[0].references().empty())
    << "S1 returned" << describe(targets_of(outcome.results[0]));
  EXPECT_EQ(outcome.results[1].status_code().as_status(), Status::Good)
    << to_string(outcome.results[1].status_code());
  EXPECT_EQ(targets_of(outcome.results[1]), std::vector<NodeId>{t2});
  EXPECT_TRUE(queries_naming(*a, s1).empty()) << "a read_references_async query named S1";
}

// Part 4 section 5.8.3: BrowseNext returns one result per continuation point supplied, in the order the
// points were supplied, and a point the server no longer holds fails on its own row rather than shortening
// the array. The client pairs results positionally (the same contract `AC-CL-VIEW-004-PERNODE-STATUS` states
// for the initial browse), so a server that compacts makes it read the third point's data as the answer to
// its second. The stimulus is three points the server genuinely issued, of which the MIDDLE one is released
// before the call: a compacting server answers with two rows, and a server that appends failures answers
// [Good, Good, Bad]. Only a positional one answers [Good, Bad_ContinuationPointInvalid, Good]. Each Node
// holds two References and A pages at the query's maxReferences, so with requestedMaxReferencesPerNode 1 each
// operation halts with a continuation point holding A's resume token.
// @relation(AC-SVR-VIEW-BNX-006-RESULTS-ALIGNED, scope=function)
TEST(BrowseFlow, BrowseNextResultsAlignPositionallyWithTheContinuationPointsSupplied)
{
  BrowseHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:aligned", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  a->page_references_by_max_references();
  std::vector<NodeId> sources;
  for (uint32_t i = 0; i < 3; ++i)
  {
    sources.push_back(harness.create(NodeId{index, 600u + i}, "S" + std::to_string(i + 1)));
    for (uint32_t k = 0; k < 2; ++k)
    {
      harness.link(sources.back(),
        ReferenceTypeId::HasComponent,
        harness.create(NodeId{index, 610u + 2 * i + k}, "T" + std::to_string(2 * i + k + 1)));
    }
  }
  a->reset();

  auto first = harness.browse(request_of({description_of(sources[0], BrowseDirection::Both),
                                           description_of(sources[1], BrowseDirection::Both),
                                           description_of(sources[2], BrowseDirection::Both)},
    1));
  ASSERT_TRUE(first.answered);
  ASSERT_EQ(first.results.size(), 3U);
  std::vector<ByteString> points;
  for (std::size_t i = 0; i < 3; ++i)
  {
    ASSERT_TRUE(first.results[i].status_code().is_good())
      << "control: operation " << i << " must have succeeded before it can be continued";
    ASSERT_FALSE(first.results[i].continuation_point().empty())
      << "control: operation " << i
      << " must have halted with a continuation point, otherwise the BrowseNext below is not supplying three "
         "real points";
    points.push_back(first.results[i].continuation_point());
  }
  ASSERT_EQ(first.store.size(), 3U);

  // The middle point goes stale: the server issued it, and no longer holds it.
  Guid staleGuid;
  staleGuid.from_ua_binary(points[1]);
  ASSERT_EQ(first.store.erase(staleGuid), 1U)
    << "fixture: the point being staled must be one the server issued";

  const auto next = harness.browse_next(points, first.store);

  ASSERT_TRUE(next.answered);
  EXPECT_EQ(next.serviceResult.as_status(), Status::Good)
    << "one stale point among three is a per-operation failure, not a service-level fault";
  ASSERT_EQ(next.results.size(), 3U) << "one result per continuation point supplied";
  EXPECT_TRUE(next.results[0].status_code().is_good())
    << "the live point supplied at position 0 must be continued at position 0: "
    << to_string(next.results[0].status_code());
  EXPECT_EQ(next.results[1].status_code().as_status(), Status::BadContinuationPointInvalid)
    << "the stale point must fail on the row it was supplied at: "
    << to_string(next.results[1].status_code());
  EXPECT_TRUE(next.results[2].status_code().is_good())
    << "a stale point earlier in the list must not displace the point after it: "
    << to_string(next.results[2].status_code());
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-A-BROWSE-THAT-READS-MORE-THAN-1024-PAGES-IS-ANSWERED, scope=function)
TEST(BrowseFlow, ABrowseThatReadsMoreThan1024PagesIsAnswered)
{
  BrowseHarness harness;
  auto a =
    default_ns::Namespace::create("urn:test:browse-flow:many-pages", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({a}).at(0);
  const NodeId s = harness.create(NodeId{index, 1u}, "S");
  for (uint32_t i = 1; i <= 1100; ++i)
  {
    harness.link(s, ReferenceTypeId::HasComponent, harness.create(NodeId{index, 1000u + i}, "C"));
  }
  // The inverse Organizes Reference from F, added last.
  const NodeId f = harness.create(NodeId{index, 2u}, "F");
  harness.link(f, ReferenceTypeId::Organizes, s);

  const auto outcome = harness.browse(request_of({description_of(s, BrowseDirection::Inverse)}, 1));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_EQ(outcome.results.size(), 1U);
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::Good)
    << "S answered " << to_string(outcome.results[0].status_code()) << " ("
    << detail_code(outcome.results[0].status_code()) << ")";
  EXPECT_EQ(targets_of(outcome.results[0]), std::vector<NodeId>{f});
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-09-AN-UNKNOWN-VIEW-FOUND-AFTER-THE-RESPONSE-ANSWERS-THE-PAUSED-OPERATIONS, scope=function)
TEST(BrowseFlow, AnUnknownViewFoundAfterTheResponseAnswersThePausedOperations)
{
  BrowseHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:browse-flow:late-view", harness.threadPool.get_executor());
  const uint16_t index = harness.setup({r}).at(0);
  const NodeId s = harness.create(NodeId{index, 100u}, "S");
  harness.link(s, ReferenceTypeId::HasComponent, harness.create(NodeId{index, 101u}, "T"));
  // No namespace holds this NodeId.
  const NodeId view{index, 999u};
  r->hold_lookups_of({s});
  r->reset();

  auto first = harness.browse(request_of({description_of(s)}, 0, 500, view));
  r->hold_lookups_of({});
  const bool held = r->wait_for_held_lookups(1, 0ms);
  const std::size_t released = r->release_held_lookups();
  ASSERT_TRUE(first.answered);
  EXPECT_EQ(first.serviceResult.as_status(), Status::Good) << to_string(first.serviceResult);
  ASSERT_EQ(first.results.size(), 1U);
  EXPECT_TRUE(first.results[0].references().empty())
    << "S returned" << describe(targets_of(first.results[0]));
  ASSERT_FALSE(first.results[0].continuation_point().empty())
    << "S's operation was not paused: it answered " << to_string(first.results[0].status_code())
    << "; the lookup of S was " << (held ? "" : "not ") << "held, " << released << " lookups released";

  std::this_thread::sleep_for(200ms);
  // The arm bounds its own wait: a BrowseNext that is never answered fails here.
  const auto sent = std::chrono::steady_clock::now();
  const auto next =
    harness.browse_next({first.results[0].continuation_point()}, first.store, false, 2000, 4000ms);
  const auto elapsed = std::chrono::steady_clock::now() - sent;

  ASSERT_TRUE(next.answered) << "the BrowseNext was not answered within 4 s";
  EXPECT_LT(elapsed, 2000ms) << "the BrowseNext was not answered within its timeoutHint";
  EXPECT_EQ(next.serviceResult.as_status(), Status::Good) << to_string(next.serviceResult);
  ASSERT_EQ(next.results.size(), 1U);
  EXPECT_EQ(next.results[0].status_code().as_status(), Status::BadViewIdUnknown)
    << "S answered " << to_string(next.results[0].status_code());
  EXPECT_TRUE(next.results[0].references().empty()) << "S returned" << describe(targets_of(next.results[0]));
  EXPECT_TRUE(next.results[0].continuation_point().empty()) << "S handed out a continuation point";
}
