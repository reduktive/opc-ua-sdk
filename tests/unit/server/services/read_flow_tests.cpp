// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the Read service calls the namespaces that own its Nodes: one read_values_async call per namespace per
// request, carrying the Nodes the lookup returned, the request's deadline and the Session's identity; the
// request's maxAge given to the lookup of a Node read for a non-Value Attribute only; and a Value the
// namespace answered larger than the item's IndexRange failed rather than passed on.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_server.h"
#include "ua_service_fault.h"
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

namespace
{

struct ReadOutcome
{
  bool answered{false};
  StatusCode serviceResult;
  std::optional<ReadResponse> response;
};

// A server with the given namespaces registered, and a Session on it.
struct FlowHarness
{
  ~FlowHarness()
  {
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool;
  shared_ptr<SessionInfoStub> sessionInfo;

  std::vector<uint16_t> setup(const std::vector<shared_ptr<ua::Namespace>>& namespaces)
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = ServerConfig{}};
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

  // A readable Variable holding @p value, its DisplayName its NodeId.
  NodeId create_variable(uint16_t namespaceIndex, uint32_t numericId, Variant value)
  {
    const NodeId nodeId{namespaceIndex, numericId};
    auto created =
      sessionInfo->address_space().try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
    if (created.is_good())
    {
      AccessLevelType accessLevel;
      accessLevel.set(AccessLevelType::Bit::CurrentRead);
      created.value().set_access_level(accessLevel);
      created.value().set_display_name(LocalizedText{"", nodeId.as_definition()});
      created.value().write_value_sync(DataValue{std::move(value)});
    }
    return nodeId;
  }

  ReadOutcome read(ReadRequest request)
  {
    auto promise = std::make_shared<std::promise<ReadOutcome>>();
    auto future = promise->get_future();
    std::vector<LocaleId> locales{"en"};
    auto service = AttributeServiceSet::create(sessionInfo,
      locales,
      0,
      std::move(request),
      threadPool.get_executor(),
      [promise](Response response)
      {
        ReadOutcome outcome;
        outcome.answered = true;
        if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get()))
        {
          outcome.serviceResult = readResponse->response_header().service_result();
          outcome.response = std::move(*readResponse);
        }
        promise->set_value(std::move(outcome));
      });
    if (future.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "Read did not complete";
      return {};
    }
    return future.get();
  }
};

ReadValueId read_of(const NodeId& nodeId, AttributeId attribute = AttributeId::Value)
{
  ReadValueId item;
  item.node_id() = nodeId;
  item.attribute_id() = utils::to_underlying(attribute);
  return item;
}

ReadRequest request_of(std::vector<ReadValueId> items, Duration maxAge = 0, uint32_t timeoutHint = 0)
{
  ReadRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = timeoutHint;
  request.max_age() = maxAge;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  for (auto& item : items)
  {
    request.nodes_to_read().payload().push_back(std::move(item));
  }
  return request;
}

ReadRequest values_of(const std::vector<NodeId>& nodeIds)
{
  std::vector<ReadValueId> items;
  for (const auto& nodeId : nodeIds)
  {
    items.push_back(read_of(nodeId));
  }
  return request_of(std::move(items));
}

// A DataValue without a status is Good.
Status status_of(const DataValue& value)
{
  return value.status().has_value() ? value.status()->as_status() : Status::Good;
}

std::vector<NodeId> sorted(std::vector<NodeId> nodeIds)
{
  std::sort(nodeIds.begin(), nodeIds.end());
  return nodeIds;
}

std::vector<NodeId> of_namespace(const std::vector<NodeId>& all, uint16_t index)
{
  std::vector<NodeId> selected;
  for (const auto& nodeId : all)
  {
    if (nodeId.namespace_index() == index)
    {
      selected.push_back(nodeId);
    }
  }
  return selected;
}

// The one read_values_async call @p nameSpace received holds @p expected, and each item's Node is the Node
// the namespace's own lookup answers for that NodeId.
void expect_one_value_read_of(
  BatchRecordingNamespace& nameSpace, const std::vector<NodeId>& expected, const char* name)
{
  const auto reads = nameSpace.calls(Member::ReadValues);
  EXPECT_EQ(reads.size(), 1U) << name << ": read_values_async calls";
  if (reads.size() != 1U)
  {
    return;
  }
  const auto& read = reads.front();
  EXPECT_EQ(sorted(read.nodeIds), sorted(expected)) << name << ": the call holds its namespace's Value items";
  ASSERT_EQ(read.itemNodes.size(), read.nodeIds.size()) << name;
  for (std::size_t k = 0; k < read.nodeIds.size(); ++k)
  {
    const auto found = nameSpace.find_node(read.nodeIds[k], std::nullopt);
    ASSERT_TRUE(found.has_value() && found->is_good()) << name << ": " << read.nodeIds[k].as_definition();
    EXPECT_EQ(read.itemNodes[k], found->value().get())
      << name << ": the item's Node is not the Node the lookup returned for "
      << read.nodeIds[k].as_definition();
  }
}

bool is_lookup(const BatchRecordingNamespace::Call& call)
{
  return call.member == Member::BatchedLookup || call.member == Member::SingleLookup;
}

bool names(const BatchRecordingNamespace::Call& call, const NodeId& nodeId)
{
  return std::find(call.nodeIds.begin(), call.nodeIds.end(), nodeId) != call.nodeIds.end();
}

std::string describe_lookups(const std::vector<BatchRecordingNamespace::Call>& calls)
{
  std::string text;
  for (const auto& call : calls)
  {
    if (!is_lookup(call))
    {
      continue;
    }
    text += call.member == Member::BatchedLookup ? "\n  batched" : "\n  single";
    text += call.maxAge ? " maxAge " + std::to_string(*call.maxAge) : std::string{" no maxAge"};
    for (const auto& nodeId : call.nodeIds)
    {
      text += " " + nodeId.as_definition();
    }
  }
  return text;
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-01-ONE-VALUE-READ-PER-NAMESPACE-PER-REQUEST, scope=function)
TEST(ReadFlow, OneValueReadPerNamespacePerRequest)
{
  FlowHarness harness;
  auto r1 = make_shared<BatchRecordingNamespace>("urn:test:read-flow:r1", harness.threadPool.get_executor());
  auto r2 = make_shared<BatchRecordingNamespace>("urn:test:read-flow:r2", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r1, r2});
  std::vector<NodeId> order;
  for (uint32_t i = 0; i < 3; ++i)
  {
    order.push_back(
      harness.create_variable(indexes.at(0), 100 + i, Variant{static_cast<int32_t>(1000 + order.size())}));
    order.push_back(
      harness.create_variable(indexes.at(1), 200 + i, Variant{static_cast<int32_t>(1000 + order.size())}));
  }
  r1->reset();
  r2->reset();

  const auto outcome = harness.read(values_of(order));

  expect_one_value_read_of(*r1, of_namespace(order, indexes.at(0)), "R1");
  expect_one_value_read_of(*r2, of_namespace(order, indexes.at(1)), "R2");

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), order.size());
  for (std::size_t i = 0; i < order.size(); ++i)
  {
    const auto& result = outcome.response->results()[i];
    EXPECT_EQ(status_of(result), Status::Good) << "item " << i;
    ASSERT_TRUE(result.value().is_int32()) << "item " << i;
    EXPECT_EQ(result.value().as<int32_t>(), static_cast<int32_t>(1000 + i)) << "item " << i;
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-01-MAXAGE-REACHES-THE-LOOKUP-ONLY-FOR-NON-VALUE-ITEMS, scope=function)
TEST(ReadFlow, MaxAgeReachesTheLookupOnlyForNonValueItems)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:read-flow:max-age", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId a = harness.create_variable(index, 100, Variant{int32_t{7}});
  const NodeId b = harness.create_variable(index, 101, Variant{int32_t{8}});
  r->decline_single_lookups();
  r->reset();

  const auto outcome =
    harness.read(request_of({read_of(a), read_of(b, AttributeId::DisplayName)}, Duration{500}));

  const auto calls = r->calls();
  bool bWithMaxAge = false;
  bool aWithout = false;
  bool aWith = false;
  for (const auto& call : calls)
  {
    if (!is_lookup(call))
    {
      continue;
    }
    bWithMaxAge = bWithMaxAge || (names(call, b) && call.maxAge.has_value() && *call.maxAge == Duration{500});
    aWithout = aWithout || (names(call, a) && !call.maxAge.has_value());
    aWith = aWith || (names(call, a) && call.maxAge.has_value());
  }
  EXPECT_TRUE(bWithMaxAge) << "no lookup named B with maxAge 500 ms; the lookups:" << describe_lookups(calls);
  EXPECT_TRUE(aWithout) << "no lookup named A without a maxAge; the lookups:" << describe_lookups(calls);
  EXPECT_FALSE(aWith) << "a lookup named A, read only for its Value, with a maxAge; the lookups:"
                      << describe_lookups(calls);

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(status_of(outcome.response->results()[0]), Status::Good) << "A's Value";
  EXPECT_EQ(status_of(outcome.response->results()[1]), Status::Good) << "B's DisplayName";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-01-A-VALUE-LARGER-THAN-ITS-RANGE-FAILS-WITH-BAD-INTERNAL-ERROR, scope=function)
TEST(ReadFlow, AValueLargerThanItsRangeFailsWithBadInternalError)
{
  constexpr const char* wholeUri = "urn:test:read-flow:whole-values";
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(wholeUri, harness.threadPool.get_executor());
  auto c = default_ns::Namespace::create("urn:test:read-flow:in-memory", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r, c});
  const Array<int32_t> oneToTen{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  const NodeId inR = harness.create_variable(indexes.at(0), 100, Variant{oneToTen});
  const NodeId inC = harness.create_variable(indexes.at(1), 100, Variant{oneToTen});
  r->answer_whole_values();

  auto rangedR = read_of(inR);
  rangedR.index_range() = "2:4";
  auto rangedC = read_of(inC);
  rangedC.index_range() = "2:4";
  const auto outcome = harness.read(request_of({rangedR, rangedC}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);

  const auto& fromR = outcome.response->results()[0];
  EXPECT_EQ(status_of(fromR), Status::BadInternalError)
    << "the namespace answered the whole Value for the range 2:4 and the item was not failed";
  const auto detail = fromR.status().has_value() ? fromR.status()->shared_detail() : nullptr;
  ASSERT_NE(detail, nullptr) << "the failure names no ErrorDetail";
  EXPECT_EQ(detail->code, "NamespaceValueExceedsRange");
  const bool namesUri = std::any_of(detail->context.begin(),
    detail->context.end(),
    [&](const NamedValue& entry)
    { return entry.key == ContextKeys::namespaceUri.value() && entry.value == wholeUri; });
  EXPECT_TRUE(namesUri) << "the ErrorDetail's context does not name the namespace URI " << wholeUri;

  const auto& fromC = outcome.response->results()[1];
  EXPECT_EQ(status_of(fromC), Status::Good) << "the in-memory namespace's item";
  ASSERT_TRUE(fromC.value().is_array());
  EXPECT_EQ(fromC.value().as<Array<int32_t>>(), (Array<int32_t>{3, 4, 5}));
}

// The accessor's read of one Variable checks its IndexRange as the batched Read does: a range that does not
// parse is answered Bad_IndexRangeInvalid without calling the namespace, and a Value larger than its range
// fails with Bad_InternalError. The in-memory namespace's answer to the same range is the control.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-25-AN-ACCESSOR-READ-CHECKS-ITS-INDEX-RANGE, scope=function)
TEST(ReadFlow, AnAccessorReadChecksItsIndexRangeAsTheBatchedReadDoes)
{
  constexpr const char* wholeUri = "urn:test:read-flow:accessor-whole-values";
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(wholeUri, harness.threadPool.get_executor());
  auto c =
    default_ns::Namespace::create("urn:test:read-flow:accessor-in-memory", harness.threadPool.get_executor());
  const auto indexes = harness.setup({r, c});
  const Array<int32_t> oneToTen{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  const NodeId inR = harness.create_variable(indexes.at(0), 101, Variant{oneToTen});
  const NodeId inC = harness.create_variable(indexes.at(1), 101, Variant{oneToTen});
  r->answer_whole_values();

  auto readThroughTheAccessor = [&](const NodeId& nodeId, const char* range)
  {
    auto found = harness.sessionInfo->address_space().try_find_node_sync(nodeId);
    EXPECT_TRUE(found.is_good()) << "finding " << nodeId.as_definition();
    if (found.is_bad())
    {
      return DataValueResult{found.status_code()};
    }
    auto variable = found.value().as<VariableAccessor>();
    EXPECT_TRUE(variable.has_value());
    if (!variable.has_value())
    {
      return DataValueResult{StatusCode{Status::BadNodeClassInvalid}};
    }
    ReadValueId item = read_of(nodeId);
    item.index_range() = range;
    auto promise = std::make_shared<std::promise<DataValueResult>>();
    auto future = promise->get_future();
    variable->read_value_async(Duration{0},
      true,
      item,
      nullptr,
      [promise](DataValueResult answer) { promise->set_value(std::move(answer)); });
    if (future.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the accessor's read did not complete";
      return DataValueResult{StatusCode{Status::BadTimeout}};
    }
    return future.get();
  };
  auto valueReads = [&r]
  {
    return r->calls(Member::ReadValues).size();
  };

  const auto readsBefore = valueReads();
  const auto malformed = readThroughTheAccessor(inR, "abc");
  EXPECT_EQ(malformed.status_code().as_status(), Status::BadIndexRangeInvalid)
    << to_string(malformed.status_code());
  EXPECT_EQ(valueReads(), readsBefore) << "a range that does not parse reached the namespace";

  const auto excess = readThroughTheAccessor(inR, "2:4");
  ASSERT_EQ(excess.status_code().as_status(), Status::BadInternalError)
    << "the namespace answered the whole Value for the range 2:4 and the read was not failed: "
    << to_string(excess.status_code());
  const auto detail = excess.status_code().shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "NamespaceValueExceedsRange");

  const auto control = readThroughTheAccessor(inC, "2:4");
  ASSERT_TRUE(control.is_good()) << to_string(control.status_code());
  EXPECT_EQ(control.value().value().as<Array<int32_t>>(), (Array<int32_t>{3, 4, 5}));
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-01-THE-NAMESPACE-CALLS-CARRY-THE-REQUEST, scope=function)
TEST(ReadFlow, TheNamespaceCallsCarryTheRequest)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:read-flow:request", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId a = harness.create_variable(index, 100, Variant{int32_t{4711}});
  r->decline_immediate_permissions();
  r->reset();
  const auto identity = harness.sessionInfo->access_identity();
  ASSERT_NE(identity, nullptr) << "the Session must hold an identity for this test to mean anything";

  const auto sent = std::chrono::steady_clock::now();
  const auto outcome = harness.read(request_of({read_of(a)}, Duration{0}, 5000));

  const auto permissions = r->calls(Member::PermissionsAsyncForRequest);
  EXPECT_EQ(permissions.size(), 1U) << "effective_permissions_async calls taking a RequestInfo";
  if (permissions.size() == 1U)
  {
    EXPECT_GE(permissions.front().deadline, sent + 4s) << "the permissions call's deadline";
    EXPECT_LE(permissions.front().deadline, sent + 6s) << "the permissions call's deadline";
  }
  const auto reads = r->calls(Member::ReadValues);
  EXPECT_EQ(reads.size(), 1U) << "read_values_async calls";
  if (reads.size() == 1U)
  {
    const auto& read = reads.front();
    EXPECT_TRUE(read.hasRequest);
    EXPECT_GE(read.deadline, sent + 4s) << "the Value read's deadline";
    EXPECT_LE(read.deadline, sent + 6s) << "the Value read's deadline";
    EXPECT_TRUE(read.hasCaller) << "the Value read carries no CallerInfo";
    EXPECT_EQ(read.identity.get(), identity.get()) << "the Value read's caller is not the Session's identity";
  }

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 1U);
  EXPECT_EQ(status_of(outcome.response->results()[0]), Status::Good);
  ASSERT_TRUE(outcome.response->results()[0].value().is_int32());
  EXPECT_EQ(outcome.response->results()[0].value().as<int32_t>(), 4711);
}

// At the timeoutHint the Read answers the Values of a read still running Bad_Timeout and tells the namespace
// running it to stop: the cancellation flag of the held call's RequestInfo is set by the time the response
// arrives.
// @relation(AC-SVR-PARTIAL-RESULTS-003-A-NAMESPACE-STILL-RUNNING-AT-THE-HINT-IS-TOLD-TO-STOP, scope=function)
TEST(ReadFlow, ANamespaceStillRunningAtTheHintIsToldToStop)
{
  FlowHarness harness;
  auto a =
    make_shared<BatchRecordingNamespace>("urn:test:read-flow:hint-a", harness.threadPool.get_executor());
  auto b =
    make_shared<BatchRecordingNamespace>("urn:test:read-flow:hint-b", harness.threadPool.get_executor());
  const auto indexes = harness.setup({a, b});
  const NodeId x = harness.create_variable(indexes.at(0), 100, Variant{int32_t{1}});
  const NodeId y = harness.create_variable(indexes.at(1), 100, Variant{int32_t{2}});
  b->hold_value_reads_of({y});

  const auto sent = std::chrono::steady_clock::now();
  const auto outcome = harness.read(request_of({read_of(x), read_of(y)}, Duration{0}, 300));
  const auto arrived = std::chrono::steady_clock::now();

  // What B was given, taken before it is released.
  const bool held = b->wait_for_held_value_reads(1, 1000ms);
  const RequestInfo heldRequest = b->held_value_read_request(0);
  const bool cancelledAtResponse = heldRequest.cancelled && heldRequest.cancelled->load();
  b->hold_value_reads_of({});
  b->release_held_value_reads();

  ASSERT_TRUE(outcome.answered);
  EXPECT_GE(arrived, sent + 300ms) << "the response arrived before the timeoutHint";
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(status_of(outcome.response->results()[0]), Status::Good) << "X, which A read at once";
  EXPECT_EQ(status_of(outcome.response->results()[1]), Status::BadTimeout) << "Y, whose read B held";
  ASSERT_TRUE(held) << "B held no read_values_async";
  EXPECT_GE(heldRequest.deadline, sent + 300ms) << "the deadline of B's read_values_async";
  EXPECT_LE(heldRequest.deadline, sent + 350ms) << "the deadline of B's read_values_async";
  EXPECT_FALSE(heldRequest.answerBy.has_value()) << "a Read carries no partial-results deadline";
  EXPECT_TRUE(cancelledAtResponse)
    << "the cancellation flag of B's RequestInfo is not set after the response";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-01-THE-RANGE-CHECK-COVERS-EVERY-DIMENSION, scope=function)
TEST(ReadFlow, TheRangeCheckCoversEveryDimension)
{
  constexpr const char* wholeUri = "urn:test:read-flow:whole-values-every-dimension";
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(wholeUri, harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId s = harness.create_variable(index, 100, Variant{String{"abcdef"}});
  const NodeId m{index, 101};
  {
    auto created =
      harness.sessionInfo->address_space().try_create_sync<VariableAccessor>(m, NodeClass::Variable);
    ASSERT_TRUE(created.is_good()) << "creating M";
    AccessLevelType accessLevel;
    accessLevel.set(AccessLevelType::Bit::CurrentRead);
    created.value().set_access_level(accessLevel);
    created.value().set_display_name(LocalizedText{"", m.as_definition()});
    created.value().set_value_rank(ValueRank{2});
    created.value().set_array_dimensions(std::vector<uint32_t>{3, 3});
    const auto written = created.value().try_write_value_sync(
      DataValue{Variant{Array<int32_t>{Dimensions{3, 3}, std::vector<int32_t>{1, 2, 3, 4, 5, 6, 7, 8, 9}}}});
    ASSERT_TRUE(written.is_good()) << "writing M's 3 by 3 matrix";
  }
  const NodeId t =
    harness.create_variable(index, 102, Variant{Array<String>{String{"abcdef"}, String{"gh"}}});
  const NodeId u = harness.create_variable(index, 103, Variant{Array<int32_t>{1, 2, 3}});
  const NodeId w = harness.create_variable(index, 104, Variant{String{"\xC3\xA4\xC3\xB6"}});
  r->answer_whole_values();

  auto rangedS = read_of(s);
  rangedS.index_range() = "1:2";
  auto rangedM = read_of(m);
  rangedM.index_range() = "0:1,0:1";
  auto rangedT = read_of(t);
  rangedT.index_range() = "0:1,0:1";
  auto rangedU = read_of(u);
  rangedU.index_range() = "0:9";
  auto rangedUWhole = read_of(u);
  rangedUWhole.index_range() = "0:4294967295";
  auto rangedW = read_of(w);
  rangedW.index_range() = "0:1";
  const auto outcome = harness.read(request_of({rangedS, rangedM, rangedT, rangedU, rangedUWhole, rangedW}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 6U);

  const auto expectRefused = [&](const DataValue& result, const char* name, const char* range)
  {
    EXPECT_EQ(status_of(result), Status::BadInternalError)
      << name << ": the namespace answered the whole Value for the range " << range
      << " and the item was not failed";
    const auto detail = result.status().has_value() ? result.status()->shared_detail() : nullptr;
    ASSERT_NE(detail, nullptr) << name << ": the failure names no ErrorDetail";
    EXPECT_EQ(detail->code, "NamespaceValueExceedsRange") << name;
    const bool namesUri = std::any_of(detail->context.begin(),
      detail->context.end(),
      [&](const NamedValue& entry)
      { return entry.key == ContextKeys::namespaceUri.value() && entry.value == wholeUri; });
    EXPECT_TRUE(namesUri) << name << ": the ErrorDetail's context does not name the namespace URI "
                          << wholeUri;
  };
  expectRefused(outcome.response->results()[0], "S, the String \"abcdef\"", "1:2");
  expectRefused(outcome.response->results()[1], "M, the 3 by 3 matrix", "0:1,0:1");
  expectRefused(outcome.response->results()[2], "T, the String array [\"abcdef\", \"gh\"]", "0:1,0:1");

  const auto& fromU = outcome.response->results()[3];
  EXPECT_EQ(status_of(fromU), Status::Good) << "U, whose whole Value [1, 2, 3] is smaller than its range 0:9";
  EXPECT_TRUE(fromU.value().is_array()) << "U";
  if (fromU.value().is_array())
  {
    EXPECT_EQ(fromU.value().as<Array<int32_t>>(), (Array<int32_t>{1, 2, 3})) << "U";
  }

  const auto& fromUWhole = outcome.response->results()[4];
  EXPECT_EQ(status_of(fromUWhole), Status::Good) << "U read for 0:4294967295, every index a UInt32 can name";
  EXPECT_TRUE(fromUWhole.value().is_array()) << "U read for 0:4294967295, every index a UInt32 can name";
  if (fromUWhole.value().is_array())
  {
    EXPECT_EQ(fromUWhole.value().as<Array<int32_t>>(), (Array<int32_t>{1, 2, 3}))
      << "U read for 0:4294967295, every index a UInt32 can name";
  }

  const auto& fromW = outcome.response->results()[5];
  EXPECT_EQ(status_of(fromW), Status::Good) << "W, two characters in four bytes, read for 0:1";
  EXPECT_TRUE(fromW.value().is_string()) << "W, two characters in four bytes, read for 0:1";
  if (fromW.value().is_string())
  {
    EXPECT_EQ(fromW.value().as<String>(), String{"\xC3\xA4\xC3\xB6"})
      << "W, two characters in four bytes, read for 0:1";
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-24-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-OPERATION, scope=function)
TEST(ReadFlow, AnUncertainLookupAnswerRefusesOnlyItsOperation)
{
  FlowHarness harness;
  auto r =
    make_shared<BatchRecordingNamespace>("urn:test:read-flow:uncertain", harness.threadPool.get_executor());
  const auto index = harness.setup({r}).at(0);
  const NodeId a = harness.create_variable(index, 100, Variant{int32_t{7}});
  const NodeId b = harness.create_variable(index, 101, Variant{int32_t{8}});
  r->decline_single_lookups();
  r->answer_lookup_of(b, StatusCode{Status::UncertainNoCommunicationLastUsableValue});
  r->reset();

  const auto outcome = harness.read(values_of({a, b}));

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), 2U);
  EXPECT_EQ(status_of(outcome.response->results()[0]), Status::Good) << "A";
  const auto& refused = outcome.response->results()[1];
  ASSERT_TRUE(refused.status().has_value());
  EXPECT_EQ(refused.status()->as_status(), Status::BadInternalError) << to_string(*refused.status());
  ASSERT_NE(refused.status()->shared_detail(), nullptr);
  EXPECT_EQ(refused.status()->shared_detail()->code, "LookupAnswerUncertain");
  EXPECT_EQ(refused.status()->shared_detail()->innerStatus,
    StatusCode{Status::UncertainNoCommunicationLastUsableValue}.value());
}
