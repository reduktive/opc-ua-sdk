// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How HistoryRead and HistoryUpdate call the namespaces that own their Nodes: one batched lookup and one
// permissions call per namespace per request, the request's deadlines on the permissions call, and an entry
// whose Node is deleted answered with a bad status.

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <map>
#include <mutex>
#include <vector>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_history_data.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_service.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_history_update_result.h"
#include "ua_history_update_service.h"
#include "ua_node_accessor.h"
#include "ua_read_raw_modified_details.h"
#include "ua_server.h"
#include "ua_update_data_details.h"
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

// A history delegate that answers each raw read with one value, the one the test gave the item's Node, and
// accepts every update with the status the test gave the item's Node. It records the Nodes it is asked to
// update.
class AnsweringHistoryDelegate final : public NamespaceHistoryDelegate
{
public:
  void answer(const NodeId& nodeId, int32_t value, Status updateStatus = Status::Good)
  {
    const std::lock_guard lock{mMutex};
    mValues[nodeId] = value;
    mUpdateStatuses[nodeId] = updateStatus;
  }

  std::vector<NodeId> updated() const
  {
    const std::lock_guard lock{mMutex};
    return mUpdated;
  }

  void read_raw_async(const ReadContext& /*context*/, std::vector<ReadRawItem> items,
    ReadRawCallback callback) noexcept override
  {
    BatchResult<ReadRawItemResult> batch;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& item : items)
      {
        HistoryReadRawSuccess success;
        DataValue value;
        value.value() = mValues.contains(item.nodeId) ? mValues.at(item.nodeId) : int32_t{-1};
        value.source_timestamp() = DateTime::now();
        value.server_timestamp() = DateTime::now();
        success.values.push_back(std::move(value));
        batch.items.emplace_back(std::move(success));
      }
    }
    callback(std::move(batch));
  }

  void update_data_async(const UpdateContext& /*context*/, std::vector<UpdateDataItem> items,
    UpdateDataCallback callback) noexcept override
  {
    BatchResult<UpdateDataItemResult> batch;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& item : items)
      {
        mUpdated.push_back(item.nodeId);
        HistoryUpdateSuccess success;
        const auto status =
          mUpdateStatuses.contains(item.nodeId) ? mUpdateStatuses.at(item.nodeId) : Status::Good;
        for (std::size_t i = 0; i < item.values.size(); ++i)
        {
          success.operationResults.emplace_back(status);
        }
        batch.items.emplace_back(std::move(success));
      }
    }
    callback(std::move(batch));
  }

private:
  mutable std::mutex mMutex;
  std::map<NodeId, int32_t> mValues;
  std::map<NodeId, Status> mUpdateStatuses;
  std::vector<NodeId> mUpdated;
};

// A recording namespace whose lookup of one NodeId finds the Node and then deletes it from the namespace, so
// the Node handed back is a deleted one. Every lookup route of the default namespace (the single-Node form
// and the batched form) finds its Nodes through `resolve_here`, so this reaches whichever the address space
// asks.
class DeletingOnLookupNamespace final : public BatchRecordingNamespace
{
public:
  using BatchRecordingNamespace::BatchRecordingNamespace;

  void delete_on_next_lookup(const NodeId& nodeId)
  {
    const std::lock_guard lock{mArmMutex};
    mArmed = nodeId;
  }

  bool deleted_on_lookup() const
  {
    const std::lock_guard lock{mArmMutex};
    return mDeleted;
  }

protected:
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    auto found = BatchRecordingNamespace::resolve_here(nodeId);
    bool deleteIt = false;
    {
      const std::lock_guard lock{mArmMutex};
      if (found.is_good() && mArmed && *mArmed == nodeId)
      {
        mArmed.reset();
        deleteIt = true;
      }
    }
    if (deleteIt)
    {
      const auto removed = default_ns::Namespace::delete_node(nodeId, false);
      const std::lock_guard lock{mArmMutex};
      mDeleted = removed.is_good();
    }
    return found;
  }

private:
  mutable std::mutex mArmMutex;
  std::optional<NodeId> mArmed;
  bool mDeleted{false};
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

  NodeId create_variable(uint16_t namespaceIndex, uint32_t numericId, bool historyWrite)
  {
    const NodeId nodeId{namespaceIndex, numericId};
    auto created =
      sessionInfo->address_space().try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
    if (created.is_good())
    {
      AccessLevelType accessLevel;
      accessLevel.set(AccessLevelType::Bit::CurrentRead);
      accessLevel.set(AccessLevelType::Bit::HistoryRead);
      if (historyWrite)
      {
        accessLevel.set(AccessLevelType::Bit::HistoryWrite);
      }
      created.value().set_access_level(accessLevel);
    }
    return nodeId;
  }

  HistoryReadService::HistoryReadServiceResponse history_read(HistoryReadRequest request)
  {
    HistoryContinuationPoints continuationPoints;
    auto promise = std::make_shared<std::promise<HistoryReadService::HistoryReadServiceResponse>>();
    auto future = promise->get_future();
    auto service = HistoryReadService::create(sessionInfo,
      {},
      0,
      std::move(request),
      continuationPoints,
      threadPool.get_executor(),
      [promise](HistoryReadService::HistoryReadServiceResponse response)
      { promise->set_value(std::move(response)); });
    if (future.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "HistoryRead did not complete";
      return {};
    }
    return future.get();
  }

  Response history_update(HistoryUpdateRequest request)
  {
    auto promise = std::make_shared<std::promise<Response>>();
    auto future = promise->get_future();
    auto service = HistoryUpdateService::create(sessionInfo,
      0,
      std::move(request),
      threadPool.get_executor(),
      [promise](Response response) { promise->set_value(std::move(response)); });
    if (future.wait_for(3s) != std::future_status::ready)
    {
      ADD_FAILURE() << "HistoryUpdate did not complete";
      return {};
    }
    return future.get();
  }
};

HistoryReadRequest raw_read_of(const std::vector<NodeId>& nodeIds, uint32_t timeoutHint = 0)
{
  HistoryReadRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().timeout_hint() = timeoutHint;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  auto details = std::make_unique<ReadRawModifiedDetails>();
  details->start_time() = DateTime{DateTime::min()};
  details->end_time() = DateTime::now();
  details->num_values_per_node() = 100;
  details->return_bounds() = false;
  request.history_read_details() = std::move(details);
  request.nodes_to_read().resize(nodeIds.size());
  for (std::size_t i = 0; i < nodeIds.size(); ++i)
  {
    request.nodes_to_read()[i].node_id() = nodeIds[i];
  }
  return request;
}

HistoryUpdateRequest insert_into(const std::vector<NodeId>& nodeIds)
{
  HistoryUpdateRequest request;
  request.request_header().request_handle() = 1;
  request.history_update_details().resize(nodeIds.size());
  for (std::size_t i = 0; i < nodeIds.size(); ++i)
  {
    auto details = std::make_unique<UpdateDataDetails>();
    details->node_id() = nodeIds[i];
    details->perform_insert_replace() = PerformUpdateType::Insert;
    details->update_values().push_back(DataValue{Variant{int32_t{42}}, DateTime::now()});
    request.history_update_details()[i] = std::move(details);
  }
  return request;
}

HistoryReadResponse* read_response_of(const Response& response)
{
  return dynamic_cast<HistoryReadResponse*>(std::get<shared_ptr<Structure>>(response).get());
}

HistoryUpdateResponse* update_response_of(const Response& response)
{
  return dynamic_cast<HistoryUpdateResponse*>(std::get<shared_ptr<Structure>>(response).get());
}

// The NodeIds of @p all that belong to namespace @p index, in order.
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

// Two recording namespaces R1 and R2 that decline single-Node lookups and the immediate permission forms,
// each holding three Variables, the six interleaved R1, R2, R1, R2, ... in @p order. The delegate answers
// each with a value of its own.
struct TwoNamespaces
{
  shared_ptr<BatchRecordingNamespace> r1;
  shared_ptr<BatchRecordingNamespace> r2;
  shared_ptr<AnsweringHistoryDelegate> delegate = make_shared<AnsweringHistoryDelegate>();
  std::vector<NodeId> order;
  uint16_t index1{0};
  uint16_t index2{0};

  void setup(FlowHarness& harness, bool historyWrite)
  {
    r1 = make_shared<BatchRecordingNamespace>("urn:test:history-flow:r1", harness.threadPool.get_executor());
    r2 = make_shared<BatchRecordingNamespace>("urn:test:history-flow:r2", harness.threadPool.get_executor());
    r1->set_history_delegate(delegate);
    r2->set_history_delegate(delegate);
    const auto indexes = harness.setup({r1, r2});
    index1 = indexes.at(0);
    index2 = indexes.at(1);
    for (uint32_t i = 0; i < 3; ++i)
    {
      order.push_back(harness.create_variable(index1, 100 + i, historyWrite));
      order.push_back(harness.create_variable(index2, 200 + i, historyWrite));
    }
    for (std::size_t i = 0; i < order.size(); ++i)
    {
      delegate->answer(order[i],
        static_cast<int32_t>(1000 + i),
        order[i].namespace_index() == index1 ? Status::GoodEntryInserted : Status::GoodEntryReplaced);
    }
    for (const auto& nameSpace : {r1, r2})
    {
      nameSpace->decline_single_lookups();
      nameSpace->decline_immediate_permissions();
      nameSpace->reset();
    }
  }
};

void expect_one_lookup_and_one_permissions_call(
  const BatchRecordingNamespace& nameSpace, const std::vector<NodeId>& expected, const char* name)
{
  const auto lookups = nameSpace.calls(Member::BatchedLookup);
  EXPECT_EQ(lookups.size(), 1U) << name << ": batched lookups";
  if (lookups.size() == 1U)
  {
    EXPECT_EQ(lookups.front().nodeIds, expected) << name << ": the lookup names its three Variables";
  }
  const auto permissions = nameSpace.calls(Member::PermissionsAsyncForRequest);
  EXPECT_EQ(permissions.size(), 1U) << name << ": effective_permissions_async calls taking a RequestInfo";
  if (permissions.size() == 1U)
  {
    EXPECT_EQ(permissions.front().nodeIds, expected)
      << name << ": the permissions call names its three Variables";
  }
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-04-ONE-LOOKUP-AND-ONE-PERMISSIONS-CALL-PER-NAMESPACE-PER-HISTORY-READ, scope=function)
TEST(HistoryReadFlow, OneLookupAndOnePermissionCallPerNamespacePerRequest)
{
  FlowHarness harness;
  TwoNamespaces two;
  two.setup(harness, false);

  const auto result = harness.history_read(raw_read_of(two.order));

  expect_one_lookup_and_one_permissions_call(*two.r1, of_namespace(two.order, two.index1), "R1");
  expect_one_lookup_and_one_permissions_call(*two.r2, of_namespace(two.order, two.index2), "R2");

  auto* response = read_response_of(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), two.order.size());
  for (std::size_t i = 0; i < two.order.size(); ++i)
  {
    const auto& item = response->results()[i];
    EXPECT_EQ(item.status_code().as_status(), Status::Good) << "item " << i;
    const auto* data = dynamic_cast<const HistoryData*>(item.history_data().get());
    ASSERT_NE(data, nullptr) << "item " << i;
    ASSERT_EQ(data->data_values().size(), 1U) << "item " << i;
    EXPECT_EQ(data->data_values()[0].value().as<int32_t>(), static_cast<int32_t>(1000 + i)) << "item " << i;
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-04-THE-PERMISSIONS-CALL-CARRIES-THE-REQUESTS-DEADLINES, scope=function)
TEST(HistoryReadFlow, ThePermissionCallCarriesTheRequestsDeadlines)
{
  FlowHarness harness;
  auto r = make_shared<BatchRecordingNamespace>(
    "urn:test:history-flow:deadlines", harness.threadPool.get_executor());
  auto delegate = make_shared<AnsweringHistoryDelegate>();
  r->set_history_delegate(delegate);
  const auto index = harness.setup({r}).at(0);
  const NodeId a = harness.create_variable(index, 100, false);
  delegate->answer(a, 4711);
  r->decline_immediate_permissions();
  r->reset();

  const auto sent = std::chrono::steady_clock::now();
  const auto result = harness.history_read(raw_read_of({a}, 5000));

  const auto permissions = r->calls(Member::PermissionsAsyncForRequest);
  ASSERT_EQ(permissions.size(), 1U) << "effective_permissions_async calls taking a RequestInfo";
  const auto& call = permissions.front();
  EXPECT_EQ(call.nodeIds, std::vector<NodeId>{a});
  EXPECT_GE(call.deadline, sent + 4500ms);
  EXPECT_LE(call.deadline, sent + 5500ms);
  ASSERT_TRUE(call.answerBy.has_value()) << "a HistoryRead's RequestInfo carries a partial-results deadline";
  EXPECT_GE(*call.answerBy, sent + 3500ms);
  EXPECT_LE(*call.answerBy, sent + 4500ms);

  auto* response = read_response_of(result.response);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1U);
  EXPECT_EQ(response->results()[0].status_code().as_status(), Status::Good);
  const auto* data = dynamic_cast<const HistoryData*>(response->results()[0].history_data().get());
  ASSERT_NE(data, nullptr);
  ASSERT_EQ(data->data_values().size(), 1U);
  EXPECT_EQ(data->data_values()[0].value().as<int32_t>(), 4711);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-04-ONE-LOOKUP-AND-ONE-PERMISSIONS-CALL-PER-NAMESPACE-PER-HISTORY-UPDATE, scope=function)
TEST(HistoryUpdateFlow, OneLookupAndOnePermissionCallPerNamespacePerRequest)
{
  FlowHarness harness;
  TwoNamespaces two;
  two.setup(harness, true);

  const auto result = harness.history_update(insert_into(two.order));

  expect_one_lookup_and_one_permissions_call(*two.r1, of_namespace(two.order, two.index1), "R1");
  expect_one_lookup_and_one_permissions_call(*two.r2, of_namespace(two.order, two.index2), "R2");

  auto* response = update_response_of(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), two.order.size());
  for (std::size_t i = 0; i < two.order.size(); ++i)
  {
    const auto& item = response->results()[i];
    EXPECT_EQ(item.status_code().as_status(), Status::Good) << "item " << i;
    ASSERT_EQ(item.operation_results().size(), 1U) << "item " << i;
    const Status expected =
      two.order[i].namespace_index() == two.index1 ? Status::GoodEntryInserted : Status::GoodEntryReplaced;
    EXPECT_EQ(item.operation_results()[0].as_status(), expected) << "item " << i;
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-04-A-DELETED-NODE-IS-NOT-ANSWERED-GOOD, scope=function)
TEST(HistoryUpdateFlow, AnEntryWhoseNodeIsDeletedIsNotAnsweredGood)
{
  FlowHarness harness;
  auto n = make_shared<DeletingOnLookupNamespace>(
    "urn:test:history-flow:deleting", harness.threadPool.get_executor());
  auto delegate = make_shared<AnsweringHistoryDelegate>();
  n->set_history_delegate(delegate);
  const auto index = harness.setup({n}).at(0);
  const NodeId a = harness.create_variable(index, 100, true);
  n->delete_on_next_lookup(a);

  const auto result = harness.history_update(insert_into({a}));

  ASSERT_TRUE(n->deleted_on_lookup()) << "the lookup of A did not reach the namespace's lookup";
  auto* response = update_response_of(result);
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1U);
  EXPECT_EQ(response->results()[0].status_code().as_status(), Status::BadNodeIdUnknown);
  EXPECT_TRUE(delegate->updated().empty()) << "the delegate was asked to update A";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-24-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-OPERATION, scope=function)
TEST(HistoryReadFlow, AnUncertainLookupAnswerRefusesOnlyItsOperation)
{
  FlowHarness harness;
  TwoNamespaces two;
  two.setup(harness, false);
  const NodeId uncertain = two.order.at(1);
  two.r2->answer_lookup_of(uncertain, StatusCode{Status::UncertainNoCommunicationLastUsableValue});

  const auto result = harness.history_read(raw_read_of(two.order));

  auto* response = read_response_of(result.response);
  ASSERT_NE(response, nullptr) << "the request was faulted";
  ASSERT_EQ(response->results().size(), two.order.size());
  for (std::size_t i = 0; i < two.order.size(); ++i)
  {
    const auto& status = response->results()[i].status_code();
    if (i == 1)
    {
      EXPECT_EQ(status.as_status(), Status::BadInternalError) << to_string(status);
      ASSERT_NE(status.shared_detail(), nullptr);
      EXPECT_EQ(status.shared_detail()->code, "LookupAnswerUncertain");
      continue;
    }
    EXPECT_EQ(status.as_status(), Status::Good) << "item " << i << ": " << to_string(status);
  }
}

namespace
{

// A recording namespace whose lookups answer one NodeId with the Node it holds and an Uncertain code given by
// the test. Both lookup routes of the default namespace (the single-Node form and the batched form) find
// their Nodes through `resolve_here`, so this reaches whichever the address space asks.
class UncertainWithNodeNamespace final : public BatchRecordingNamespace
{
public:
  using BatchRecordingNamespace::BatchRecordingNamespace;

  void answer_uncertain_with_node(const NodeId& nodeId, StatusCode answer)
  {
    const std::lock_guard lock{mArmMutex};
    mArmed = nodeId;
    mAnswer = std::move(answer);
  }

  bool answered_with_node() const
  {
    const std::lock_guard lock{mArmMutex};
    return mAnswered;
  }

protected:
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    auto found = BatchRecordingNamespace::resolve_here(nodeId);
    std::optional<StatusCode> answer;
    {
      const std::lock_guard lock{mArmMutex};
      if (found.is_good() && found.value() && mArmed && *mArmed == nodeId)
      {
        answer = mAnswer;
        mAnswered = true;
      }
    }
    if (!answer)
    {
      return found;
    }
    return NodeResult{std::move(found).value(), std::move(*answer)};
  }

private:
  mutable std::mutex mArmMutex;
  std::optional<NodeId> mArmed;
  StatusCode mAnswer{Status::Good};
  bool mAnswered{false};
};

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-24-AN-UNCERTAIN-LOOKUP-ANSWER-REFUSES-ONLY-ITS-OPERATION, scope=function)
TEST(HistoryUpdateFlow, AnUncertainLookupAnswerRefusesOnlyItsOperation)
{
  FlowHarness harness;
  auto n = make_shared<UncertainWithNodeNamespace>(
    "urn:test:history-flow:uncertain-update", harness.threadPool.get_executor());
  auto delegate = make_shared<AnsweringHistoryDelegate>();
  n->set_history_delegate(delegate);
  const auto index = harness.setup({n}).at(0);
  const NodeId good = harness.create_variable(index, 100, true);
  const NodeId withoutNode = harness.create_variable(index, 101, true);
  const NodeId withNode = harness.create_variable(index, 102, true);
  delegate->answer(good, 0, Status::GoodEntryInserted);
  const StatusCode answeredWithoutNode{Status::UncertainNoCommunicationLastUsableValue};
  const StatusCode answeredWithNode{Status::UncertainLastUsableValue};
  n->decline_single_lookups();
  n->answer_lookup_of(withoutNode, answeredWithoutNode);
  n->answer_uncertain_with_node(withNode, answeredWithNode);
  n->reset();

  const auto result = harness.history_update(insert_into({good, withoutNode, withNode}));

  ASSERT_TRUE(n->answered_with_node()) << "the lookup of the third Variable did not reach the namespace";
  auto* response = update_response_of(result);
  ASSERT_NE(response, nullptr) << "the request was faulted";
  EXPECT_EQ(response->response_header().service_result().as_status(), Status::Good)
    << to_string(response->response_header().service_result());
  ASSERT_EQ(response->results().size(), 3U);

  const auto& control = response->results()[0];
  EXPECT_EQ(control.status_code().as_status(), Status::Good) << to_string(control.status_code());
  ASSERT_EQ(control.operation_results().size(), 1U);
  EXPECT_EQ(control.operation_results()[0].as_status(), Status::GoodEntryInserted);

  const auto expectRefused = [&](std::size_t i, const StatusCode& answered, const char* name)
  {
    const auto& status = response->results()[i].status_code();
    EXPECT_EQ(status.as_status(), Status::BadInternalError) << name << ": " << to_string(status);
    const auto detail = status.shared_detail();
    ASSERT_NE(detail, nullptr) << name << ": the refusal names no ErrorDetail";
    EXPECT_EQ(detail->code, "LookupAnswerUncertain") << name;
    EXPECT_EQ(detail->innerStatus, answered.value())
      << name << ": the ErrorDetail's inner status is not the lookup's Uncertain answer";
  };
  expectRefused(1, answeredWithoutNode, "Uncertain without the Node");
  expectRefused(2, answeredWithNode, "Uncertain with the Node");

  EXPECT_EQ(delegate->updated(), std::vector<NodeId>{good})
    << "the delegate was not asked to update exactly the Variable whose lookup was answered Good";
}
