// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The route of an accessor's operations through the address space to the owning namespace's batched
/// members (COMP-ADDRSP-ACCESSOR-ROUTE-01, -02 and -05).
///
/// The recording namespaces hold an in-memory namespace, forward the members to it, and record each call of a
/// batched member before answering through the in-memory namespace, which works on the Nodes it holds.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "test_utilities.h"
#include "ua_access_level_ex_type.h"
#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_default_base_node.h"
#include "ua_default_namespace.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_namespace.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_role_permission_type.h"
#include "ua_status.h"
#include "ua_structure_definition.h"
#include "ua_structure_type.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"
#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// One call of a batched member, as the namespace received it: the member, the namespace, the caller, the
/// number of items, and the facts of the first item that the criteria name.
struct MemberCall
{
  std::string member;
  std::string space;
  const CallerInfo* caller{nullptr};
  std::size_t items{0};
  const Node* node{nullptr};
  NodeId nodeId;
  AttributeId attribute{AttributeId::Value};
  Variant value;
  NodeId referenceType;
  ExpandedNodeId target;
  bool isForward{false};
  NodeId view;
  std::vector<NodeId> nodes;
  const Node* object{nullptr};
  const Node* method{nullptr};
  NodeId objectId;
  NodeId methodId;
};

/// The calls of every recording namespace of a test, in the order they arrived.
class MemberLog
{
public:
  void record(MemberCall call)
  {
    const std::lock_guard lock(mMutex);
    mCalls.push_back(std::move(call));
  }

  std::vector<MemberCall> calls_of(const std::string& member) const
  {
    const std::lock_guard lock(mMutex);
    std::vector<MemberCall> found;
    for (const auto& call : mCalls)
    {
      if (call.member == member)
      {
        found.push_back(call);
      }
    }
    return found;
  }

  void clear()
  {
    const std::lock_guard lock(mMutex);
    mCalls.clear();
  }

private:
  mutable std::mutex mMutex;
  std::vector<MemberCall> mCalls;
};

/// Holds an in-memory namespace, forwards the members to it, and records each call of a batched member
/// before answering through the in-memory namespace. `call_async` answers as the test chooses.
class RecordingNamespace final : public Namespace
{
public:
  using Namespace::find_node;

  enum class CallAnswer
  {
    ByDefault,
    OutputFive,
    Decline,
  };

  RecordingNamespace(std::string name, std::shared_ptr<default_ns::Namespace> inner,
    std::shared_ptr<MemberLog> log, CallAnswer callAnswer)
    : mName(std::move(name)), mInner(std::move(inner)), mLog(std::move(log)), mCallAnswer(callAnswer)
  {}

  String uri() const override
  {
    return mInner->uri();
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    mInner->find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    return mInner->find_node(nodeId, maxAge);
  }

  void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> callback) override
  {
    mInner->enumerate_nodes_async(request, std::move(callback));
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mInner->create_nodes_async(request, nodes, std::move(complete));
  }

  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override
  {
    mInner->delete_nodes_async(request, nodes, halves, std::move(complete));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    auto call = begin("read_references_async", nullptr, queries.size());
    if (!queries.empty())
    {
      call.node = &queries[0].node;
      call.nodeId = queries[0].nodeId;
    }
    mLog->record(std::move(call));
    mInner->read_references_async(request, queries, std::move(complete));
  }

  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mLog->record(change_call("add_references_async", changes));
    mInner->add_references_async(request, changes, std::move(complete));
  }

  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mLog->record(change_call("remove_references_async", changes));
    mInner->remove_references_async(request, changes, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    auto call = begin("read_values_async", caller, items.size());
    if (!items.empty())
    {
      call.node = &items[0].node;
      call.nodeId = items[0].value.node_id();
    }
    mLog->record(std::move(call));
    mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    auto call = begin("write_async", caller, items.size());
    if (!items.empty())
    {
      call.node = &items[0].node;
      call.nodeId = items[0].value.node_id();
      call.attribute = static_cast<AttributeId>(items[0].value.attribute_id());
      call.value = items[0].value.value().value();
    }
    mLog->record(std::move(call));
    mInner->write_async(request, caller, items, std::move(complete));
  }

  void view_contains_async(const RequestInfo& request, const NodeId& view,
    std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete) override
  {
    auto call = begin("view_contains_async", nullptr, nodes.size());
    call.view = view;
    for (const auto& node : nodes)
    {
      call.nodes.push_back(node.node_id());
    }
    mLog->record(std::move(call));
    mInner->view_contains_async(request, view, nodes, std::move(complete));
  }

  void add_to_view_async(const RequestInfo& request, const NodeId& view, std::span<const NodeId> nodes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    auto call = begin("add_to_view_async", nullptr, nodes.size());
    call.view = view;
    call.nodes.assign(nodes.begin(), nodes.end());
    mLog->record(std::move(call));
    mInner->add_to_view_async(request, view, nodes, std::move(complete));
  }

  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override
  {
    auto call = begin("call_async", caller, items.size());
    if (!items.empty())
    {
      call.object = &items[0].object;
      call.method = &items[0].method;
      call.objectId = items[0].request.object_id();
      call.methodId = items[0].request.method_id();
    }
    mLog->record(std::move(call));
    switch (mCallAnswer)
    {
    case CallAnswer::ByDefault:
      mInner->call_async(request, caller, items, std::move(complete));
      return;
    case CallAnswer::OutputFive:
    {
      BatchResult<std::optional<CallResult>> answer;
      for (std::size_t index = 0; index < items.size(); ++index)
      {
        CallMethodResult result;
        result.output_arguments().payload().push_back(Variant{uint32_t{5}});
        answer.items.emplace_back(CallResult{std::move(result)});
      }
      complete(std::move(answer));
      return;
    }
    case CallAnswer::Decline:
    {
      BatchResult<std::optional<CallResult>> answer;
      for (std::size_t index = 0; index < items.size(); ++index)
      {
        answer.items.emplace_back(std::nullopt);
      }
      complete(std::move(answer));
      return;
    }
    }
  }

private:
  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mInner->attach(context);
  }

  MemberCall begin(const char* member, const CallerInfo* caller, std::size_t items) const
  {
    MemberCall call;
    call.member = member;
    call.space = mName;
    call.caller = caller;
    call.items = items;
    return call;
  }

  MemberCall change_call(const char* member, std::span<const ReferenceChange> changes) const
  {
    auto call = begin(member, nullptr, changes.size());
    if (!changes.empty())
    {
      call.nodeId = changes[0].source;
      call.referenceType = changes[0].referenceType;
      call.target = changes[0].target;
      call.isForward = changes[0].isForward;
    }
    return call;
  }

  std::string mName;
  std::shared_ptr<default_ns::Namespace> mInner;
  std::shared_ptr<MemberLog> mLog;
  CallAnswer mCallAnswer;
};

struct Registered
{
  std::shared_ptr<RecordingNamespace> space;
  uint16_t index{0};
};

struct RouteFixture
{
  RouteFixture()
  {
    addressSpace.emplace(AddressSpace::create("urn:test:node-accessor-route", pool.get_executor()));
  }

  ~RouteFixture()
  {
    addressSpace.reset();
    ::ua::test_utils::drain_with_timeout(pool);
  }

  RouteFixture(const RouteFixture&) = delete;
  RouteFixture& operator=(const RouteFixture&) = delete;

  /// Registers a recording namespace named @p name in the address space.
  Registered add(const std::string& name, const std::string& uri,
    RecordingNamespace::CallAnswer callAnswer = RecordingNamespace::CallAnswer::ByDefault)
  {
    auto space = std::make_shared<RecordingNamespace>(
      name, default_ns::Namespace::create(uri, pool.get_executor()), log, callAnswer);
    const auto index = addressSpace->add_namespace_sync(space);
    return Registered{std::move(space), index};
  }

  /// Creates a Node through the address space, then looks it up there; nullopt when either fails.
  std::optional<NodeAccessor> create(const NodeId& nodeId, NodeClass nodeClass)
  {
    if (addressSpace->try_create_node_sync(nodeId, nodeClass, {}).is_bad())
    {
      return std::nullopt;
    }
    auto looked = addressSpace->try_find_node_sync(nodeId);
    if (looked.is_bad())
    {
      return std::nullopt;
    }
    return looked.value();
  }

  boost::asio::thread_pool pool{2};
  std::shared_ptr<MemberLog> log = std::make_shared<MemberLog>();
  std::optional<AddressSpace> addressSpace;
};

/// Starts an operation with a completion and waits up to 5 s for its first answer.
template<typename T, typename Start>
std::optional<T> await_answer(Start&& start)
{
  auto promise = std::make_shared<std::promise<T>>();
  auto answered = std::make_shared<std::atomic<bool>>(false);
  auto future = promise->get_future();
  start(std::function<void(T)>{[promise, answered](T answer)
    {
      if (!answered->exchange(true))
      {
        promise->set_value(std::move(answer));
      }
    }});
  if (future.wait_for(5s) != std::future_status::ready)
  {
    return std::nullopt;
  }
  return future.get();
}

/// The status of an answer, or Bad_Timeout when none came.
template<typename T>
Status status_of(const std::optional<T>& answer)
{
  return answer.has_value() ? answer->status_code().as_status() : Status::BadTimeout;
}

/// The status an answer carries, as text, for a failure message.
template<typename T>
std::string text_of(const std::optional<T>& answer)
{
  std::ostringstream text;
  if (answer.has_value())
  {
    text << to_string(answer->status_code());
  }
  else
  {
    text << "no answer within 5 s";
  }
  return text.str();
}

/// Waits up to 5 s for every handle of the address space to be released.
bool wait_until_gone(const WeakAddressSpace& weak)
{
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (!weak.lock().has_value())
    {
      return true;
    }
    std::this_thread::sleep_for(1ms);
  }
  return false;
}

ReadValueId value_of(const NodeId& nodeId)
{
  ReadValueId read;
  read.node_id() = nodeId;
  read.attribute_id() = utils::to_underlying(AttributeId::Value);
  return read;
}

CallMethodRequest call_of(const NodeId& objectId, const NodeId& methodId)
{
  CallMethodRequest request;
  request.object_id() = objectId;
  request.method_id() = methodId;
  return request;
}

/// The first output argument of a call's answer as a UInt32, or nullopt.
std::optional<uint32_t> first_output(const std::optional<CallResult>& called)
{
  if (!called.has_value() || called->is_bad() || called->value().output_arguments().payload().empty())
  {
    return std::nullopt;
  }
  const auto& output = called->value().output_arguments().payload()[0];
  if (!output.is_uint32())
  {
    return std::nullopt;
  }
  return output.as<uint32_t>();
}

/// Installs on the Method @p method a call handler that answers the UInt32 9 and counts its runs.
bool install_nine(const NodeAccessor& method, const std::shared_ptr<std::atomic<int>>& ran)
{
  auto* source = method->method_call_source();
  if (source == nullptr)
  {
    return false;
  }
  return source
    ->set_call_handler(
      [ran](const CallMethodRequest&,
        shared_ptr<const MethodCallContext>,
        std::function<void(CallResult)>
          callback)
      {
        ran->fetch_add(1);
        CallMethodResult result;
        result.output_arguments().payload().push_back(Variant{uint32_t{9}});
        callback(CallResult{std::move(result)});
      })
    .is_good();
}

const NodeId hasComponent{ReferenceTypeId::HasComponent};

}  // namespace

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-01-EACH-OPERATION-REACHES-ITS-BATCHED-MEMBER, scope=function)
TEST(NodeAccessorRoute, EachOperationReachesItsBatchedMember)
{
  // A type the address space does not pair, so that the add makes one call; the removal names this half only,
  // since a removal of both halves also removes the target's (DL-124 (3)), so that it makes one call too.
  const NodeId hasDictionaryEntry{ReferenceTypeId::HasDictionaryEntry};
  RouteFixture fixture;
  const auto r = fixture.add("R", "urn:test:accessor-route-r");
  ASSERT_NE(r.index, 0);
  const NodeId vId{r.index, "V"};
  const NodeId oId{r.index, "O"};
  const NodeId wId{r.index, "W"};
  const auto vNode = fixture.create(vId, NodeClass::Variable);
  const auto oNode = fixture.create(oId, NodeClass::Object);
  const auto wNode = fixture.create(wId, NodeClass::View);
  ASSERT_TRUE(vNode && oNode && wNode) << "V, O and W could not be created and looked up";
  auto v = vNode->as<VariableAccessor>();
  auto w = wNode->as<ViewAccessor>();
  ASSERT_TRUE(v.has_value());
  ASSERT_TRUE(w.has_value());
  const Node* vHeld = &**v;
  fixture.log->clear();

  const auto references =
    await_answer<ReferencesResult>([&](auto done) { v->get_references_async(std::move(done)); });
  const auto added = await_answer<VoidResult>(
    [&](auto done)
    {
      v->add_reference_async(
        hasDictionaryEntry, ExpandedNodeId{oId}, true, ReferenceHalves::Both, std::move(done));
    });
  const auto removed = await_answer<VoidResult>(
    [&](auto done)
    {
      v->remove_reference_async(
        hasDictionaryEntry, ExpandedNodeId{oId}, true, ReferenceHalves::ThisHalfOnly, std::move(done));
    });
  // The write comes before the read, so that the read answering 5 shows the write took effect.
  const auto written = await_answer<VoidResult>(
    [&](auto done) { v->write_value_async(DataValue{Variant{int32_t{5}}}, std::move(done)); });
  const auto read = await_answer<DataValueResult>(
    [&](auto done) { v->read_value_async(Duration{0}, true, value_of(vId), nullptr, std::move(done)); });
  EXPECT_NO_THROW(v->set_display_name(LocalizedText{LocaleId{"en"}, String{"V2"}}));
  const auto addedToView =
    await_answer<VoidResult>([&](auto done) { w->add_node_to_view_async(oId, std::move(done)); });
  const auto inView =
    await_answer<BoolResult>([&](auto done) { w->is_node_in_view_async(oId, std::move(done)); });

  EXPECT_EQ(status_of(references), Status::Good) << "answered " << text_of(references) << ' ';
  EXPECT_EQ(status_of(added), Status::Good) << "answered " << text_of(added) << ' ';
  EXPECT_EQ(status_of(removed), Status::Good) << "answered " << text_of(removed) << ' ';
  EXPECT_EQ(status_of(written), Status::Good) << "answered " << text_of(written) << ' ';
  EXPECT_EQ(status_of(read), Status::Good) << "answered " << text_of(read) << ' ';
  EXPECT_EQ(status_of(addedToView), Status::Good) << "answered " << text_of(addedToView) << ' ';
  EXPECT_EQ(status_of(inView), Status::Good) << "answered " << text_of(inView) << ' ';
  if (read.has_value() && read->is_good())
  {
    ASSERT_TRUE(read->value().value().is_int32()) << to_string(read->value().value());
    EXPECT_EQ(read->value().value().as<int32_t>(), 5);
  }
  if (inView.has_value() && inView->is_good())
  {
    EXPECT_TRUE(inView->value()) << "O is not in W after it was added";
  }
  const auto displayName = v->read_attribute(AttributeId::DisplayName);
  const auto* text = displayName.try_as<LocalizedText>();
  ASSERT_NE(text, nullptr) << "V's DisplayName is not a LocalizedText";
  EXPECT_EQ(text->locale(), LocaleId{"en"});
  EXPECT_EQ(text->text(), String{"V2"});

  const auto one = [&](const char* member) -> std::optional<MemberCall>
  {
    const auto calls = fixture.log->calls_of(member);
    EXPECT_EQ(calls.size(), 1u) << "R's " << member << " was called " << calls.size() << " times";
    if (calls.size() != 1u)
    {
      return std::nullopt;
    }
    EXPECT_EQ(calls[0].items, 1u) << member;
    return calls[0];
  };

  if (const auto call = one("read_references_async"))
  {
    EXPECT_EQ(call->node, vHeld) << "the query does not carry V's Node";
    EXPECT_EQ(call->nodeId, vId);
  }
  for (const char* member : {"add_references_async", "remove_references_async"})
  {
    if (const auto call = one(member))
    {
      EXPECT_EQ(call->nodeId, vId) << member << ": the source is not V";
      EXPECT_EQ(call->referenceType, hasDictionaryEntry) << member;
      EXPECT_EQ(call->target, ExpandedNodeId{oId}) << member;
      EXPECT_TRUE(call->isForward) << member;
    }
  }
  if (const auto call = one("read_values_async"))
  {
    EXPECT_EQ(call->node, vHeld) << "the item does not carry V's Node";
    EXPECT_EQ(call->nodeId, vId);
  }

  const auto writes = fixture.log->calls_of("write_async");
  EXPECT_EQ(writes.size(), 2u) << "R's write_async was called " << writes.size() << " times";
  bool valueWrite = false;
  bool displayNameWrite = false;
  for (const auto& call : writes)
  {
    EXPECT_EQ(call.items, 1u);
    EXPECT_EQ(call.node, vHeld) << "a write item does not carry V's Node";
    EXPECT_EQ(call.nodeId, vId);
    if (call.attribute == AttributeId::Value && call.value.is_int32() && call.value.as<int32_t>() == 5)
    {
      valueWrite = true;
    }
    const auto* written = call.value.try_as<LocalizedText>();
    if (call.attribute == AttributeId::DisplayName && written != nullptr &&
        written->locale() == LocaleId{"en"} && written->text() == String{"V2"})
    {
      displayNameWrite = true;
    }
  }
  EXPECT_TRUE(valueWrite) << "no write_async item wrote V's Value with the Int32 5";
  EXPECT_TRUE(displayNameWrite) << "no write_async item wrote V's DisplayName with \"en\" \"V2\"";

  for (const char* member : {"add_to_view_async", "view_contains_async"})
  {
    if (const auto call = one(member))
    {
      EXPECT_EQ(call->view, wId) << member;
      EXPECT_EQ(call->nodes, std::vector<NodeId>{oId}) << member;
    }
  }
}

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-01-A-VALUE-READ-WITHOUT-A-NODEID-NAMES-THE-ACCESSORS-NODE, scope=function)
TEST(NodeAccessorRoute, AValueReadWithoutANodeIdNamesTheAccessorsNode)
{
  RouteFixture fixture;
  const auto r = fixture.add("R", "urn:test:accessor-route-r");
  ASSERT_NE(r.index, 0);
  const NodeId vId{r.index, "V"};
  const auto vNode = fixture.create(vId, NodeClass::Variable);
  ASSERT_TRUE(vNode) << "V could not be created and looked up";
  auto v = vNode->as<VariableAccessor>();
  ASSERT_TRUE(v.has_value());
  const auto written = await_answer<VoidResult>(
    [&](auto done) { v->write_value_async(DataValue{Variant{int32_t{5}}}, std::move(done)); });
  ASSERT_EQ(status_of(written), Status::Good) << "answered " << text_of(written);
  fixture.log->clear();

  ReadValueId withoutNodeId;
  withoutNodeId.attribute_id() = utils::to_underlying(AttributeId::Value);
  const auto read = await_answer<DataValueResult>(
    [&](auto done) { v->read_value_async(Duration{0}, true, withoutNodeId, nullptr, std::move(done)); });

  const auto calls = fixture.log->calls_of("read_values_async");
  ASSERT_EQ(calls.size(), 1u) << "R's read_values_async was called " << calls.size() << " times";
  EXPECT_EQ(calls[0].items, 1u);
  EXPECT_EQ(calls[0].nodeId, vId) << "the item's ReadValueId does not name V";
  ASSERT_EQ(status_of(read), Status::Good) << "answered " << text_of(read);
  ASSERT_TRUE(read->value().value().is_int32()) << to_string(read->value().value());
  EXPECT_EQ(read->value().value().as<int32_t>(), 5);
}

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-01-AN-OPERATION-AFTER-THE-ADDRESS-SPACE-IS-GONE-ANSWERS-BAD-SHUTDOWN, scope=function)
TEST(NodeAccessorRoute, AnOperationAfterTheAddressSpaceIsGoneAnswersBadShutdown)
{
  boost::asio::thread_pool pool{2};
  std::optional<AddressSpace> addressSpace;
  addressSpace.emplace(AddressSpace::create("urn:test:node-accessor-route-gone", pool.get_executor()));
  const NodeId vId{1, "accessor-route-gone:V"};
  auto created = addressSpace->try_create_sync<VariableAccessor>(vId, NodeClass::Variable);
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  VariableAccessor v = created.value();
  ASSERT_TRUE(v.try_write_value_sync(DataValue{Variant{int32_t{1}}}).is_good());

  const WeakAddressSpace weak = addressSpace->weak();
  addressSpace.reset();
  ASSERT_TRUE(wait_until_gone(weak))
    << "an AddressSpace handle outlived the release: the address space is not gone";

  const NodeId objectsFolder{ObjectId::ObjectsFolder};
  const auto written = await_answer<VoidResult>(
    [&](auto done) { v.write_value_async(DataValue{Variant{int32_t{2}}}, std::move(done)); });
  const auto read = await_answer<DataValueResult>(
    [&](auto done) { v.read_value_async(Duration{0}, true, value_of(vId), nullptr, std::move(done)); });
  const auto references =
    await_answer<ReferencesResult>([&](auto done) { v.get_references_async(std::move(done)); });
  const auto added = await_answer<VoidResult>(
    [&](auto done)
    {
      v.add_reference_async(
        hasComponent, ExpandedNodeId{objectsFolder}, true, ReferenceHalves::Both, std::move(done));
    });

  EXPECT_EQ(status_of(written), Status::BadShutdown)
    << "answered " << text_of(written) << ' ' << " write_value_async ";
  EXPECT_EQ(status_of(read), Status::BadShutdown)
    << "answered " << text_of(read) << ' ' << " read_value_async ";
  EXPECT_EQ(status_of(references), Status::BadShutdown)
    << "answered " << text_of(references) << ' ' << " get_references_async ";
  EXPECT_EQ(status_of(added), Status::BadShutdown)
    << "answered " << text_of(added) << ' ' << " add_reference_async ";

  // The Node itself, read directly, holds no Reference to i=85.
  auto* const base = dynamic_cast<default_ns::BaseNode*>(v.operator->());
  ASSERT_NE(base, nullptr);
  const auto held =
    await_answer<ReferencesResult>([&](auto done) { base->get_references_async(std::move(done)); });
  ASSERT_EQ(status_of(held), Status::Good) << "V's Node does not answer its References";
  for (const auto& reference : held->value())
  {
    EXPECT_FALSE(reference.target_id().node_id() == objectsFolder) << "V's Node holds a Reference to i=85";
  }
  EXPECT_EQ(v.get_node_id(), vId);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-02-A-METHOD-CALL-IS-OFFERED-TO-THE-OBJECTS-NAMESPACE-FIRST, scope=function)
TEST(NodeAccessorRoute, AMethodCallIsOfferedToTheObjectsNamespaceFirst)
{
  RouteFixture fixture;
  const auto p = fixture.add("P", "urn:test:accessor-route-p", RecordingNamespace::CallAnswer::OutputFive);
  const NodeId oId{p.index, "O"};
  const NodeId mId{1, "accessor-route-call:M"};
  const auto object = fixture.create(oId, NodeClass::Object);
  const auto methodNode = fixture.create(mId, NodeClass::Method);
  ASSERT_TRUE(object && methodNode);
  auto ran = std::make_shared<std::atomic<int>>(0);
  ASSERT_TRUE(install_nine(*methodNode, ran));
  auto method = methodNode->as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  fixture.log->clear();

  const auto called = await_answer<CallResult>(
    [&](auto done) { method->call_async(call_of(oId, mId), nullptr, std::move(done)); });

  const auto calls = fixture.log->calls_of("call_async");
  ASSERT_EQ(calls.size(), 1u) << "P's call_async was called " << calls.size() << " times";
  EXPECT_EQ(calls[0].space, "P");
  EXPECT_EQ(calls[0].items, 1u);
  EXPECT_EQ(calls[0].objectId, oId);
  EXPECT_EQ(calls[0].methodId, mId);
  EXPECT_EQ(calls[0].object, &**object) << "the item's object is not O's Node";
  EXPECT_EQ(calls[0].method, &**methodNode) << "the item's method is not M's Node";
  EXPECT_EQ(status_of(called), Status::Good) << "answered " << text_of(called) << ' ';
  EXPECT_EQ(first_output(called), std::optional<uint32_t>{5u});
  EXPECT_EQ(ran->load(), 0) << "M's handler ran";
}

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-02-A-CALL-DECLINED-BY-THE-OBJECTS-NAMESPACE-RUNS-IN-THE-METHODS, scope=function)
TEST(NodeAccessorRoute, ACallDeclinedByTheObjectsNamespaceRunsInTheMethodsNamespace)
{
  RouteFixture fixture;
  const auto p = fixture.add("P", "urn:test:accessor-route-p", RecordingNamespace::CallAnswer::Decline);
  const NodeId oId{p.index, "O"};
  const NodeId mId{1, "accessor-route-call:M"};
  const auto object = fixture.create(oId, NodeClass::Object);
  const auto methodNode = fixture.create(mId, NodeClass::Method);
  ASSERT_TRUE(object && methodNode);
  auto ran = std::make_shared<std::atomic<int>>(0);
  ASSERT_TRUE(install_nine(*methodNode, ran));
  auto method = methodNode->as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  fixture.log->clear();

  const auto called = await_answer<CallResult>(
    [&](auto done) { method->call_async(call_of(oId, mId), nullptr, std::move(done)); });

  const auto calls = fixture.log->calls_of("call_async");
  ASSERT_EQ(calls.size(), 1u) << "P's call_async was called " << calls.size() << " times";
  EXPECT_EQ(calls[0].space, "P");
  EXPECT_EQ(calls[0].items, 1u);
  EXPECT_EQ(calls[0].objectId, oId);
  EXPECT_EQ(calls[0].methodId, mId);
  EXPECT_EQ(ran->load(), 1) << "M's handler did not run once";
  EXPECT_EQ(status_of(called), Status::Good) << "answered " << text_of(called) << ' ';
  EXPECT_EQ(first_output(called), std::optional<uint32_t>{9u});
}

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-02-A-CALL-DECLINED-BY-BOTH-ANSWERS-BAD-NOT-IMPLEMENTED, scope=function)
TEST(NodeAccessorRoute, ACallDeclinedByBothNamespacesAnswersBadNotImplemented)
{
  RouteFixture fixture;
  const auto p = fixture.add("P", "urn:test:accessor-route-p", RecordingNamespace::CallAnswer::Decline);
  const auto q = fixture.add("Q", "urn:test:accessor-route-q", RecordingNamespace::CallAnswer::Decline);
  const NodeId oId{p.index, "O"};
  const NodeId mId{q.index, "M"};
  const auto object = fixture.create(oId, NodeClass::Object);
  const auto methodNode = fixture.create(mId, NodeClass::Method);
  ASSERT_TRUE(object && methodNode);
  auto method = methodNode->as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  fixture.log->clear();

  const auto called = await_answer<CallResult>(
    [&](auto done) { method->call_async(call_of(oId, mId), nullptr, std::move(done)); });

  const auto calls = fixture.log->calls_of("call_async");
  ASSERT_EQ(calls.size(), 2u) << "P's and Q's call_async were called " << calls.size() << " times in all";
  EXPECT_EQ(calls[0].space, "P") << "the Object's namespace was not asked first";
  EXPECT_EQ(calls[1].space, "Q");
  for (const auto& call : calls)
  {
    EXPECT_EQ(call.items, 1u) << call.space;
    EXPECT_EQ(call.objectId, oId) << call.space;
    EXPECT_EQ(call.methodId, mId) << call.space;
  }
  EXPECT_EQ(status_of(called), Status::BadNotImplemented) << "answered " << text_of(called) << ' ';
}

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-05-SETTERS-KEEP-THEIR-VALUES-THROUGH-THE-ROUTE, scope=function)
TEST(NodeAccessorRoute, SettersKeepTheirValuesThroughTheRoute)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:node-accessor-route-setters", pool.get_executor());
    auto v = addressSpace.try_create_sync<VariableAccessor>(
      NodeId{1, "accessor-route-setters:V"}, NodeClass::Variable);
    auto o =
      addressSpace.try_create_sync<ObjectAccessor>(NodeId{1, "accessor-route-setters:O"}, NodeClass::Object);
    auto t = addressSpace.try_create_sync<VariableTypeAccessor>(
      NodeId{1, "accessor-route-setters:T"}, NodeClass::VariableType);
    auto d = addressSpace.try_create_sync<DataTypeAccessor>(
      NodeId{1, "accessor-route-setters:D"}, NodeClass::DataType);
    ASSERT_TRUE(v.is_good() && o.is_good() && t.is_good() && d.is_good());

    EXPECT_NO_THROW(v.value().set_minimum_sampling_interval(Duration{100}));
    EXPECT_EQ(v.value().get_minimum_sampling_interval(), std::optional<Duration>{100});
    EXPECT_NO_THROW(v.value().set_minimum_sampling_interval(std::nullopt));
    EXPECT_NO_THROW(v.value().set_access_level_ex(AccessLevelExType{AccessLevelExType::Bit::NonatomicRead}));
    EXPECT_TRUE(v.value().get_access_level_ex().has_value());
    EXPECT_NO_THROW(v.value().set_access_level_ex(std::nullopt));
    EXPECT_NO_THROW(
      o.value().set_access_restrictions(AccessRestrictionType{AccessRestrictionType::Bit::SigningRequired}));
    EXPECT_TRUE(o.value().get_access_restrictions().has_value());
    EXPECT_NO_THROW(o.value().set_access_restrictions(std::nullopt));
    auto definition = std::make_shared<StructureDefinition>();
    definition->structure_type() = StructureType::Structure;
    definition->base_data_type() = NodeId{DataTypeId::Structure};
    EXPECT_NO_THROW(d.value().set_data_type_definition(definition));
    EXPECT_NE(d.value().get_data_type_definition(), nullptr);
    EXPECT_NO_THROW(d.value().set_data_type_definition(nullptr));

    RolePermissionType entry;
    entry.role_id() = NodeId{ObjectId::WellKnownRole_AuthenticatedUser};
    entry.permissions() = PermissionType{PermissionType::Bit::Browse};
    EXPECT_NO_THROW(o.value().set_role_permissions(std::vector<RolePermissionType>{entry}));

    const DateTime sourceTimestamp = DateTime::now();
    EXPECT_NO_THROW(t.value().set_value(Variant{int32_t{7}}, sourceTimestamp));

    EXPECT_FALSE(v.value().get_minimum_sampling_interval().has_value())
      << "MinimumSamplingInterval was not cleared";
    EXPECT_FALSE(v.value().get_access_level_ex().has_value()) << "AccessLevelEx was not cleared";
    EXPECT_FALSE(o.value().get_access_restrictions().has_value()) << "AccessRestrictions were not cleared";
    EXPECT_EQ(d.value().get_data_type_definition(), nullptr) << "DataTypeDefinition was not cleared";
    const auto permissions = o.value().get_role_permissions();
    ASSERT_TRUE(permissions.has_value()) << "O has no RolePermissions";
    ASSERT_EQ(permissions->size(), 1u);
    EXPECT_EQ((*permissions)[0].role_id(), entry.role_id());
    EXPECT_TRUE((*permissions)[0].permissions() == entry.permissions());
    const auto typeValue = t.value().get_value();
    ASSERT_TRUE(typeValue.has_value()) << "T has no Value";
    ASSERT_TRUE(typeValue->value().is_int32()) << to_string(typeValue->value());
    EXPECT_EQ(typeValue->value().as<int32_t>(), 7);
    ASSERT_TRUE(typeValue->source_timestamp().has_value()) << "T's Value has no SourceTimestamp";
    EXPECT_TRUE(*typeValue->source_timestamp() == sourceTimestamp) << "T's Value has another SourceTimestamp";
  }
  ::ua::test_utils::drain_with_timeout(pool);
}
