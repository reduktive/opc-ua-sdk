// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_history_namespace.h"
#include "ua_error_detail.h"
#include "ua_namespace_service_delegates.h"
#include "ua_node.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_server_authentication.h"
#include "ua_to_string.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_request_info.h"

#include <array>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <utility>
#include <vector>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string_view>

using namespace ua;
using namespace ua::history;
using namespace ua::server;

namespace
{

class RecordingNamespace final : public default_ns::Namespace
{
public:
  explicit RecordingNamespace(boost::asio::any_io_executor executor)
    : default_ns::Namespace{"urn:test:history-wrapper", std::move(executor)}
  {}

  std::optional<PermissionType> effective_permissions(const AccessIdentity&, const Node*) const override
  {
    ++permissionCalls;
    return PermissionType{PermissionType::Bit::Call};
  }

  void effective_permissions_async(const RequestInfo&, shared_ptr<const AccessIdentity> identity,
    std::optional<std::vector<NodeId>> nodes, EffectivePermissionsCallback callback) override
  {
    fetchedIdentity = identity->key();
    fetchedNodes = std::move(nodes);
    EffectivePermissionsResult result;
    result.items.emplace_back(PermissionType{PermissionType::Bit::Call});
    callback(std::move(result));
  }

  void validate_role_permissions_updates_async(const RequestInfo&,
    std::span<const RolePermissionsUpdate> updates,
    std::function<void(BatchResult<VoidResult>)> complete) override
  {
    BatchResult<VoidResult> result;
    for (const auto& update : updates)
    {
      validatedNode = update.nodeId;
      validatedProposal = update.proposed;
      result.items.emplace_back(StatusCode{Status::BadRequestNotAllowed,
        ErrorDetail::build("HistoryInnerValidationSentinel",
          "The wrapped namespace rejected the prospective policy",
          "RecordingNamespace")});
    }
    complete(std::move(result));
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    RolePermissionType entry;
    entry.role_id() = NodeId{ObjectId::WellKnownRole_Engineer};
    entry.permissions() = PermissionType{PermissionType::Bit::Write};
    return std::vector<RolePermissionType>{std::move(entry)};
  }

  std::optional<AccessRestrictionType> default_access_restrictions() const override
  {
    return AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired};
  }

  void on_identity_released(const AccessIdentityKey& key) noexcept override
  {
    released = key;
  }

  std::optional<NodeId> metadata_object() const override
  {
    return NodeId{2, 9001U};
  }

  mutable std::size_t permissionCalls{0};
  AccessIdentityKey fetchedIdentity;
  std::optional<std::vector<NodeId>> fetchedNodes;
  NodeId validatedNode;
  std::optional<std::vector<RolePermissionType>> validatedProposal;
  AccessIdentityKey released;
};

shared_ptr<const AccessIdentity> make_identity(AccessIdentityKey key)
{
  return std::make_shared<const AccessIdentity>(key,
    std::vector<NodeId>{NodeId{ObjectId::WellKnownRole_Engineer}},
    std::make_shared<const UserIdentity>(),
    std::make_shared<const EndpointSecurityContext>(),
    String{"urn:test:client"});
}

}  // namespace

// @relation(AC-SVR-AUTHZ-017-SHIPPED-WRAPPER-FORWARDS, scope=function)
TEST(HistoryNamespaceTest, ForwardsEveryAddedMemberToInner)
{
  boost::asio::thread_pool pool{1};
  auto inner = std::make_shared<RecordingNamespace>(pool.get_executor());
  auto addressSpace = AddressSpace::create("urn:test:history-wrapper-host", pool.get_executor());
  const auto registered = addressSpace.try_add_namespace_sync(inner);
  ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());
  HistoryNamespace wrapper{inner, nullptr};
  const NodeId nodeId{registered.value(), 42U};
  const auto node = inner->create_node(nodeId, NodeClass::Object);
  ASSERT_NE(node, nullptr);
  const auto identity = make_identity(AccessIdentityKey{17});

  const auto permissions = wrapper.effective_permissions(*identity, node.get());
  ASSERT_TRUE(permissions.has_value());
  EXPECT_TRUE(permissions->test(PermissionType::Bit::Call));
  EXPECT_EQ(inner->permissionCalls, 1U);

  bool resolved{false};
  wrapper.effective_permissions_async(RequestInfo{},
    identity,
    std::vector<NodeId>{nodeId},
    [&resolved](EffectivePermissionsResult result)
    {
      EXPECT_TRUE(result.batchStatus.is_good());
      ASSERT_EQ(result.items.size(), 1U);
      ASSERT_TRUE(result.items.front().is_good());
      EXPECT_TRUE(result.items.front().value().test(PermissionType::Bit::Call));
      resolved = true;
    });
  EXPECT_TRUE(resolved);
  EXPECT_EQ(inner->fetchedIdentity, identity->key());
  EXPECT_EQ(inner->fetchedNodes, (std::optional<std::vector<NodeId>>{{nodeId}}));

  const std::vector<RolePermissionType> proposedUpdate{RolePermissionType{}};
  bool validationCompleted{false};
  const std::vector<RolePermissionsUpdate> updates{{nodeId, proposedUpdate}};
  wrapper.validate_role_permissions_updates_async(RequestInfo{},
    updates,
    [&validationCompleted](BatchResult<VoidResult> result)
    {
      ASSERT_EQ(result.items.size(), 1U);
      EXPECT_EQ(result.items.front().status_code().as_status(), Status::BadRequestNotAllowed);
      ASSERT_NE(result.items.front().shared_detail(), nullptr);
      EXPECT_EQ(result.items.front().shared_detail()->code, "HistoryInnerValidationSentinel");
      validationCompleted = true;
    });
  EXPECT_TRUE(validationCompleted);
  EXPECT_EQ(inner->validatedNode, nodeId);
  EXPECT_EQ(inner->validatedProposal, proposedUpdate);

  const auto roleDefault = wrapper.default_role_permissions();
  ASSERT_TRUE(roleDefault.has_value());
  ASSERT_EQ(roleDefault->size(), 1U);
  EXPECT_EQ(roleDefault->front().role_id(), NodeId{ObjectId::WellKnownRole_Engineer});
  EXPECT_TRUE(roleDefault->front().permissions().test(PermissionType::Bit::Write));

  const auto restrictions = wrapper.default_access_restrictions();
  ASSERT_TRUE(restrictions.has_value());
  EXPECT_TRUE(restrictions->test(AccessRestrictionType::Bit::EncryptionRequired));
  EXPECT_EQ(wrapper.metadata_object(), (std::optional<NodeId>{NodeId{2, 9001U}}));

  wrapper.on_identity_released(identity->key());
  EXPECT_EQ(inner->released, identity->key());

  wrapper.shutdown_async([](VoidResult result) { EXPECT_TRUE(result.is_good()); });
  pool.join();
}

namespace
{

/// A RegisterNodes delegate that answers every call; only its identity matters to the tests below.
class InnerRegisterNodesDelegate final : public NamespaceRegisterNodesDelegate
{
public:
  void register_nodes_async(
    const Context& /*context*/, std::vector<Item> items, RegisterCompleteCallback callback) noexcept override
  {
    BatchResult<NodeId> answer;
    for (auto& item : items)
      answer.items.push_back(std::move(item.nodeId));
    callback(std::move(answer));
  }

  void unregister_nodes_async(const Context& /*context*/, std::vector<Item> /*items*/,
    UnregisterCompleteCallback callback) noexcept override
  {
    callback(VoidResult{});
  }
};

/// An inner namespace whose enumeration and delegates are distinguishable from the base defaults: it
/// enumerates the NodeIds it is given, or refuses with Bad_NotSupported and its own ErrorDetail, and it has
/// the RegisterNodes delegate it is given, or none.
class EnumeratingNamespace final : public default_ns::Namespace
{
public:
  EnumeratingNamespace(boost::asio::any_io_executor executor, std::optional<std::vector<NodeId>> nodeIds,
    shared_ptr<NamespaceRegisterNodesDelegate> delegate)
    : default_ns::Namespace{"urn:test:history-forwarding", std::move(executor)}, mNodeIds(std::move(nodeIds)),
      mDelegate(std::move(delegate))
  {}

  void enumerate_nodes_async(
    const RequestInfo& /*request*/, std::function<void(Result<std::vector<NodeId>>)> complete) override
  {
    if (mNodeIds)
    {
      complete(Result<std::vector<NodeId>>{*mNodeIds});
      return;
    }
    complete(Result<std::vector<NodeId>>{StatusCode{Status::BadNotSupported,
      ErrorDetail::build(
        "InnerEnumerationRefused", "The wrapped namespace refuses to enumerate", "EnumeratingNamespace")}});
  }

  shared_ptr<NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override
  {
    return mDelegate;
  }

  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override
  {
    ++callCount;
    calledRequest = request;
    calledCaller.reset();
    if (caller)
    {
      calledCaller = *caller;
    }
    calledObjects.clear();
    calledMethods.clear();
    calledItems.clear();
    calledContexts.clear();
    for (const auto& item : items)
    {
      calledObjects.push_back(&item.object);
      calledMethods.push_back(&item.method);
      calledItems.push_back(item.request);
      calledContexts.push_back(item.context);
    }
    complete(callAnswer);
  }

  std::size_t callCount{0};
  RequestInfo calledRequest;
  std::optional<CallerInfo> calledCaller;
  std::vector<const Node*> calledObjects;
  std::vector<const Node*> calledMethods;
  std::vector<CallMethodRequest> calledItems;
  std::vector<shared_ptr<const MethodCallContext>> calledContexts;
  BatchResult<std::optional<CallResult>> callAnswer;

private:
  std::optional<std::vector<NodeId>> mNodeIds;
  shared_ptr<NamespaceRegisterNodesDelegate> mDelegate;
};

Result<std::vector<NodeId>> enumerate(HistoryNamespace& wrapper)
{
  auto answered = std::make_shared<std::promise<Result<std::vector<NodeId>>>>();
  auto future = answered->get_future();
  wrapper.enumerate_nodes_async(RequestInfo{},
    [answered](Result<std::vector<NodeId>> result) { answered->set_value(std::move(result)); });
  if (future.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
  {
    ADD_FAILURE() << "the wrapper's enumeration did not answer";
    return Result<std::vector<NodeId>>{StatusCode{Status::BadTimeout}};
  }
  return future.get();
}

}  // namespace

// NR-54: the event-graph check reads every namespace's Nodes through enumerate_nodes_async. The wrapper
// answers with the inner namespace's NodeIds, and passes the inner refusal through with the inner ErrorDetail
// (the control), rather than the base default's Bad_NotSupported with EnumerateNotSupported.
// @relation(AC-COMP-HISTORY-NAMESPACE-FORWARDING-01-FORWARDS-ENUMERATION-AND-REGISTRATION, scope=function)
TEST(HistoryNamespaceForwarding, EnumerateNodesReachesTheInnerNamespace)
{
  boost::asio::thread_pool pool{1};
  const std::vector<NodeId> innerNodes{NodeId{2, "First"}, NodeId{2, "Second"}};
  HistoryNamespace enumerating{
    std::make_shared<EnumeratingNamespace>(pool.get_executor(), innerNodes, nullptr), nullptr};
  HistoryNamespace refusing{
    std::make_shared<EnumeratingNamespace>(pool.get_executor(), std::nullopt, nullptr), nullptr};

  const auto answered = enumerate(enumerating);
  ASSERT_TRUE(answered.is_good()) << "the wrapper answered " << to_string(answered.status_code())
                                  << (answered.shared_detail() ? " (" + answered.shared_detail()->code + ")"
                                                               : "");
  EXPECT_EQ(answered.value(), innerNodes);

  const auto refused = enumerate(refusing);
  EXPECT_EQ(refused.status_code().as_status(), Status::BadNotSupported);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "InnerEnumerationRefused")
    << "the wrapper replaced the wrapped namespace's refusal with its own";
  pool.join();
}

// NR-39: RegisterNodes reaches a namespace through register_nodes_delegate. The wrapper returns the inner
// namespace's delegate object, and null where the inner namespace has none (the control).
// @relation(AC-COMP-HISTORY-NAMESPACE-FORWARDING-01-FORWARDS-ENUMERATION-AND-REGISTRATION, scope=function)
TEST(HistoryNamespaceForwarding, TheRegisterNodesDelegateIsTheInnerOne)
{
  boost::asio::thread_pool pool{1};
  const auto delegate = std::make_shared<InnerRegisterNodesDelegate>();
  HistoryNamespace withDelegate{
    std::make_shared<EnumeratingNamespace>(pool.get_executor(), std::vector<NodeId>{}, delegate), nullptr};
  HistoryNamespace withoutDelegate{
    std::make_shared<EnumeratingNamespace>(pool.get_executor(), std::vector<NodeId>{}, nullptr), nullptr};

  EXPECT_EQ(withDelegate.register_nodes_delegate().get(), delegate.get())
    << "the wrapper did not return the wrapped namespace's RegisterNodes delegate";
  EXPECT_EQ(withoutDelegate.register_nodes_delegate(), nullptr);
  pool.join();
}

#include "batch_recording_namespace.h"

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-04-HISTORY-NAMESPACE-FORWARDS-THE-REQUEST-FORMS, scope=function)
TEST(HistoryNamespaceTest, ForwardsTheFormsTakingARequestToInner)
{
  using Member = ua::test::BatchRecordingNamespace::Member;
  boost::asio::thread_pool pool{1};
  auto inner = std::make_shared<ua::test::BatchRecordingNamespace>(
    "urn:test:history-wrapper-request-forms", pool.get_executor());
  auto addressSpace = AddressSpace::create("urn:test:history-wrapper-request-host", pool.get_executor());
  const auto registered = addressSpace.try_add_namespace_sync(inner);
  ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());
  HistoryNamespace wrapper{inner, nullptr};
  // Called through the interface, as the SDK calls a namespace.
  ua::Namespace& wrapped = wrapper;
  const NodeId nodeId{registered.value(), 42U};
  const auto node = inner->create_node(nodeId, NodeClass::Object);
  ASSERT_NE(node, nullptr);
  inner->decline_immediate_permissions();
  inner->grant(nodeId, PermissionType{PermissionType::Bit::Call});
  inner->reset();
  const auto identity = make_identity(AccessIdentityKey{23});

  RequestInfo request;
  request.deadline = std::chrono::steady_clock::now() + std::chrono::seconds{7};
  auto answered = std::make_shared<std::promise<EffectivePermissionsResult>>();
  auto answer = answered->get_future();
  wrapped.effective_permissions_async(request,
    identity,
    std::vector<NodeId>{nodeId},
    [answered](EffectivePermissionsResult result) { answered->set_value(std::move(result)); });
  ASSERT_EQ(answer.wait_for(std::chrono::seconds{2}), std::future_status::ready);
  const auto asynchronous = answer.get();

  const auto asyncCalls = inner->calls(Member::PermissionsAsyncForRequest);
  EXPECT_EQ(asyncCalls.size(), 1U) << "the inner namespace's form taking a RequestInfo was not called once";
  if (asyncCalls.size() == 1U)
  {
    EXPECT_EQ(asyncCalls.front().nodeIds, std::vector<NodeId>{nodeId});
    EXPECT_EQ(asyncCalls.front().deadline, request.deadline);
  }
  EXPECT_TRUE(asynchronous.batchStatus.is_good());
  ASSERT_EQ(asynchronous.items.size(), 1U);
  ASSERT_TRUE(asynchronous.items.front().is_good()) << to_string(asynchronous.items.front().status_code());
  EXPECT_TRUE(asynchronous.items.front().value().test(PermissionType::Bit::Call));
  EXPECT_FALSE(asynchronous.items.front().value().test(PermissionType::Bit::Browse))
    << "the wrapper did not answer the inner namespace's mask";

  inner->reset();
  const auto immediate = wrapped.effective_permissions(*identity, static_cast<const Node*>(node.get()));
  const auto immediateCalls = inner->calls(Member::ImmediatePermissionsOfNode);
  EXPECT_EQ(immediateCalls.size(), 1U)
    << "the inner namespace's immediate form taking a Node was not called once";
  if (immediateCalls.size() == 1U)
  {
    EXPECT_EQ(immediateCalls.front().node, node.get());
    EXPECT_EQ(immediateCalls.front().nodeIds, std::vector<NodeId>{nodeId});
  }
  EXPECT_EQ(immediate, std::nullopt) << "the wrapper did not answer what the inner namespace answers";

  wrapper.shutdown_async([](VoidResult result) { EXPECT_TRUE(result.is_good()); });
  pool.join();
}

// @relation(AC-COMP-HISTORY-NAMESPACE-FORWARDING-01-FORWARDS-ENUMERATION-AND-REGISTRATION, scope=function)
TEST(HistoryNamespaceForwarding, ACallReachesTheInnerNamespace)
{
  for (const std::string_view answer : {"GoodAndDeclined", "ItemRefusals", "BatchRefused"})
  {
    for (const bool nullCaller : {false, true})
    {
      SCOPED_TRACE(answer);
      SCOPED_TRACE(nullCaller);
      boost::asio::io_context executor;
      auto inner =
        std::make_shared<EnumeratingNamespace>(executor.get_executor(), std::vector<NodeId>{}, nullptr);
      HistoryNamespace wrapper{inner, nullptr};
      ua::Namespace& wrapped = wrapper;

      const std::array<NodeId, 2> objectIds{
        NodeId{0, "history-call:first-object"}, NodeId{0, "history-call:second-object"}};
      const std::array<NodeId, 2> methodIds{
        NodeId{0, "history-call:first-method"}, NodeId{0, "history-call:second-method"}};
      const std::array<shared_ptr<Node>, 2> objects{inner->create_node(objectIds[0], NodeClass::Object),
        inner->create_node(objectIds[1], NodeClass::Object)};
      const std::array<shared_ptr<Node>, 2> methods{inner->create_node(methodIds[0], NodeClass::Method),
        inner->create_node(methodIds[1], NodeClass::Method)};
      const auto handlerCalls = std::make_shared<std::array<std::size_t, 2>>();
      for (std::size_t index = 0; index < methods.size(); ++index)
      {
        ASSERT_NE(objects[index], nullptr);
        ASSERT_NE(methods[index], nullptr);
        ASSERT_NE(methods[index]->method_call_source(), nullptr);
        ASSERT_TRUE(methods[index]
                      ->method_call_source()
                      ->set_call_handler(
                        [handlerCalls, index](const CallMethodRequest&,
                          shared_ptr<const MethodCallContext>,
                          std::function<void(CallResult)>
                            complete)
                        {
                          ++(*handlerCalls)[index];
                          CallMethodResult result;
                          result.output_arguments().payload().push_back(Variant{int32_t{1}});
                          complete(CallResult{std::move(result)});
                        })
                      .is_good());
      }

      RequestInfo request;
      const auto now = std::chrono::steady_clock::now();
      request.deadline = now + std::chrono::seconds{7};
      request.cancelled = std::make_shared<const std::atomic_bool>(false);
      request.locales = {LocaleId{"en-IE"}, LocaleId{"fr-FR"}};
      CallerInfo caller;
      caller.identity = make_identity(AccessIdentityKey{71});
      caller.sessionId = NodeId{2, "history-call:session"};
      caller.clientUserId = "history-call:user";
      caller.channelSecurityMode = MessageSecurityMode::SignAndEncrypt;
      const CallerInfo* suppliedCaller{&caller};
      if (nullCaller)
      {
        suppliedCaller = nullptr;
      }

      std::array<CallMethodRequest, 2> requests;
      std::array<shared_ptr<const MethodCallContext>, 2> contexts;
      for (std::size_t index = 0; index < requests.size(); ++index)
      {
        requests[index].object_id() = objectIds[index];
        requests[index].method_id() = methodIds[index];
        requests[index].input_arguments().payload().push_back(Variant{numeric_cast<int32_t>(index + 11)});
        requests[index].input_arguments().payload().push_back(Variant{String{"history-call:argument"}});
        auto context = std::make_shared<MethodCallContext>();
        context->clientUserId = caller.clientUserId;
        context->sessionId = NodeId{2, numeric_cast<uint32_t>(index + 71)};
        context->channelSecurityMode = caller.channelSecurityMode;
        context->sessionLocales = request.locales;
        contexts[index] = std::move(context);
      }
      const std::vector<CallItem> items{{*objects[0], *methods[0], requests[0], contexts[0]},
        {*objects[1], *methods[1], requests[1], contexts[1]}};

      const shared_ptr<const ErrorDetail> badDetail =
        ErrorDetail::build("HistoryCallItemUnavailable",
          "The inner namespace refused the first Method call",
          "EnumeratingNamespace")
          .detail("The independently retained inner Method refusal detail");
      const shared_ptr<const ErrorDetail> uncertainDetail =
        ErrorDetail::build("HistoryCallItemUncertain",
          "The inner namespace supplied no usable second Method answer",
          "EnumeratingNamespace")
          .detail("This is an unsuccessful outer CallResult, not a usable output value");
      const shared_ptr<const ErrorDetail> batchDetail =
        ErrorDetail::build("HistoryCallBatchUnavailable",
          "The inner namespace refused the Method batch before any item",
          "EnumeratingNamespace")
          .detail("The independently retained inner batch refusal detail");
      StatusCode bad{Status::BadResourceUnavailable, badDetail};
      bad.semantics_changed(true);
      StatusCode uncertain{Status::UncertainNoCommunicationLastUsableValue, uncertainDetail};
      uncertain.structure_changed(true);
      StatusCode batchBad{Status::BadResourceUnavailable, batchDetail};
      batchBad.structure_changed(true);

      CallMethodResult successful;
      successful.output_arguments().payload().push_back(Variant{int32_t{7}});
      if (answer == "GoodAndDeclined")
      {
        inner->callAnswer.items.emplace_back(CallResult{successful});
        inner->callAnswer.items.emplace_back(std::nullopt);
      }
      else if (answer == "ItemRefusals")
      {
        inner->callAnswer.items.emplace_back(CallResult{bad});
        inner->callAnswer.items.emplace_back(CallResult{uncertain});
      }
      else
      {
        inner->callAnswer.batchStatus = VoidResult{batchBad};
      }

      const auto completionCount = std::make_shared<std::size_t>(0);
      const auto received = std::make_shared<std::optional<BatchResult<std::optional<CallResult>>>>();
      EXPECT_NO_THROW(wrapped.call_async(request,
        suppliedCaller,
        items,
        [completionCount, received](BatchResult<std::optional<CallResult>> result)
        {
          ++*completionCount;
          received->emplace(std::move(result));
        }));
      EXPECT_NO_THROW({
        for (std::size_t step = 0; step < 64; ++step)
        {
          if (executor.poll_one() == 0)
          {
            break;
          }
        }
        EXPECT_EQ(executor.poll_one(), 0U) << "the bounded foreground completion drain did not finish";
      });

      EXPECT_EQ(inner->callCount, 1U);
      EXPECT_EQ(*completionCount, 1U);
      EXPECT_EQ((*handlerCalls)[0], 0U) << "the wrapper used the first Method handler as a fallback";
      EXPECT_EQ((*handlerCalls)[1], 0U) << "the wrapper used the second Method handler as a fallback";
      if (inner->callCount == 1)
      {
        EXPECT_EQ(inner->calledRequest.answerBy, request.answerBy);
        EXPECT_EQ(inner->calledRequest.deadline, request.deadline);
        EXPECT_EQ(inner->calledRequest.cancelled, request.cancelled);
        EXPECT_EQ(inner->calledRequest.locales, request.locales);
        EXPECT_EQ(inner->calledCaller.has_value(), !nullCaller);
        if (inner->calledCaller)
        {
          EXPECT_EQ(inner->calledCaller->identity, caller.identity);
          EXPECT_EQ(inner->calledCaller->sessionId, caller.sessionId);
          EXPECT_EQ(inner->calledCaller->clientUserId, caller.clientUserId);
          EXPECT_EQ(inner->calledCaller->channelSecurityMode, caller.channelSecurityMode);
        }
        EXPECT_EQ(inner->calledObjects, (std::vector<const Node*>{objects[0].get(), objects[1].get()}));
        EXPECT_EQ(inner->calledMethods, (std::vector<const Node*>{methods[0].get(), methods[1].get()}));
        EXPECT_EQ(inner->calledItems, (std::vector<CallMethodRequest>{requests[0], requests[1]}));
        EXPECT_EQ(inner->calledContexts,
          (std::vector<shared_ptr<const MethodCallContext>>{contexts[0], contexts[1]}));
      }

      EXPECT_TRUE(received->has_value());
      if (!*received)
      {
        continue;
      }
      const auto& completed = **received;
      if (answer == "BatchRefused")
      {
        EXPECT_FALSE(completed.batchStatus.is_good());
        EXPECT_EQ(completed.batchStatus.status_code().value(), batchBad.value());
        EXPECT_EQ(completed.batchStatus.shared_detail(), batchDetail);
        EXPECT_TRUE(completed.items.empty());
        continue;
      }
      EXPECT_TRUE(completed.batchStatus.is_good());
      EXPECT_EQ(completed.items.size(), 2U);
      if (completed.items.size() != 2)
      {
        continue;
      }
      EXPECT_TRUE(completed.items[0].has_value());
      if (answer == "GoodAndDeclined")
      {
        if (completed.items[0])
        {
          EXPECT_TRUE(completed.items[0]->is_good());
          if (completed.items[0]->is_good())
          {
            EXPECT_EQ(completed.items[0]->value(), successful);
          }
        }
        EXPECT_FALSE(completed.items[1].has_value());
      }
      else
      {
        if (completed.items[0])
        {
          EXPECT_FALSE(completed.items[0]->is_good());
          EXPECT_EQ(completed.items[0]->status_code().value(), bad.value());
          EXPECT_EQ(completed.items[0]->shared_detail(), badDetail);
        }
        EXPECT_TRUE(completed.items[1].has_value());
        if (completed.items[1])
        {
          EXPECT_FALSE(completed.items[1]->is_good());
          EXPECT_EQ(completed.items[1]->status_code().value(), uncertain.value());
          EXPECT_EQ(completed.items[1]->shared_detail(), uncertainDetail);
        }
      }
    }
  }
}
