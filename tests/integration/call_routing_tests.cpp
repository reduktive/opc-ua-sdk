// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Which namespace runs a Method call (NR-15 rules 2 to 4): the namespace that holds the Object is offered the
// call first, so it may run a namespace-0 Method on its own Object; a call that the Object's namespace and
// the Method's namespace both decline is Bad_NotImplemented. A real server whose application namespaces
// override call_async; the calls come from a Client over the wire.

#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "requests.h"

#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_default_namespace.h"
#include "ua_instance_utils.h"
#include "ua_method_id.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_session_method_services.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

// An in-memory namespace whose call_async either takes the items whose Object it holds, answering each Good
// with the one Int32 output 42 and declining the others, or declines every item.
class CallAnsweringNamespace : public default_ns::Namespace
{
public:
  enum class Answer
  {
    TakeItsOwnObjects,
    DeclineEvery,
  };

  CallAnsweringNamespace(string_view uri, boost::asio::any_io_executor executor, Answer answer)
    : default_ns::Namespace(uri, std::move(executor)), mAnswer(answer)
  {}

  void call_async(const RequestInfo&, const CallerInfo*, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override
  {
    mCalls.fetch_add(1);
    BatchResult<std::optional<CallResult>> answers;
    for (const auto& item : items)
    {
      if (mAnswer == Answer::TakeItsOwnObjects && find_node<Node>(item.request.object_id()) != nullptr)
      {
        CallMethodResult result;
        result.status_code() = Status::Good;
        result.output_arguments().push_back(Variant{int32_t{42}});
        answers.items.emplace_back(CallResult{std::move(result)});
      }
      else
      {
        answers.items.emplace_back(std::nullopt);
      }
    }
    complete(std::move(answers));
  }

  // How many call_async calls this namespace has answered.
  int calls() const
  {
    return mCalls.load();
  }

private:
  Answer mAnswer;
  std::atomic<int> mCalls{0};
};

class CallRouting : public ComplianceWithSession
{
protected:
  using Answer = CallAnsweringNamespace::Answer;

  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    const auto executor = mServer.thread_pool().executor();
    mTaking = std::make_shared<CallAnsweringNamespace>(
      "urn:test:call-routing:n", executor, Answer::TakeItsOwnObjects);
    mDecliningObjects =
      std::make_shared<CallAnsweringNamespace>("urn:test:call-routing:n1", executor, Answer::DeclineEvery);
    mDecliningMethods =
      std::make_shared<CallAnsweringNamespace>("urn:test:call-routing:n2", executor, Answer::DeclineEvery);
    const uint16_t n = addressSpace.add_namespace_sync(mTaking);
    const uint16_t n1 = addressSpace.add_namespace_sync(mDecliningObjects);
    const uint16_t n2 = addressSpace.add_namespace_sync(mDecliningMethods);

    // o in N, the source of a HasComponent Reference to the namespace-0 Method Server.GetMonitoredItems.
    mObjectOfN = NodeId{n, "o"};
    auto o = create_object(addressSpace, mObjectOfN, "o");
    o.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, NodeId{MethodId::Server_GetMonitoredItems});

    // An Object of N1, the source of a HasComponent Reference to a Method of N2.
    mObjectOfN1 = NodeId{n1, "O"};
    mMethodOfN2 = NodeId{n2, "M"};
    auto object = create_object(addressSpace, mObjectOfN1, "O");
    auto methodNode = addressSpace.create_node_sync(mMethodOfN2, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    ASSERT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{n2, "M"});
    method->set_display_name(LocalizedText{"", "M"});
    method->set_executable(true);
    object.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMethodOfN2);
  }

  static NodeAccessor create_object(AddressSpace& addressSpace, const NodeId& nodeId, const std::string& name)
  {
    auto object = addressSpace.create_node_sync(nodeId, NodeClass::Object);
    object.set_browse_name(QualifiedName{nodeId.namespace_index(), name});
    object.set_display_name(LocalizedText{"", name});
    object.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    return object;
  }

  std::shared_ptr<CallAnsweringNamespace> mTaking;
  std::shared_ptr<CallAnsweringNamespace> mDecliningObjects;
  std::shared_ptr<CallAnsweringNamespace> mDecliningMethods;
  NodeId mObjectOfN;
  NodeId mObjectOfN1;
  NodeId mMethodOfN2;
};

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-AN-OBJECTS-NAMESPACE-RUNS-A-NAMESPACE-ZERO-METHOD-ON-ITS-OBJECT, scope=function)
TEST_F(CallRouting, AnObjectsNamespaceRunsANamespaceZeroMethodOnItsObject)
{
  // The namespace-0 Method's handler records each run.
  auto handlerRuns = std::make_shared<std::atomic<int>>(0);
  auto installed = std::make_shared<std::promise<VoidResult>>();
  auto installation = installed->get_future();
  instance_utils::resolve_and_set_method_handler_async(
    mServer.server().address_space(),
    NodeId{ObjectId::Server},
    QualifiedName{0, "GetMonitoredItems"},
    [handlerRuns](const CallMethodRequest&,
      std::shared_ptr<const MethodCallContext>,
      std::function<void(CallResult)>
        callback)
    {
      handlerRuns->fetch_add(1);
      CallMethodResult result;
      result.status_code() = Status::Good;
      callback(CallResult{std::move(result)});
    },
    [installed](VoidResult result) { installed->set_value(std::move(result)); });
  ASSERT_EQ(installation.wait_for(5s), std::future_status::ready) << "the handler was not installed";
  const auto installResult = installation.get();
  ASSERT_TRUE(installResult.is_good()) << to_string(installResult.status_code());

  // GetMonitoredItems declares one UInt32 input argument, SubscriptionId.
  auto called = mSession->methods().try_call_sync(
    call_method(mObjectOfN, NodeId{MethodId::Server_GetMonitoredItems}, {Variant{uint32_t{1}}}));

  ASSERT_TRUE(called.is_good()) << to_string(called.status_code());
  const auto response = std::move(called).value();
  ASSERT_EQ(response.results().size(), 1u);
  const auto& result = response.results()[0];
  EXPECT_EQ(result.status_code().as_status(), Status::Good) << to_string(result.status_code());
  ASSERT_EQ(result.output_arguments().size(), 1u) << "the result's output arguments";
  ASSERT_TRUE(result.output_arguments()[0].is_int32());
  EXPECT_EQ(result.output_arguments()[0].as<int32_t>(), 42) << "the result's output";
  EXPECT_EQ(handlerRuns->load(), 0) << "the namespace-0 Method's handler ran";
  EXPECT_GE(mTaking->calls(), 1) << "N's call_async was not called";
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-19-AN-ITEM-DECLINED-BY-BOTH-NAMESPACES-IS-BAD-NOT-IMPLEMENTED, scope=function)
TEST_F(CallRouting, AnItemDeclinedByBothNamespacesIsBadNotImplemented)
{
  auto called = mSession->methods().try_call_sync(call_method(mObjectOfN1, mMethodOfN2));

  ASSERT_TRUE(called.is_good()) << to_string(called.status_code());
  EXPECT_EQ(mDecliningObjects->calls(), 1) << "N1's call_async calls";
  EXPECT_EQ(mDecliningMethods->calls(), 1) << "N2's call_async calls";
  const auto response = std::move(called).value();
  ASSERT_EQ(response.results().size(), 1u);
  const auto& status = response.results()[0].status_code();
  EXPECT_EQ(status.as_status(), Status::BadNotImplemented) << to_string(status);
}
