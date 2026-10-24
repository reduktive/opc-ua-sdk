// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the address space answers a View's membership and adds to a View, through the View's accessor: the
// View's own Node is a member and the Server Object (i=2253) is not, decided without asking the View's
// namespace; adding the Server Object is refused before the namespace is asked (NR-16 rule 6, NR-41).

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ua_address_space.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include "batch_recording_namespace.h"
#include "test_utilities.h"

using namespace ua;
using namespace std::chrono_literals;
using ua::test::BatchRecordingNamespace;
using Member = BatchRecordingNamespace::Member;

namespace
{

// An address space with one recording namespace registered, holding a View V and an Object O.
struct ViewFixture
{
  ViewFixture()
  {
    addressSpace.emplace(AddressSpace::create("urn:test:view-membership-route", pool.get_executor()));
    space =
      std::make_shared<BatchRecordingNamespace>("urn:test:view-membership-route:r", pool.get_executor());
    index = addressSpace->add_namespace_sync(space);
    v = NodeId{index, 100u};
    o = NodeId{index, 101u};
    EXPECT_TRUE(addressSpace->try_create_node_sync(v, NodeClass::View).is_good()) << "creating V";
    EXPECT_TRUE(addressSpace->try_create_node_sync(o, NodeClass::Object).is_good()) << "creating O";
  }

  ~ViewFixture()
  {
    addressSpace.reset();
    ::ua::test_utils::drain_with_timeout(pool);
  }

  ViewFixture(const ViewFixture&) = delete;
  ViewFixture& operator=(const ViewFixture&) = delete;

  // V's accessor, looked up through the address space.
  std::optional<ViewAccessor> view()
  {
    auto found = addressSpace->try_find_node_sync(v);
    if (found.is_bad())
    {
      return std::nullopt;
    }
    auto typed = found.value().as<ViewAccessor>();
    if (!typed)
    {
      return std::nullopt;
    }
    return *typed;
  }

  boost::asio::thread_pool pool{2};
  std::optional<AddressSpace> addressSpace;
  std::shared_ptr<BatchRecordingNamespace> space;
  uint16_t index{0};
  NodeId v;
  NodeId o;
};

// The answer an asynchronous form gives, or nullopt when it gives none within five seconds.
template<typename T, typename Start>
std::optional<T> await_answer(Start&& start)
{
  auto promise = std::make_shared<std::promise<T>>();
  auto future = promise->get_future();
  start([promise](T answer) { promise->set_value(std::move(answer)); });
  if (future.wait_for(5s) != std::future_status::ready)
  {
    return std::nullopt;
  }
  return future.get();
}

std::string describe(const std::vector<BatchRecordingNamespace::Call>& calls)
{
  std::string text;
  for (const auto& call : calls)
  {
    text += "\n  call";
    for (const auto& candidate : call.candidates)
    {
      text += " " + to_string(candidate);
    }
    for (const auto& nodeId : call.nodeIds)
    {
      text += " " + nodeId.as_definition();
    }
  }
  return text;
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-08-THE-SERVER-OBJECT-IS-REFUSED-AS-A-MEMBER-BEFORE-THE-NAMESPACE-IS-ASKED, scope=function)
// @relation(AC-SVR-EVT-ATTR-007-SERVER-OBJECT-NOT-IN-VIEW, scope=function)
TEST(ViewMembershipRoute, TheServerObjectIsRefusedAsAMemberBeforeTheNamespaceIsAsked)
{
  ViewFixture fixture;
  auto view = fixture.view();
  ASSERT_TRUE(view.has_value()) << "V's accessor";
  fixture.space->accept_view_additions();
  fixture.space->reset();
  const NodeId server{ObjectId::Server};

  const auto addedServer = await_answer<VoidResult>([&](auto done)
    { view->add_node_to_view_async(server, NodeAccessor::ViewModifyCallback{std::move(done)}); });
  const auto addedO = await_answer<VoidResult>([&](auto done)
    { view->add_node_to_view_async(fixture.o, NodeAccessor::ViewModifyCallback{std::move(done)}); });

  ASSERT_TRUE(addedServer.has_value()) << "adding i=2253 gave no answer";
  EXPECT_EQ(addedServer->status_code().as_status(), Status::BadReferenceNotAllowed)
    << "adding i=2253 answered " << to_string(addedServer->status_code());
  const auto detail = addedServer->shared_detail();
  EXPECT_NE(detail, nullptr) << "the refusal names no ErrorDetail";
  if (detail != nullptr)
  {
    EXPECT_EQ(detail->code, "ServerObjectInView");
  }

  const auto additions = fixture.space->calls(Member::AddToView);
  const bool serverAsked = std::any_of(additions.begin(),
    additions.end(),
    [&server](const BatchRecordingNamespace::Call& call)
    { return std::find(call.nodeIds.begin(), call.nodeIds.end(), server) != call.nodeIds.end(); });
  EXPECT_FALSE(serverAsked) << "R's add_to_view_async was asked to add i=2253:" << describe(additions);

  ASSERT_TRUE(addedO.has_value()) << "adding O gave no answer";
  EXPECT_TRUE(addedO->is_good()) << "adding O answered " << to_string(addedO->status_code());
  const bool oRecorded = std::any_of(additions.begin(),
    additions.end(),
    [&fixture](const BatchRecordingNamespace::Call& call)
    {
      return call.view == fixture.v &&
             std::find(call.nodeIds.begin(), call.nodeIds.end(), fixture.o) != call.nodeIds.end();
    });
  EXPECT_TRUE(oRecorded) << "R recorded no addition of O to V:" << describe(additions);
}

// The accessor's membership form takes one candidate, so V, i=2253 and O are asked in three calls.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-08-THE-VIEW-NODE-AND-THE-SERVER-OBJECT-ARE-ANSWERED-WITHOUT-ASKING-THE-NAMESPACE, scope=function)
TEST(ViewMembershipRoute, TheViewNodeAndTheServerObjectAreAnsweredWithoutAskingTheNamespace)
{
  ViewFixture fixture;
  auto view = fixture.view();
  ASSERT_TRUE(view.has_value()) << "V's accessor";
  const NodeId server{ObjectId::Server};
  // The opposite of the rule for V and i=2253: V not a member, every other candidate a member.
  fixture.space->answer_view_membership(
    [](const NodeId& viewId, const NodeId& candidate) { return candidate != viewId; });
  fixture.space->reset();

  const auto ask = [&view](const NodeId& candidate)
  {
    return await_answer<BoolResult>([&](auto done)
      { view->is_node_in_view_async(candidate, NodeAccessor::IsNodeInViewCallback{std::move(done)}); });
  };
  const auto vAnswer = ask(fixture.v);
  const auto serverAnswer = ask(server);
  const auto oAnswer = ask(fixture.o);

  ASSERT_TRUE(vAnswer.has_value()) << "asking about V gave no answer";
  ASSERT_TRUE(vAnswer->is_good()) << "asking about V answered " << to_string(vAnswer->status_code());
  EXPECT_TRUE(vAnswer->value()) << "V is not a member of its own View";
  ASSERT_TRUE(serverAnswer.has_value()) << "asking about i=2253 gave no answer";
  ASSERT_TRUE(serverAnswer->is_good())
    << "asking about i=2253 answered " << to_string(serverAnswer->status_code());
  EXPECT_FALSE(serverAnswer->value()) << "the Server Object is a member of V";
  ASSERT_TRUE(oAnswer.has_value()) << "asking about O gave no answer";
  ASSERT_TRUE(oAnswer->is_good()) << "asking about O answered " << to_string(oAnswer->status_code());
  EXPECT_TRUE(oAnswer->value()) << "O, which R answers a member, is not";

  const auto asked = fixture.space->calls(Member::ViewContains);
  EXPECT_EQ(asked.size(), 1U) << "R's view_contains_async calls:" << describe(asked);
  if (asked.size() == 1U)
  {
    EXPECT_EQ(asked[0].view, fixture.v);
    EXPECT_EQ(asked[0].candidates, std::vector<ExpandedNodeId>{ExpandedNodeId{fixture.o}})
      << "R's call names other candidates than O:" << describe(asked);
  }
}
