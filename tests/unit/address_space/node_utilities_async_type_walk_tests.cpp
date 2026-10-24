// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// node_utils type walks must not block the thread they run on.
///
/// `get_super_type_async` and `get_type_definition_async` run on SDK strands (Write, Call, Browse, the event
/// bus, DeleteNodes). The node they read may belong to a namespace that answers by POSTING its reference set
/// to an executor rather than completing inline. If the walk waited for that answer on the executor's only
/// thread - as the old `get_super_type_async` did through `get_references_sync` - the posted answer could
/// never run and the thread would hang. These tests drive exactly that: a one-thread executor, and a
/// namespace whose answer to the node's Reference read is posted to it. The walk must complete.

#include "fake_async_namespace.h"
#include "fake_node.h"
#include "ua_address_space.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_utilities.h"
#include "ua_objecttype_id.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"

#include <gtest/gtest.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using ua::test::behaviour_pins::FakeAsyncNamespace;
using ua::test::behaviour_pins::FakeNode;

namespace
{

/// A FakeAsyncNamespace whose answer to each Reference read is delivered by a task posted to @p executor,
/// never inline.
class PostingNamespace final : public FakeAsyncNamespace
{
public:
  PostingNamespace(std::string uri, boost::asio::io_context::executor_type executor)
    : FakeAsyncNamespace(std::move(uri)), mExecutor(std::move(executor))
  {}

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    FakeAsyncNamespace::read_references_async(request,
      queries,
      [executor = mExecutor, complete = std::move(complete)](BatchResult<NodeReferencesResult> answer)
      {
        boost::asio::post(
          executor, [complete, answer = std::move(answer)]() mutable { complete(std::move(answer)); });
      });
  }

private:
  boost::asio::io_context::executor_type mExecutor;
};

/// A one-thread executor that runs until the test ends. If the code under test blocks that thread the
/// test fails on its timeout; the context and thread are then leaked on purpose, because a blocked thread
/// cannot be joined and the failure must not become a hang.
struct OneThreadExecutor
{
  std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work =
    boost::asio::make_work_guard(*context);
  std::thread thread{[context = context]
    {
      context->run();
    }};

  ~OneThreadExecutor()
  {
    work.reset();
    context->stop();
    if (thread.joinable())
    {
      thread.detach();
    }
  }
};

/// A namespace registered with an address space, holding the Nodes a test makes and answering their
/// Reference reads by posting to @p executor. The accessor it hands out for a Node is the address space's,
/// as the lookup of a namespace's own Node is.
struct HoldingNamespace
{
  std::shared_ptr<PostingNamespace> holder;
  AddressSpace& addressSpace;
  uint16_t index;

  HoldingNamespace(AddressSpace& space, boost::asio::io_context::executor_type executor)
    : holder(std::make_shared<PostingNamespace>("urn:test:type-walk-holder", std::move(executor))),
      addressSpace(space), index(space.add_namespace_sync(holder))
  {}

  NodeAccessor accessor_for(const NodeId& nodeId, std::shared_ptr<Node> node)
  {
    holder->hold(nodeId, std::move(node));
    return addressSpace.find_node_sync(nodeId);
  }
};

constexpr auto timeout = std::chrono::seconds{5};

}  // namespace

// The walk is started ON the executor's thread and the type's references are posted to that same thread:
// the blocking read this replaced waited there for an answer that could only run there.
TEST(NodeUtilitiesAsyncTypeWalk, SuperTypeWalkCompletesWhenTheNamespaceAnswersByPosting)
{
  OneThreadExecutor executor;
  auto addressSpace = AddressSpace::create("urn:test", executor.context->get_executor());

  HoldingNamespace held{addressSpace, executor.context->get_executor()};
  const NodeId typeId{held.index, "SubType"};
  held.holder->set_next_get_references(typeId,
    NodeAccessor::ReferencesResult{References{std::vector<Reference>{
      Reference{NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{NodeId{1, "Missing"}}, false}}}});

  const auto typeAccessor =
    held.accessor_for(typeId, std::make_shared<FakeNode>(typeId, NodeClass::ObjectType));
  std::promise<node_utils::OptionalNodeAccessorResult> outcome;
  boost::asio::post(*executor.context,
    [&addressSpace, typeAccessor, &outcome]
    {
      node_utils::get_super_type_async(addressSpace,
        typeAccessor,
        [&outcome](node_utils::OptionalNodeAccessorResult result) { outcome.set_value(std::move(result)); });
    });

  auto future = outcome.get_future();
  ASSERT_EQ(future.wait_for(timeout), std::future_status::ready)
    << "the super-type walk blocked the thread its type's namespace answers on";
  // The supertype named by the reference does not exist, so the walk reports that - not "no supertype".
  EXPECT_TRUE(future.get().is_bad());
}

// A type with no HasSubtype inverse reference is the top of its hierarchy: the walk ends with no supertype.
TEST(NodeUtilitiesAsyncTypeWalk, SuperTypeWalkEndsAtTheTopOfTheHierarchy)
{
  OneThreadExecutor executor;
  auto addressSpace = AddressSpace::create("urn:test", executor.context->get_executor());

  HoldingNamespace held{addressSpace, executor.context->get_executor()};
  const NodeId typeId{held.index, "RootType"};
  held.holder->set_next_get_references(typeId, NodeAccessor::ReferencesResult{References{}});

  const auto typeAccessor =
    held.accessor_for(typeId, std::make_shared<FakeNode>(typeId, NodeClass::ObjectType));
  std::promise<node_utils::OptionalNodeAccessorResult> outcome;
  boost::asio::post(*executor.context,
    [&addressSpace, typeAccessor, &outcome]
    {
      node_utils::get_super_type_async(addressSpace,
        typeAccessor,
        [&outcome](node_utils::OptionalNodeAccessorResult result) { outcome.set_value(std::move(result)); });
    });

  auto future = outcome.get_future();
  ASSERT_EQ(future.wait_for(timeout), std::future_status::ready);
  auto result = future.get();
  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value().has_value());
}

// A failed reference read is reported with its status, not swallowed into "no supertype": the old walk
// caught every exception and ended the walk, so a namespace fault looked like the top of the hierarchy.
TEST(NodeUtilitiesAsyncTypeWalk, SuperTypeWalkReportsAFailedReferenceRead)
{
  OneThreadExecutor executor;
  auto addressSpace = AddressSpace::create("urn:test", executor.context->get_executor());

  HoldingNamespace held{addressSpace, executor.context->get_executor()};
  const NodeId typeId{held.index, "BrokenType"};
  held.holder->set_next_get_references(
    typeId, NodeAccessor::ReferencesResult{StatusCode{Status::BadCommunicationError}});

  const auto typeAccessor =
    held.accessor_for(typeId, std::make_shared<FakeNode>(typeId, NodeClass::ObjectType));
  std::promise<node_utils::OptionalNodeAccessorResult> outcome;
  boost::asio::post(*executor.context,
    [&addressSpace, typeAccessor, &outcome]
    {
      node_utils::get_super_type_async(addressSpace,
        typeAccessor,
        [&outcome](node_utils::OptionalNodeAccessorResult result) { outcome.set_value(std::move(result)); });
    });

  auto future = outcome.get_future();
  ASSERT_EQ(future.wait_for(timeout), std::future_status::ready);
  EXPECT_EQ(future.get().status_code(), StatusCode{Status::BadCommunicationError});
}

// The TypeDefinition read used by Browse and Call: started on the executor's thread, answered by a post to
// it.
TEST(NodeUtilitiesAsyncTypeWalk, TypeDefinitionReadCompletesWhenTheNamespaceAnswersByPosting)
{
  OneThreadExecutor executor;

  auto addressSpace = AddressSpace::create("urn:test", executor.context->get_executor());
  HoldingNamespace held{addressSpace, executor.context->get_executor()};
  const NodeId instanceId{held.index, "Instance"};
  held.holder->set_next_get_references(instanceId,
    NodeAccessor::ReferencesResult{
      References{std::vector<Reference>{Reference{NodeId{ReferenceTypeId::HasTypeDefinition},
        ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}},
        true}}}});

  const auto instanceAccessor =
    held.accessor_for(instanceId, std::make_shared<FakeNode>(instanceId, NodeClass::Object));

  std::promise<node_utils::ExpandedNodeIdResult> outcome;
  boost::asio::post(*executor.context,
    [instanceAccessor, &outcome]
    {
      node_utils::get_type_definition_async(instanceAccessor,
        [&outcome](node_utils::ExpandedNodeIdResult result) { outcome.set_value(std::move(result)); });
    });

  auto future = outcome.get_future();
  ASSERT_EQ(future.wait_for(timeout), std::future_status::ready)
    << "the TypeDefinition read blocked the thread its node's namespace answers on";
  auto result = future.get();
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}});
}
