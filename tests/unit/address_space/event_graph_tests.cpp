// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// The event-graph check reads every namespace through its batched members (NR-54; NR-70 B9b).
//
// The namespaces under test are `HistoryNamespace` wrappers, as on the compliance server: the address space
// holds a namespace it cannot see into except through the members of `Namespace`.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "batch_recording_namespace.h"

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_event_notifier_type.h"
#include "ua_history_namespace.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_status_to_string.h"
#include "ua_to_string.h"
#include "ua_exceptions.h"
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace ua;

namespace
{

using namespace std::chrono_literals;

/// A wrapped namespace that declines to list its Nodes, as a namespace over a remote server may.
class NotListingNamespace final : public history::HistoryNamespace
{
public:
  using history::HistoryNamespace::HistoryNamespace;

  void enumerate_nodes_async(
    const RequestInfo& /*request*/, std::function<void(Result<std::vector<NodeId>>)> complete) override
  {
    complete(Result<std::vector<NodeId>>{StatusCode{Status::BadNotSupported}});
  }
};

/// A wrapped namespace whose listing fails, as one whose device is offline may.
class FailingListingNamespace final : public history::HistoryNamespace
{
public:
  using history::HistoryNamespace::HistoryNamespace;

  void enumerate_nodes_async(
    const RequestInfo& /*request*/, std::function<void(Result<std::vector<NodeId>>)> complete) override
  {
    complete(Result<std::vector<NodeId>>{StatusCode{Status::BadTimeout}});
  }
};

class EventGraph : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:event-graph", mThreadPool.get_executor()));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// Registers a default namespace wrapped as @p Wrapper, and answers its index.
  template<typename Wrapper = history::HistoryNamespace>
  uint16_t wrapped(const std::string& uri)
  {
    auto inner = default_ns::Namespace::create(uri, mThreadPool.get_executor());
    auto index = mAddressSpace->try_add_namespace_sync(std::make_shared<Wrapper>(std::move(inner), nullptr));
    EXPECT_TRUE(index.is_good()) << to_string(index.status_code());
    return index.value();
  }

  /// An Object, a source of Event subscriptions unless @p subscribable is false.
  NodeAccessor object(const NodeId& id, bool subscribable = true)
  {
    auto created = mAddressSpace->try_create_node_sync(id, NodeClass::Object, {});
    EXPECT_TRUE(created.is_good()) << to_string(id) << ": " << to_string(created.status_code());
    auto accessor = std::move(created).value();
    EventNotifierType notifier;
    if (subscribable)
    {
      notifier.set(EventNotifierType::Bit::SubscribeToEvents);
    }
    accessor.as<ObjectAccessor>()->set_event_notifier(notifier);
    return accessor;
  }

  VoidResult check()
  {
    return mAddressSpace->try_validate_event_graph_sync();
  }

  static void expect_cycle(const VoidResult& verdict)
  {
    EXPECT_EQ(verdict.status_code(), Status::BadReferenceNotAllowed) << to_string(verdict.status_code());
    ASSERT_NE(verdict.shared_detail(), nullptr);
    EXPECT_EQ(verdict.shared_detail()->code, "EventReferenceCycle");
    ASSERT_NE(verdict.shared_detail()->cause, nullptr);
    EXPECT_EQ(verdict.shared_detail()->cause->code, "EventReferenceCycleTarget");
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace;
  const NodeId mHasEventSource{ReferenceTypeId::HasEventSource};
};

// @relation(AC-COMP-ADDRSP-EVENT-GRAPH-CHECK-01-A-LOOP-INSIDE-ANOTHER-NAMESPACE-IS-FOUND, scope=function)
TEST_F(EventGraph, ALoopInsideAnotherNamespaceIsFound)
{
  const auto index = wrapped("urn:test:event-graph:wrapped");
  const NodeId aId{index, "A"};
  const NodeId bId{index, "B"};
  auto a = object(aId);
  auto b = object(bId);
  ASSERT_TRUE(a.try_add_reference_sync(mHasEventSource, ExpandedNodeId{bId}).is_good());
  ASSERT_TRUE(b.try_add_reference_sync(mHasEventSource, ExpandedNodeId{aId}).is_good());

  expect_cycle(check());
}

// @relation(AC-COMP-ADDRSP-EVENT-GRAPH-CHECK-01-A-NOTIFIER-INTO-ANOTHER-NAMESPACE-IS-LEGAL, scope=function)
TEST_F(EventGraph, TheComplianceServersTreeIsLegal)
{
  // The Server Object notifies for an alarm source in a wrapped namespace, as on the compliance server.
  const auto index = wrapped("urn:test:event-graph:wrapped");
  auto server = object(NodeId{ObjectId::Server});
  const NodeId alarmSource{index, "AlarmSource"};
  object(alarmSource);
  ASSERT_TRUE(server.try_add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, ExpandedNodeId{alarmSource})
                .is_good());

  const auto verdict = check();
  EXPECT_TRUE(verdict.is_good()) << to_string(verdict.status_code())
                                 << (verdict.shared_detail() ? " " + verdict.shared_detail()->code : "");
}

// @relation(AC-COMP-ADDRSP-EVENT-GRAPH-CHECK-01-A-NAMESPACE-THAT-DECLINES-ENUMERATION-IS-UNCERTAIN, scope=function)
TEST_F(EventGraph, ANamespaceThatDeclinesEnumerationGivesUncertainNotAllNodesAvailable)
{
  const auto index = wrapped<NotListingNamespace>("urn:test:event-graph:not-listing");
  object(NodeId{index, "Unlisted"});

  const auto verdict = check();
  EXPECT_EQ(verdict.status_code(), Status::UncertainNotAllNodesAvailable) << to_string(verdict.status_code());
  ASSERT_NE(verdict.shared_detail(), nullptr);
  EXPECT_EQ(verdict.shared_detail()->code, "EventGraphNotFullyChecked");
  EXPECT_EQ(
    ::ua::test_utils::error_context(verdict.shared_detail().get(), ContextKeys::namespaceIndex.value()),
    std::to_string(index));
  // A graph only partly read has not been shown to conform.
  EXPECT_THROW(mAddressSpace->validate_event_graph_sync(), UaException);
}

// @relation(AC-COMP-ADDRSP-EVENT-GRAPH-CHECK-01-A-LOOP-THROUGH-A-NAMESPACE-THAT-DECLINES-IS-FOUND, scope=function)
TEST_F(EventGraph, ALoopThroughANamespaceThatDeclinesEnumerationIsFound)
{
  // X is listed by its namespace; Y is reached only by following X's HasEventSource into a namespace that
  // lists nothing, and closes the loop from there.
  const auto index = wrapped<NotListingNamespace>("urn:test:event-graph:not-listing");
  const NodeId xId{1, "X"};
  const NodeId yId{index, "Y"};
  auto x = object(xId);
  auto y = object(yId);
  ASSERT_TRUE(x.try_add_reference_sync(mHasEventSource, ExpandedNodeId{yId}).is_good());
  ASSERT_TRUE(y.try_add_reference_sync(mHasEventSource, ExpandedNodeId{xId}).is_good());

  expect_cycle(check());
}

// @relation(AC-COMP-ADDRSP-EVENT-GRAPH-CHECK-01-AN-ENDPOINT-WHOSE-LOOKUP-FAILS-IS-UNCERTAIN, scope=function)
TEST_F(EventGraph, AnEndpointWhoseLookupFailsGivesUncertainNotAllNodesAvailable)
{
  // A notifies for B; B's namespace cannot answer for B now, which is not B being absent.
  auto failing = std::make_shared<ua::test::BatchRecordingNamespace>(
    "urn:test:event-graph:failing", mThreadPool.get_executor());
  const auto added = mAddressSpace->try_add_namespace_sync(failing);
  ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
  const auto index = wrapped("urn:test:event-graph:wrapped");
  const NodeId bId{added.value(), "B"};
  auto a = object(NodeId{index, "A"});
  object(bId);
  ASSERT_TRUE(a.try_add_reference_sync(NodeId{ReferenceTypeId::HasNotifier}, ExpandedNodeId{bId}).is_good());
  failing->decline_single_lookups();
  failing->answer_lookup_of(bId, StatusCode{Status::BadTimeout});

  const auto verdict = check();
  EXPECT_EQ(verdict.status_code(), Status::UncertainNotAllNodesAvailable)
    << to_string(verdict.status_code())
    << (verdict.shared_detail() ? " " + verdict.shared_detail()->code : "");
  ASSERT_NE(verdict.shared_detail(), nullptr);
  EXPECT_EQ(verdict.shared_detail()->code, "EventGraphNotFullyChecked");
}

// @relation(AC-COMP-ADDRSP-EVENT-GRAPH-CHECK-01-A-NAMESPACE-THAT-DECLINES-ENUMERATION-IS-UNCERTAIN, scope=function)
TEST_F(EventGraph, AListingThatFailsIsTheUncertainAnswersCause)
{
  const auto index = wrapped<FailingListingNamespace>("urn:test:event-graph:failing-listing");
  object(NodeId{index, "Unlisted"});

  const auto verdict = check();
  EXPECT_EQ(verdict.status_code(), Status::UncertainNotAllNodesAvailable) << to_string(verdict.status_code());
  ASSERT_NE(verdict.shared_detail(), nullptr);
  EXPECT_EQ(verdict.shared_detail()->innerStatus, StatusCode{Status::BadTimeout}.value())
    << "the listing's failure is not the cause";
}

// @relation(AC-COMP-ADDRSP-EVENT-GRAPH-CHECK-01-A-SYNC-CHECK-ON-AN-ADDRESS-SPACE-THREAD-WOULD-BLOCK, scope=function)
TEST_F(EventGraph, TrySyncOnAnAddressSpaceThreadAnswersBadWouldBlock)
{
  std::promise<VoidResult> answered;
  auto future = answered.get_future();
  boost::asio::post(mAddressSpace->executor(),
    [this, &answered] { answered.set_value(mAddressSpace->try_validate_event_graph_sync()); });
  ASSERT_EQ(future.wait_for(10s), std::future_status::ready);
  const auto verdict = future.get();
  EXPECT_EQ(verdict.status_code(), Status::BadWouldBlock) << to_string(verdict.status_code());
}

}  // namespace
