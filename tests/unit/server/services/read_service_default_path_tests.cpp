// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Default-path Read service behaviour that was previously exercised through the (now-removed)
// per-namespace Read override delegate. The interface refactor deleted the Read/Write delegates: every
// namespace resolves and caches its nodes on find_node (invariant I2), so the SDK's authorized,
// address-space-backed Read path serves them all and the override fork - which was the source of the
// authorization bypass - is gone. These tests assert the scenarios the override tests covered now
// hold on that single default path: per-node authorization actually runs (deny -> Bad_UserAccessDenied),
// a partial denial scatters results to their original request slots, an unknown namespace is
// rejected, and cancellation mid-resolution completes once with a service fault.

#include <gtest/gtest.h>

#include <atomic>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

#include "per_item_join.h"
#include "ua_access_level_type.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_connection_protocol_limits.h"
#include "ua_default_namespace.h"
#include "ua_exceptions.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_result.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>

#include "fake_node.h"
#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

ua::server::Server make_server(boost::asio::any_io_executor executor)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(
    executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  return server;
}

ReadResponse drive_read(
  shared_ptr<SessionInfoStub> sessionInfo, boost::asio::any_io_executor executor, ReadRequest request)
{
  std::promise<void> done;
  ReadResponse result;
  std::vector<LocaleId> locales{"en"};
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(request),
    executor,
    [&done, &result](Response response)
    {
      if (auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get()))
        result = std::move(*readResponse);
      done.set_value();
    });
  EXPECT_EQ(done.get_future().wait_for(2s), std::future_status::ready);
  return result;
}

// In-memory namespace that PARKS its batched resolution: find_nodes_async stores the request and its
// callback instead of completing, so a Read sits mid-resolution until complete() fires it. Used to
// drive cancellation while the service is waiting on the address space.
class DeferringResolveNamespace final : public default_ns::Namespace
{
public:
  DeferringResolveNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  /// Starts parking. Until this is called the namespace resolves normally.
  ///
  /// `find_nodes_async` is the only resolution interface, so the SDK's own single-node lookups -
  /// registration, the namespace metadata object - come through here too. Parking from construction would
  /// park those and the server would never finish standing up. Arm it once the fixture is built and only the
  /// request under test is left to resolve.
  void park_from_now()
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mParking = true;
  }

  /// Declines the synchronous form once parking is armed, which is the whole of what parking means:
  /// a namespace that can answer on the caller's stack has no window to be cancelled during.
  ///
  /// Before it is armed it answers normally, so standing the server up costs nothing.
  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      if (mParking)
      {
        return std::nullopt;
      }
    }
    return default_ns::Namespace::find_node(nodeId, maxAge);
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      if (mParking && !mParkedCallback)
      {
        mParkedRequest = request;
        mParkedIds.assign(nodeIds.begin(), nodeIds.end());
        mParkedMaxAge = maxAge;
        mParkedCallback = std::move(complete);
        return;
      }
    }
    // Qualified, so it reaches the in-memory base rather than re-entering this override.
    default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(complete));
  }

  // Resolve the parked ids via the in-memory store and fire the parked callback (a "late" completion
  // after the request was cancelled). No-op if nothing is parked.
  void complete()
  {
    std::function<void(BatchResult<NodeResult>)> callback;
    RequestInfo request;
    std::vector<NodeId> ids;
    std::optional<Duration> maxAge;
    {
      std::lock_guard<std::mutex> lock(mMutex);
      callback = std::move(mParkedCallback);
      request = mParkedRequest;
      ids = std::move(mParkedIds);
      maxAge = mParkedMaxAge;
    }
    if (!callback)
      return;

    // Qualified, so it resolves through the in-memory base rather than re-entering the parking
    // override above.
    default_ns::Namespace::find_nodes_async(request, ids, maxAge, std::move(callback));
  }

private:
  std::mutex mMutex;
  bool mParking{false};
  RequestInfo mParkedRequest;
  std::vector<NodeId> mParkedIds;
  std::optional<Duration> mParkedMaxAge;
  std::function<void(BatchResult<NodeResult>)> mParkedCallback;
};

}  // namespace

// Per-node authorization runs on the default path: a Value Read the Namespace denies is answered
// Bad_UserAccessDenied (no override fork can bypass it any more).
TEST(ReadServiceDefaultPathTests, DeniedItemReturnsBadUserAccessDenied)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = default_ns::Namespace::create("uri://default-path-deny", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  const NodeId nodeId{nsIndex, 8000u};
  ns->create_node(nodeId, NodeClass::Variable);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);
  auto deniedNode = sessionInfo->address_space().try_find_node_sync(nodeId);
  ASSERT_TRUE(deniedNode.is_good());
  ua::test_helpers::set_test_node_permissions(deniedNode.value(), PermissionType{});

  ReadRequest readRequest;
  readRequest.nodes_to_read().resize(1);
  readRequest.nodes_to_read()[0].node_id() = nodeId;
  readRequest.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::Value);

  auto result = drive_read(sessionInfo, executor, std::move(readRequest));

  ASSERT_EQ(result.results().size(), 1u);
  ASSERT_TRUE(result.results()[0].status().has_value());
  EXPECT_EQ(*result.results()[0].status(), Status::BadUserAccessDenied);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Partial denial scatters to original slots: in a three-item single-Namespace batch where policy
// denies exactly the MIDDLE node, the denied slot is answered Bad_UserAccessDenied and the two
// surviving reads land at their original (non-contiguous) indices, each carrying its OWN node's value.
TEST(ReadServiceDefaultPathTests, PartialDenialScattersResultsToOriginalSlots)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = default_ns::Namespace::create("uri://default-path-partial-deny", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  const NodeId firstNode{nsIndex, 9000u};
  const NodeId deniedNode{nsIndex, 9001u};  // the MIDDLE item - denied
  const NodeId lastNode{nsIndex, 9002u};
  ns->create_node(firstNode, NodeClass::Object);
  ns->create_node(deniedNode, NodeClass::Object);
  ns->create_node(lastNode, NodeClass::Object);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);
  auto deniedMiddle = sessionInfo->address_space().try_find_node_sync(deniedNode);
  ASSERT_TRUE(deniedMiddle.is_good());
  ua::test_helpers::set_test_node_permissions(deniedMiddle.value(), PermissionType{});

  ReadRequest readRequest;
  readRequest.nodes_to_read().resize(3);
  for (auto* op :
    {&readRequest.nodes_to_read()[0], &readRequest.nodes_to_read()[1], &readRequest.nodes_to_read()[2]})
  {
    op->attribute_id() = utils::to_underlying(AttributeId::NodeId);
  }
  readRequest.nodes_to_read()[0].node_id() = firstNode;
  readRequest.nodes_to_read()[1].node_id() = deniedNode;
  readRequest.nodes_to_read()[2].node_id() = lastNode;

  auto result = drive_read(sessionInfo, executor, std::move(readRequest));

  ASSERT_EQ(result.results().size(), 3u);

  // Surviving item 0 lands at its own slot with its own id.
  if (result.results()[0].status().has_value())
    EXPECT_TRUE(result.results()[0].status()->is_good());
  EXPECT_EQ(result.results()[0].value().as<NodeId>(), firstNode);

  // The denied middle item is answered at its original index.
  ASSERT_TRUE(result.results()[1].status().has_value());
  EXPECT_EQ(*result.results()[1].status(), Status::BadUserAccessDenied);

  // Surviving item 2 lands at its original (non-contiguous) slot with its own id.
  if (result.results()[2].status().has_value())
    EXPECT_TRUE(result.results()[2].status()->is_good());
  EXPECT_EQ(result.results()[2].value().as<NodeId>(), lastNode);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// An item in an unregistered namespace is answered Bad_NodeIdUnknown on the default path.
TEST(ReadServiceDefaultPathTests, UnknownNamespaceIndexReturnsBadNodeIdUnknown)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  // Pick an index with no registered namespace.
  const uint16_t unknownNsIndex = 250;

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.nodes_to_read().resize(1);
  readRequest.nodes_to_read()[0].node_id() = NodeId{unknownNsIndex, 1u};
  readRequest.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::NodeClass);

  auto result = drive_read(sessionInfo, executor, std::move(readRequest));

  ASSERT_EQ(result.results().size(), 1u);
  ASSERT_TRUE(result.results()[0].status().has_value());
  EXPECT_EQ(*result.results()[0].status(), Status::BadNodeIdUnknown);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Cancelling while the Read is parked on resolution completes the request exactly once, with a
// Bad_RequestCancelledByClient service fault, and a late resolution completion is ignored (no
// second completion).
TEST(ReadServiceDefaultPathTests, CancelDuringResolveCompletesOnceWithServiceFault)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<DeferringResolveNamespace>("uri://default-path-cancel", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  const NodeId nodeId{nsIndex, 123u};
  ns->create_node(nodeId, NodeClass::Object);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);
  ns->park_from_now();

  ReadRequest readRequest;
  readRequest.nodes_to_read().resize(1);
  readRequest.nodes_to_read()[0].node_id() = nodeId;
  readRequest.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::NodeClass);

  std::promise<void> done;
  std::atomic_int completions{0};
  StatusCode serviceResult;

  std::vector<LocaleId> locales{"en"};
  auto readService = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&done, &completions, &serviceResult](Response response)
    {
      ++completions;
      if (auto* serviceFault = dynamic_cast<ServiceFault*>(response.second.get()))
        serviceResult = serviceFault->response_header().service_result();
      done.set_value();
    });

  // The Read is now parked on DeferringResolveNamespace::find_nodes_async. Cancel it.
  readService->cancel();

  ASSERT_EQ(done.get_future().wait_for(2s), std::future_status::ready);

  // Fire the parked resolution late; the service must not complete a second time.
  ns->complete();

  std::promise<void> drain;
  auto drainFuture = drain.get_future();
  boost::asio::post(executor, [&drain]() { drain.set_value(); });
  drainFuture.wait_for(3s);

  EXPECT_EQ(completions.load(), 1);
  EXPECT_EQ(serviceResult, Status::BadRequestCancelledByClient);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A node whose Attributes cannot be read - its attributes() THROWS - must fail its own operation, not
// hang the whole request.
//
// A namespace is customer code, and a dependency accessor reached after teardown throws by design -
// which is the stated reason ua::async::guarded exists. Every read of the Node's Attributes on the
// Read path - the access decision's, the class check's and the attribute read's - reaches this throw,
// and wherever it is caught the operation must be finalized with a Bad status: an uncaught throw in
// the operation's coroutine goes to the promise's unhandled_exception, the operation never finalizes,
// `pendingUnits` never reaches zero, and with the default timeoutHint of 0 the request hangs for the
// life of the session.
//
// drive_read waits two seconds for the response, so a regression fails by TIMING OUT rather than by
// asserting a status, which is the honest shape for a test whose subject is a hang.
namespace
{

class ThrowingAttributeNode final : public Node
{
public:
  NodeDescription attributes() const override
  {
    throw ua::UaException{Status::BadShutdown, nullptr};
  }
};

/// Resolves one id to a node whose Attributes cannot be read.
class ThrowingNodeNamespace final : public default_ns::Namespace
{
public:
  ThrowingNodeNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  /// Fakes ONE node. Everything else resolves from the in-memory base.
  ///
  /// It has to be one: the SDK's own single-node lookups - the namespace metadata object among them -
  /// arrive here too, and a throwing node cannot answer them. A fixture that fakes every id breaks the
  /// server rather than the node under test.
  void fake_one(NodeId nodeId)
  {
    mFaked = std::move(nodeId);
  }

protected:
  /// Both lookup forms of the in-memory namespace answer from here, so the faked node answers whichever
  /// the address space asks.
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    if (mFaked && nodeId == *mFaked)
    {
      return NodeResult{shared_ptr<Node>{std::make_shared<ThrowingAttributeNode>()}};
    }
    return default_ns::Namespace::resolve_here(nodeId);
  }

private:
  std::optional<NodeId> mFaked;
};

}  // namespace

TEST(ReadServiceDefaultPathTests, AThrowingAttributeReadFailsItsOperationRatherThanHangingTheRequest)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = std::make_shared<ThrowingNodeNamespace>("uri://default-path-throwing-attribute", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  ns->fake_one(NodeId{nsIndex, 8100u});

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.nodes_to_read().resize(1);
  readRequest.nodes_to_read()[0].node_id() = NodeId{nsIndex, 8100u};
  readRequest.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::Description);

  const auto response = drive_read(sessionInfo, executor, std::move(readRequest));

  ASSERT_EQ(response.results().size(), 1u) << "the request must complete at all";
  const auto& status = response.results()[0].status();
  ASSERT_TRUE(status.has_value());
  EXPECT_TRUE(status->is_bad()) << "the throw must surface as this operation's status";

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// COMP-REQUEST-OP-LIFECYCLE-04: after the namespace has answered a Value, the read service reads the Node's
// BrowseName (finish_value) before it records the item. A Node whose Attributes cannot be read from then on
// fails its own operation with the status thrown, and the request's other item is answered as its namespace
// answered it.
namespace
{

/// A Variable whose Attributes can be read until the test switches it to throwing Bad_Shutdown.
class SwitchedNode final : public Node
{
public:
  explicit SwitchedNode(const NodeId& nodeId)
    : mDescription(
        NodeDescription::try_from_attributes(nodeId, NodeClass::Variable, InitialAttributes{}).value())
  {}

  NodeDescription attributes() const override
  {
    if (mThrows.load())
    {
      throw ua::UaException{Status::BadShutdown, nullptr};
    }
    return mDescription;
  }

  void start_throwing()
  {
    mThrows.store(true);
  }

private:
  NodeDescription mDescription;
  std::atomic<bool> mThrows{false};
};

/// Resolves two ids to SwitchedNodes and answers their Values inline, Int32 1 and 2. Before it answers, the
/// first Node's Attributes start throwing.
class ThrowsOnceAnsweredNamespace final : public default_ns::Namespace
{
public:
  ThrowsOnceAnsweredNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void fake(const NodeId& throwing, const NodeId& readable)
  {
    mThrowing = std::make_shared<SwitchedNode>(throwing);
    mReadable = std::make_shared<SwitchedNode>(readable);
    mThrowingId = throwing;
    mReadableId = readable;
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem> items,
    Duration, bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    BatchResult<DataValueResult> answer;
    for (const ValueReadItem& item : items)
    {
      const int32_t value = &item.node == mThrowing.get() ? 1 : 2;
      answer.items.emplace_back(DataValue{Variant{value}});
    }
    mThrowing->start_throwing();
    complete(std::move(answer));
  }

protected:
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    if (mThrowing && nodeId == mThrowingId)
    {
      return NodeResult{shared_ptr<Node>{mThrowing}};
    }
    if (mReadable && nodeId == mReadableId)
    {
      return NodeResult{shared_ptr<Node>{mReadable}};
    }
    return default_ns::Namespace::resolve_here(nodeId);
  }

private:
  shared_ptr<SwitchedNode> mThrowing;
  shared_ptr<SwitchedNode> mReadable;
  NodeId mThrowingId;
  NodeId mReadableId;
};

}  // namespace

// @relation(AC-COMP-REQUEST-OP-LIFECYCLE-04-A-FAILING-ITEM-DOES-NOT-TAKE-THE-REQUEST, scope=function)
TEST(ReadServiceDefaultPathTests, AThrowAfterTheNamespaceAnsweredFailsOnlyItsOperation)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = std::make_shared<ThrowsOnceAnsweredNamespace>("uri://default-path-throw-after-answer", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  ns->fake(NodeId{nsIndex, 8150u}, NodeId{nsIndex, 8151u});

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.nodes_to_read().resize(2);
  readRequest.nodes_to_read()[0].node_id() = NodeId{nsIndex, 8150u};
  readRequest.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::Value);
  readRequest.nodes_to_read()[1].node_id() = NodeId{nsIndex, 8151u};
  readRequest.nodes_to_read()[1].attribute_id() = utils::to_underlying(AttributeId::Value);

  const auto response = drive_read(sessionInfo, executor, std::move(readRequest));

  ASSERT_EQ(response.results().size(), 2u) << "the request must complete at all";
  const auto& failed = response.results()[0];
  ASSERT_TRUE(failed.status().has_value());
  EXPECT_EQ(failed.status()->as_status(), Status::BadShutdown) << to_string(*failed.status());
  const auto& read = response.results()[1];
  EXPECT_TRUE(!read.status().has_value() || read.status()->is_good())
    << to_string(read.status().value_or(StatusCode{}));
  ASSERT_TRUE(read.value().is_int32()) << "the other item's Value was not returned";
  EXPECT_EQ(read.value().as<int32_t>(), 2);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// SVC-12 (Read half): a Read is refused with Bad_ResponseTooLarge once the values it has read exceed
// the response limit - the Session's negotiated maxResponseMessageSize, else the configured maximum
// message size (OPC 10000-4 5.3, 5.6.2.2) - and no further nodes are read. The nodes answer their
// values INLINE and the namespace counts every read, so "stopped early" is observable as fewer reads than
// nodes.
namespace
{

constexpr uint32_t largeValueNodeCount = 10;
constexpr size_t largeValueBytes = 16 * 1024;

/// A Variable whose Value is a large ByteString, answered by LargeValueNamespace.
class LargeValueNode final : public ua::test::behaviour_pins::FakeNode
{
public:
  explicit LargeValueNode(NodeId nodeId)
    : ua::test::behaviour_pins::FakeNode(std::move(nodeId), NodeClass::Variable)
  {}
};

/// Resolves ids [base, base + largeValueNodeCount) to LargeValueNodes; everything else from the base.
class LargeValueNamespace final : public default_ns::Namespace
{
public:
  LargeValueNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void fake_range(uint16_t namespaceIndex, uint32_t base)
  {
    mNamespaceIndex = namespaceIndex;
    mBase = base;
  }

  std::shared_ptr<std::atomic_int> reads() const
  {
    return mReads;
  }

  /// A LargeValueNode's Value is answered and counted here, inline and in item order; every other item's is
  /// read through the in-memory member.
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    auto join = std::make_shared<test::PerItemJoin<DataValueResult>>(items.size(), std::move(complete));
    for (std::size_t index = 0; index < items.size(); ++index)
    {
      const ValueReadItem& item = items[index];
      if (dynamic_cast<const LargeValueNode*>(&item.node) != nullptr)
      {
        ++*mReads;
        join->answer(index, DataValueResult{DataValue{Variant{ByteString(largeValueBytes, uint8_t{0xA5})}}});
        continue;
      }
      const ValueReadItem one[]{item};
      default_ns::Namespace::read_values_async(request,
        caller,
        one,
        maxAge,
        setSourceTimestamp,
        [join, index](BatchResult<DataValueResult> read)
        { join->answer(index, test::only_item(std::move(read))); });
    }
    join->started();
  }

protected:
  /// Both lookup forms of the in-memory namespace answer from here, so the faked ids answer whichever the
  /// address space asks.
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    if (is_faked(nodeId))
    {
      return NodeResult{shared_ptr<Node>{std::make_shared<LargeValueNode>(nodeId)}};
    }
    return default_ns::Namespace::resolve_here(nodeId);
  }

private:
  bool is_faked(const NodeId& nodeId) const
  {
    if (!mNamespaceIndex || nodeId.namespace_index() != *mNamespaceIndex)
    {
      return false;
    }
    for (uint32_t i = 0; i < largeValueNodeCount; ++i)
    {
      if (nodeId == NodeId{*mNamespaceIndex, mBase + i})
      {
        return true;
      }
    }
    return false;
  }

  std::optional<uint16_t> mNamespaceIndex;
  uint32_t mBase{0};
  std::shared_ptr<std::atomic_int> mReads{std::make_shared<std::atomic_int>(0)};
};

/// A Session stub whose Client negotiated @p maxResponseMessageSize in CreateSession.
class NegotiatedResponseSizeSessionInfo final : public SessionInfoStub
{
public:
  NegotiatedResponseSizeSessionInfo(
    ua::server::Server server, boost::asio::any_io_executor executor, uint32_t maxResponseMessageSize)
    : SessionInfoStub(std::move(server), std::move(executor)), mMaxResponseMessageSize(maxResponseMessageSize)
  {}

  uint32_t max_response_message_size() const override
  {
    return mMaxResponseMessageSize;
  }

private:
  uint32_t mMaxResponseMessageSize;
};

struct LargeReadOutcome
{
  bool answered{false};
  StatusCode serviceResult;
  std::optional<ReadResponse> response;
  int reads{0};
};

/// Reads the Value of every LargeValueNode in one request. @p maxMessageSize is the configured
/// maximum message size; @p negotiated the Session's maxResponseMessageSize (0 = not used).
LargeReadOutcome read_large_values(uint32_t maxMessageSize, uint32_t negotiated)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto application = test_utils::create_test_config();
  application.stack_limits().connectionProtocolLimits.maxMessageSize = maxMessageSize;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = std::move(application),
    .server = ua::server::ServerConfig{}};
  auto server = ua::server::Server::create(
    executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  auto ns = std::make_shared<LargeValueNamespace>("uri://default-path-large-values", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  constexpr uint32_t base = 8200u;
  ns->fake_range(nsIndex, base);

  auto sessionInfo =
    std::make_shared<NegotiatedResponseSizeSessionInfo>(std::move(server), executor, negotiated);

  ReadRequest readRequest;
  readRequest.nodes_to_read().resize(largeValueNodeCount);
  for (uint32_t i = 0; i < largeValueNodeCount; ++i)
  {
    readRequest.nodes_to_read()[i].node_id() = NodeId{nsIndex, base + i};
    readRequest.nodes_to_read()[i].attribute_id() = utils::to_underlying(AttributeId::Value);
  }

  std::promise<void> done;
  LargeReadOutcome outcome;
  std::vector<LocaleId> locales{"en"};
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&done, &outcome](Response response)
    {
      if (auto* serviceFault = dynamic_cast<ServiceFault*>(response.second.get()))
      {
        outcome.serviceResult = serviceFault->response_header().service_result();
      }
      else if (auto* readResponse = dynamic_cast<ReadResponse*>(response.second.get()))
      {
        outcome.serviceResult = readResponse->response_header().service_result();
        outcome.response = std::move(*readResponse);
      }
      done.set_value();
    });
  outcome.answered = done.get_future().wait_for(2s) == std::future_status::ready;
  outcome.reads = ns->reads()->load();

  service.reset();
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
  return outcome;
}

// Each answered value counts at least 16390 bytes (16384 data, 4 length, 2 masks), so four exceed 64 KiB.
constexpr uint32_t smallResponseLimit = 64 * 1024;

}  // namespace

// @verifies AC-SVR-ATTR-READ-013-READ-RESPONSE-TOO-LARGE
TEST(ReadServiceDefaultPathTests, AReadExceedingTheConfiguredMessageSizeIsRefused)
{
  const auto outcome = read_large_values(smallResponseLimit, 0);

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult, Status::BadResponseTooLarge);
  EXPECT_FALSE(outcome.response.has_value()) << "the whole request is refused with a service fault";
}

// @verifies AC-SVR-ATTR-READ-013-READ-RESPONSE-TOO-LARGE
TEST(ReadServiceDefaultPathTests, AReadExceedingTheNegotiatedMaxResponseMessageSizeIsRefused)
{
  // The configured maximum message size (16 MiB) would admit the response; the Client's own
  // maxResponseMessageSize does not, and it is the limit that applies.
  const auto outcome =
    read_large_values(ua::connection_protocol::Limits::defaultMaxMessageSize, smallResponseLimit);

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult, Status::BadResponseTooLarge);
}

// Control: the same request under the limit reads every node and answers every value.
// @verifies AC-SVR-ATTR-READ-013-READ-RESPONSE-TOO-LARGE
TEST(ReadServiceDefaultPathTests, AReadUnderTheResponseLimitReadsEveryNode)
{
  const auto outcome = read_large_values(ua::connection_protocol::Limits::defaultMaxMessageSize, 0);

  ASSERT_TRUE(outcome.answered);
  EXPECT_TRUE(outcome.serviceResult.is_good());
  ASSERT_TRUE(outcome.response.has_value());
  ASSERT_EQ(outcome.response->results().size(), largeValueNodeCount);
  for (const auto& result : outcome.response->results())
  {
    if (result.status().has_value())
    {
      EXPECT_TRUE(result.status()->is_good());
    }
    const auto* bytes = result.value().try_as<ByteString>();
    ASSERT_NE(bytes, nullptr);
    EXPECT_EQ(bytes->size(), largeValueBytes);
  }
  EXPECT_EQ(outcome.reads, static_cast<int>(largeValueNodeCount));
}
