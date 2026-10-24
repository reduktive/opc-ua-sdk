// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Falsifiable coverage for withdrawal reaching a REAL service, not just the primitive.
//
// `tests/unit/async/coro_tests.cpp` proves that a `ua::async::Task` stops when its cancellation
// token is set. It cannot prove that AttributeServiceSet's token is the one its coroutines adopt:
// the token is not passed anywhere, it is taken from `cancellation_token()` by the promise
// constructor, and if that accessor were renamed, moved or shadowed, everything would still compile,
// the primitive's own tests would still pass, and every request-scoped coroutine in the service
// would silently become unwithdrawable.
//
// So this drives the production path. The namespace holds the request's resolution, the client
// cancels, and the namespace then answers late. What must NOT happen is the rest of the request:
// `Namespace::effective_permissions` is the first thing the read path asks a namespace AFTER
// resolution, so a count of zero is the evidence that the body unwound instead of carrying on into
// state that `cancel()` has already torn down.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <optional>
#include <span>
#include <thread>
#include <vector>

#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_browse_path.h"
#include "ua_default_namespace.h"
#include "ua_node_accessor.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_translate_browse_paths_service.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include <boost/asio/thread_pool.hpp>

#include "stubs.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

/// Holds the first resolution asked of it after @ref arm, and counts what the service asks next.
///
/// Deferring is what creates the window a withdrawal has to survive: while the request is suspended
/// on this namespace, `cancel()` runs, answers the client, and drops the response the request was
/// going to fill in. Everything the body would do on resuming is work against state that is gone.
class DeferringResolveNamespace final : public default_ns::Namespace
{
public:
  DeferringResolveNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  /// Starts deferring. Called after the fixture is built, so registration and node creation - which
  /// resolve through this same interface - are answered normally.
  void arm()
  {
    mArmed.store(true);
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    // exchange, not load-then-store: only the FIRST resolution after arming is held, and this interface
    // is entered from the service's strand while the test thread is waiting on mHeld.
    if (!mArmed.exchange(false))
    {
      default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(callback));
      return;
    }

    {
      const std::lock_guard<std::mutex> lock(mMutex);
      // Copied: the span is the caller's, and the caller is about to suspend.
      mHeldIds.assign(nodeIds.begin(), nodeIds.end());
      mHeldMaxAge = maxAge;
      mHeldCallback = std::move(callback);
    }
    mHeld.set_value();
  }

  /// Declines the synchronous form. A namespace that can answer on the caller's stack has no window
  /// to be withdrawn in - deferring IS what it means to have to go away for the answer.
  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    (void)nodeId;
    (void)maxAge;
    return std::nullopt;
  }

  /// Answers the held resolution, truthfully and far too late.
  void release()
  {
    std::vector<NodeId> ids;
    std::optional<Duration> maxAge;
    std::function<void(BatchResult<NodeResult>)> callback;
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      ids = std::move(mHeldIds);
      maxAge = mHeldMaxAge;
      callback = std::move(mHeldCallback);
    }
    ASSERT_TRUE(static_cast<bool>(callback));
    default_ns::Namespace::find_nodes_async(RequestInfo{}, ids, maxAge, std::move(callback));
  }

  std::future<void> held()
  {
    return mHeld.get_future();
  }

  std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node* node) const override
  {
    ++mPermissionCalls;
    return default_ns::Namespace::effective_permissions(identity, node);
  }

  /// How far past the resolution the request got. Zero is the assertion.
  size_t permission_calls() const
  {
    return mPermissionCalls.load();
  }

  void reset_counts()
  {
    mPermissionCalls.store(0);
  }

private:
  std::atomic_bool mArmed{false};
  std::promise<void> mHeld;
  std::mutex mMutex;
  std::vector<NodeId> mHeldIds;
  std::optional<Duration> mHeldMaxAge;
  std::function<void(BatchResult<NodeResult>)> mHeldCallback;
  mutable std::atomic_size_t mPermissionCalls{0};
};

/// Answers its resolution on the caller's own stack, after parking it. A namespace or value source
/// that computes synchronously - a slow device read, a lock - pins the service strand for the whole
/// call, so a withdrawal posted to that strand cannot run until the answer is already in hand. The
/// only thing that can still stop the request is the token, and only if it was set BEFORE the post.
class BlockingResolveNamespace final : public default_ns::Namespace
{
public:
  BlockingResolveNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void arm()
  {
    mArmed.store(true);
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    if (!mArmed.exchange(false))
    {
      default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(callback));
      return;
    }
    mEntered.set_value();
    // The strand stays parked here until the test has issued the cancel; bounded so a mistake in the
    // test cannot hang the suite.
    (void)mProceed.get_future().wait_for(5s);
    default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  /// Lets the parked resolution answer; called once the cancel has been issued.
  void proceed()
  {
    mProceed.set_value();
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    (void)nodeId;
    (void)maxAge;
    return std::nullopt;
  }

  std::future<void> entered()
  {
    return mEntered.get_future();
  }

private:
  std::atomic_bool mArmed{false};
  std::promise<void> mEntered;
  std::promise<void> mProceed;
};

ua::server::Server make_server(boost::asio::any_io_executor executor)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  return ua::server::Server::create(
    executor, std::move(cfg), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
}

}  // namespace

TEST(RequestWithdrawalTests, CancellingAReadStopsItsCoroutineWhereItWasSuspended)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<DeferringResolveNamespace>("uri://withdrawal-read", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  constexpr size_t nodeCount = 3;
  std::vector<NodeId> ids;
  ids.reserve(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    NodeId id{nsIndex, static_cast<uint32_t>(3000 + i)};
    ns->create_node(id, NodeClass::Object);
    ids.push_back(id);
  }

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.timestamps_to_return() = TimestampsToReturn::Neither;
  readRequest.nodes_to_read().resize(nodeCount);
  for (size_t i = 0; i < nodeCount; ++i)
  {
    readRequest.nodes_to_read()[i].node_id() = ids[i];
    readRequest.nodes_to_read()[i].attribute_id() = utils::to_underlying(AttributeId::NodeId);
  }

  std::promise<void> answered;
  std::atomic_int responses{0};
  std::optional<StatusCode> faultStatus;
  bool sawReadResponse = false;

  ns->reset_counts();
  ns->arm();
  std::vector<LocaleId> locales{"en"};
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&](Response response)
    {
      if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
      {
        faultStatus = fault->response_header().service_result();
      }
      if (dynamic_cast<ReadResponse*>(response.second.get()) != nullptr)
      {
        sawReadResponse = true;
      }
      if (++responses == 1)
      {
        answered.set_value();
      }
    });

  ASSERT_EQ(ns->held().wait_for(2s), std::future_status::ready)
    << "the request must be suspended on the namespace before anything is withdrawn";
  ASSERT_EQ(ns->permission_calls(), 0u) << "nothing past the resolution should have run yet";

  // The client withdraws. `cancel()` answers the fault and drops the response the request was
  // filling in, so from here every step of the read body is work against state that is gone.
  service->cancel();
  ASSERT_EQ(answered.get_future().wait_for(2s), std::future_status::ready);

  // ...and only now does the namespace answer the resolution, exactly as a slow collaborator would.
  // Everything stays alive across this: dropping the service here would retire its tasks, the
  // completion would be discarded as `taskGone`, and the assertion below would hold for a reason
  // that has nothing to do with withdrawal.
  ns->release();

  // Waits for the WRONG thing, because a body that unwound leaves no signal to wait for and adding
  // one to the service purely to watch it do nothing would be an interface that exists for this test.
  // Under a mutation that removes the check the read carries straight on and authorizes within
  // milliseconds, so this is a long time to be sure it did not.
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (ns->permission_calls() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(10ms);
  }

  EXPECT_EQ(ns->permission_calls(), 0u)
    << "the resumed body must have unwound at its co_await, not carried on into authorization";
  EXPECT_FALSE(sawReadResponse) << "a withdrawn request must not also answer with a Read response";
  EXPECT_EQ(responses.load(), 1) << "exactly one answer reaches the client";
  ASSERT_TRUE(faultStatus.has_value());
  EXPECT_EQ(*faultStatus, Status::BadRequestCancelledByClient);

  // The session holds the Server, whose timers keep the pool busy; it goes before the join.
  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A Session that ends aborts the Read it still owns (OPC 10000-4 5.6.2.1): the Read answers now with
// Bad_SessionClosed, the reason it was given, and its body unwinds as for a Cancel, so the namespace's late
// answer drives nothing further.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-26-AN-ABORTED-CALL-ANSWERS-ITS-REASON-AND-STOPS, scope=function)
TEST(RequestWithdrawalTests, AbortingAReadAnswersItsReasonAndStopsItsCoroutine)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<DeferringResolveNamespace>("uri://withdrawal-abort", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId id{nsIndex, uint32_t{3100}};
  ns->create_node(id, NodeClass::Object);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.timestamps_to_return() = TimestampsToReturn::Neither;
  readRequest.nodes_to_read().resize(1);
  readRequest.nodes_to_read()[0].node_id() = id;
  readRequest.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::NodeId);

  std::promise<void> answered;
  std::atomic_int responses{0};
  std::optional<StatusCode> faultStatus;
  bool sawReadResponse = false;

  ns->reset_counts();
  ns->arm();
  std::vector<LocaleId> locales{"en"};
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&](Response response)
    {
      if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
      {
        faultStatus = fault->response_header().service_result();
      }
      if (dynamic_cast<ReadResponse*>(response.second.get()) != nullptr)
      {
        sawReadResponse = true;
      }
      if (++responses == 1)
      {
        answered.set_value();
      }
    });

  ASSERT_EQ(ns->held().wait_for(2s), std::future_status::ready)
    << "the request must be suspended on the namespace before it is aborted";

  service->abort(StatusCode{Status::BadSessionClosed});
  ASSERT_EQ(answered.get_future().wait_for(2s), std::future_status::ready)
    << "the aborted Read did not answer";
  ns->release();
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (ns->permission_calls() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(10ms);
  }

  EXPECT_EQ(ns->permission_calls(), 0u) << "the aborted body carried on into authorization";
  EXPECT_FALSE(sawReadResponse) << "an aborted request must not also answer with a Read response";
  EXPECT_EQ(responses.load(), 1) << "exactly one answer reaches the client";
  ASSERT_TRUE(faultStatus.has_value());
  EXPECT_EQ(*faultStatus, Status::BadSessionClosed);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// A Read whose namespace answers on the strand itself: the withdrawal is posted behind the answer, so
// the token has to be set at the moment of the cancel, not inside the post. Without that the read
// body carries on with the answer in hand (the await never suspends: the answer is already there, and
// it is await_resume that must see the token), sends the Read response, and the fault the post then
// tries to send finds the request already finished. The shape of the client_errors book example, whose
// SlowSensor read handler parks the strand for 900 ms.
// @verifies AC-SVR-SESS-041-CANCEL
TEST(RequestWithdrawalTests, CancellingAReadWhoseNamespaceAnswersOnTheStrandStillAnswersOnlyWithTheFault)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<BlockingResolveNamespace>("uri://withdrawal-blocking-read", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);
  const NodeId id{nsIndex, 3100};
  ns->create_node(id, NodeClass::Object);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  ReadRequest readRequest;
  readRequest.timestamps_to_return() = TimestampsToReturn::Neither;
  readRequest.nodes_to_read().resize(1);
  readRequest.nodes_to_read()[0].node_id() = id;
  readRequest.nodes_to_read()[0].attribute_id() = utils::to_underlying(AttributeId::NodeId);

  std::promise<void> answered;
  std::atomic_int responses{0};
  std::optional<StatusCode> faultStatus;
  std::atomic_bool sawReadResponse{false};

  ns->arm();
  std::vector<LocaleId> locales{"en"};
  auto service = AttributeServiceSet::create(sessionInfo,
    locales,
    0,
    std::move(readRequest),
    executor,
    [&](Response response)
    {
      if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
      {
        faultStatus = fault->response_header().service_result();
      }
      if (dynamic_cast<ReadResponse*>(response.second.get()) != nullptr)
      {
        sawReadResponse = true;
      }
      if (++responses == 1)
      {
        answered.set_value();
      }
    });

  ASSERT_EQ(ns->entered().wait_for(2s), std::future_status::ready)
    << "the request must be inside the namespace before it is withdrawn";
  // The client withdraws while the strand is parked inside the namespace; only then does the
  // namespace answer, on the strand, inline.
  service->cancel();
  ns->proceed();

  ASSERT_EQ(answered.get_future().wait_for(3s), std::future_status::ready);
  // Room for a second answer to arrive if the request answers twice.
  std::this_thread::sleep_for(200ms);

  EXPECT_FALSE(sawReadResponse.load()) << "a withdrawn request must not answer with a Read response";
  EXPECT_EQ(responses.load(), 1) << "exactly one answer reaches the client";
  ASSERT_TRUE(faultStatus.has_value());
  EXPECT_EQ(*faultStatus, Status::BadRequestCancelledByClient);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// The same proof for TranslateBrowsePaths, which needs its own because the token is adopted from a
// per-component accessor: `TranslateBrowsePathsService::cancellation_token()` could be renamed,
// shadowed or deleted and nothing above would notice - the Read test drives a different service, and
// the primitive's own tests pass a token in by hand.
//
// The namespace holds the request's starting-node resolution, the client cancels, and the namespace
// then answers late. `Namespace::effective_permissions` is the first thing the translate path asks a
// namespace AFTER resolution - it authorizes the starting node before walking anything - so a count
// of zero is the evidence that the body unwound instead of walking a path whose response `cancel()`
// has already released.
TEST(RequestWithdrawalTests, CancellingATranslateStopsItsCoroutineWhereItWasSuspended)
{
  boost::asio::thread_pool threadPool;
  auto executor = threadPool.get_executor();

  auto server = make_server(executor);
  auto ns = make_shared<DeferringResolveNamespace>("uri://withdrawal-translate", executor);
  const uint16_t nsIndex = server.address_space().add_namespace_sync(ns);

  const NodeId start{nsIndex, 4000u};
  const NodeId child{nsIndex, 4001u};
  ns->create_node(start, NodeClass::Object);
  ns->create_node(child, NodeClass::Object);

  auto addressSpace = server.address_space();
  const QualifiedName childName{nsIndex, "Child"};
  auto childAccessor = addressSpace.try_find_node_sync(child);
  ASSERT_TRUE(childAccessor.is_good());
  childAccessor.value().set_browse_name(childName);
  auto startAccessor = addressSpace.try_find_node_sync(start);
  ASSERT_TRUE(startAccessor.is_good());
  startAccessor.value().try_add_reference_sync(
    NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{child}, /*isForward=*/true);

  auto sessionInfo = make_shared<SessionInfoStub>(std::move(server), executor);

  TranslateBrowsePathsToNodeIdsRequest request;
  request.request_header().request_handle() = 1;
  BrowsePath browsePath;
  browsePath.starting_node() = start;
  RelativePath relativePath;
  RelativePathElement element;
  element.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  element.is_inverse() = false;
  element.include_subtypes() = true;
  element.target_name() = childName;
  relativePath.elements().payload().push_back(std::move(element));
  browsePath.relative_path() = std::move(relativePath);
  request.browse_paths().payload().push_back(std::move(browsePath));

  std::promise<void> answered;
  std::atomic_int responses{0};
  std::optional<StatusCode> faultStatus;
  bool sawTranslateResponse = false;

  ns->reset_counts();
  ns->arm();
  auto service = TranslateBrowsePathsService::create(sessionInfo,
    {"en"},
    1,
    std::move(request),
    executor,
    [&](Response response)
    {
      if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
      {
        faultStatus = fault->response_header().service_result();
      }
      if (dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get()) != nullptr)
      {
        sawTranslateResponse = true;
      }
      if (++responses == 1)
      {
        answered.set_value();
      }
    });

  ASSERT_EQ(ns->held().wait_for(2s), std::future_status::ready)
    << "the request must be suspended on the namespace before anything is withdrawn";
  ASSERT_EQ(ns->permission_calls(), 0u) << "nothing past the resolution should have run yet";

  service->cancel();
  ASSERT_EQ(answered.get_future().wait_for(2s), std::future_status::ready);

  // ...and only now does the namespace answer the resolution, exactly as a slow collaborator would.
  ns->release();

  // Waits for the WRONG thing, because a body that unwound leaves no signal to wait for. Under a
  // mutation that removes the check the walk carries straight on and authorizes within milliseconds.
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (ns->permission_calls() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(10ms);
  }

  EXPECT_EQ(ns->permission_calls(), 0u)
    << "the resumed body must have unwound at its co_await, not carried on into authorization";
  EXPECT_FALSE(sawTranslateResponse)
    << "a withdrawn request must not also answer with a TranslateBrowsePaths response";
  EXPECT_EQ(responses.load(), 1) << "exactly one answer reaches the client";
  ASSERT_TRUE(faultStatus.has_value());
  EXPECT_EQ(*faultStatus, Status::BadRequestCancelledByClient);

  sessionInfo.reset();
  ::ua::test_utils::drain_with_timeout(threadPool);
}
