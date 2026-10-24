// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include "ua_claim_keys.h"

#include "test_utilities.h"

#include <chrono>
#include <memory>
#include <thread>

namespace
{

/// Waits for @p predicate to hold, bounded by the shared poll budget.
///
/// The rows below used to "flush" by posting ONE sentinel to the thread pool and waiting on it. That
/// proves only that some thread ran the sentinel - not that teardown or registry work queued earlier has
/// finished, because another pool thread can still be running it. The subscription-unregister row passed
/// alone and failed in a full run for exactly that reason: the assertion raced the unregister.
///
/// The budget bounds a hang; it asserts no latency. A row that needs the whole budget still passes, and
/// one whose effect never arrives fails with the assertion that names it.
template<typename Predicate>
bool wait_for_condition(Predicate predicate)
{
  const auto deadline = std::chrono::steady_clock::now() + ua::test_utils::default_poll_budget();
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
  }
  return predicate();
}

}  // namespace

#include "ua_subscriptions_pipeline.h"
#include "ua_subscriptions_pipeline_test_access.h"
#include "ua_subscription_test_access.h"
#include "ua_subscription_transfer_authorization.h"
#include "ua_subscription_router.h"
#include "ua_orphaned_subscription_store.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_subscription_id_allocator.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_transfer_result.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_service_fault.h"
#include "ua_status_change_notification.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_monitored_item.h"
#include "ua_session_security.h"
#include "security/ua_server_authentication.h"
#include "ua_address_space.h"
#include "ua_audit_session_event_payload.h"
#include "ua_base_event.h"
#include "ua_data_change_notification.h"
#include "ua_event_bus.h"
#include "ua_event_notification_list.h"

#include "access_control_test_support.h"

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <future>
#include <mutex>
#include <thread>

using namespace ua;
using namespace ua::server;
using STA = SubscriptionTestAccess;
using SMTA = SubscriptionsPipelineTestAccess;

namespace
{

struct alignas(std::max_align_t) SessionRegistryOwnerToken
{};

std::shared_ptr<Session> make_session_registry_placeholder()
{
  auto owner = std::make_shared<SessionRegistryOwnerToken>();
  auto* identity = reinterpret_cast<Session*>(owner.get());
  return std::shared_ptr<Session>{std::move(owner), identity};
}

/// Minimal SessionSecurityContext for tests.
class FakeSecurityContext : public SessionSecurityContext
{
public:
  ua::NodeId session_id() const override
  {
    return sessionId;
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return endpointSecurity;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return userIdentity;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return accessIdentity;
  }

  ua::NodeId sessionId;
  std::shared_ptr<const EndpointSecurityContext> endpointSecurity{
    std::make_shared<EndpointSecurityContext>()};
  std::shared_ptr<const UserIdentity> userIdentity{std::make_shared<UserIdentity>()};
  std::shared_ptr<const AccessIdentity> accessIdentity;
};

/// Test harness for TransferSubscriptions tests.
class TransferSubTest : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  SubscriptionIdAllocator mIdAllocator;
  SubscriptionRouter mRegistry;
  OrphanedSubscriptionStore mOrphanStore;
  std::shared_ptr<ServerSummaryCounters> mCounters{std::make_shared<ServerSummaryCounters>()};
  optional<AddressSpace> mAccessAddressSpace;
  const NodeId mAccessNodeId{0, 7000u};
  /// Resolved once in SetUp, on the test thread: configure_replay_item runs on a Subscription's strand,
  /// where a blocking lookup is refused.
  std::optional<NodeAccessor> mAccessNode;

  // Session A (source)
  std::mutex mMutexA;
  std::condition_variable mCvA;
  std::vector<Response> mResponsesA;
  std::shared_ptr<SubscriptionsPipeline> mMgrA;
  std::shared_ptr<FakeSecurityContext> mSecCtxA{std::make_shared<FakeSecurityContext>()};

  // Session B (target)
  std::mutex mMutexB;
  std::condition_variable mCvB;
  std::vector<Response> mResponsesB;
  std::shared_ptr<SubscriptionsPipeline> mMgrB;
  std::shared_ptr<FakeSecurityContext> mSecCtxB{std::make_shared<FakeSecurityContext>()};

  // Non-dereferenceable Session identities used only for registry ownership.
  std::shared_ptr<Session> mFakeSessionA;
  std::shared_ptr<Session> mFakeSessionB;

  void SetUp() override
  {
    mFakeSessionA = make_session_registry_placeholder();
    mFakeSessionB = make_session_registry_placeholder();

    // Set up default user identities.
    mSecCtxA->userIdentity = std::make_shared<const UserIdentity>(
      UserIdentity{.userId = "testUser", .kind = UserTokenKind::UserName});
    mSecCtxB->userIdentity = std::make_shared<const UserIdentity>(
      UserIdentity{.userId = "testUser", .kind = UserTokenKind::UserName});

    mAccessAddressSpace = AddressSpace::create("urn:transfer-access-test", mThreadPool.get_executor());
    mAccessNode = mAccessAddressSpace->create_node_sync(mAccessNodeId, NodeClass::Variable);
    mSecCtxA->accessIdentity = ua::test_helpers::configure_test_access(
      *mAccessAddressSpace, mSecCtxA->userIdentity, mSecCtxA->endpointSecurity);
    mSecCtxB->accessIdentity = std::make_shared<AccessIdentity>(AccessIdentityKey{2},
      std::vector<NodeId>{ua::test_helpers::test_access_role_id()},
      mSecCtxB->userIdentity,
      mSecCtxB->endpointSecurity,
      String{"urn:test:transfer-client"});
  }

  /// Waits for everything already handed to @p strand to have run.
  ///
  /// The service entry points hop onto the session strand when called from off it, which the test
  /// thread is. A strand runs its handlers in order, so a barrier posted after the call has
  /// necessarily run after it.
  static void settle(boost::asio::strand<boost::asio::any_io_executor>& strand)
  {
    std::promise<void> reached;
    auto barrier = reached.get_future();
    boost::asio::post(strand, [&reached] { reached.set_value(); });
    barrier.wait();
  }

  /// Runs `handle_transfer_subscriptions` ON the session strand, and waits.
  ///
  /// `ua_subscriptions_pipeline.h` declares that entry point as running on the session strand, and
  /// the pipeline relies on it: `start_transfer` assigns `mTransferTask` directly, while
  /// `release_transfer_slot` clears the same member from a handler POSTED to that strand. Called
  /// straight from the test thread, those two race - TSan reports both sides inside
  /// `Task::operator=`, each destroying a coroutine frame - and the damage surfaces later as
  /// `malloc(): unaligned tcache chunk` in whatever test runs next.
  void transfer_on_strand(const std::shared_ptr<SubscriptionsPipeline>& pipeline,
    boost::asio::strand<boost::asio::any_io_executor>& strand, uint32_t requestId,
    const TransferSubscriptionsRequest& request)
  {
    std::promise<void> done;
    auto finished = done.get_future();
    boost::asio::dispatch(strand,
      [&]
      {
        pipeline->handle_transfer_subscriptions(requestId, request);
        done.set_value();
      });
    finished.wait();
  }

  /// Runs `close_all` ON the session strand, and waits: it reads the transfer slot that
  /// `release_transfer_slot` clears from a handler posted to that strand.
  static void close_all_on_strand(const std::shared_ptr<SubscriptionsPipeline>& pipeline,
    boost::asio::strand<boost::asio::any_io_executor>& strand)
  {
    std::promise<void> done;
    auto finished = done.get_future();
    boost::asio::dispatch(strand,
      [&]
      {
        pipeline->close_all();
        done.set_value();
      });
    finished.wait();
  }

  boost::asio::strand<boost::asio::any_io_executor> mStrandA{
    boost::asio::make_strand(mThreadPool.get_executor())};
  boost::asio::strand<boost::asio::any_io_executor> mStrandB{
    boost::asio::make_strand(mThreadPool.get_executor())};

  void TearDown() override
  {
    // Reset every executor-pinned member before draining the pool, otherwise
    // pool.join() blocks on the work-tracking any_io_executor that mMgrA/B
    // (and the fake sessions) keep alive.
    mFakeSessionA.reset();
    mFakeSessionB.reset();
    mMgrA.reset();
    mMgrB.reset();
    // Close any subscriptions still parked in the orphan store so their timers are cancelled before
    // the pool drains (an un-transferred orphan keeps its publishing timer armed).
    mOrphanStore.clear();
    mAccessAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void configure_replay_item(MonitoredItem& item)
  {
    item.itemToMonitor.node_id() = mAccessNodeId;
    item.itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    item.accessControlNode = *mAccessNode;
    item.accessSecurityContext = mSecCtxA;
    item.accessAddressSpace = mAccessAddressSpace->weak();
  }

  void create_manager_a(ServerConfig::ServerCapabilities caps = {})
  {
    auto ex = mThreadPool.get_executor();
    auto strand = boost::asio::make_strand(ex);
    mStrandA = strand;
    mMgrA = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
      .executor = ex,
      .sessionStrand = strand,
      .logger = Logger{},
      .idAllocator = mIdAllocator,
      .summaryCounters = mCounters,
      .capabilities = std::move(caps),
      .sendResponse =
        [this](Response r)
      {
        std::lock_guard lk(mMutexA);
        mResponsesA.push_back(std::move(r));
        mCvA.notify_all();
      },
      .addressSpace = mAccessAddressSpace->weak(),
      .subscriptionRouter = mRegistry.weak(),
      .orphanedSubscriptionStore = mOrphanStore.weak(),
      .owningSession = mFakeSessionA,
      .securityContext = mSecCtxA,
    });
  }

  void create_manager_b(ServerConfig::ServerCapabilities caps = {})
  {
    auto ex = mThreadPool.get_executor();
    auto strand = boost::asio::make_strand(ex);
    mStrandB = strand;
    mMgrB = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
      .executor = ex,
      .sessionStrand = strand,
      .logger = Logger{},
      .idAllocator = mIdAllocator,
      .summaryCounters = mCounters,
      .capabilities = std::move(caps),
      .sendResponse =
        [this](Response r)
      {
        std::lock_guard lk(mMutexB);
        mResponsesB.push_back(std::move(r));
        mCvB.notify_all();
      },
      .addressSpace = mAccessAddressSpace->weak(),
      .subscriptionRouter = mRegistry.weak(),
      .orphanedSubscriptionStore = mOrphanStore.weak(),
      .owningSession = mFakeSessionB,
      .securityContext = mSecCtxB,
    });
  }

  Response last_response_a()
  {
    std::lock_guard lk(mMutexA);
    EXPECT_FALSE(mResponsesA.empty());
    return mResponsesA.back();
  }

  Response last_response_b()
  {
    std::lock_guard lk(mMutexB);
    EXPECT_FALSE(mResponsesB.empty());
    return mResponsesB.back();
  }

  bool wait_for_responses_a(size_t count, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000})
  {
    std::unique_lock lk(mMutexA);
    return mCvA.wait_for(lk, timeout, [&] { return mResponsesA.size() >= count; });
  }

  bool wait_for_responses_b(size_t count, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000})
  {
    std::unique_lock lk(mMutexB);
    return mCvB.wait_for(lk, timeout, [&] { return mResponsesB.size() >= count; });
  }

  bool wait_for_notifications(const std::shared_ptr<Subscription>& subscription,
    std::chrono::milliseconds timeout = std::chrono::seconds{2})
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (subscription->get_info().hasNotifications)
        return true;
      std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    return subscription->get_info().hasNotifications;
  }

  IntegerId create_subscription_on_a(Duration interval = 1000)
  {
    CreateSubscriptionRequest req;
    req.requested_publishing_interval() = interval;
    req.requested_lifetime_count() = 30;
    req.requested_max_keep_alive_count() = 10;
    req.max_notifications_per_publish() = 0;
    req.publishing_enabled() = true;
    req.priority() = 0;
    mMgrA->handle_create_subscription(1, req);
    settle(mStrandA);
    auto resp = last_response_a();
    auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(resp.second.get());
    EXPECT_NE(csResp, nullptr);
    return csResp->subscription_id();
  }
};

// ============================================================
// SubscriptionRouter tests
// ============================================================

TEST_F(TransferSubTest, RegistryRegisterAndFind)
{
  SubscriptionRouter reg;
  auto session = mFakeSessionA;
  reg.register_subscription(42, session, {});
  EXPECT_EQ(reg.find_owner(42), session);
}

TEST_F(TransferSubTest, RegistryUnregister)
{
  SubscriptionRouter reg;
  reg.register_subscription(42, mFakeSessionA, {});
  reg.unregister_subscription(42);
  EXPECT_EQ(reg.find_owner(42), nullptr);
}

TEST_F(TransferSubTest, RegistryFindNonexistent)
{
  SubscriptionRouter reg;
  EXPECT_EQ(reg.find_owner(999), nullptr);
}

// ============================================================
// RAII Registration tests
// ============================================================

TEST_F(TransferSubTest, SubscriptionRegistersWithRegistryOnCreate)
{
  create_manager_a();
  auto subId = create_subscription_on_a();

  // The subscription should be registered in the server-level registry.
  auto owner = mRegistry.find_owner(subId);
  EXPECT_EQ(owner, mFakeSessionA);
}

TEST_F(TransferSubTest, SubscriptionUnregistersFromRegistryOnDestruction)
{
  create_manager_a();
  auto subId = create_subscription_on_a();
  EXPECT_NE(mRegistry.find_owner(subId), nullptr);

  // Close all subscriptions - this will eventually destroy them.
  mMgrA->close_all();
  mMgrA.reset();

  // Registry should no longer have the subscription.
  EXPECT_TRUE(wait_for_condition([&] { return mRegistry.find_owner(subId) == nullptr; }))
    << "a destroyed subscription must unregister from the server registry";
}

// ============================================================
// Detach tests (SubscriptionsPipeline level)
// ============================================================

TEST_F(TransferSubTest, DetachSubscriptionReturnsResultForExistingSubscription)
{
  create_manager_a();
  auto subId = create_subscription_on_a();

  auto result = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->subscription->id(), subId);

  // Subscription should no longer be in manager A.
  EXPECT_FALSE(mMgrA->has_subscription(subId));
}

TEST_F(TransferSubTest, DetachNonexistentReturnsNullopt)
{
  create_manager_a();
  auto result = mMgrA->detach_subscription_for_transfer(999);
  EXPECT_FALSE(result.has_value());
}

TEST_F(TransferSubTest, DetachQueuesStatusChangeNotificationForOldSession)
{
  create_manager_a();
  auto subId = create_subscription_on_a();

  auto result = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(result.has_value());

  // The StatusChangeNotification is pending for delivery to the old session
  // via a Publish request - it is NOT transferred to the new session.
  SMTA::on_strand(*mMgrA,
    [&](auto& g)
    {
      const auto& pending = g.pending_status_changes();
      ASSERT_FALSE(pending.empty());

      bool foundStatusChange = false;
      for (const auto& entry : pending)
      {
        EXPECT_EQ(entry.subscriptionId, subId);
        for (const auto& nd : entry.message.notification_data())
        {
          auto* inner = nd.inner_unique_ptr().get();
          if (dynamic_cast<const StatusChangeNotification*>(inner))
          {
            foundStatusChange = true;
          }
        }
      }
      EXPECT_TRUE(foundStatusChange);
    });

  // The retransmission entries returned for transfer should NOT contain the SCN.
  for (const auto& entry : result->retransmissionEntries)
  {
    for (const auto& nd : entry.message.notification_data())
    {
      EXPECT_EQ(dynamic_cast<const StatusChangeNotification*>(nd.inner_unique_ptr().get()), nullptr)
        << "StatusChangeNotification must not be transferred to new session";
    }
  }
}

// ============================================================
// Attach tests (SubscriptionsPipeline level)
// ============================================================

TEST_F(TransferSubTest, AttachAddsSubscriptionToNewManager)
{
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();
  auto result = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(result.has_value());

  mMgrB->attach_transferred_subscription(
    std::move(result->subscription), std::move(result->retransmissionEntries), false);

  EXPECT_TRUE(mMgrB->has_subscription(subId));
  EXPECT_FALSE(mMgrA->has_subscription(subId));
}

TEST_F(TransferSubTest, AttachMergesRetransmissionEntries)
{
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();
  auto result = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(result.has_value());

  size_t entryCount = result->retransmissionEntries.size();
  mMgrB->attach_transferred_subscription(
    std::move(result->subscription), std::move(result->retransmissionEntries), false);

  EXPECT_EQ(mMgrB->retransmission_queue_size(), entryCount);
}

// @relation(AC-SVR-AUTHZ-016-TRANSFER-REEVALUATES, scope=function)
TEST_F(TransferSubTest, AttachRetargetsSecurityViewAndReleasesSource)
{
  create_manager_a();
  create_manager_b();

  const auto subId = create_subscription_on_a();
  auto detached = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(detached.has_value());
  auto subscription = detached->subscription;

  STA::on_strand(*subscription,
    [source = mSecCtxA](auto& guard)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->accessSecurityContext = source;
      guard.add_monitored_item(std::move(item));
    });

  std::weak_ptr<FakeSecurityContext> sourceLifetime = mSecCtxA;
  mMgrB->attach_transferred_subscription(
    std::move(detached->subscription), std::move(detached->retransmissionEntries), false);
  STA::strand_barrier(*subscription);

  STA::on_strand(*subscription,
    [target = mSecCtxB](auto& guard)
    {
      ASSERT_EQ(guard.monitored_items().size(), 1U);
      EXPECT_EQ(guard.monitored_items().begin()->second->accessSecurityContext.lock(), target);
    });

  mSecCtxA.reset();
  EXPECT_TRUE(sourceLifetime.expired())
    << "pipeline, subscription and monitored item must not retain the source Session security view";
}

// ============================================================
// Server counter tests
// ============================================================

TEST_F(TransferSubTest, DetachDecrementsSubscriptionCount)
{
  create_manager_a();
  auto subId = create_subscription_on_a();

  auto before = mCounters->currentSubscriptionCount.load();
  mMgrA->detach_subscription_for_transfer(subId);
  auto after = mCounters->currentSubscriptionCount.load();

  EXPECT_EQ(after, before - 1);
}

TEST_F(TransferSubTest, AttachIncrementsSubscriptionCount)
{
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();
  auto result = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(result.has_value());

  auto before = mCounters->currentSubscriptionCount.load();
  mMgrB->attach_transferred_subscription(
    std::move(result->subscription), std::move(result->retransmissionEntries), false);
  auto after = mCounters->currentSubscriptionCount.load();

  EXPECT_EQ(after, before + 1);
}

// ============================================================
// handle_transfer_subscriptions tests (empty array)
// ============================================================

// @relation(SVR-XFER-OP-002, SVR-XFER-SVC-001, scope=function)
TEST_F(TransferSubTest, TransferEmptyArrayBadNothingToDo)
{
  create_manager_b();

  TransferSubscriptionsRequest req;
  // Empty subscription_ids.
  transfer_on_strand(mMgrB, mStrandB, 1, req);

  auto resp = last_response_b();
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadNothingToDo});
}

// ============================================================
// handle_transfer_subscriptions - nonexistent subscription
// ============================================================

// @relation(SVR-XFER-OP-001, SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubTest, TransferBadSubscriptionIdInvalid)
{
  create_manager_b();

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(999);
  size_t baseCount;
  {
    std::lock_guard lk(mMutexB);
    baseCount = mResponsesB.size();
  }
  transfer_on_strand(mMgrB, mStrandB, 1, req);

  ASSERT_TRUE(wait_for_responses_b(baseCount + 1));

  auto resp = last_response_b();
  auto* tsResp = dynamic_cast<TransferSubscriptionsResponse*>(resp.second.get());
  ASSERT_NE(tsResp, nullptr);
  ASSERT_EQ(tsResp->results().size(), 1u);
  EXPECT_EQ(tsResp->results()[0].status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
}

// The gate that refuses a second TransferSubscriptions while one is running is the transfer's own
// running flag, and a transfer that has answered is not running. What used to say so was a
// `unique_ptr` being reset at the one place the response was sent from; a body that ends in more
// than one place has to say so in all of them, and a Session that could never transfer again after
// its first attempt would have no way back.

// @relation(SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubTest, ASecondTransferIsAcceptedOnceTheFirstHasFinished)
{
  create_manager_b();

  const auto transferUnknownId = [&](uint32_t requestId)
  {
    size_t baseCount;
    {
      std::lock_guard lk(mMutexB);
      baseCount = mResponsesB.size();
    }
    TransferSubscriptionsRequest req;
    req.subscription_ids().push_back(999);
    transfer_on_strand(mMgrB, mStrandB, requestId, req);
    EXPECT_TRUE(wait_for_responses_b(baseCount + 1));
    return last_response_b();
  };

  auto first = transferUnknownId(1);
  auto* firstResponse = dynamic_cast<TransferSubscriptionsResponse*>(first.second.get());
  ASSERT_NE(firstResponse, nullptr);
  ASSERT_EQ(firstResponse->results().size(), 1u);
  ASSERT_EQ(firstResponse->results()[0].status_code(), StatusCode{Status::BadSubscriptionIdInvalid});

  auto second = transferUnknownId(2);
  ASSERT_EQ(dynamic_cast<ServiceFault*>(second.second.get()), nullptr)
    << "the second transfer was refused, so the first left the single-flight gate closed";
  auto* secondResponse = dynamic_cast<TransferSubscriptionsResponse*>(second.second.get());
  ASSERT_NE(secondResponse, nullptr);
  ASSERT_EQ(secondResponse->results().size(), 1u);
  EXPECT_EQ(secondResponse->results()[0].status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
}

// Ownership is the (token kind, user id) pair: an X.509 identity whose certificate name equals the
// owning UserName user's name does not own that user's Subscription.
// @relation(AC-SVR-XFER-002-OWNERSHIP-IS-THE-KIND-QUALIFIED-PRINCIPAL, scope=function)
TEST(TransferAuthorizationTest, OwnershipIsTheTokenKindAndUserIdPair)
{
  UserIdentity owner{.userId = "operator", .kind = UserTokenKind::UserName};
  UserIdentity sameNameX509{.userId = "operator", .kind = UserTokenKind::X509};
  SubscriptionTransferContext source{.owningUser = owner,
    .verifiedApplicationUri = "urn:test:source",
    .sourceSecurityMode = MessageSecurityMode::SignAndEncrypt};
  EndpointSecurityContext requestingSecurity;
  requestingSecurity.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  requestingSecurity.clientApplicationUri = "urn:test:source";

  EXPECT_EQ(validate_subscription_transfer(source, sameNameX509, requestingSecurity),
    StatusCode{Status::BadUserAccessDenied})
    << "a different token kind with the same user id is not the owner";
  EXPECT_TRUE(validate_subscription_transfer(source, owner, requestingSecurity).is_good())
    << "control: the owning (kind, user id) pair transfers";
}

// An X.509 user id is the certificate's common name, which two different certificates can share:
// the principal is the thumbprint claim the authenticator stored, and a missing claim fails closed.
// @relation(AC-SVR-XFER-002-OWNERSHIP-IS-THE-KIND-QUALIFIED-PRINCIPAL, scope=function)
TEST(TransferAuthorizationTest, X509OwnershipIsTheThumbprintNotTheCommonName)
{
  UserIdentity owner{
    .userId = "operator", .kind = UserTokenKind::X509, .claims = {{ClaimKeys::thumbprint, "AA11"}}};
  UserIdentity sameNameOtherCertificate{
    .userId = "operator", .kind = UserTokenKind::X509, .claims = {{ClaimKeys::thumbprint, "BB22"}}};
  UserIdentity sameNameNoClaim{.userId = "operator", .kind = UserTokenKind::X509};
  SubscriptionTransferContext source{.owningUser = owner,
    .verifiedApplicationUri = "urn:test:source",
    .sourceSecurityMode = MessageSecurityMode::SignAndEncrypt};
  EndpointSecurityContext requestingSecurity;
  requestingSecurity.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  requestingSecurity.clientApplicationUri = "urn:test:source";

  EXPECT_EQ(validate_subscription_transfer(source, sameNameOtherCertificate, requestingSecurity),
    StatusCode{Status::BadUserAccessDenied})
    << "another certificate with the same common name is not the owner";
  EXPECT_EQ(validate_subscription_transfer(source, sameNameNoClaim, requestingSecurity),
    StatusCode{Status::BadUserAccessDenied})
    << "an X.509 identity without a thumbprint claim cannot prove ownership";
  EXPECT_TRUE(validate_subscription_transfer(source, owner, requestingSecurity).is_good())
    << "control: the same certificate transfers";
}

// @relation(AC-SVR-XFER-003-ORPHAN-CONTEXT, scope=function)
TEST(TransferAuthorizationTest, AnonymousTransferRequiresSameApplicationUri)
{
  UserIdentity anonymous{.kind = UserTokenKind::Anonymous};
  SubscriptionTransferContext source{.owningUser = anonymous,
    .verifiedApplicationUri = "urn:test:source",
    .sourceSecurityMode = MessageSecurityMode::SignAndEncrypt};
  EndpointSecurityContext requestingSecurity;
  requestingSecurity.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  requestingSecurity.clientApplicationUri = "urn:test:target";

  const auto status = validate_subscription_transfer(source, anonymous, requestingSecurity);

  EXPECT_EQ(status, StatusCode{Status::BadUserAccessDenied});
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->source, "SubscriptionTransferAuthorization");
}

// @relation(AC-SVR-XFER-003-ORPHAN-CONTEXT, scope=function)
TEST(TransferAuthorizationTest, AnonymousTransferRequiresAuthenticatedRequestingChannel)
{
  UserIdentity anonymous{.kind = UserTokenKind::Anonymous};
  SubscriptionTransferContext source{.owningUser = anonymous,
    .verifiedApplicationUri = "urn:test:client",
    .sourceSecurityMode = MessageSecurityMode::SignAndEncrypt};
  EndpointSecurityContext requestingSecurity;
  requestingSecurity.messageSecurityMode = MessageSecurityMode::None;
  requestingSecurity.clientApplicationUri = "urn:test:client";

  const auto status = validate_subscription_transfer(source, anonymous, requestingSecurity);

  EXPECT_EQ(status, StatusCode{Status::BadUserAccessDenied});
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->source, "SubscriptionTransferAuthorization");
}

// @relation(AC-SVR-XFER-003-ORPHAN-CONTEXT, scope=function)
TEST(TransferAuthorizationTest, AnonymousTransferAcceptsSameClientOnAuthenticatedRequestingChannel)
{
  UserIdentity anonymous{.kind = UserTokenKind::Anonymous};
  SubscriptionTransferContext source{.owningUser = anonymous,
    .verifiedApplicationUri = "urn:test:client",
    .sourceSecurityMode = MessageSecurityMode::SignAndEncrypt};
  EndpointSecurityContext requestingSecurity;
  requestingSecurity.messageSecurityMode = MessageSecurityMode::Sign;
  requestingSecurity.clientApplicationUri = "urn:test:client";

  EXPECT_TRUE(validate_subscription_transfer(source, anonymous, requestingSecurity).is_good());
}

// @relation(AC-SVR-XFER-003-ORPHAN-CONTEXT, scope=function)
TEST(TransferAuthorizationTest, AnonymousTransferRejectsUnsignedSourceChannel)
{
  UserIdentity anonymous{.kind = UserTokenKind::Anonymous};
  SubscriptionTransferContext source{.owningUser = anonymous,
    .verifiedApplicationUri = "urn:test:client",
    .sourceSecurityMode = MessageSecurityMode::None};
  EndpointSecurityContext requestingSecurity;
  requestingSecurity.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  requestingSecurity.clientApplicationUri = "urn:test:client";

  EXPECT_EQ(validate_subscription_transfer(source, anonymous, requestingSecurity),
    StatusCode{Status::BadUserAccessDenied});
}

// ============================================================
// SVR-XFER-001: Subscription and MonitoredItems transferred to target Session
// ============================================================

// @relation(SVR-XFER-OP-002, SVR-XFER-SM-023, scope=function)
TEST_F(TransferSubTest, TransferBasicSuccess_SubscriptionMovedFromAToB)
{
  // SVR-XFER-001: The subscription shall be transferred to the target Session.
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();
  EXPECT_TRUE(mMgrA->has_subscription(subId));
  EXPECT_FALSE(mMgrB->has_subscription(subId));

  auto detachResult = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(detachResult.has_value());
  mMgrB->attach_transferred_subscription(
    std::move(detachResult->subscription), std::move(detachResult->retransmissionEntries), false);

  EXPECT_FALSE(mMgrA->has_subscription(subId));
  EXPECT_TRUE(mMgrB->has_subscription(subId));

  EXPECT_TRUE(wait_for_condition([&] { return mRegistry.find_owner(subId) == mFakeSessionB; }))
    << "the transfer must move registry ownership to the receiving session; it is "
    << (mRegistry.find_owner(subId) == mFakeSessionA ? "still session A" : "neither session");
}

// @relation(AC-SVR-XFER-004-TRANSFER-NOTIFICATION, scope=function)

// ============================================================
// SVR-XFER-004: StatusChangeNotification with Good_SubscriptionTransferred
// ============================================================

// @relation(SVR-XFER-OP-002, scope=function)
// @verifies AC-SVR-SUB-GEN-101-TRANSFERRED-CODE
TEST_F(TransferSubTest, StatusChangeNotificationHasGoodSubscriptionTransferredStatus)
{
  // SVR-XFER-004: Server shall issue StatusChangeNotification with status code
  // Good_SubscriptionTransferred to the old Session.
  create_manager_a();
  auto subId = create_subscription_on_a();

  auto result = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(result.has_value());

  // Verify the pending StatusChangeNotification has the correct status code.
  SMTA::on_strand(*mMgrA,
    [&](auto& g)
    {
      const auto& pending = g.pending_status_changes();

      bool foundWithCorrectStatus = false;
      for (const auto& entry : pending)
      {
        for (const auto& nd : entry.message.notification_data())
        {
          auto* scn = dynamic_cast<const StatusChangeNotification*>(nd.inner_unique_ptr().get());
          if (scn)
          {
            EXPECT_EQ(scn->status(), StatusCode{Status::GoodSubscriptionTransferred});
            foundWithCorrectStatus = true;
          }
        }
      }
      EXPECT_TRUE(foundWithCorrectStatus);
    });
}

TEST_F(TransferSubTest, DetachWithoutStatusChangeNotificationIfNotFound)
{
  // Negative: no StatusChangeNotification when subscription doesn't exist.
  create_manager_a();
  auto result = mMgrA->detach_subscription_for_transfer(999);
  EXPECT_FALSE(result.has_value());
}

// ============================================================
// SVR-XFER-005/006: sendInitialValues behavior
// ============================================================

// @relation(SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubTest, SendInitialValuesTrueRequeuesLastSentValues)
{
  // SVR-XFER-005: sendInitialValues=TRUE: first Publish response(s) shall contain
  // current values of Reporting MonitoredItems with empty queues and a lastSentValue.
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();

  // Get the subscription and add a monitored item with a lastSentValue.
  auto sub = SMTA::on_strand(*mMgrA,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      configure_replay_item(*item);
      // Simulate the two caches production owns after a value was published: the client-facing last
      // value and the user-independent source retained for projection under a transferred identity.
      DataValue lastValue{Variant{int32_t{42}}};
      lastValue.status() = StatusCode{Status::Good};
      item->lastSentValue = lastValue;
      item->lastUserIndependentValue = lastValue;
      g.add_monitored_item(std::move(item));
    });

  auto detachResult = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(detachResult.has_value());

  auto subBForFlush = detachResult->subscription;
  mMgrB->attach_transferred_subscription(
    std::move(detachResult->subscription), std::move(detachResult->retransmissionEntries), true);

  ASSERT_TRUE(wait_for_notifications(subBForFlush))
    << "sendInitialValues authorization and replay did not complete";

  // The subscription should now have notifications ready (re-queued lastSentValue).
  auto subB = SMTA::on_strand(*mMgrB,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(subB, nullptr);
  EXPECT_TRUE(subB->get_info().hasNotifications);
  STA::on_strand(*subB,
    [](auto& guard)
    {
      ASSERT_EQ(guard.monitored_items().size(), 1u);
      const auto& item = *guard.monitored_items().begin()->second;
      ASSERT_EQ(item.queue.size(), 1u);
      EXPECT_EQ(item.queue.front().status(), StatusCode{Status::Good});
      EXPECT_EQ(item.queue.front().value(), Variant{int32_t{42}});
    });
}

// @relation(AC-SVR-AUTHZ-016-TRANSFER-REEVALUATES, scope=function)
// @verifies(AC-SVR-AUTHZ-016-TRANSFER-REEVALUATES)
// @relation(AC-SVR-AUTHZ-016-TRANSFER-REEVALUATES, scope=function)
TEST_F(TransferSubTest, SendInitialValuesUsesTheTargetIdentity)
{
  create_manager_a();
  create_manager_b();

  mSecCtxB->accessIdentity = std::make_shared<AccessIdentity>(AccessIdentityKey{3},
    std::vector<NodeId>{},
    mSecCtxB->userIdentity,
    mSecCtxB->endpointSecurity,
    String{"urn:test:restricted-transfer-client"});

  const auto subId = create_subscription_on_a();
  auto sub = SMTA::on_strand(*mMgrA,
    [subId](auto& guard) -> std::shared_ptr<Subscription>
    {
      auto found = guard.subscriptions().find(subId);
      if (found == guard.subscriptions().end())
        return nullptr;
      return found->second;
    });
  ASSERT_NE(sub, nullptr);

  STA::on_strand(*sub,
    [&](auto& guard)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      configure_replay_item(*item);
      item->lastSentValue = DataValue{Variant{int32_t{42}}};
      guard.add_monitored_item(std::move(item));
    });

  auto detached = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(detached.has_value());
  auto transferred = detached->subscription;
  mMgrB->attach_transferred_subscription(
    std::move(detached->subscription), std::move(detached->retransmissionEntries), true);

  ASSERT_TRUE(wait_for_notifications(transferred)) << "target-identity denial was not queued";
  STA::on_strand(*transferred,
    [](auto& guard)
    {
      ASSERT_EQ(guard.monitored_items().size(), 1u);
      const auto& item = *guard.monitored_items().begin()->second;
      ASSERT_EQ(item.queue.size(), 1u);
      EXPECT_EQ(item.queue.front().status(), StatusCode{Status::BadUserAccessDenied});
      EXPECT_TRUE(item.queue.front().value().empty()) << "the source identity's cached value leaked";
    });
}

// @relation(SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubTest, SendInitialValuesFalseDoesNotRequeue)
{
  // SVR-XFER-006: sendInitialValues=FALSE: no re-queuing occurs.
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();

  auto sub = SMTA::on_strand(*mMgrA,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);

  STA::on_strand(*sub,
    [&](auto& g)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      configure_replay_item(*item);
      DataValue lastValue{Variant{int32_t{42}}};
      lastValue.status() = StatusCode{Status::Good};
      item->lastSentValue = lastValue;
      g.add_monitored_item(std::move(item));
    });

  auto detachResult = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(detachResult.has_value());

  auto subBForFlush = detachResult->subscription;
  mMgrB->attach_transferred_subscription(
    std::move(detachResult->subscription), std::move(detachResult->retransmissionEntries), false);

  // Flush the subscription strand to ensure attach processing is complete.
  STA::strand_barrier(*subBForFlush);

  // The subscription should NOT have re-queued notifications.
  auto subB = SMTA::on_strand(*mMgrB,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(subB, nullptr);
  EXPECT_FALSE(subB->get_info().hasNotifications);
}

// ============================================================
// SVR-XFER-007: subscriptionId shall be unique for entire Server
// ============================================================

// @relation(SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubTest, SubscriptionIdsAreServerWideUnique)
{
  // SVR-XFER-007: subscriptionId shall be unique for the entire Server, not just per-Session.
  // Both managers share the same allocator, so IDs should be unique across sessions.
  create_manager_a();
  create_manager_b();

  auto subIdA = create_subscription_on_a();

  // Create a subscription on manager B.
  CreateSubscriptionRequest req;
  req.requested_publishing_interval() = 1000;
  req.requested_lifetime_count() = 30;
  req.requested_max_keep_alive_count() = 10;
  req.max_notifications_per_publish() = 0;
  req.publishing_enabled() = true;
  req.priority() = 0;
  mMgrB->handle_create_subscription(2, req);
  settle(mStrandB);
  auto resp = last_response_b();
  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(resp.second.get());
  ASSERT_NE(csResp, nullptr);
  auto subIdB = csResp->subscription_id();

  EXPECT_NE(subIdA, subIdB);
}

// ============================================================
// SVR-XFER-008: Retransmission queue moved from old to new Session
// ============================================================

// @relation(SVR-XFER-OP-002, scope=function)
TEST_F(TransferSubTest, RetransmissionQueueEntriesMovedToNewSession)
{
  // SVR-XFER-008: queued NotificationMessages are moved from the old to the new Session.
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();

  // A fresh subscription has no retransmission entries. Manually add one to simulate
  // a previously-sent notification sitting in the retransmission queue. Its immutable
  // diagnostic table must move with the message because DiagnosticInfo stores table indices.
  auto diagnosticTable = std::make_shared<const Array<String>>(Array<String>{String{"transfer-diagnostic"}});
  SMTA::on_strand(*mMgrA,
    [&](auto& g)
    {
      NotificationMessage fakeMsg;
      fakeMsg.sequence_number() = 42;
      fakeMsg.publish_time() = DateTime::now();
      g.retransmission_queue().push_back(
        SubscriptionsPipeline::RetransmissionEntry{subId, std::move(fakeMsg), diagnosticTable});
    });

  auto result = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(result.has_value());

  // Retransmission entries extracted from A's queue.
  EXPECT_FALSE(result->retransmissionEntries.empty());

  // A's retransmission queue should be empty for this sub.
  SMTA::on_strand(*mMgrA,
    [&](auto& g)
    {
      const auto& retransmitA = g.retransmission_queue();
      for (const auto& entry : retransmitA)
      {
        EXPECT_NE(entry.subscriptionId, subId);
      }
    });

  // After attach, entries should be in B's queue.
  size_t count = result->retransmissionEntries.size();
  mMgrB->attach_transferred_subscription(
    std::move(result->subscription), std::move(result->retransmissionEntries), false);

  SMTA::on_strand(*mMgrB,
    [&](auto& g)
    {
      const auto& retransmitB = g.retransmission_queue();
      size_t bCount = 0;
      for (const auto& entry : retransmitB)
      {
        if (entry.subscriptionId == subId)
        {
          ++bCount;
          ASSERT_NE(entry.diagnosticStringTable, nullptr);
          ASSERT_EQ(entry.diagnosticStringTable->size(), 1u);
          EXPECT_EQ(std::string{(*entry.diagnosticStringTable)[0]}, "transfer-diagnostic");
          EXPECT_EQ(entry.diagnosticStringTable, diagnosticTable)
            << "direct transfer should retain the exact immutable table object";
        }
      }
      EXPECT_EQ(bCount, count);
    });
}

TEST_F(TransferSubTest, RetransmissionQueueNotMovedIfNoEntries)
{
  // Negative: no entries to move when there are no retransmission entries.
  create_manager_a();
  create_manager_b();

  // Close manager A's subscription normally and try detach - should return nullopt.
  auto result = mMgrA->detach_subscription_for_transfer(999);
  EXPECT_FALSE(result.has_value());
}

// ============================================================
// SVR-XFER-SM-022: Self-transfer rejected
// ============================================================

// @verifies AC-SVR-XFER-SM-022-SAME-SESSION-REFUSED
// @relation(AC-SVR-XFER-SM-022-SAME-SESSION-REFUSED, scope=function)
TEST_F(TransferSubTest, SelfTransferRejected)
{
  // SVR-XFER-SM-022: SessionChanged()==FALSE -> ReturnNegativeResponse().
  // When the subscription already belongs to this session, transfer should return BadNothingToDo.
  create_manager_a();
  auto subId = create_subscription_on_a();
  auto subscription = mMgrA->find_subscription(subId);
  ASSERT_NE(subscription, nullptr);

  constexpr uint32_t decayedLifetime = 7;
  STA::on_strand(*subscription, [](auto& guard) { guard.lifetime_counter() = decayedLifetime; });
  EXPECT_EQ(
    STA::on_strand(*subscription, [](auto& guard) { return guard.lifetime_counter(); }), decayedLifetime);

  // Try to transfer to the same manager (same session).
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  size_t baseCountA;
  {
    std::lock_guard lk(mMutexA);
    baseCountA = mResponsesA.size();
  }
  transfer_on_strand(mMgrA, mStrandA, 1, req);

  ASSERT_TRUE(wait_for_responses_a(baseCountA + 1));

  auto resp = last_response_a();
  auto* tsResp = dynamic_cast<TransferSubscriptionsResponse*>(resp.second.get());
  ASSERT_NE(tsResp, nullptr);
  ASSERT_EQ(tsResp->results().size(), 1u);
  EXPECT_EQ(tsResp->results()[0].status_code(), StatusCode{Status::BadNothingToDo});

  // A strand round-trip queues after on_service_call_async(), so this assertion
  // proves transition 22 ran ResetLifetimeCounter() for the refused request.
  const auto [currentLifetime, maximumLifetime] = STA::on_strand(
    *subscription, [](auto& guard) { return std::pair{guard.lifetime_counter(), guard.lifetime_count()}; });
  EXPECT_EQ(currentLifetime, maximumLifetime);

  // Subscription should still be in manager A (not detached).
  EXPECT_TRUE(mMgrA->has_subscription(subId));
}

// ============================================================
// SVR-XFER-SVC-001: BadNothingToDo for empty subscription list
// ============================================================

// Already tested by TransferEmptyArrayBadNothingToDo above.

// ============================================================
// SVR-XFER-OP-001: BadSubscriptionIdInvalid for nonexistent subscription
// ============================================================

// Already tested by TransferBadSubscriptionIdInvalid above.

// ============================================================
// Mixed results: some valid, some invalid
// ============================================================

// @relation(SVR-XFER-OP-001, scope=function)
TEST_F(TransferSubTest, MixedResultsSomeValidSomeInvalid)
{
  // Tests mixed detach results: one valid subscription, one nonexistent.
  // This tests the per-item error handling at the SubscriptionsPipeline level.
  create_manager_a();
  create_manager_b();

  auto subId1 = create_subscription_on_a();

  // Detach the valid one - should succeed.
  auto result1 = mMgrA->detach_subscription_for_transfer(subId1);
  EXPECT_TRUE(result1.has_value());

  // Try to detach a nonexistent one - should return nullopt.
  auto result2 = mMgrA->detach_subscription_for_transfer(99999);
  EXPECT_FALSE(result2.has_value());

  // Attach only the valid one.
  mMgrB->attach_transferred_subscription(
    std::move(result1->subscription), std::move(result1->retransmissionEntries), false);
  EXPECT_TRUE(mMgrB->has_subscription(subId1));
}

// @relation(SVR-XFER-OP-001, scope=function)
TEST_F(TransferSubTest, TransferMultipleNonexistentBadSubscriptionIdInvalid)
{
  // Negative: multiple nonexistent subscription IDs all return BadSubscriptionIdInvalid.
  create_manager_b();

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(111);
  req.subscription_ids().push_back(222);
  req.subscription_ids().push_back(333);
  size_t baseCountB;
  {
    std::lock_guard lk(mMutexB);
    baseCountB = mResponsesB.size();
  }
  transfer_on_strand(mMgrB, mStrandB, 1, req);

  ASSERT_TRUE(wait_for_responses_b(baseCountB + 1));

  auto resp = last_response_b();
  auto* tsResp = dynamic_cast<TransferSubscriptionsResponse*>(resp.second.get());
  ASSERT_NE(tsResp, nullptr);
  ASSERT_EQ(tsResp->results().size(), 3u);
  for (size_t i = 0; i < 3; ++i)
  {
    EXPECT_EQ(tsResp->results()[i].status_code(), StatusCode{Status::BadSubscriptionIdInvalid});
  }
}

// ============================================================
// XFER-RAII: Subscription destructor unregisters from registry
// ============================================================

TEST_F(TransferSubTest, RegistryRAII_DestructorUnregisters)
{
  // Verify the RAII pattern: Subscription destructor removes from registry.
  auto ex = mThreadPool.get_executor();

  auto sub = Subscription::create(
    42, 1000, 30, 10, 0, true, 0, ex, [](IntegerId) {}, [](IntegerId) {}, mRegistry.weak(), mFakeSessionA);

  EXPECT_NE(mRegistry.find_owner(42), nullptr);

  // Close on the strand and wait for it to complete.
  STA::on_strand(*sub, [](auto& g) { g.close(); });
  sub.reset();

  EXPECT_TRUE(wait_for_condition([&] { return mRegistry.find_owner(42) == nullptr; }))
    << "the destructor must remove the subscription's registry entry";
}

TEST_F(TransferSubTest, RegistryRAII_NoRegistryDoesNotCrash)
{
  // Negative: Subscription without registry (nullptr) - no crash on destruction.
  auto ex = mThreadPool.get_executor();

  auto sub = Subscription::create(42, 1000, 30, 10, 0, true, 0, ex, [](IntegerId) {}, [](IntegerId) {});

  STA::on_strand(*sub, [](auto& g) { g.close(); });
  sub.reset();

  // Flush the executor to ensure destructor side effects are processed.
  {
    std::promise<void> flushed;
    boost::asio::post(ex, [&flushed]() { flushed.set_value(); });
    flushed.get_future().get();
  }
  // No crash expected.
}

// ============================================================
// F34: CloseSession(deleteSubscriptions=false) -> orphan -> transfer to a new session
// ============================================================

// A parked (orphaned) subscription holds no session; its MonitoredItems must not keep counting against
// the server-wide MaxMonitoredItems, or a closed session's orphans deny every other client their
// slots. A transfer gives it a session again and re-acquires them; closing an orphan releases nothing
// twice.
// @relation(AC-SVR-SUB-GEN-032-ORPHANS-RELEASE-MONITORED-ITEM-SLOTS, scope=function)
TEST_F(TransferSubTest, OrphaningReleasesServerMonitoredItemSlotsAndTransferReacquiresThem)
{
  create_manager_a();
  create_manager_b();

  const auto subId = create_subscription_on_a();
  auto owner = mRegistry.find_owner(subId);
  ASSERT_NE(owner, nullptr);
  auto subscription = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(subscription.has_value());
  // Two MonitoredItems, counted against the server gauge the way CreateMonitoredItems counts them.
  STA::on_strand(*subscription->subscription,
    [source = mSecCtxA](auto& guard)
    {
      for (int i = 0; i < 2; ++i)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->accessSecurityContext = source;
        guard.add_monitored_item(std::move(item));
      }
    });
  STA::strand_barrier(*subscription->subscription);
  auto held = subscription->subscription;  // to barrier on the subscription strand after close_all
  mCounters->currentMonitoredItemCount.store(2, std::memory_order_relaxed);
  mMgrA->attach_transferred_subscription(
    std::move(subscription->subscription), std::move(subscription->retransmissionEntries), false);

  UserIdentity user{.userId = "testUser", .kind = UserTokenKind::UserName};
  mMgrA->orphan_all(SubscriptionTransferContext{.owningUser = user});
  ASSERT_TRUE(mOrphanStore.contains(subId));
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 0u)
    << "an orphaned subscription's MonitoredItems are released from the server-wide gauge";

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;
  transfer_on_strand(mMgrB, mStrandB, 1, req);
  settle(mStrandB);
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 2u)
    << "a transferred subscription's MonitoredItems count against the gauge again";

  close_all_on_strand(mMgrB, mStrandB);
  settle(mStrandB);
  STA::strand_barrier(*held);  // close_async runs on the subscription strand
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 0u) << "closing releases them once";
}

// A parked subscription holds no slots, whatever path an item arrives by: a create-time reservation
// that commits after the subscription was parked (the create was in flight on the subscription
// strand while the session closed) is handed straight back to the gauge, and the item is claimed
// again, with the others, only when a transfer gives it a session.
// @relation(AC-SVR-SUB-GEN-032-ORPHANS-RELEASE-MONITORED-ITEM-SLOTS, scope=function)
TEST_F(TransferSubTest, AReservedSlotCommittedWhileParkedIsHandedBackToTheGauge)
{
  create_manager_a();
  create_manager_b();

  const auto subId = create_subscription_on_a();
  auto subscription = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(subscription.has_value());
  STA::on_strand(*subscription->subscription,
    [source = mSecCtxA](auto& guard)
    {
      for (int i = 0; i < 2; ++i)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->accessSecurityContext = source;
        guard.add_monitored_item(std::move(item));
      }
    });
  STA::strand_barrier(*subscription->subscription);
  auto held = subscription->subscription;
  mCounters->currentMonitoredItemCount.store(2, std::memory_order_relaxed);
  mMgrA->attach_transferred_subscription(
    std::move(subscription->subscription), std::move(subscription->retransmissionEntries), false);

  UserIdentity user{.userId = "testUser", .kind = UserTokenKind::UserName};
  mMgrA->orphan_all(SubscriptionTransferContext{.owningUser = user});
  ASSERT_TRUE(mOrphanStore.contains(subId));
  ASSERT_EQ(mCounters->currentMonitoredItemCount.load(), 0u);

  // The reservation of an in-flight CreateMonitoredItems raised the gauge; its item commits now, on
  // the parked subscription.
  mCounters->currentMonitoredItemCount.fetch_add(1, std::memory_order_relaxed);
  STA::on_strand(*held, [](auto& guard) { guard.account_committed_item(/*reservedInGauge=*/true); });
  STA::strand_barrier(*held);
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 0u)
    << "a slot that commits on a parked subscription is handed back: an orphan holds none";

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;
  transfer_on_strand(mMgrB, mStrandB, 1, req);
  settle(mStrandB);
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 3u)
    << "the transfer claims every live item, including the one that committed while parked";

  close_all_on_strand(mMgrB, mStrandB);
  settle(mStrandB);
  STA::strand_barrier(*held);
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 0u) << "closing releases exactly the live count";
}

// The direct-remove seam is the partner of the direct-add seam: an item removed through it leaves
// the live count, so a later close releases exactly the items still held and the gauge never goes
// below its baseline.
// @relation(AC-SVR-SUB-GEN-032-ORPHANS-RELEASE-MONITORED-ITEM-SLOTS, scope=function)
TEST_F(TransferSubTest, RemovingADirectlyAddedItemKeepsTheReleaseExact)
{
  create_manager_a();
  const auto subId = create_subscription_on_a();
  auto subscription = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(subscription.has_value());
  auto held = subscription->subscription;
  mCounters->currentMonitoredItemCount.store(2, std::memory_order_relaxed);
  STA::on_strand(*held,
    [source = mSecCtxA](auto& guard)
    {
      ua::IntegerId first = 0;
      for (int i = 0; i < 2; ++i)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->accessSecurityContext = source;
        const auto id = guard.add_monitored_item(std::move(item));
        if (i == 0)
        {
          first = id;
        }
      }
      guard.remove_monitored_item(first);
    });
  STA::strand_barrier(*held);
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 1u) << "removing a held item releases its slot";
  mMgrA->attach_transferred_subscription(
    std::move(subscription->subscription), std::move(subscription->retransmissionEntries), false);

  mMgrA->close_all();
  settle(mStrandA);
  STA::strand_barrier(*held);
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 0u)
    << "closing releases exactly the one item still held; a stale count would wrap the gauge";
}

// Claiming an orphan's slots back is bounded by MaxMonitoredItems like any create: a transfer that
// would push the gauge past the cap is refused, and the orphan stays parked for a later attempt.
// @relation(AC-SVR-SUB-GEN-032-ORPHANS-RELEASE-MONITORED-ITEM-SLOTS, scope=function)
TEST_F(TransferSubTest, TransferringAnOrphanThatWouldExceedMaxMonitoredItemsIsRefused)
{
  create_manager_a();
  ServerConfig::ServerCapabilities caps;
  caps.maxMonitoredItems = 2;
  create_manager_b(caps);

  const auto subId = create_subscription_on_a();
  auto subscription = mMgrA->detach_subscription_for_transfer(subId);
  ASSERT_TRUE(subscription.has_value());
  STA::on_strand(*subscription->subscription,
    [source = mSecCtxA](auto& guard)
    {
      for (int i = 0; i < 2; ++i)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->accessSecurityContext = source;
        guard.add_monitored_item(std::move(item));
      }
    });
  STA::strand_barrier(*subscription->subscription);
  mCounters->currentMonitoredItemCount.store(2, std::memory_order_relaxed);
  mMgrA->attach_transferred_subscription(
    std::move(subscription->subscription), std::move(subscription->retransmissionEntries), false);
  UserIdentity user{.userId = "testUser", .kind = UserTokenKind::UserName};
  mMgrA->orphan_all(SubscriptionTransferContext{.owningUser = user});
  ASSERT_TRUE(mOrphanStore.contains(subId));
  ASSERT_EQ(mCounters->currentMonitoredItemCount.load(), 0u);

  // Another client took one of the two server-wide slots while the subscription was parked.
  mCounters->currentMonitoredItemCount.store(1, std::memory_order_relaxed);

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = false;
  size_t baseB;
  {
    std::lock_guard lk(mMutexB);
    baseB = mResponsesB.size();
  }
  transfer_on_strand(mMgrB, mStrandB, 1, req);
  ASSERT_TRUE(wait_for_responses_b(baseB + 1));
  auto* refused = dynamic_cast<TransferSubscriptionsResponse*>(last_response_b().second.get());
  ASSERT_NE(refused, nullptr);
  ASSERT_EQ(refused->results().size(), 1u);
  EXPECT_EQ(refused->results()[0].status_code().as_status(), Status::BadTooManyMonitoredItems)
    << "1 held + 2 claimed exceeds the server-wide ceiling of 2";
  EXPECT_TRUE(mOrphanStore.contains(subId)) << "a refused transfer leaves the orphan parked";
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 1u) << "nothing was claimed";

  // The other client released its slot: the same transfer now fits exactly.
  mCounters->currentMonitoredItemCount.store(0, std::memory_order_relaxed);
  transfer_on_strand(mMgrB, mStrandB, 2, req);
  ASSERT_TRUE(wait_for_responses_b(baseB + 2));
  auto* accepted = dynamic_cast<TransferSubscriptionsResponse*>(last_response_b().second.get());
  ASSERT_NE(accepted, nullptr);
  ASSERT_EQ(accepted->results().size(), 1u);
  EXPECT_TRUE(accepted->results()[0].status_code().is_good()) << "control: a transfer within the cap";
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(), 2u);
  EXPECT_FALSE(mOrphanStore.contains(subId));
}

// @relation(SVR-XFER-OP-002, AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY, scope=function)
TEST_F(TransferSubTest, OrphanedSubscriptionTransfersToNewSession)
{
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();
  ASSERT_NE(mRegistry.find_owner(subId), nullptr);
  constexpr uint32_t orphanedSequence = 73;
  auto orphanedTable = std::make_shared<const Array<String>>(Array<String>{String{"orphan-diagnostic"}});
  SMTA::on_strand(*mMgrA,
    [&](auto& pipeline)
    {
      NotificationMessage message;
      message.sequence_number() = orphanedSequence;
      message.publish_time() = DateTime::now();
      pipeline.retransmission_queue().push_back(
        SubscriptionsPipeline::RetransmissionEntry{subId, std::move(message), orphanedTable});
    });

  // Source session closes with deleteSubscriptions=false -> orphan instead of delete.
  UserIdentity owner{.userId = "testUser", .kind = UserTokenKind::UserName};
  mMgrA->orphan_all(SubscriptionTransferContext{.owningUser = owner});

  EXPECT_TRUE(mOrphanStore.contains(subId));
  EXPECT_EQ(mRegistry.find_owner(subId), nullptr) << "an orphaned subscription has no live owner";

  // A new session transfers the orphaned subscription.
  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  req.send_initial_values() = true;
  size_t baseB;
  {
    std::lock_guard lk(mMutexB);
    baseB = mResponsesB.size();
  }
  transfer_on_strand(mMgrB, mStrandB, 1, req);
  ASSERT_TRUE(wait_for_responses_b(baseB + 1));

  auto* tsResp = dynamic_cast<TransferSubscriptionsResponse*>(last_response_b().second.get());
  ASSERT_NE(tsResp, nullptr);
  ASSERT_EQ(tsResp->results().size(), 1u);
  EXPECT_EQ(tsResp->results()[0].status_code(), StatusCode{Status::Good});

  EXPECT_TRUE(mMgrB->has_subscription(subId));
  EXPECT_FALSE(mOrphanStore.contains(subId)) << "taken out of the store on transfer";
  EXPECT_EQ(mRegistry.find_owner(subId), mFakeSessionB) << "the new session now owns it";

  RepublishRequest republishRequest;
  republishRequest.subscription_id() = subId;
  republishRequest.retransmit_sequence_number() = orphanedSequence;
  {
    std::lock_guard lk(mMutexB);
    baseB = mResponsesB.size();
  }
  mMgrB->handle_republish(2, republishRequest);
  settle(mStrandB);
  ASSERT_TRUE(wait_for_responses_b(baseB + 1));

  // The retained message moves with the Subscription. Its diagnostics are rebuilt for the new Session
  // rather than replayed from the string table retained under the old one; this message has none.
  auto* republishResponse = dynamic_cast<RepublishResponse*>(last_response_b().second.get());
  ASSERT_NE(republishResponse, nullptr);
  EXPECT_EQ(republishResponse->notification_message().sequence_number(), orphanedSequence);
  EXPECT_TRUE(republishResponse->response_header().string_table().empty())
    << "a string table retained under the old Session must not be replayed to the new one";
}

// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-01-LIFETIME, scope=function)
TEST_F(TransferSubTest, RetransmissionProjectionSidecarsMoveWithTheirMessage)
{
  create_manager_a();
  create_manager_b();

  const auto subscriptionId = create_subscription_on_a();
  constexpr uint32_t sequenceNumber = 74;
  auto rawEvent = std::make_shared<BaseEvent>();
  rawEvent->eventId = ByteString{0x74};
  rawEvent->sourceNode = NodeId{0, 7401u};
  rawEvent->eventType = NodeId{0, 7402u};
  SMTA::on_strand(*mMgrA,
    [&](auto& pipeline)
    {
      NotificationMessage message;
      message.sequence_number() = sequenceNumber;
      auto data = std::make_unique<DataChangeNotification>();
      MonitoredItemNotification dataItem;
      dataItem.client_handle() = 741;
      dataItem.value() = DataValue{Variant{int32_t{941}}};
      data->monitored_items().push_back(std::move(dataItem));
      RefStructure<Structure> dataReference;
      dataReference.inner_unique_ptr() = std::move(data);
      message.notification_data().push_back(std::move(dataReference));

      auto events = std::make_unique<EventNotificationList>();
      EventFieldList event;
      event.client_handle() = 742;
      event.event_fields().push_back(Variant{ByteString{0x74}});
      events->events().push_back(std::move(event));
      RefStructure<Structure> eventReference;
      eventReference.inner_unique_ptr() = std::move(events);
      message.notification_data().push_back(std::move(eventReference));

      std::vector<RetainedDataProjection> dataProjections{
        RetainedDataProjection{741, NodeId{0, 7400u}, AttributeId::Value, DataValue{Variant{int32_t{141}}}}};
      std::vector<RetainedEventProjection> eventProjections{
        RetainedEventProjection{742, rawEvent->sourceNode, rawEvent->eventType, rawEvent, {}, {}}};
      pipeline.retransmission_queue().push_back(SubscriptionsPipeline::RetransmissionEntry{subscriptionId,
        std::move(message),
        nullptr,
        std::move(eventProjections),
        std::move(dataProjections)});
    });

  UserIdentity owner{.userId = "testUser", .kind = UserTokenKind::UserName};
  mMgrA->orphan_all(SubscriptionTransferContext{.owningUser = owner});
  ASSERT_TRUE(mOrphanStore.contains(subscriptionId));

  TransferSubscriptionsRequest request;
  request.subscription_ids().push_back(subscriptionId);
  size_t responseBase;
  {
    std::lock_guard lock(mMutexB);
    responseBase = mResponsesB.size();
  }
  transfer_on_strand(mMgrB, mStrandB, 1, request);
  ASSERT_TRUE(wait_for_responses_b(responseBase + 1));
  auto* response = dynamic_cast<TransferSubscriptionsResponse*>(last_response_b().second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  ASSERT_TRUE(response->results()[0].status_code().is_good());

  SMTA::on_strand(*mMgrB,
    [&](auto& pipeline)
    {
      const auto retained = std::ranges::find_if(pipeline.retransmission_queue(),
        [](const SubscriptionsPipeline::RetransmissionEntry& entry)
        { return entry.message.sequence_number() == sequenceNumber; });
      ASSERT_NE(retained, pipeline.retransmission_queue().end());
      ASSERT_EQ(retained->message.notification_data().size(), 2u);
      ASSERT_EQ(retained->dataProjections.size(), 1u);
      ASSERT_EQ(retained->eventProjections.size(), 1u);
      ASSERT_TRUE(retained->dataProjections[0].userIndependentValue.has_value());
      EXPECT_EQ(retained->dataProjections[0].userIndependentValue->value(), Variant{int32_t{141}});
      EXPECT_EQ(retained->eventProjections[0].clientHandle, 742u);
      EXPECT_EQ(retained->eventProjections[0].sourceNode, rawEvent->sourceNode);
      EXPECT_EQ(retained->eventProjections[0].eventType, rawEvent->eventType);
      EXPECT_EQ(retained->eventProjections[0].userIndependentEvent, rawEvent)
        << "transfer copied the wire message but detached its raw Event projection input";
    });
}

TEST_F(TransferSubTest, OrphanedSubscriptionTransferRejectedForDifferentUser)
{
  create_manager_a();
  create_manager_b();

  auto subId = create_subscription_on_a();

  // Orphaned by a different user than session B's requesting user (testUser).
  UserIdentity owner{.userId = "otherUser", .kind = UserTokenKind::UserName};
  mMgrA->orphan_all(SubscriptionTransferContext{.owningUser = owner});
  ASSERT_TRUE(mOrphanStore.contains(subId));

  TransferSubscriptionsRequest req;
  req.subscription_ids().push_back(subId);
  size_t baseB;
  {
    std::lock_guard lk(mMutexB);
    baseB = mResponsesB.size();
  }
  transfer_on_strand(mMgrB, mStrandB, 1, req);
  ASSERT_TRUE(wait_for_responses_b(baseB + 1));

  auto* tsResp = dynamic_cast<TransferSubscriptionsResponse*>(last_response_b().second.get());
  ASSERT_NE(tsResp, nullptr);
  ASSERT_EQ(tsResp->results().size(), 1u);
  EXPECT_EQ(tsResp->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_TRUE(mOrphanStore.contains(subId)) << "a rejected transfer must leave the orphan available";
}

// @relation(AC-SVR-XFER-003-ORPHAN-CONTEXT, scope=function)
TEST_F(TransferSubTest, OrphanedAnonymousTransferRetainsApplicationAndChannelContext)
{
  create_manager_a();
  mSecCtxB->userIdentity =
    std::make_shared<const UserIdentity>(UserIdentity{.kind = UserTokenKind::Anonymous});
  create_manager_b();

  const auto subscriptionId = create_subscription_on_a();
  UserIdentity anonymous{.kind = UserTokenKind::Anonymous};
  mMgrA->orphan_all(SubscriptionTransferContext{.owningUser = anonymous,
    .verifiedApplicationUri = "urn:test:application:x",
    .sourceSecurityMode = MessageSecurityMode::SignAndEncrypt});
  ASSERT_TRUE(mOrphanStore.contains(subscriptionId));

  auto transfer = [&](uint32_t requestId)
  {
    TransferSubscriptionsRequest request;
    request.subscription_ids().push_back(subscriptionId);
    size_t responseCount;
    {
      std::lock_guard lock(mMutexB);
      responseCount = mResponsesB.size();
    }
    transfer_on_strand(mMgrB, mStrandB, requestId, request);
    EXPECT_TRUE(wait_for_responses_b(responseCount + 1));
    auto* response = dynamic_cast<TransferSubscriptionsResponse*>(last_response_b().second.get());
    EXPECT_NE(response, nullptr);
    if (!response || response->results().empty())
    {
      return StatusCode{Status::BadInternalError};
    }
    return response->results()[0].status_code();
  };

  auto setTarget = [&](MessageSecurityMode mode, std::string_view applicationUri)
  {
    auto security = std::make_shared<EndpointSecurityContext>();
    security->messageSecurityMode = mode;
    security->clientApplicationUri = String{applicationUri};
    mSecCtxB->endpointSecurity = std::move(security);
  };

  setTarget(MessageSecurityMode::SignAndEncrypt, "urn:test:application:y");
  auto differentApplication = transfer(1);
  EXPECT_EQ(differentApplication, StatusCode{Status::BadUserAccessDenied});
  ASSERT_NE(differentApplication.shared_detail(), nullptr);
  EXPECT_EQ(differentApplication.shared_detail()->code, "AnonymousTransferContextInvalid");
  EXPECT_TRUE(mOrphanStore.contains(subscriptionId));

  setTarget(MessageSecurityMode::None, "urn:test:application:x");
  EXPECT_EQ(transfer(2), StatusCode{Status::BadUserAccessDenied});
  EXPECT_TRUE(mOrphanStore.contains(subscriptionId));

  setTarget(MessageSecurityMode::Sign, "urn:test:application:x");
  EXPECT_TRUE(transfer(3).is_good());
  EXPECT_FALSE(mOrphanStore.contains(subscriptionId));
  EXPECT_TRUE(mMgrB->has_subscription(subscriptionId));
}

// Part 4 section 5.13: the subscriptionId space is server-wide, not per-Session. An implementation that
// allocates ids from a per-Session counter passes a single-session test and still allocates the same id
// twice on two Sessions, at which point TransferSubscriptions - which names a Subscription by id
// alone - is ambiguous. Comparing one id per Session is not enough to catch it: two per-Session
// counters agree on their *whole sequence*, so the collision only shows when several ids are drawn
// from each Session and all of them are compared.
// @verifies AC-SVR-XFER-007-SUBSCRIPTIONID-SERVER-UNIQUE
TEST_F(TransferSubTest, SubscriptionIdsAreUniqueAcrossSessionsAndWithinASession)
{
  create_manager_a();
  create_manager_b();

  auto createSubscriptionOnB = [this](uint32_t requestId) -> IntegerId
  {
    CreateSubscriptionRequest req;
    req.requested_publishing_interval() = 1000;
    req.requested_lifetime_count() = 30;
    req.requested_max_keep_alive_count() = 10;
    req.max_notifications_per_publish() = 0;
    req.publishing_enabled() = true;
    req.priority() = 0;
    mMgrB->handle_create_subscription(requestId, req);
    settle(mStrandB);
    auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response_b().second.get());
    EXPECT_NE(csResp, nullptr);
    return csResp != nullptr ? csResp->subscription_id() : 0u;
  };

  // Interleave the two Sessions so a per-Session counter would hand out matching values.
  std::vector<IntegerId> idsA;
  std::vector<IntegerId> idsB;
  for (uint32_t round = 0; round < 3; ++round)
  {
    idsA.push_back(create_subscription_on_a());
    idsB.push_back(createSubscriptionOnB(100 + round));
  }

  ASSERT_EQ(idsA.size(), 3u);
  ASSERT_EQ(idsB.size(), 3u);

  std::vector<IntegerId> all;
  all.insert(all.end(), idsA.begin(), idsA.end());
  all.insert(all.end(), idsB.begin(), idsB.end());
  ASSERT_EQ(all.size(), 6u);

  for (size_t i = 0; i < all.size(); ++i)
  {
    for (size_t j = i + 1; j < all.size(); ++j)
    {
      EXPECT_NE(all[i], all[j]) << "subscriptionIds at " << i << " and " << j << " collide (both " << all[i]
                                << "): the id space is not server-wide";
    }
  }

  // A collision would also be invisible in the server-wide router, which keys owners by id alone:
  // each id must still resolve to the Session that created it.
  for (const auto id : idsA)
  {
    EXPECT_EQ(mRegistry.find_owner(id), mFakeSessionA) << "subscriptionId " << id;
  }
  for (const auto id : idsB)
  {
    EXPECT_EQ(mRegistry.find_owner(id), mFakeSessionB) << "subscriptionId " << id;
  }
}

// Part 4 section 6.5.10 requires an audit entry for every TransferSubscriptions call, not only the ones
// that succeed. The refused attempt is the security-relevant record - a client reaching for a
// Subscription owned by another user - and it is exactly the one a plausible implementation loses,
// either by emitting the audit on the success branch only or by leaving the refusal path short of
// the completion step that emits it.
// @verifies AC-SVR-XFER-010-TRANSFER-AUDIT
TEST_F(TransferSubTest, TransferIsAuditedOnRefusalAndOnSuccess)
{
  create_manager_a();

  auto addressSpace = AddressSpace::create("urn:transfer-audit-test", mThreadPool.get_executor());
  auto eventBus = std::make_shared<EventBus>(addressSpace);

  // Owned by the listener so a late dispatch cannot reference dead test locals.
  struct AuditSink
  {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<bool> transferAuditStatuses;
  };

  auto sink = std::make_shared<AuditSink>();

  eventBus->set_event_listener(
    [sink](const BaseEvent& event)
    {
      const auto* audit = dynamic_cast<const AuditSessionEventPayload*>(&event);
      if (audit == nullptr || audit->sourceName != "Session/TransferSubscriptions")
        return;
      {
        std::lock_guard lk(sink->mutex);
        sink->transferAuditStatuses.push_back(audit->status);
      }
      sink->cv.notify_all();
    });
  ASSERT_TRUE(eventBus->has_event_interest());

  // Target session with auditing enabled and the bus wired in.
  auto ex = mThreadPool.get_executor();
  auto strand = boost::asio::make_strand(ex);
  mStrandB = strand;
  mMgrB = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = ex,
    .sessionStrand = strand,
    .logger = Logger{},
    .idAllocator = mIdAllocator,
    .summaryCounters = mCounters,
    .sendResponse =
      [this](Response r)
    {
      std::lock_guard lk(mMutexB);
      mResponsesB.push_back(std::move(r));
      mCvB.notify_all();
    },
    .subscriptionRouter = mRegistry.weak(),
    .orphanedSubscriptionStore = mOrphanStore.weak(),
    .owningSession = mFakeSessionB,
    .securityContext = mSecCtxB,
    .eventBus = eventBus,
    .auditingEnabled = true,
    .applicationUri = "urn:transfer-audit-test",
  });

  const auto refusedId = create_subscription_on_a();
  const auto grantedId = create_subscription_on_a();

  // Both Subscriptions belong to "otherUser"; session B authenticates as "testUser" for now.
  UserIdentity owner{.userId = "otherUser", .kind = UserTokenKind::UserName};
  mMgrA->orphan_all(SubscriptionTransferContext{.owningUser = owner});
  ASSERT_TRUE(mOrphanStore.contains(refusedId));
  ASSERT_TRUE(mOrphanStore.contains(grantedId));

  auto waitForAudits = [&sink](size_t count)
  {
    std::unique_lock lk(sink->mutex);
    return sink->cv.wait_for(lk,
      std::chrono::milliseconds{2000},
      [&sink, count] { return sink->transferAuditStatuses.size() >= count; });
  };

  // 1. Refused: claiming another user's Subscription.
  {
    TransferSubscriptionsRequest req;
    req.subscription_ids().push_back(refusedId);
    size_t baseB;
    {
      std::lock_guard lk(mMutexB);
      baseB = mResponsesB.size();
    }
    transfer_on_strand(mMgrB, mStrandB, 1, req);
    ASSERT_TRUE(wait_for_responses_b(baseB + 1));

    auto* tsResp = dynamic_cast<TransferSubscriptionsResponse*>(last_response_b().second.get());
    ASSERT_NE(tsResp, nullptr);
    ASSERT_EQ(tsResp->results().size(), 1u);
    ASSERT_EQ(tsResp->results()[0].status_code(), StatusCode{Status::BadUserAccessDenied})
      << "the refusal under test must come from the transfer authorization, not from the fixture";
  }
  EXPECT_TRUE(waitForAudits(1)) << "a refused TransferSubscriptions raised no audit entry";

  // 2. Accepted: the owning user asks for the other Subscription.
  mSecCtxB->userIdentity = std::make_shared<const UserIdentity>(
    UserIdentity{.userId = "otherUser", .kind = UserTokenKind::UserName});
  {
    TransferSubscriptionsRequest req;
    req.subscription_ids().push_back(grantedId);
    size_t baseB;
    {
      std::lock_guard lk(mMutexB);
      baseB = mResponsesB.size();
    }
    transfer_on_strand(mMgrB, mStrandB, 2, req);
    ASSERT_TRUE(wait_for_responses_b(baseB + 1));

    auto* tsResp = dynamic_cast<TransferSubscriptionsResponse*>(last_response_b().second.get());
    ASSERT_NE(tsResp, nullptr);
    ASSERT_EQ(tsResp->results().size(), 1u);
    ASSERT_EQ(tsResp->results()[0].status_code(), StatusCode{Status::Good});
    ASSERT_TRUE(mMgrB->has_subscription(grantedId));
  }
  EXPECT_TRUE(waitForAudits(2)) << "a successful TransferSubscriptions raised no audit entry";

  std::lock_guard lk(sink->mutex);
  ASSERT_EQ(sink->transferAuditStatuses.size(), 2u);
  EXPECT_FALSE(sink->transferAuditStatuses[0]) << "the refused transfer must be audited as a failure";
  EXPECT_TRUE(sink->transferAuditStatuses[1]) << "the successful transfer must be audited as a success";
}

// A session that closes with deleteSubscriptions=false after the server's orphaned-subscription store has
// gone finds no store to park its Subscriptions in, and closes them instead: the router then lists none.
// @relation(AC-COMP-SVR-SUBSCRIPTION-SERVER-STATE-01-A-SESSION-CLOSE-AFTER-THE-STORE-HAS-GONE-CLOSES-ITS-SUBSCRIPTIONS, scope=function)
TEST_F(TransferSubTest, ASessionClosedAfterTheOrphanStoreHasGoneClosesItsSubscriptions)
{
  auto store = std::make_unique<OrphanedSubscriptionStore>();
  auto ex = mThreadPool.get_executor();
  mStrandA = boost::asio::make_strand(ex);
  mMgrA = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = ex,
    .sessionStrand = mStrandA,
    .logger = Logger{},
    .idAllocator = mIdAllocator,
    .summaryCounters = mCounters,
    .sendResponse =
      [this](Response r)
    {
      std::lock_guard lk(mMutexA);
      mResponsesA.push_back(std::move(r));
      mCvA.notify_all();
    },
    .addressSpace = mAccessAddressSpace->weak(),
    .subscriptionRouter = mRegistry.weak(),
    .orphanedSubscriptionStore = store->weak(),
    .owningSession = mFakeSessionA,
    .securityContext = mSecCtxA,
  });
  const auto subId = create_subscription_on_a();
  ASSERT_EQ(mRegistry.live_subscriptions().size(), 1u) << "precondition: the Subscription is registered";

  store.reset();
  mMgrA->orphan_all(SubscriptionTransferContext{
    .owningUser = UserIdentity{.userId = "testUser", .kind = UserTokenKind::UserName}});
  settle(mStrandA);

  // The close runs on the Subscription's own strand, and the Subscription leaves the router only when it is
  // destroyed after that: wait for both before asserting either.
  const auto left = [&]
  {
    return mRegistry.live_subscriptions().empty() && mRegistry.find_owner(subId) == nullptr;
  };
  bool closed = left();
  for (int attempt = 0; attempt < 300 && !closed; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
    closed = left();
  }
  EXPECT_EQ(mRegistry.find_owner(subId), nullptr);
  EXPECT_TRUE(mRegistry.live_subscriptions().empty()) << "the Subscription was neither parked nor closed";
}

// A CreateSubscription that runs after the server's SubscriptionId allocator has gone still allocates an id:
// the pipeline holds a copy of the allocator, which shares its counter.
// @relation(AC-COMP-SVR-SUBSCRIPTION-SERVER-STATE-01-A-CREATE-AFTER-THE-ALLOCATOR-HAS-GONE-ALLOCATES, scope=function)
TEST_F(TransferSubTest, ACreateSubscriptionAfterTheServersAllocatorHasGoneStillAllocates)
{
  auto allocator = std::make_unique<SubscriptionIdAllocator>();
  auto ex = mThreadPool.get_executor();
  mStrandA = boost::asio::make_strand(ex);
  mMgrA = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = ex,
    .sessionStrand = mStrandA,
    .logger = Logger{},
    .idAllocator = *allocator,
    .summaryCounters = mCounters,
    .sendResponse =
      [this](Response r)
    {
      std::lock_guard lk(mMutexA);
      mResponsesA.push_back(std::move(r));
      mCvA.notify_all();
    },
    .addressSpace = mAccessAddressSpace->weak(),
    .subscriptionRouter = mRegistry.weak(),
    .owningSession = mFakeSessionA,
    .securityContext = mSecCtxA,
  });

  allocator.reset();
  const auto subId = create_subscription_on_a();

  EXPECT_NE(subId, 0u);
  EXPECT_NE(mRegistry.find_owner(subId), nullptr) << "the Subscription was not created";
  mMgrA->close_all();
  settle(mStrandA);
}

// An operation-limit arm was retired here on 2026-08-10. Part 5 section 6.3.11 Table 19 scopes
// MaxMonitoredItemsPerCall to itemsToCreate/itemsToModify/monitoredItemIds/linksToAdd and
// linksToRemove, and no advertised limit covers subscriptionIds[] - so the ceiling this arm tried
// to build is unconstructible against a conforming Server. AC-SVR-XFER-SVC-002-TOOMANYOPERATIONS
// is discharged by the integration row rewritten to the narrowed reading.

}  // namespace
