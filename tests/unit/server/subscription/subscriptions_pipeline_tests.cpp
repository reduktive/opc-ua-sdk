// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include <limits>
#include <tuple>
#include <string>

#include "ua_diagnostic_bits.h"

#include "test_utilities.h"

#include "ua_subscriptions_pipeline.h"
#include "ua_subscriptions_pipeline_test_access.h"
#include "ua_subscription_test_access.h"
#include "ua_monitored_item.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_subscription_id_allocator.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_error_detail.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_service_fault.h"
#include "ua_status_change_notification.h"
#include <boost/asio/thread_pool.hpp>
#include <optional>

#include <atomic>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>

using namespace ua;
using namespace ua::server;

namespace
{

class PublishFaultLogSink final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    std::lock_guard lock{mutex};
    text += entry.message;
    for (const auto& field : entry.fields)
    {
      if (const auto* value = std::get_if<std::string_view>(&field.value))
        text += *value;
    }
  }

  bool contains(std::string_view expected)
  {
    std::lock_guard lock{mutex};
    return text.find(expected) != std::string::npos;
  }

private:
  std::mutex mutex;
  std::string text;
};

/// Test harness for SubscriptionsPipeline tests.
class SubMgrTest : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool{1};
  SubscriptionIdAllocator mIdAllocator;
  std::shared_ptr<ServerSummaryCounters> mCounters{std::make_shared<ServerSummaryCounters>()};
  std::chrono::steady_clock::time_point mMonotonicNow{};
  Logger mLogger;
  DiagnosticSecurityContext mDiagnosticSecurityContext{.authenticated = true,
    .securedChannel = true,
    .effectiveLevel = ServerConfig::DiagnosticPolicy::Level::Full,
    .maskPreAuthErrors = true};

  // Collected responses
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
  std::mutex mMutex;
  std::vector<Response> mResponses;
  std::optional<uint32_t> mMonitoredItemCountAtDeleteResponse;

  std::shared_ptr<SubscriptionsPipeline> mMgr;

  void SetUp() override
  {}

  void TearDown() override
  {
    // Reset members holding the work-tracking any_io_executor before draining.
    mMgr.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void create_manager(
    ServerConfig::ServerCapabilities caps = {}, ServerConfig::SubscriptionLimits subLimits = {})
  {
    auto ex = mThreadPool.get_executor();
    auto strand = boost::asio::make_strand(ex);
    mStrand = strand;
    mMgr = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
      .executor = ex,
      .sessionStrand = strand,
      .logger = mLogger,
      .idAllocator = mIdAllocator,
      .summaryCounters = mCounters,
      .capabilities = std::move(caps),
      .subscriptionLimits = std::move(subLimits),
      .sendResponse =
        [this](Response r)
      {
        std::lock_guard lk(mMutex);
        if (dynamic_cast<DeleteSubscriptionsResponse*>(r.second.get()) != nullptr)
        {
          mMonitoredItemCountAtDeleteResponse =
            mCounters->currentMonitoredItemCount.load(std::memory_order_relaxed);
        }
        mResponses.push_back(std::move(r));
        mResponseCv.notify_all();
      },
      .diagnosticSecurityContext = [this] { return mDiagnosticSecurityContext; },
      .monotonicNow = [this] { return mMonotonicNow; },
    });
  }

  /// Waits for everything already handed to the session strand to have run.
  ///
  /// The service entry points hop onto that strand when called from off it, which the test thread
  /// is. A strand runs its handlers in order, so a barrier posted after the call has necessarily run
  /// after it - no timeout, no polling, and no assumption about how long the work takes.
  void settle()
  {
    if (!mStrand)
    {
      return;
    }
    std::promise<void> reached;
    auto barrier = reached.get_future();
    boost::asio::post(*mStrand, [&reached] { reached.set_value(); });
    barrier.wait();
  }

  Response last_response()
  {
    settle();
    std::lock_guard lk(mMutex);
    EXPECT_FALSE(mResponses.empty());
    return mResponses.back();
  }

  size_t response_count()
  {
    settle();
    std::lock_guard lk(mMutex);
    return mResponses.size();
  }

  std::optional<uint32_t> monitored_item_count_at_delete_response()
  {
    std::lock_guard lk(mMutex);
    return mMonitoredItemCountAtDeleteResponse;
  }

  /// Wait until response_count() reaches at least `count`.
  bool wait_for_responses(size_t count, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000})
  {
    std::unique_lock lk(mMutex);
    return mResponseCv.wait_for(lk, timeout, [&] { return mResponses.size() >= count; });
  }

  std::condition_variable mResponseCv;

  CreateSubscriptionRequest make_create_request(
    Duration interval = 1000, uint32_t lifetime = 30, uint32_t keepAlive = 10, bool enabled = true)
  {
    CreateSubscriptionRequest req;
    req.requested_publishing_interval() = interval;
    req.requested_lifetime_count() = lifetime;
    req.requested_max_keep_alive_count() = keepAlive;
    req.max_notifications_per_publish() = 0;
    req.publishing_enabled() = enabled;
    req.priority() = 0;
    return req;
  }

  ModifySubscriptionRequest make_modify_request(
    IntegerId subId, Duration interval = 500, uint32_t lifetime = 30, uint32_t keepAlive = 10)
  {
    ModifySubscriptionRequest req;
    req.subscription_id() = subId;
    req.requested_publishing_interval() = interval;
    req.requested_lifetime_count() = lifetime;
    req.requested_max_keep_alive_count() = keepAlive;
    req.max_notifications_per_publish() = 0;
    req.priority() = 0;
    return req;
  }

  DeleteSubscriptionsRequest make_delete_request(std::vector<IntegerId> ids)
  {
    DeleteSubscriptionsRequest req;
    req.subscription_ids() = ids;
    return req;
  }

  /// Helper: create a subscription and return its ID from the response.
  IntegerId create_one_subscription(Duration interval = 1000)
  {
    auto req = make_create_request(interval);
    mMgr->handle_create_subscription(1, req);
    settle();
    auto resp = last_response();
    auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(resp.second.get());
    EXPECT_NE(csResp, nullptr);
    return csResp->subscription_id();
  }

  void seed_owned_resources(const std::shared_ptr<Subscription>& subscription, IntegerId subscriptionId,
    bool addRetransmission = true)
  {
    SubscriptionTestAccess::on_strand(*subscription,
      [this](auto& guard)
      {
        guard.summary_counters() = mCounters;
        EXPECT_NE(guard.add_monitored_item(std::make_unique<MonitoredItem>()), 0u);
      });
    mCounters->currentMonitoredItemCount.store(1, std::memory_order_relaxed);

    SubscriptionsPipelineTestAccess::on_strand(*mMgr,
      [subscriptionId, addRetransmission](auto& guard)
      {
        guard.atomic_total_monitored_item_count().store(1, std::memory_order_relaxed);
        if (addRetransmission)
        {
          NotificationMessage message;
          message.sequence_number() = 77;
          guard.retransmission_queue().push_back(
            SubscriptionsPipeline::RetransmissionEntry{subscriptionId, std::move(message), nullptr});
        }
      });
  }

  void wait_for_posted_work_to_drain()
  {
    std::promise<void> drained;
    auto drainedFuture = drained.get_future();
    boost::asio::post(mThreadPool, [&drained] { drained.set_value(); });
    drainedFuture.get();
  }

  bool wait_for_lifetime_to_expire(const std::weak_ptr<Subscription>& lifetime,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{2000})
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!lifetime.expired())
    {
      if (std::chrono::steady_clock::now() >= deadline)
        return false;
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return true;
  }

  size_t retransmission_queue_size_on_strand()
  {
    return SubscriptionsPipelineTestAccess::on_strand(
      *mMgr, [](auto& guard) { return guard.retransmission_queue().size(); });
  }
};

// ============================================================
// CreateSubscription tests
// ============================================================

TEST_F(SubMgrTest, CreateSub_ReturnsSubscriptionId)
{
  create_manager();
  auto req = make_create_request(1000);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto resp = last_response();
  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(resp.second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_GT(csResp->subscription_id(), 0u);
  EXPECT_EQ(mMgr->subscription_count(), 1u);
}

TEST_F(SubMgrTest, CreateSub_IdsAreUnique)
{
  create_manager();
  auto req1 = make_create_request(1000);
  mMgr->handle_create_subscription(1, req1);
  settle();
  auto resp1 = last_response();
  auto* csResp1 = dynamic_cast<CreateSubscriptionResponse*>(resp1.second.get());

  auto req2 = make_create_request(2000);
  mMgr->handle_create_subscription(2, req2);
  settle();
  auto resp2 = last_response();
  auto* csResp2 = dynamic_cast<CreateSubscriptionResponse*>(resp2.second.get());

  ASSERT_NE(csResp1, nullptr);
  ASSERT_NE(csResp2, nullptr);
  EXPECT_NE(csResp1->subscription_id(), csResp2->subscription_id());
}

TEST_F(SubMgrTest, CreateSub_UpdatesServerCounters)
{
  create_manager();
  EXPECT_EQ(mCounters->currentSubscriptionCount.load(), 0u);
  EXPECT_EQ(mCounters->cumulatedSubscriptionCount.load(), 0u);

  create_one_subscription();
  EXPECT_EQ(mCounters->currentSubscriptionCount.load(), 1u);
  EXPECT_EQ(mCounters->cumulatedSubscriptionCount.load(), 1u);

  create_one_subscription();
  EXPECT_EQ(mCounters->currentSubscriptionCount.load(), 2u);
  EXPECT_EQ(mCounters->cumulatedSubscriptionCount.load(), 2u);
}

TEST_F(SubMgrTest, ModifyMonitoredItemsOverConfiguredPerCallLimitIsRejected)
{
  ServerConfig::ServerCapabilities capabilities;
  capabilities.operationLimits.maxMonitoredItemsPerCall = 1;
  create_manager(capabilities);
  const auto subscriptionId = create_one_subscription();

  ModifyMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  request.items_to_modify().resize(2);

  mMgr->handle_modify_monitored_items(2, request);
  settle();

  auto response = last_response();
  auto* fault = dynamic_cast<ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadTooManyOperations});
}

// @verifies AC-SVR-BASE-007-DELETEMONITOREDITEMS-HONOURS-MAXMONITOREDITEMSPERCALL
TEST_F(SubMgrTest, DeleteMonitoredItemsOverConfiguredPerCallLimitIsRejected)
{
  ServerConfig::ServerCapabilities capabilities;
  capabilities.operationLimits.maxMonitoredItemsPerCall = 1;
  create_manager(capabilities);
  const auto subscriptionId = create_one_subscription();

  DeleteMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.monitored_item_ids().resize(2);

  mMgr->handle_delete_monitored_items(2, request);
  settle();

  auto response = last_response();
  auto* fault = dynamic_cast<ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "two ids over a limit of one is a service fault, nothing is deleted";
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadTooManyOperations});
}

// @verifies AC-SVR-BASE-007-DELETEMONITOREDITEMS-HONOURS-MAXMONITOREDITEMSPERCALL
// The control: a batch exactly at the limit is not refused for its size.
TEST_F(SubMgrTest, DeleteMonitoredItemsAtTheConfiguredPerCallLimitIsNotRefused)
{
  ServerConfig::ServerCapabilities capabilities;
  capabilities.operationLimits.maxMonitoredItemsPerCall = 1;
  create_manager(capabilities);
  const auto subscriptionId = create_one_subscription();

  DeleteMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.monitored_item_ids().resize(1);

  mMgr->handle_delete_monitored_items(2, request);
  settle();

  auto response = last_response();
  auto* fault = dynamic_cast<ServiceFault*>(response.second.get());
  EXPECT_TRUE(fault == nullptr || fault->response_header().service_result() != Status::BadTooManyOperations);
}

TEST_F(SubMgrTest, SetMonitoringModeOverConfiguredPerCallLimitIsRejected)
{
  ServerConfig::ServerCapabilities capabilities;
  capabilities.operationLimits.maxMonitoredItemsPerCall = 1;
  create_manager(capabilities);
  const auto subscriptionId = create_one_subscription();

  SetMonitoringModeRequest request;
  request.subscription_id() = subscriptionId;
  request.monitoring_mode() = MonitoringMode::Reporting;
  request.monitored_item_ids().push_back(11);
  request.monitored_item_ids().push_back(12);

  mMgr->handle_set_monitoring_mode(2, request);
  settle();

  auto response = last_response();
  auto* fault = dynamic_cast<ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadTooManyOperations});
}

// Part 5 section 6.3.11 defines MaxMonitoredItemsPerCall for SetTriggering as the combined size of
// linksToAdd and linksToRemove. Part 4 section 5.12.5.3 assigns an over-limit request
// Bad_TooManyOperations at service level, so no per-link mutation may run.
// @relation(AC-SVR-MI-GEN-105-SETTRIGGERING-SERVICE-CODES, scope=function)
TEST_F(SubMgrTest, SetTriggeringCombinedOperationLimitReturnsRichServiceFaultWithoutDispatch)
{
  constexpr uint32_t operationLimit = 2;
  ServerConfig::ServerCapabilities capabilities;
  capabilities.operationLimits.maxMonitoredItemsPerCall = operationLimit;
  create_manager(capabilities);
  const auto subscriptionId = create_one_subscription();
  auto subscription = mMgr->find_subscription(subscriptionId);
  ASSERT_NE(subscription, nullptr);

  const auto addMonitoredItem = [&]()
  {
    return SubscriptionTestAccess::on_strand(
      *subscription, [](auto& guard) { return guard.add_monitored_item(std::make_unique<MonitoredItem>()); });
  };
  const auto triggeringItemId = addMonitoredItem();
  const auto firstLinkedItemId = addMonitoredItem();
  const auto secondLinkedItemId = addMonitoredItem();

  // Control: exactly the combined limit is accepted and reaches the Subscription.
  SetTriggeringRequest atLimitRequest;
  atLimitRequest.subscription_id() = subscriptionId;
  atLimitRequest.triggering_item_id() = triggeringItemId;
  atLimitRequest.links_to_add().push_back(firstLinkedItemId);
  atLimitRequest.links_to_add().push_back(secondLinkedItemId);
  const auto beforeAtLimit = response_count();
  mMgr->handle_set_triggering(2, atLimitRequest);
  settle();
  ASSERT_TRUE(wait_for_responses(beforeAtLimit + 1u));

  auto atLimitResponse = last_response();
  auto* atLimitResults = dynamic_cast<SetTriggeringResponse*>(atLimitResponse.second.get());
  ASSERT_NE(atLimitResults, nullptr);
  ASSERT_EQ(atLimitResults->add_results().size(), size_t{operationLimit});
  EXPECT_EQ(atLimitResults->add_results()[0], StatusCode{Status::Good});
  EXPECT_EQ(atLimitResults->add_results()[1], StatusCode{Status::Good});

  // Leave only the first link installed before the negative arm.
  auto cleanupResult = SubscriptionTestAccess::on_strand(*subscription,
    [&](auto& guard)
    {
      return guard.set_triggering(
        triggeringItemId, std::vector<IntegerId>{}, std::vector<IntegerId>{secondLinkedItemId});
    });
  ASSERT_EQ(cleanupResult.removeResults.size(), 1u);
  ASSERT_EQ(cleanupResult.removeResults[0], StatusCode{Status::Good});

  // Each array is individually within the limit; only their overflow-safe combined size is too large.
  SetTriggeringRequest overLimitRequest;
  overLimitRequest.subscription_id() = subscriptionId;
  overLimitRequest.triggering_item_id() = triggeringItemId;
  overLimitRequest.links_to_remove().push_back(firstLinkedItemId);
  overLimitRequest.links_to_add().push_back(secondLinkedItemId);
  overLimitRequest.links_to_add().push_back(secondLinkedItemId);
  ASSERT_LE(overLimitRequest.links_to_add().size(), size_t{operationLimit});
  ASSERT_LE(overLimitRequest.links_to_remove().size(), size_t{operationLimit});

  const auto beforeOverLimit = response_count();
  mMgr->handle_set_triggering(3, overLimitRequest);
  settle();
  ASSERT_TRUE(wait_for_responses(beforeOverLimit + 1u));

  auto overLimitResponse = last_response();
  auto* overLimitFault = dynamic_cast<ServiceFault*>(overLimitResponse.second.get());
  EXPECT_NE(overLimitFault, nullptr)
    << "an over-limit SetTriggering is a whole-request ServiceFault, not per-link results";
  const auto overLimitStatus =
    overLimitFault ? overLimitFault->response_header().service_result() : StatusCode{Status::Good};
  EXPECT_EQ(overLimitStatus, StatusCode{Status::BadTooManyOperations});
  const auto detail = overLimitStatus.shared_detail();
  EXPECT_NE(detail, nullptr) << "the manufactured service failure must retain ErrorDetail";
  if (detail)
  {
    EXPECT_EQ(detail->code, "SetTriggeringTooManyOperations");
    ASSERT_EQ(detail->context.size(), 2u);
    EXPECT_EQ(detail->context[0].key, ContextKeys::sizeActual.value());
    EXPECT_EQ(detail->context[0].value, "3");
    EXPECT_EQ(detail->context[1].key, ContextKeys::sizeMax.value());
    EXPECT_EQ(detail->context[1].value, "2");
  }

  // A downstream call would remove the first link and add the second. Probe both sides of that state
  // change so the service-level refusal cannot pass while still mutating the Subscription.
  const auto [firstRemoval, secondRemoval] = SubscriptionTestAccess::on_strand(*subscription,
    [&](auto& guard)
    {
      auto first = guard.set_triggering(
        triggeringItemId, std::vector<IntegerId>{}, std::vector<IntegerId>{firstLinkedItemId});
      auto second = guard.set_triggering(
        triggeringItemId, std::vector<IntegerId>{}, std::vector<IntegerId>{secondLinkedItemId});
      return std::make_pair(first.removeResults.front(), second.removeResults.front());
    });
  EXPECT_EQ(firstRemoval, StatusCode{Status::Good})
    << "the rejected request must not remove an existing triggering link";
  EXPECT_EQ(secondRemoval, StatusCode{Status::BadMonitoredItemIdInvalid})
    << "the rejected request must not add a new triggering link";
}

// ============================================================
// Parameter revision tests
// ============================================================

// @relation(SVR-SUB-GEN-002, SVR-SUB-GEN-126, scope=function)
TEST_F(SubMgrTest, Gen002_ZeroPublishingIntervalRevisedToFastest)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.minPublishingInterval = std::chrono::milliseconds{100};
  create_manager({}, subLimits);

  auto req = make_create_request(0);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_EQ(csResp->revised_publishing_interval(), 100.0);
}

// @relation(SVR-SUB-GEN-002, scope=function)
TEST_F(SubMgrTest, Gen002_NegativePublishingIntervalRevisedToFastest)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.minPublishingInterval = std::chrono::milliseconds{100};
  create_manager({}, subLimits);

  auto req = make_create_request(-1.0);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_EQ(csResp->revised_publishing_interval(), 100.0);
}

// @relation(SVR-SUB-GEN-001, SVR-SUB-GEN-003, SVR-SUB-GEN-126, scope=function)
TEST_F(SubMgrTest, Gen003_PublishingIntervalHonoured)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.minPublishingInterval = std::chrono::milliseconds{100};
  subLimits.maxPublishingInterval = std::chrono::milliseconds{60000};
  create_manager({}, subLimits);

  auto req = make_create_request(500);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_EQ(csResp->revised_publishing_interval(), 500.0);
}

// @relation(SVR-SUB-GEN-003, scope=function)
TEST_F(SubMgrTest, Gen003_PublishingIntervalNegotiatedUp)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.minPublishingInterval = std::chrono::milliseconds{200};
  create_manager({}, subLimits);

  auto req = make_create_request(50);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_EQ(csResp->revised_publishing_interval(), 200.0);
}

TEST_F(SubMgrTest, CreateSub009_IntervalNegotiatedDown)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxPublishingInterval = std::chrono::milliseconds{5000};
  create_manager({}, subLimits);

  auto req = make_create_request(10000);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_EQ(csResp->revised_publishing_interval(), 5000.0);
}

// Covers SVR-SUB-GEN-114 (coverage-audit retag).
TEST_F(SubMgrTest, CreateSub005_ZeroKeepAliveRevisedToMin)
{
  create_manager();
  auto req = make_create_request(1000, 30, 0);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_GE(csResp->revised_max_keep_alive_count(), 1u);
}

// @relation(SVR-SUB-GEN-034, SVR-SUB-GEN-126, scope=function)
TEST_F(SubMgrTest, CreateSub003_LifetimeMinThreeTimesKeepAlive)
{
  create_manager();
  auto req = make_create_request(1000, 1, 10);  // lifetime=1, keepAlive=10 -> revised lifetime >= 30
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_GE(csResp->revised_lifetime_count(), 3 * csResp->revised_max_keep_alive_count());
}

// A parked subscription lives for lifetimeCount publishing intervals; the requested count is revised
// down to the configured maximum (never below three keep-alive counts).
// @relation(AC-SVR-SUB-GEN-034-LIFETIME-COUNT-IS-CAPPED, scope=function)
TEST_F(SubMgrTest, CreateSub_LifetimeCountIsRevisedDownToTheConfiguredMaximum)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxLifetimeCount = 100;
  create_manager({}, subLimits);

  auto req = make_create_request(1000, std::numeric_limits<uint32_t>::max(), 10);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_EQ(csResp->revised_lifetime_count(), 100u);
}

// @relation(AC-SVR-SUB-GEN-034-LIFETIME-COUNT-IS-CAPPED, scope=function)  // control arm
TEST_F(SubMgrTest, CreateSub_LifetimeCountUnderTheMaximumIsHonoured)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxLifetimeCount = 100;
  create_manager({}, subLimits);

  auto req = make_create_request(1000, 60, 10);
  mMgr->handle_create_subscription(1, req);
  settle();

  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  EXPECT_EQ(csResp->revised_lifetime_count(), 60u);
}

TEST_F(SubMgrTest, CreateSub006_ZeroMaxNotificationsIsUnlimited)
{
  create_manager();
  auto req = make_create_request();
  req.max_notifications_per_publish() = 0;
  mMgr->handle_create_subscription(1, req);
  settle();
  // Zero means unlimited - implementation should not fault.
  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
}

// ============================================================
// TooManySubscriptions
// ============================================================

// Covers SVR-SUB-GEN-116 (coverage-audit retag).
TEST_F(SubMgrTest, CreateSub_TooManySubscriptionsReturnsServiceFault)
{
  ServerConfig::ServerCapabilities caps;
  caps.maxSubscriptionsPerSession = 2;
  create_manager(caps);

  create_one_subscription();
  create_one_subscription();
  EXPECT_EQ(mMgr->subscription_count(), 2u);

  // Third should fail.
  auto req = make_create_request();
  mMgr->handle_create_subscription(100, req);
  settle();

  auto resp = last_response();
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadTooManySubscriptions});
  EXPECT_EQ(mMgr->subscription_count(), 2u);
}

// ============================================================
// ModifySubscription tests
// ============================================================

TEST_F(SubMgrTest, ModSub_ChangesApplied)
{
  create_manager();
  auto subId = create_one_subscription(1000);

  auto req = make_modify_request(subId, 2000, 60, 20);
  mMgr->handle_modify_subscription(2, req);
  settle();

  auto* resp = dynamic_cast<ModifySubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_EQ(resp->revised_publishing_interval(), 2000.0);
}

// ModifySubscription has no PublishingEnabled parameter (OPC 10000-4 5.13.3): a Subscription the client
// created with publishing disabled is still disabled after a modify, and only SetPublishingMode enables it.
// @relation(AC-SVR-SUB-GEN-117-MODIFY-KEEPS-PUBLISHING-MODE, scope=function)
TEST_F(SubMgrTest, ModSub_KeepsPublishingDisabled)
{
  create_manager();
  mMgr->handle_create_subscription(1, make_create_request(1000, 30, 10, /*enabled=*/false));
  settle();
  auto* created = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(created, nullptr);
  const auto subId = created->subscription_id();
  auto subscription = mMgr->find_subscription(subId);
  ASSERT_NE(subscription, nullptr);
  ASSERT_FALSE(
    SubscriptionTestAccess::on_strand(*subscription, [](auto& guard) { return guard.publishing_enabled(); }));

  mMgr->handle_modify_subscription(2, make_modify_request(subId, 2000, 60, 20));
  settle();
  ASSERT_NE(dynamic_cast<ModifySubscriptionResponse*>(last_response().second.get()), nullptr);

  // The modify is posted to the Subscription's strand; reading the state there orders after it.
  const auto [interval, enabled] = SubscriptionTestAccess::on_strand(*subscription,
    [](auto& guard) { return std::pair{guard.publishing_interval(), guard.publishing_enabled()}; });
  EXPECT_EQ(interval, 2000.0) << "the modify was not applied";
  EXPECT_FALSE(enabled) << "ModifySubscription enabled publishing the client had disabled";
}

// ModifySubscription revises the lifetime count through the same clamp as CreateSubscription.
// @relation(AC-SVR-SUB-GEN-034-LIFETIME-COUNT-IS-CAPPED, scope=function)
TEST_F(SubMgrTest, ModSub_LifetimeCountIsRevisedDownToTheConfiguredMaximum)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxLifetimeCount = 100;
  create_manager({}, subLimits);
  auto subId = create_one_subscription(1000);

  auto req = make_modify_request(subId, 1000, std::numeric_limits<uint32_t>::max(), 10);
  mMgr->handle_modify_subscription(2, req);
  settle();
  auto* resp = dynamic_cast<ModifySubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(resp, nullptr);
  EXPECT_EQ(resp->revised_lifetime_count(), 100u);

  auto under = make_modify_request(subId, 1000, 50, 10);
  mMgr->handle_modify_subscription(3, under);
  settle();
  auto* underResp = dynamic_cast<ModifySubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(underResp, nullptr);
  EXPECT_EQ(underResp->revised_lifetime_count(), 50u) << "control: a request below the ceiling is honoured";
}

// Covers SVR-SUB-GEN-118 (coverage-audit retag).
TEST_F(SubMgrTest, ModSub_InvalidIdReturnsBadSubscriptionIdInvalid)
{
  create_manager();

  auto req = make_modify_request(999, 500);
  mMgr->handle_modify_subscription(2, req);
  settle();

  auto* fault = dynamic_cast<ServiceFault*>(last_response().second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid});
}

// ============================================================
// DeleteSubscriptions tests
// ============================================================

TEST_F(SubMgrTest, DeleteSub001_SubscriptionDeleted)
{
  create_manager();
  auto subId = create_one_subscription();

  const auto responsesBeforeDelete = response_count();
  auto req = make_delete_request({subId});
  mMgr->handle_delete_subscriptions(3, req);
  settle();
  ASSERT_TRUE(wait_for_responses(responsesBeforeDelete + 1u));

  auto* resp = dynamic_cast<DeleteSubscriptionsResponse*>(last_response().second.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], StatusCode{Status::Good});
  EXPECT_EQ(mMgr->subscription_count(), 0u);
}

// Covers SVR-SUB-GEN-126 (coverage-audit retag).
TEST_F(SubMgrTest, DeleteSub001_InvalidIdReturnsBadSubscriptionIdInvalid)
{
  create_manager();

  const auto responsesBeforeDelete = response_count();
  auto req = make_delete_request({999});
  mMgr->handle_delete_subscriptions(3, req);
  settle();
  EXPECT_EQ(response_count(), responsesBeforeDelete + 1u)
    << "an all-invalid batch has no close completion to await and responds inline";

  auto* resp = dynamic_cast<DeleteSubscriptionsResponse*>(last_response().second.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], StatusCode{Status::BadSubscriptionIdInvalid});
}

TEST_F(SubMgrTest, DeleteSub_EmptyArrayReturnsBadNothingToDo)
{
  create_manager();

  auto req = make_delete_request({});
  mMgr->handle_delete_subscriptions(3, req);
  settle();

  auto* fault = dynamic_cast<ServiceFault*>(last_response().second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadNothingToDo});
}

TEST_F(SubMgrTest, DeleteSub_DecrementsServerCounters)
{
  create_manager();
  create_one_subscription();
  auto subId2 = create_one_subscription();
  EXPECT_EQ(mCounters->currentSubscriptionCount.load(), 2u);

  const auto responsesBeforeDelete = response_count();
  auto req = make_delete_request({subId2});
  mMgr->handle_delete_subscriptions(3, req);
  settle();
  ASSERT_TRUE(wait_for_responses(responsesBeforeDelete + 1u));
  EXPECT_EQ(mCounters->currentSubscriptionCount.load(), 1u);
}

// Covers SVR-SUB-GEN-124 (coverage-audit retag).
TEST_F(SubMgrTest, DeleteSub003_LastSubDrainsPublishQueue)
{
  create_manager();
  auto subId = create_one_subscription();

  // Queue some Publish requests.
  PublishRequest pubReq;
  mMgr->handle_publish(10, pubReq);
  settle();
  mMgr->handle_publish(11, pubReq);
  settle();
  EXPECT_EQ(mMgr->pending_publish_count(), 2u);

  // Delete last subscription -> should drain publish queue after close and before the delete response.
  const auto responsesBeforeDelete = response_count();
  auto req = make_delete_request({subId});
  mMgr->handle_delete_subscriptions(3, req);
  settle();
  ASSERT_TRUE(wait_for_responses(responsesBeforeDelete + 3u));

  EXPECT_EQ(mMgr->pending_publish_count(), 0u);
  // Drained publishes should have produced ServiceFault responses.
  // We should have: create response + 2 publish responses + delete response = responses from drain
}

// Part 4 section 5.13.8.1 makes deletion of every owned MonitoredItem a consequence of successful
// DeleteSubscriptions. The pipeline map is the Subscription's last strong owner here; the test catches
// an erase that destroys the Subscription before its weak-borrowing close turn can release the item gauge.
// The duplicate id controls that counters/resources are released once, and the keyed retransmission entry
// proves the Session queue does not retain data for a deleted Subscription.
// @relation(AC-SVR-SUB-GEN-124-EXPLICIT-DELETE-RELEASES-RESOURCES, scope=function)
TEST_F(SubMgrTest, DeleteSubscriptionsRetainsLastOwnerThroughCloseAndPurgesResources)
{
  create_manager();
  const auto subscriptionId = create_one_subscription();
  auto subscription = mMgr->find_subscription(subscriptionId);
  ASSERT_NE(subscription, nullptr);
  seed_owned_resources(subscription, subscriptionId);

  std::weak_ptr<Subscription> lifetime = subscription;
  subscription.reset();
  ASSERT_FALSE(lifetime.expired()) << "the pipeline map must be the only remaining strong owner";
  ASSERT_EQ(mCounters->currentMonitoredItemCount.load(std::memory_order_relaxed), 1u);
  ASSERT_EQ(retransmission_queue_size_on_strand(), 1u);

  const auto responsesBeforeDelete = response_count();
  auto request = make_delete_request({subscriptionId, subscriptionId});
  mMgr->handle_delete_subscriptions(3, request);
  settle();
  ASSERT_TRUE(wait_for_responses(responsesBeforeDelete + 1u));
  ASSERT_EQ(response_count(), responsesBeforeDelete + 1u)
    << "the response-timing observation must be captured before the executor-drain sentinel";
  auto* response = dynamic_cast<DeleteSubscriptionsResponse*>(last_response().second.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_EQ(response->results()[0], StatusCode{Status::Good});
  EXPECT_EQ(response->results()[1], StatusCode{Status::BadSubscriptionIdInvalid});
  const auto countAtResponse = monitored_item_count_at_delete_response();
  ASSERT_TRUE(countAtResponse.has_value());
  EXPECT_EQ(*countAtResponse, 0u)
    << "a Good DeleteSubscriptionsResponse must not precede the owned MonitoredItems' close cleanup";

  wait_for_posted_work_to_drain();
  EXPECT_TRUE(lifetime.expired());
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(std::memory_order_relaxed), 0u)
    << "close must release the real MonitoredItem exactly once before the retained owner is dropped";
  EXPECT_EQ(mMgr->atomic_total_monitored_item_count(), 0u);
  EXPECT_EQ(retransmission_queue_size_on_strand(), 0u)
    << "a deleted Subscription must leave no keyed retransmission entries in its Session";
}

// Lifetime expiry calls the private direct-delete helper instead of the batch handler. It shares the same
// last-owner boundary and must use the same retain-through-close resource release path.
// @relation(AC-SVR-SUB-GEN-124-EXPLICIT-DELETE-RELEASES-RESOURCES, scope=function)
TEST_F(SubMgrTest, DirectDeleteRetainsLastOwnerThroughCloseAndPurgesResources)
{
  create_manager();
  const auto subscriptionId = create_one_subscription();
  auto subscription = mMgr->find_subscription(subscriptionId);
  ASSERT_NE(subscription, nullptr);
  seed_owned_resources(subscription, subscriptionId);

  std::weak_ptr<Subscription> lifetime = subscription;
  subscription.reset();
  ASSERT_FALSE(lifetime.expired()) << "the pipeline map must be the only remaining strong owner";

  SubscriptionsPipelineTestAccess::on_strand(
    *mMgr, [subscriptionId](auto& guard) { guard.delete_subscription(subscriptionId); });

  ASSERT_TRUE(wait_for_lifetime_to_expire(lifetime))
    << "direct deletion must release the completion-owned Subscription after its close strand turn";
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(std::memory_order_relaxed), 0u);
  EXPECT_EQ(mMgr->atomic_total_monitored_item_count(), 0u);
  EXPECT_EQ(retransmission_queue_size_on_strand(), 0u);
}

// Control for the intended lifetime shape: Subscription::close_async(completion) can perform close when
// its completion owns the final strong reference, and Subscription::close remains idempotent at the
// resource boundary. Production deletion should centralise this bounded ownership pattern.
// @relation(AC-SVR-SUB-GEN-124-EXPLICIT-DELETE-RELEASES-RESOURCES, scope=function)
TEST_F(SubMgrTest, CompletionOwningCloseReleasesResourcesExactlyOnce)
{
  create_manager();
  const auto subscriptionId = create_one_subscription();
  auto subscription = mMgr->find_subscription(subscriptionId);
  ASSERT_NE(subscription, nullptr);
  seed_owned_resources(subscription, subscriptionId, false);

  SubscriptionsPipelineTestAccess::on_strand(*mMgr,
    [subscriptionId](auto& guard)
    {
      guard.subscriptions().erase(subscriptionId);
      guard.atomic_total_monitored_item_count().store(0, std::memory_order_relaxed);
    });
  mCounters->currentSubscriptionCount.store(0, std::memory_order_relaxed);
  mCounters->publishingIntervalCount.store(0, std::memory_order_relaxed);

  std::weak_ptr<Subscription> lifetime = subscription;
  auto retainedSubscription = subscription;
  std::atomic<uint32_t> completionCount{0};
  std::atomic<bool> completionObservedLiveSubscription{false};
  subscription->close_async(
    [retainedSubscription = std::move(retainedSubscription),
      lifetime,
      &completionCount,
      &completionObservedLiveSubscription]() mutable
    {
      completionObservedLiveSubscription.store(!lifetime.expired(), std::memory_order_relaxed);
      completionCount.fetch_add(1, std::memory_order_relaxed);
      retainedSubscription.reset();
    });
  subscription.reset();

  wait_for_posted_work_to_drain();
  EXPECT_EQ(completionCount.load(std::memory_order_relaxed), 1u);
  EXPECT_TRUE(completionObservedLiveSubscription.load(std::memory_order_relaxed))
    << "the close completion must observe the subscription alive before releasing its retained owner";
  EXPECT_TRUE(lifetime.expired());
  EXPECT_EQ(mCounters->currentMonitoredItemCount.load(std::memory_order_relaxed), 0u);
}

// A SecureChannel loss discards the queued Publish requests WITHOUT responding (unlike the close-time
// drain). They arrived on the now-dead channel; the client abandons them and resends fresh ones on the
// reconnect channel (Part 4 6.7), so answering is impossible/pointless. Crucially, leaving them queued
// would strand a post-reconnect NotificationMessage against a stale requestId the client no longer has
// outstanding, so the client drops the response and the notification is lost (regression-covered by the
// integration test Chaos.ConnectionImplSubscriptionSurvivesRealDrop).
TEST_F(SubMgrTest, DiscardPendingPublishRequests_ClearsQueueWithoutResponding)
{
  create_manager();
  create_one_subscription();

  // Queue two Publish requests (a fresh subscription has nothing ready, so they stay pending).
  PublishRequest pubReq;
  mMgr->handle_publish(10, pubReq);
  settle();
  mMgr->handle_publish(11, pubReq);
  settle();
  ASSERT_EQ(mMgr->pending_publish_count(), 2u);

  const auto responsesBefore = response_count();
  const auto discarded = mMgr->discard_pending_publish_requests();

  EXPECT_EQ(mMgr->pending_publish_count(), 0u) << "channel loss must clear the pending Publish queue";
  EXPECT_EQ(response_count(), responsesBefore)
    << "discard must NOT emit responses for the abandoned requests (the channel is gone) - unlike "
       "drain_publish_queue, which sends ServiceFaults";
  // The discarded requestIds are reported (in FIFO order) so the session can release the per-request
  // bookkeeping that response_received would otherwise reap - preventing an orphan-map leak across
  // reconnects.
  EXPECT_EQ(discarded, (std::vector<uint32_t>{10u, 11u}));
}

// ============================================================
// SetPublishingMode tests
// ============================================================

TEST_F(SubMgrTest, SetPublishingMode_ValidSubscription)
{
  create_manager();
  auto subId = create_one_subscription();

  SetPublishingModeRequest req;
  req.publishing_enabled() = false;
  req.subscription_ids() = std::vector<uint32_t>{subId};

  mMgr->handle_set_publishing_mode(4, req);
  settle();

  auto* resp = dynamic_cast<SetPublishingModeResponse*>(last_response().second.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], StatusCode{Status::Good});
}

// Covers SVR-SUB-GEN-120 (coverage-audit retag).
TEST_F(SubMgrTest, SetPublishingMode_InvalidSubscription)
{
  create_manager();

  SetPublishingModeRequest req;
  req.publishing_enabled() = false;
  req.subscription_ids() = std::vector<uint32_t>{999};

  mMgr->handle_set_publishing_mode(4, req);
  settle();

  auto* resp = dynamic_cast<SetPublishingModeResponse*>(last_response().second.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], StatusCode{Status::BadSubscriptionIdInvalid});
}

TEST_F(SubMgrTest, SetPublishingMode_EmptyArrayReturnsBadNothingToDo)
{
  create_manager();

  SetPublishingModeRequest req;
  req.publishing_enabled() = false;

  mMgr->handle_set_publishing_mode(4, req);
  settle();

  auto* fault = dynamic_cast<ServiceFault*>(last_response().second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadNothingToDo});
}

// Part 4 5.13.4.3 - SetPublishingMode is a batch service and carries the two service faults every
// batched service carries: an empty subscriptionIds[] is Bad_NothingToDo, and a batch larger than the
// server's operation limit is Bad_TooManyOperations. Both are pre-dispatch faults that short-circuit
// before any Subscription is touched, so neither may come back as a SetPublishingModeResponse carrying
// per-operation results. A plausible implementation gets the second one wrong by treating the batch as
// unbounded - it validates each id individually and answers an arbitrarily long request with a results[]
// array of Good/Bad_SubscriptionIdInvalid, which lets a client force unbounded per-call work no matter
// what ceiling the session advertises.
// @verifies AC-SVR-SUB-GEN-119-SETPUBLISHINGMODE-SERVICE-ERRORS
TEST_F(SubMgrTest, SetPublishingModeRejectsEmptyAndOverLimitBatchesAtServiceLevel)
{
  const uint32_t perSessionLimit = 2;
  ServerConfig::ServerCapabilities capabilities;
  capabilities.maxSubscriptionsPerSession = perSessionLimit;
  create_manager(capabilities);

  const auto firstId = create_one_subscription();
  const auto secondId = create_one_subscription();
  ASSERT_EQ(mMgr->subscription_count(), 2u);

  // Empty subscriptionIds[] -> service-level Bad_NothingToDo.
  SetPublishingModeRequest emptyRequest;
  emptyRequest.publishing_enabled() = false;

  const auto beforeEmpty = response_count();
  mMgr->handle_set_publishing_mode(4, emptyRequest);
  settle();
  ASSERT_EQ(response_count(), beforeEmpty + 1u);

  auto emptyResponse = last_response();
  EXPECT_EQ(dynamic_cast<SetPublishingModeResponse*>(emptyResponse.second.get()), nullptr)
    << "an empty batch is a pre-dispatch service fault, not a response carrying per-operation results";
  auto* emptyFault = dynamic_cast<ServiceFault*>(emptyResponse.second.get());
  ASSERT_NE(emptyFault, nullptr);
  EXPECT_EQ(emptyFault->response_header().service_result(), StatusCode{Status::BadNothingToDo});

  // More subscriptionIds than the session may hold -> service-level Bad_TooManyOperations. The two
  // valid ids are included so the refusal cannot be mistaken for per-id validation.
  SetPublishingModeRequest overLimitRequest;
  overLimitRequest.publishing_enabled() = false;
  overLimitRequest.subscription_ids() = std::vector<uint32_t>{firstId, secondId, firstId, secondId, firstId};
  ASSERT_GT(overLimitRequest.subscription_ids().size(), size_t{perSessionLimit});

  const auto beforeOverLimit = response_count();
  mMgr->handle_set_publishing_mode(5, overLimitRequest);
  settle();
  ASSERT_EQ(response_count(), beforeOverLimit + 1u);

  auto overLimitResponse = last_response();
  EXPECT_EQ(dynamic_cast<SetPublishingModeResponse*>(overLimitResponse.second.get()), nullptr)
    << "an over-limit batch must short-circuit before any Subscription is touched, so it cannot come "
       "back as a SetPublishingModeResponse with per-operation results";
  auto* overLimitFault = dynamic_cast<ServiceFault*>(overLimitResponse.second.get());
  ASSERT_NE(overLimitFault, nullptr);
  const auto overLimitStatus = overLimitFault->response_header().service_result();
  EXPECT_EQ(overLimitStatus, StatusCode{Status::BadTooManyOperations});
  ASSERT_NE(overLimitStatus.shared_detail(), nullptr);
  EXPECT_EQ(overLimitStatus.shared_detail()->code, "SetPublishingModeTooManyOperations");
}

// Part 4 5.13.4.3 - SetPublishingMode is a batch service and carries the two service-level faults every
// batched service carries: an empty subscriptionIds[] is Bad_NothingToDo, and a batch exceeding the
// server's operation limit is Bad_TooManyOperations. Both short-circuit before any Subscription is
// touched, so neither may come back as a SetPublishingModeResponse carrying per-operation results. A
// plausible implementation gets the second one wrong by treating the subscription-id batch as unbounded:
// it validates each id individually and answers an arbitrarily long request with a results[] array of
// Good, which lets a client force unbounded per-call work no matter what ceiling the session advertises.
// The batch below exceeds both the per-session subscription cap and the generic per-call operation limit,
// so it is over-limit under either ceiling a conforming implementation might adopt, and every id in it is
// valid so the refusal cannot be mistaken for per-id validation.
// This independently repeats the refusal with both candidate configuration ceilings set to the same
// value, guarding the configuration path as well as the service response shape.
// @verifies AC-SVR-SUB-GEN-119-SETPUBLISHINGMODE-SERVICE-ERRORS
TEST_F(SubMgrTest, SetPublishingModeRefusesEmptyAndOverLimitSubscriptionIdBatches)
{
  const uint32_t perSessionLimit = 2;
  ServerConfig::ServerCapabilities capabilities;
  capabilities.maxSubscriptionsPerSession = perSessionLimit;
  capabilities.operationLimits.maxMonitoredItemsPerCall = perSessionLimit;
  create_manager(capabilities);

  const auto firstId = create_one_subscription();
  const auto secondId = create_one_subscription();
  ASSERT_EQ(mMgr->subscription_count(), 2u);

  // Conjunct 1: empty subscriptionIds[] -> service-level Bad_NothingToDo.
  SetPublishingModeRequest emptyRequest;
  emptyRequest.publishing_enabled() = false;

  const auto beforeEmpty = response_count();
  mMgr->handle_set_publishing_mode(4, emptyRequest);
  settle();
  ASSERT_EQ(response_count(), beforeEmpty + 1u);

  auto emptyResponse = last_response();
  EXPECT_EQ(dynamic_cast<SetPublishingModeResponse*>(emptyResponse.second.get()), nullptr)
    << "an empty batch is a pre-dispatch service fault, not a response carrying per-operation results";
  auto* emptyFault = dynamic_cast<ServiceFault*>(emptyResponse.second.get());
  ASSERT_NE(emptyFault, nullptr);
  EXPECT_EQ(emptyFault->response_header().service_result(), StatusCode{Status::BadNothingToDo});

  // Conjunct 2: more subscriptionIds than the advertised ceiling -> service-level Bad_TooManyOperations.
  SetPublishingModeRequest overLimitRequest;
  overLimitRequest.publishing_enabled() = false;
  overLimitRequest.subscription_ids() = std::vector<uint32_t>{firstId, secondId, firstId, secondId, firstId};
  ASSERT_GT(overLimitRequest.subscription_ids().size(), size_t{perSessionLimit});

  const auto beforeOverLimit = response_count();
  mMgr->handle_set_publishing_mode(5, overLimitRequest);
  settle();
  ASSERT_EQ(response_count(), beforeOverLimit + 1u);

  auto overLimitResponse = last_response();
  EXPECT_EQ(dynamic_cast<SetPublishingModeResponse*>(overLimitResponse.second.get()), nullptr)
    << "an over-limit batch must short-circuit before any Subscription is touched, so it cannot come "
       "back as a SetPublishingModeResponse with per-operation results";
  auto* overLimitFault = dynamic_cast<ServiceFault*>(overLimitResponse.second.get());
  ASSERT_NE(overLimitFault, nullptr);
  EXPECT_EQ(overLimitFault->response_header().service_result(), StatusCode{Status::BadTooManyOperations});
}

// Part 4 5.13.4.3 - the two service-level faults SetPublishingMode carries as a batched service: an
// empty subscriptionIds[] is Bad_NothingToDo and a batch exceeding the server's operation limit is
// Bad_TooManyOperations, both decided before any Subscription is touched and therefore distinct from the
// per-operation Bad_SubscriptionIdInvalid. The two siblings above assert the refusals; this one pins the
// accepting side of the same boundary, without which either refusal is unfalsifiable. Two implementations
// get it wrong in opposite directions and neither is caught by an over-limit case alone: one treats the
// subscription-id batch as unbounded and answers any length with a results[] array, so no ceiling the
// session advertises ever bounds the per-call work a client can force; the other "fixes" that by refusing
// on >= the limit, or by refusing every non-empty batch, and silently rejects the largest request the
// server is obliged to honour. A batch of exactly the limit must therefore come back as a
// SetPublishingModeResponse with one Good per id, and only limit+1 may fault.
// @verifies AC-SVR-SUB-GEN-119-SETPUBLISHINGMODE-SERVICE-ERRORS
TEST_F(SubMgrTest, SetPublishingModeHonoursAnAtLimitBatchAndFaultsOnEmptyAndOverLimitOnes)
{
  // The server advertises no dedicated per-call ceiling for the subscription-id batch services, so the
  // batch below is over-limit under either ceiling a conforming implementation might adopt.
  const uint32_t operationLimit = 2;
  ServerConfig::ServerCapabilities capabilities;
  capabilities.maxSubscriptionsPerSession = operationLimit;
  capabilities.operationLimits.maxMonitoredItemsPerCall = operationLimit;
  create_manager(capabilities);

  const auto firstId = create_one_subscription();
  const auto secondId = create_one_subscription();
  ASSERT_EQ(mMgr->subscription_count(), size_t{operationLimit});

  // Conjunct 1: empty subscriptionIds[] -> service-level Bad_NothingToDo, never a response carrying
  // per-operation results.
  SetPublishingModeRequest emptyRequest;
  emptyRequest.publishing_enabled() = false;

  const auto beforeEmpty = response_count();
  mMgr->handle_set_publishing_mode(4, emptyRequest);
  settle();
  ASSERT_EQ(response_count(), beforeEmpty + 1u);

  auto emptyResponse = last_response();
  EXPECT_EQ(dynamic_cast<SetPublishingModeResponse*>(emptyResponse.second.get()), nullptr)
    << "an empty batch is decided before dispatch, so it cannot come back as a SetPublishingModeResponse";
  auto* emptyFault = dynamic_cast<ServiceFault*>(emptyResponse.second.get());
  ASSERT_NE(emptyFault, nullptr);
  EXPECT_EQ(emptyFault->response_header().service_result(), StatusCode{Status::BadNothingToDo});

  // Control: a batch of exactly the limit is within the ceiling and must be serviced normally. Without
  // this the over-limit assertion below is satisfied by a server that refuses everything.
  SetPublishingModeRequest atLimitRequest;
  atLimitRequest.publishing_enabled() = false;
  atLimitRequest.subscription_ids() = std::vector<uint32_t>{firstId, secondId};
  ASSERT_EQ(atLimitRequest.subscription_ids().size(), size_t{operationLimit});

  const auto beforeAtLimit = response_count();
  mMgr->handle_set_publishing_mode(5, atLimitRequest);
  settle();
  ASSERT_EQ(response_count(), beforeAtLimit + 1u);

  auto atLimitResponse = last_response();
  EXPECT_EQ(dynamic_cast<ServiceFault*>(atLimitResponse.second.get()), nullptr)
    << "a batch of exactly the operation limit is within the ceiling and must not be refused";
  auto* atLimitResults = dynamic_cast<SetPublishingModeResponse*>(atLimitResponse.second.get());
  ASSERT_NE(atLimitResults, nullptr);
  ASSERT_EQ(atLimitResults->results().size(), size_t{operationLimit});
  EXPECT_EQ(atLimitResults->results()[0], StatusCode{Status::Good});
  EXPECT_EQ(atLimitResults->results()[1], StatusCode{Status::Good});

  // Conjunct 2: one id beyond the limit -> service-level Bad_TooManyOperations. Every id is valid, so the
  // refusal cannot be mistaken for per-id validation, and the count is the only thing that changed
  // relative to the accepted control above.
  SetPublishingModeRequest overLimitRequest;
  overLimitRequest.publishing_enabled() = false;
  overLimitRequest.subscription_ids() = std::vector<uint32_t>{firstId, secondId, firstId};
  ASSERT_GT(overLimitRequest.subscription_ids().size(), size_t{operationLimit});

  const auto beforeOverLimit = response_count();
  mMgr->handle_set_publishing_mode(6, overLimitRequest);
  settle();
  ASSERT_EQ(response_count(), beforeOverLimit + 1u);

  auto overLimitResponse = last_response();
  EXPECT_EQ(dynamic_cast<SetPublishingModeResponse*>(overLimitResponse.second.get()), nullptr)
    << "an over-limit batch is decided before dispatch, so it cannot come back as a "
       "SetPublishingModeResponse carrying per-operation results";
  auto* overLimitFault = dynamic_cast<ServiceFault*>(overLimitResponse.second.get());
  ASSERT_NE(overLimitFault, nullptr);
  EXPECT_EQ(overLimitFault->response_header().service_result(), StatusCode{Status::BadTooManyOperations});
}

// ============================================================
// Publish tests
// ============================================================

// Covers SVR-SUB-GEN-121 (coverage-audit retag).
TEST_F(SubMgrTest, Publish_NoSubscriptionsReturnsBadNoSubscription)
{
  create_manager();

  PublishRequest req;
  mMgr->handle_publish(5, req);
  settle();

  auto* fault = dynamic_cast<ServiceFault*>(last_response().second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadNoSubscription});
}

// @relation(SVR-SUB-GEN-014, SVR-SUB-GEN-126, scope=function)
TEST_F(SubMgrTest, Publish_OverflowReturnsBadTooManyPublishRequests)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxPublishRequestsPerSession = 2;
  create_manager({}, subLimits);
  create_one_subscription();

  PublishRequest req;
  mMgr->handle_publish(10, req);
  settle();
  mMgr->handle_publish(11, req);
  settle();
  // Queue is at capacity (2). Third publish should dequeue oldest with BadTooManyPublishRequests.
  mMgr->handle_publish(12, req);
  settle();

  // The oldest (requestId=10) should have been returned as a fault.
  bool foundFault = false;
  std::lock_guard lk(mMutex);
  for (auto& r : mResponses)
  {
    if (r.first == 10)
    {
      auto* fault = dynamic_cast<ServiceFault*>(r.second.get());
      ASSERT_NE(fault, nullptr);
      EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadTooManyPublishRequests});
      foundFault = true;
    }
  }
  EXPECT_TRUE(foundFault);
}

using DiagnosticLevel = ServerConfig::DiagnosticPolicy::Level;

class PublishFaultDiagnostics
  : public SubMgrTest,
    public ::testing::WithParamInterface<std::tuple<bool, bool, DiagnosticLevel, uint32_t, int>>
{};

// @relation(AC-SVR-DIAG-015-PUBLISH-FAULT-CONTEXT, scope=function)
TEST_P(PublishFaultDiagnostics, CurrentContextControlsOverflowTimeoutAndDrain)
{
  const auto [authenticated, securedChannel, level, mask, failureKind] = GetParam();
  auto logs = std::make_shared<PublishFaultLogSink>();
  mLogger = Logger{logs, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test.publish"};
  ServerConfig::SubscriptionLimits limits;
  limits.maxPublishRequestsPerSession = 1;
  create_manager({}, limits);
  const auto subscriptionId = create_one_subscription(60000);

  PublishRequest queued;
  queued.request_header().return_diagnostics() = mask;
  queued.request_header().timeout_hint() = failureKind == 1 ? 10 : 0;
  mMgr->handle_publish(10, queued);
  settle();
  ASSERT_EQ(mMgr->pending_publish_count(), 1u);

  // The request was queued under Full. Disclosure is decided when its response is constructed.
  SubscriptionsPipelineTestAccess::on_strand(*mMgr,
    [this, authenticated, securedChannel, level](auto&)
    {
      mDiagnosticSecurityContext.authenticated = authenticated;
      mDiagnosticSecurityContext.securedChannel = securedChannel;
      mDiagnosticSecurityContext.effectiveLevel = level;
    });

  Status expectedStatus = Status::BadTooManyPublishRequests;
  std::string expectedCode = "TooManyPublishRequests";
  std::string expectedSummary = "Publish request rejected because the Session Publish queue is full";
  if (failureKind == 0)
  {
    PublishRequest successor;
    mMgr->handle_publish(11, successor);
    settle();
  }
  else if (failureKind == 1)
  {
    expectedStatus = Status::BadTimeout;
    expectedCode = "PublishRequestTimedOut";
    expectedSummary = "Publish request timeoutHint elapsed before response processing";
    SubscriptionsPipelineTestAccess::on_strand(*mMgr,
      [this, subscriptionId](auto& guard)
      {
        mMonotonicNow += std::chrono::milliseconds{11};
        guard.enqueue_pending_status_change(subscriptionId, NotificationMessage{});
        guard.request_dispatch();
      });
  }
  else
  {
    expectedStatus = Status::BadSessionClosed;
    expectedCode = "SessionClosed";
    expectedSummary = "Publish request rejected because session is closing";
    SubscriptionsPipelineTestAccess::on_strand(*mMgr, [this](auto&) { mMgr->close_all(); });
  }

  ASSERT_TRUE(wait_for_responses(2u));
  std::shared_ptr<ServiceFault> fault;
  {
    std::lock_guard lock{mMutex};
    for (const auto& response : mResponses)
      if (response.first == 10)
        fault = std::dynamic_pointer_cast<ServiceFault>(response.second);
  }
  ASSERT_NE(fault, nullptr);
  const auto& header = fault->response_header();
  EXPECT_EQ(header.service_result().as_status(), expectedStatus);
  const auto& diagnostic = header.service_diagnostics();
  const bool allowed = authenticated && securedChannel && level != DiagnosticLevel::None && mask != 0;
  if (!allowed)
  {
    EXPECT_TRUE(diagnostic.is_null());
    EXPECT_TRUE(header.string_table().empty());
  }
  else
  {
    ASSERT_TRUE(diagnostic.symbolic_id().has_value());
    ASSERT_TRUE(diagnostic.namespace_uri().has_value());
    ASSERT_TRUE(diagnostic.localized_text().has_value());
    const auto& table = header.string_table();
    ASSERT_EQ(table.size(), 3u);
    ASSERT_LT(static_cast<size_t>(*diagnostic.symbolic_id()), table.size());
    ASSERT_LT(static_cast<size_t>(*diagnostic.namespace_uri()), table.size());
    ASSERT_LT(static_cast<size_t>(*diagnostic.localized_text()), table.size());
    EXPECT_EQ(std::string{table[*diagnostic.symbolic_id()]}, expectedCode);
    EXPECT_EQ(std::string{table[*diagnostic.namespace_uri()]}, "SubscriptionsPipeline");
    EXPECT_EQ(std::string{table[*diagnostic.localized_text()]}, expectedSummary);
    EXPECT_FALSE(diagnostic.locale().has_value());
    EXPECT_FALSE(diagnostic.additional_info().has_value());
    EXPECT_FALSE(diagnostic.inner_status_code().has_value());
    EXPECT_EQ(diagnostic.inner_diagnostic_info(), nullptr);
  }
  EXPECT_TRUE(logs->contains(expectedCode)) << "the original failure code must remain available locally";
  EXPECT_TRUE(logs->contains(expectedSummary))
    << "the original failure summary must remain available locally";
  EXPECT_TRUE(logs->contains("SubscriptionsPipeline"));
}

INSTANTIATE_TEST_SUITE_P(CurrentSecurityContext, PublishFaultDiagnostics,
  ::testing::Combine(::testing::Bool(), ::testing::Bool(),
    ::testing::Values(DiagnosticLevel::None, DiagnosticLevel::Summary, DiagnosticLevel::Full),
    ::testing::Values(0u, diag::serviceLevelMask | diag::operationLevelMask), ::testing::Values(0, 1, 2)));

// Part 4 section 7.33 requires the Server to check a Publish request's timeoutHint before processing
// a response. Part 4 section 5.13.1.4 Table 87 requires Bad_Timeout for an expired request and continued
// FIFO dequeue so the next valid request carries the response.
// @relation(AC-SVR-SUB-GEN-112-EXPIRED-PUBLISH-BAD-TIMEOUT, scope=function)
TEST_F(SubMgrTest, ExpiredPublishRequestReturnsBadTimeoutAndSuccessorCarriesNotification)
{
  create_manager();
  const auto subscriptionId = create_one_subscription();

  PublishRequest expired;
  expired.request_header().timeout_hint() = 10;
  mMgr->handle_publish(10, expired);
  settle();

  mMonotonicNow += std::chrono::milliseconds{11};
  PublishRequest successor;
  successor.request_header().timeout_hint() = 1000;
  mMgr->handle_publish(11, successor);
  settle();
  ASSERT_EQ(mMgr->pending_publish_count(), 2u);

  SubscriptionsPipelineTestAccess::on_strand(*mMgr,
    [subscriptionId](auto& guard)
    {
      guard.enqueue_pending_status_change(subscriptionId, NotificationMessage{});
      guard.request_dispatch();
    });

  ASSERT_TRUE(wait_for_responses(3u));  // CreateSubscription + timeout fault + successor response.
  EXPECT_EQ(mMgr->pending_publish_count(), 0u);

  std::lock_guard lock{mMutex};
  ASSERT_EQ(mResponses.size(), 3u);
  ASSERT_EQ(mResponses[1].first, 10u);
  auto* timeoutFault = dynamic_cast<ServiceFault*>(mResponses[1].second.get());
  ASSERT_NE(timeoutFault, nullptr);
  EXPECT_EQ(timeoutFault->response_header().service_result(), StatusCode{Status::BadTimeout});
  ASSERT_NE(timeoutFault->response_header().service_result().shared_detail(), nullptr);
  EXPECT_EQ(timeoutFault->response_header().service_result().shared_detail()->code, "PublishRequestTimedOut");

  ASSERT_EQ(mResponses[2].first, 11u);
  EXPECT_NE(dynamic_cast<PublishResponse*>(mResponses[2].second.get()), nullptr);
}

// ============================================================
// Republish tests
// ============================================================

TEST_F(SubMgrTest, Republish_InvalidSubReturnsBadSubscriptionIdInvalid)
{
  create_manager();

  RepublishRequest req;
  req.subscription_id() = 999;
  req.retransmit_sequence_number() = 1;
  mMgr->handle_republish(6, req);
  settle();

  auto* fault = dynamic_cast<ServiceFault*>(last_response().second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid});
}

// Covers SVR-SUB-GEN-123 (coverage-audit retag).
TEST_F(SubMgrTest, Republish_NotFoundReturnsBadMessageNotAvailable)
{
  create_manager();
  auto subId = create_one_subscription();

  RepublishRequest req;
  req.subscription_id() = subId;
  req.retransmit_sequence_number() = 42;
  mMgr->handle_republish(6, req);
  settle();

  auto* fault = dynamic_cast<ServiceFault*>(last_response().second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadMessageNotAvailable});
}

// ============================================================
// close_all tests
// ============================================================

TEST_F(SubMgrTest, CloseAll_DeletesAllSubscriptionsAndDrainsQueue)
{
  create_manager();
  create_one_subscription();
  create_one_subscription();
  EXPECT_EQ(mMgr->subscription_count(), 2u);

  PublishRequest pubReq;
  mMgr->handle_publish(10, pubReq);
  settle();
  EXPECT_EQ(mMgr->pending_publish_count(), 1u);

  mMgr->close_all();

  EXPECT_EQ(mMgr->subscription_count(), 0u);
  EXPECT_EQ(mMgr->pending_publish_count(), 0u);
  EXPECT_EQ(mCounters->currentSubscriptionCount.load(), 0u);
}

// ============================================================
// Subscription ID uniqueness across managers
// ============================================================

// @relation(SVR-SUB-GEN-070, SVR-SUB-GEN-126, scope=function)
TEST_F(SubMgrTest, Gen070_SubscriptionIdUniqueAcrossSessions)
{
  // Two managers sharing the same allocator produce unique IDs.
  create_manager();
  auto subId1 = create_one_subscription();

  // Create a second manager sharing the same allocator.
  auto ex2 = mThreadPool.get_executor();
  auto mgr2 = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
    .executor = ex2,
    .sessionStrand = boost::asio::make_strand(ex2),
    .logger = Logger{},
    .idAllocator = mIdAllocator,
    .summaryCounters = mCounters,
    .capabilities = {},
    .sendResponse =
      [this](Response r)
    {
      std::lock_guard lk(mMutex);
      mResponses.push_back(std::move(r));
    },
  });

  auto req = make_create_request();
  mgr2->handle_create_subscription(2, req);
  auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last_response().second.get());
  ASSERT_NE(csResp, nullptr);
  auto subId2 = csResp->subscription_id();

  EXPECT_NE(subId1, subId2);
  mgr2.reset();
}

// ============================================================================
// StatusChangeNotification on lifetime expiry (Part 4, Row 27)
// ============================================================================

// @relation(SVR-SUB-GEN-033, SVR-SUB-GEN-126, scope=function)
TEST_F(SubMgrTest, ExpiredSubscription_StatusChangeNotificationDeliveredOnNextPublish)
{
  create_manager();
  auto subId = create_one_subscription(1000);
  size_t baseline = response_count();

  // Simulate subscription lifetime expiry.
  mMgr->on_subscription_expired(subId);
  EXPECT_EQ(mMgr->subscription_count(), 0u);

  // The StatusChangeNotification is pending. Send a Publish to receive it.
  PublishRequest pubReq;
  mMgr->handle_publish(100, pubReq);
  settle();

  // try_dispatch_publish is a coroutine - wait for the response.
  ASSERT_TRUE(wait_for_responses(baseline + 1));

  auto resp = last_response();
  auto* pubResp = dynamic_cast<PublishResponse*>(resp.second.get());
  ASSERT_NE(pubResp, nullptr) << "Expected PublishResponse, not ServiceFault";
  EXPECT_EQ(pubResp->subscription_id(), subId);

  // Verify the notification contains a StatusChangeNotification with BadTimeout.
  ASSERT_EQ(pubResp->notification_message().notification_data().size(), 1u);
  auto* scn = dynamic_cast<const StatusChangeNotification*>(
    pubResp->notification_message().notification_data()[0].get());
  ASSERT_NE(scn, nullptr);
  EXPECT_EQ(scn->status(), StatusCode{Status::BadTimeout});
}

// @relation(SVR-SUB-GEN-033, scope=function)
TEST_F(SubMgrTest, ExpiredSubscription_PublishWithNoPendingSCN_ReturnsBadNoSubscription)
{
  create_manager();
  auto subId = create_one_subscription(1000);
  size_t baseline = response_count();

  // Expire the subscription - SCN is pending.
  mMgr->on_subscription_expired(subId);

  // First Publish: consumes the pending SCN.
  PublishRequest pubReq;
  mMgr->handle_publish(100, pubReq);
  settle();
  ASSERT_TRUE(wait_for_responses(baseline + 1));

  size_t afterFirst = response_count();

  // Second Publish: no subscriptions and no pending SCN -> BadNoSubscription.
  mMgr->handle_publish(101, PublishRequest{});
  settle();
  ASSERT_TRUE(wait_for_responses(afterFirst + 1));

  auto resp = last_response();
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "Expected ServiceFault after SCN is consumed";
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadNoSubscription});
}

// @relation(SVR-SUB-GEN-033, scope=function)
TEST_F(SubMgrTest, ExpiredSubscription_PublishQueuedBeforeExpiry_DispatchesSCNImmediately)
{
  create_manager();
  auto subId = create_one_subscription(1000);
  size_t baseline = response_count();

  // Queue a Publish request before the subscription expires.
  PublishRequest pubReq;
  mMgr->handle_publish(100, pubReq);
  settle();

  // Expire the subscription - should dispatch the SCN immediately to the queued Publish.
  mMgr->on_subscription_expired(subId);

  ASSERT_TRUE(wait_for_responses(baseline + 1));

  auto resp = last_response();
  auto* pubResp = dynamic_cast<PublishResponse*>(resp.second.get());
  ASSERT_NE(pubResp, nullptr) << "Expected PublishResponse, not ServiceFault";
  EXPECT_EQ(pubResp->subscription_id(), subId);

  ASSERT_EQ(pubResp->notification_message().notification_data().size(), 1u);
  auto* scn = dynamic_cast<const StatusChangeNotification*>(
    pubResp->notification_message().notification_data()[0].get());
  ASSERT_NE(scn, nullptr);
  EXPECT_EQ(scn->status(), StatusCode{Status::BadTimeout});
}

// ============================================================================
// SubscriptionIdAllocator - random start (SVR-SUB-GEN-071)
// ============================================================================

TEST(SubscriptionIdAllocatorTests, NeverReturnsZero)
{
  SubscriptionIdAllocator allocator;
  auto id = allocator.allocate();
  EXPECT_NE(id, 0u);
}

// @relation(SVR-SUB-GEN-126, scope=function)
// @verifies AC-SVR-SUB-GEN-071-SUBSCRIPTIONID-START
TEST(SubscriptionIdAllocatorTests, StartsFromRandomValue)
{
  // Two fresh allocators should start from different values
  // (probabilistic - collision probability is ~1/2^31).
  SubscriptionIdAllocator a;
  SubscriptionIdAllocator b;
  EXPECT_NE(a.allocate(), b.allocate());
}

TEST(SubscriptionIdAllocatorTests, AllocatesSequentially)
{
  SubscriptionIdAllocator allocator;
  auto first = allocator.allocate();
  auto second = allocator.allocate();
  EXPECT_EQ(second, first + 1);
}

// Stage 3c #4: the parked StatusChangeNotification backlog (mPendingStatusChanges) is bounded by
// MaxPendingStatusChanges with an evict-oldest policy. Without it, a client that creates subscriptions
// and never sends Publish grows this deque without limit (each expiry frees its subscription slot, so
// MaxSubscriptionsPerSession never trips).
TEST_F(SubMgrTest, PendingStatusChangesBacklogEvictsOldestAtCap)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxPendingStatusChanges = 2;
  create_manager({}, std::move(subLimits));

  using TA = SubscriptionsPipelineTestAccess;

  // Park 5 status changes (subscriptionIds 1..5) - more than the cap of 2.
  const auto size = TA::on_strand(*mMgr,
    [](auto& guard)
    {
      for (IntegerId id = 1; id <= 5; ++id)
      {
        guard.enqueue_pending_status_change(id, NotificationMessage{});
      }
      return guard.pending_status_changes().size();
    });
  EXPECT_EQ(size, 2u) << "the parked-status-change backlog must be bounded by MaxPendingStatusChanges";

  // Evict-oldest: after pushing 1..5 with cap 2, the two retained entries are the newest (4 and 5).
  const auto frontId =
    TA::on_strand(*mMgr, [](auto& guard) { return guard.pending_status_changes().front().subscriptionId; });
  EXPECT_EQ(frontId, 4u) << "evict-oldest must drop the earliest parked notifications, keeping the newest";
}

}  // namespace
