// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>

#include "test_utilities.h"

#include "ua_subscriptions_pipeline.h"
#include "ua_subscriptions_pipeline_test_access.h"
#include "ua_subscription_test_access.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_subscription_id_allocator.h"
#include "ua_access_level_type.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_sample_sink_impl.h"
#include "ua_role_permission_type.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_deadband_type.h"
#include "ua_node_accessor.h"
#include "ua_base_event.h"
#include "ua_compiled_event_filter.h"
#include "ua_diagnostic_bits.h"
#include "ua_error_detail.h"
#include "ua_event_filter.h"
#include "ua_event_notification_list.h"
#include "ua_objecttype_id.h"
#include "ua_session_security.h"
#include "ua_simple_attribute_operand.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include "access_control_test_support.h"
#include "batch_recording_namespace.h"

#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <memory>
#include <string>
#include <optional>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

using STA = SubscriptionTestAccess;
using SMTA = SubscriptionsPipelineTestAccess;

namespace
{

template<typename Notification>
void append_notification(NotificationMessage& message, std::unique_ptr<Notification> notification)
{
  RefStructure<Structure> reference;
  reference.inner_unique_ptr() = std::move(notification);
  message.notification_data().push_back(std::move(reference));
}

class PublishSecurityContext final : public SessionSecurityContext
{
public:
  NodeId session_id() const override
  {
    return NodeId{1, 1u};
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

  std::shared_ptr<const EndpointSecurityContext> endpointSecurity{
    std::make_shared<EndpointSecurityContext>()};
  std::shared_ptr<const UserIdentity> userIdentity{std::make_shared<UserIdentity>()};
  std::shared_ptr<const AccessIdentity> accessIdentity;
};

/// Test fixture for publish-flow tests.
/// Creates a SubscriptionsPipeline with a real boost::asio::thread_pool and provides helpers
/// to create subscriptions, add monitored items with pre-enqueued values,
/// and wait for publish responses.
class PublishFlowTest : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  SubscriptionIdAllocator mIdAllocator;
  std::shared_ptr<ServerSummaryCounters> mCounters{std::make_shared<ServerSummaryCounters>()};
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
  DiagnosticSecurityContext mDiagnosticSecurityContext{.authenticated = true,
    .securedChannel = true,
    .effectiveLevel = ServerConfig::DiagnosticPolicy::Level::Full,
    .maskPreAuthErrors = true};
  size_t mDiagnosticSecurityContextCalls{0};

  std::mutex mMutex;
  std::condition_variable mResponseCv;
  std::vector<Response> mResponses;

  std::shared_ptr<SubscriptionsPipeline> mMgr;
  optional<AddressSpace> mAddressSpace;
  std::shared_ptr<PublishSecurityContext> mSecurityContext;
  const NodeId mMonitoredNodeId{0, 1000u};
  const NodeId mEventSourceId{0, 1001u};
  const NodeId mEventTypeId{0, 1002u};

  void SetUp() override
  {
    mAddressSpace = AddressSpace::create("urn:publish-access-test", mThreadPool.get_executor());
    mAddressSpace->create_node_sync(mMonitoredNodeId, NodeClass::Variable);
    mAddressSpace->create_node_sync(mEventSourceId, NodeClass::Object);
    mAddressSpace->create_node_sync(mEventTypeId, NodeClass::ObjectType);
    mSecurityContext = std::make_shared<PublishSecurityContext>();
    mSecurityContext->accessIdentity = ua::test_helpers::configure_test_access(
      *mAddressSpace, mSecurityContext->userIdentity, mSecurityContext->endpointSecurity);
  }

  void TearDown() override
  {
    // Drop strand/executor-pinned members before draining. any_io_executor is
    // work-tracking; while mMgr or mStrand hold one, pool.join() hangs.
    mMgr.reset();
    mStrand.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void create_manager(
    ServerConfig::ServerCapabilities caps = {}, ServerConfig::SubscriptionLimits subLimits = {})
  {
    auto executor = mThreadPool.get_executor();
    mStrand.emplace(boost::asio::make_strand(executor));
    mMgr = SubscriptionsPipeline::create(SubscriptionsPipeline::Config{
      .executor = executor,
      .sessionStrand = *mStrand,
      .logger = Logger{},
      .idAllocator = mIdAllocator,
      .summaryCounters = mCounters,
      .capabilities = std::move(caps),
      .subscriptionLimits = std::move(subLimits),
      .sendResponse =
        [this](Response r)
      {
        std::lock_guard lk(mMutex);
        mResponses.push_back(std::move(r));
        mResponseCv.notify_all();
      },
      .addressSpace = mAddressSpace->weak(),
      .securityContext = mSecurityContext,
      .diagnosticSecurityContext =
        [this]
      {
        ++mDiagnosticSecurityContextCalls;
        return mDiagnosticSecurityContext;
      },
    });
  }

  /// Wait until at least `count` responses have been collected.
  bool wait_for_responses(size_t count, std::chrono::milliseconds timeout = 5000ms)
  {
    std::unique_lock lk(mMutex);
    return mResponseCv.wait_for(lk, timeout, [&] { return mResponses.size() >= count; });
  }

  Response last_response()
  {
    std::lock_guard lk(mMutex);
    EXPECT_FALSE(mResponses.empty());
    return mResponses.back();
  }

  /// Find a PublishResponse among collected responses.
  std::shared_ptr<PublishResponse> find_publish_response(size_t index = 0)
  {
    std::lock_guard lk(mMutex);
    size_t found = 0;
    for (auto& r : mResponses)
    {
      auto* pr = dynamic_cast<PublishResponse*>(r.second.get());
      if (pr)
      {
        if (found == index)
          return std::dynamic_pointer_cast<PublishResponse>(r.second);
        ++found;
      }
    }
    return nullptr;
  }

  size_t response_count()
  {
    std::lock_guard lk(mMutex);
    return mResponses.size();
  }

  uint32_t next_request_id()
  {
    return mNextRequestId++;
  }

  /// Create a subscription and return its ID.
  IntegerId create_subscription(
    Duration interval = 50, uint8_t priority = 0, bool enabled = true, uint32_t maxNotifications = 0)
  {
    CreateSubscriptionRequest req;
    req.requested_publishing_interval() = interval;
    req.requested_lifetime_count() = 300;
    req.requested_max_keep_alive_count() = 10;
    req.max_notifications_per_publish() = maxNotifications;
    req.publishing_enabled() = enabled;
    req.priority() = priority;

    auto reqId = next_request_id();
    run_on_strand([this, reqId, &req]() { mMgr->handle_create_subscription(reqId, req); });
    auto resp = last_response();
    auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(resp.second.get());
    EXPECT_NE(csResp, nullptr);
    return csResp->subscription_id();
  }

  /// Add a monitored item with a pre-enqueued DataValue to a subscription.
  void add_item_with_value_on_strand(std::shared_ptr<Subscription>& sub, DataValue value,
    uint32_t clientHandle = 0, uint32_t queueSize = 10, uint32_t diagnosticInfoMask = 0)
  {
    // Resolved here, on the test thread: a blocking lookup on the Subscription's strand is refused.
    auto accessControlNode = mAddressSpace->try_find_node_sync(mMonitoredNodeId).value();
    STA::on_strand(*sub,
      [&](auto& g) mutable
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = MonitoringMode::Reporting;
        item->clientHandle = clientHandle;
        item->queueSize = queueSize;
        item->itemToMonitor.node_id() = mMonitoredNodeId;
        item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
        item->accessControlNode = accessControlNode;
        item->accessSecurityContext = mSecurityContext;
        item->accessAddressSpace = mAddressSpace->weak();
        auto userIndependentValue = value;
        item->enqueue_initial(std::move(value), std::move(userIndependentValue));
        item->diagnosticInfoMask = diagnosticInfoMask;
        g.add_monitored_item(std::move(item));
      });
  }

  /// Add multiple items with values.
  void add_items_with_values(
    std::shared_ptr<Subscription>& sub, size_t count, uint32_t startClientHandle = 100)
  {
    for (size_t i = 0; i < count; ++i)
    {
      DataValue dv;
      dv.value() = Variant{static_cast<int32_t>(i)};
      dv.source_timestamp() = DateTime::now();
      add_item_with_value_on_strand(sub, std::move(dv), startClientHandle + static_cast<uint32_t>(i));
    }
  }

  /// Run a callable on the session strand and block until it completes.
  /// All SubscriptionsPipeline method calls must go through this to avoid
  /// racing with strand-posted coroutine continuations and subscription timers.
  template<typename F>
  void run_on_strand(F&& fn)
  {
    std::promise<void> done;
    boost::asio::post(*mStrand,
      [&fn, &done]()
      {
        fn();
        done.set_value();
      });
    done.get_future().get();
  }

  void post_handle_publish(uint32_t requestId, const PublishRequest& req)
  {
    run_on_strand([this, requestId, &req]() { mMgr->handle_publish(requestId, req); });
  }

  /// Flush the executor to ensure pending work (including subscription timer callbacks) is processed.
  /// The subscription timer fires asynchronously; flushing ensures any already-posted timer
  /// callbacks complete before continuing. For cases where the timer has not yet fired,
  /// the subsequent wait_for_responses call provides the actual synchronization.
  void wait_for_subscription_ready(std::chrono::milliseconds /*unused*/ = std::chrono::milliseconds{200})
  {
    auto executor = mThreadPool.get_executor();
    std::promise<void> flushed;
    boost::asio::post(executor, [&flushed]() { flushed.set_value(); });
    flushed.get_future().get();
  }

  /// Wait until a subscription's publishing timer has granted a send slot
  /// (readyToPublish). Notifications are dispatched only on a publishing-interval
  /// tick, never out-of-band on data arrival, so priority/round-robin ordering is
  /// only well-defined once every contending subscription is ready.
  void wait_until_ready(const std::shared_ptr<Subscription>& sub,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{3000})
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (sub->get_info().readyToPublish)
        return;
      std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
  }

private:
  uint32_t mNextRequestId{1};
};

// ============================================================
// Priority / Ordering
// ============================================================

// @relation(SVR-SUB-GEN-060, SVR-SUB-GEN-126, scope=function)
TEST_F(PublishFlowTest, Publish_Gen060_HigherPriorityServedFirst)
{
  create_manager();

  auto lowId = create_subscription(50, /*priority=*/10);
  auto highId = create_subscription(50, /*priority=*/200);

  auto lowSub = SMTA::on_strand(*mMgr,
    [lowId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(lowId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  auto highSub = SMTA::on_strand(*mMgr,
    [highId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(highId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(lowSub, nullptr);
  ASSERT_NE(highSub, nullptr);

  add_items_with_values(lowSub, 1, 100);
  add_items_with_values(highSub, 1, 200);
  // Both subscriptions must be ready (each publishing timer has fired) before the
  // Publish requests arrive, otherwise the first-ready sub - not the higher
  // priority one - would be served first.
  wait_until_ready(lowSub);
  wait_until_ready(highSub);

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  post_handle_publish(next_request_id(), pubReq);

  wait_for_responses(baseResponses + 2, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  EXPECT_EQ(pr->subscription_id(), highId);
}

// @relation(SVR-SUB-GEN-061, SVR-SUB-GEN-126, scope=function)
TEST_F(PublishFlowTest, Publish_Gen061_EqualPriorityRoundRobin)
{
  create_manager();

  auto id1 = create_subscription(50, /*priority=*/0);
  auto id2 = create_subscription(50, /*priority=*/0);

  auto sub1 = SMTA::on_strand(*mMgr,
    [id1](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(id1);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  auto sub2 = SMTA::on_strand(*mMgr,
    [id2](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(id2);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub1, nullptr);
  ASSERT_NE(sub2, nullptr);

  add_items_with_values(sub1, 1, 100);
  add_items_with_values(sub2, 1, 200);
  // Both must be ready before publishing so round-robin sees two eligible subs.
  wait_until_ready(sub1);
  wait_until_ready(sub2);

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  post_handle_publish(next_request_id(), pubReq);

  wait_for_responses(baseResponses + 2, 3000ms);

  auto pr0 = find_publish_response(0);
  auto pr1 = find_publish_response(1);
  ASSERT_NE(pr0, nullptr);
  ASSERT_NE(pr1, nullptr);
  EXPECT_NE(pr0->subscription_id(), pr1->subscription_id());
}

// Notifications are paced by the publishing interval, never delivered out-of-band
// in response to an arriving Publish request. With a long publishing interval, a
// Publish request that arrives while data is already queued - but before the
// publishing timer has fired - must NOT be answered with data; it queues until the
// next tick. The pre-fix pipeline keyed dispatch on raw data availability and
// answered immediately, so a 1000ms-interval subscription emitted a dataChange on
// essentially every Publish (UACTT Subscription Basic 054: 136 received vs 10).
TEST_F(PublishFlowTest, Publish_DataPacedByPublishingIntervalNotPublishArrival)
{
  create_manager();

  // 10s publishing interval: the timer will not fire during this test, so the
  // only way a response could appear is the (buggy) out-of-band path.
  auto subId = create_subscription(10000, /*priority=*/0);
  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      return it == g.subscriptions().end() ? nullptr : it->second;
    });
  ASSERT_NE(sub, nullptr);

  add_items_with_values(sub, 1, 100);  // data is queued and reportable
  wait_for_subscription_ready();  // flush only - the 10s timer has NOT fired

  // Data is queued, but the publishing timer has granted no send slot yet.
  EXPECT_TRUE(sub->get_info().hasNotifications);
  EXPECT_FALSE(sub->get_info().readyToPublish);

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);

  // Give the pipeline ample opportunity to (wrongly) answer out-of-band.
  std::this_thread::sleep_for(std::chrono::milliseconds{300});

  EXPECT_EQ(response_count(), baseResponses)
    << "Publish answered out-of-band - notification delivery is not gated by the publishing interval";
}

// ============================================================
// Acknowledgements
// ============================================================

TEST_F(PublishFlowTest, Publish_SvcPub001_AcknowledgesAndReturnsNotification)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  EXPECT_EQ(pr->subscription_id(), subId);
  EXPECT_FALSE(pr->notification_message().notification_data().empty());
}

TEST_F(PublishFlowTest, Publish_SvcPub006_MultipleAcksForSameSubscription)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);

  // First publish round.
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq1;
  post_handle_publish(next_request_id(), pubReq1);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr1 = find_publish_response(0);
  ASSERT_NE(pr1, nullptr);
  uint32_t seqNum1 = pr1->notification_message().sequence_number();

  // Second publish round.
  add_items_with_values(sub, 1, 200);
  wait_for_subscription_ready();

  baseResponses = response_count();
  PublishRequest pubReq2;
  post_handle_publish(next_request_id(), pubReq2);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr2 = find_publish_response(1);
  ASSERT_NE(pr2, nullptr);
  uint32_t seqNum2 = pr2->notification_message().sequence_number();

  // Third publish acking both.
  add_items_with_values(sub, 1, 300);
  wait_for_subscription_ready();

  PublishRequest pubReq3;
  SubscriptionAcknowledgement ack1;
  ack1.subscription_id() = subId;
  ack1.sequence_number() = seqNum1;
  SubscriptionAcknowledgement ack2;
  ack2.subscription_id() = subId;
  ack2.sequence_number() = seqNum2;
  pubReq3.subscription_acknowledgements() = std::vector<SubscriptionAcknowledgement>{ack1, ack2};

  baseResponses = response_count();
  post_handle_publish(next_request_id(), pubReq3);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr3 = find_publish_response(2);
  ASSERT_NE(pr3, nullptr);
  ASSERT_EQ(pr3->results().size(), 2u);
  EXPECT_EQ(pr3->results()[0], StatusCode{Status::Good});
  EXPECT_EQ(pr3->results()[1], StatusCode{Status::Good});
}

TEST_F(PublishFlowTest, Publish_SvcPub006_UnknownSeqNumReturnsBadSeqNumUnknown)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  // First publish.
  size_t baseResponses = response_count();
  PublishRequest pubReq1;
  post_handle_publish(next_request_id(), pubReq1);
  wait_for_responses(baseResponses + 1, 3000ms);

  // Second publish acking non-existent seq num.
  add_items_with_values(sub, 1, 200);
  wait_for_subscription_ready();

  baseResponses = response_count();
  PublishRequest pubReq2;
  SubscriptionAcknowledgement badAck;
  badAck.subscription_id() = subId;
  badAck.sequence_number() = 99999;
  pubReq2.subscription_acknowledgements() = std::vector<SubscriptionAcknowledgement>{badAck};
  post_handle_publish(next_request_id(), pubReq2);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(1);
  ASSERT_NE(pr, nullptr);
  ASSERT_EQ(pr->results().size(), 1u);
  EXPECT_EQ(pr->results()[0], StatusCode{Status::BadSequenceNumberUnknown});
}

TEST_F(PublishFlowTest, Publish_SvcPub007_AckedMessageRemovedFromRetransmission)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq1;
  post_handle_publish(next_request_id(), pubReq1);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr1 = find_publish_response(0);
  ASSERT_NE(pr1, nullptr);
  uint32_t seqNum = pr1->notification_message().sequence_number();
  {
    size_t queueSize = 0;
    run_on_strand([this, &queueSize]() { queueSize = mMgr->retransmission_queue_size(); });
    EXPECT_GE(queueSize, 1u);
  }

  // Ack it.
  add_items_with_values(sub, 1, 200);
  wait_for_subscription_ready();

  baseResponses = response_count();
  PublishRequest pubReq2;
  SubscriptionAcknowledgement ack;
  ack.subscription_id() = subId;
  ack.sequence_number() = seqNum;
  pubReq2.subscription_acknowledgements() = std::vector<SubscriptionAcknowledgement>{ack};
  post_handle_publish(next_request_id(), pubReq2);
  wait_for_responses(baseResponses + 1, 3000ms);

  SMTA::on_strand(*mMgr,
    [&](auto& g)
    {
      const auto& retrans = g.retransmission_queue();
      for (const auto& entry : retrans)
      {
        if (entry.subscriptionId == subId)
        {
          EXPECT_NE(entry.message.sequence_number(), seqNum);
        }
      }
    });
}

TEST_F(PublishFlowTest, Publish_SvcPub007_UnackedMessageRetained)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  {
    size_t queueSize = 0;
    run_on_strand([this, &queueSize]() { queueSize = mMgr->retransmission_queue_size(); });
    EXPECT_GE(queueSize, 1u);
  }
}

TEST_F(PublishFlowTest, Publish_Ack_InvalidSubReturnsBadSubscriptionIdInvalid)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  SubscriptionAcknowledgement badAck;
  badAck.subscription_id() = 999999;
  badAck.sequence_number() = 1;
  pubReq.subscription_acknowledgements() = std::vector<SubscriptionAcknowledgement>{badAck};
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  ASSERT_EQ(pr->results().size(), 1u);
  EXPECT_EQ(pr->results()[0], StatusCode{Status::BadSubscriptionIdInvalid});
}

// ============================================================
// MoreNotifications
// ============================================================

TEST_F(PublishFlowTest, Publish_SvcPub011_MoreNotificationsTrueWhenOverflow)
{
  create_manager();
  auto subId = create_subscription(50, 0, true, 1);

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);

  // Add 3 items - only 1 fits per publish.
  add_items_with_values(sub, 3, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  EXPECT_TRUE(pr->more_notifications());
}

TEST_F(PublishFlowTest, Publish_SvcPub011_MoreNotificationsFalseWhenAllFit)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  EXPECT_FALSE(pr->more_notifications());
}

// ============================================================
// Sequence Numbers
// ============================================================

// @relation(SVR-SUB-GEN-054, SVR-SUB-GEN-126, scope=function)
TEST_F(PublishFlowTest, Publish_Gen054_AvailableSeqNumsReturned)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  EXPECT_FALSE(pr->available_sequence_numbers().empty());
  uint32_t seqNum = pr->notification_message().sequence_number();
  bool found = false;
  for (auto sn : pr->available_sequence_numbers())
  {
    if (sn == seqNum)
      found = true;
  }
  EXPECT_TRUE(found);
}

TEST_F(PublishFlowTest, Publish_SvcPub010_SeqNumsAfterAcks)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  // First publish.
  size_t baseResponses = response_count();
  PublishRequest pubReq1;
  post_handle_publish(next_request_id(), pubReq1);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr1 = find_publish_response(0);
  ASSERT_NE(pr1, nullptr);
  uint32_t seqNum1 = pr1->notification_message().sequence_number();

  // Second publish with ack of first.
  add_items_with_values(sub, 1, 200);
  wait_for_subscription_ready();

  baseResponses = response_count();
  PublishRequest pubReq2;
  SubscriptionAcknowledgement ack;
  ack.subscription_id() = subId;
  ack.sequence_number() = seqNum1;
  pubReq2.subscription_acknowledgements() = std::vector<SubscriptionAcknowledgement>{ack};
  post_handle_publish(next_request_id(), pubReq2);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr2 = find_publish_response(1);
  ASSERT_NE(pr2, nullptr);
  for (auto sn : pr2->available_sequence_numbers())
  {
    EXPECT_NE(sn, seqNum1);
  }
}

// Covers Part 4 section 7.25 / F35: Publish AvailableSequenceNumbers must be returned in ascending
// numeric order regardless of retransmission-queue insertion order (a cross-session transfer can
// re-home queued entries out of order). CTT Subscription Transfer 015.
TEST_F(PublishFlowTest, Publish_F35_AvailableSeqNumsReturnedInAscendingOrder)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      return it == g.subscriptions().end() ? nullptr : it->second;
    });
  ASSERT_NE(sub, nullptr);

  // Accumulate three unacknowledged notification messages in the retransmission queue.
  for (uint32_t i = 0; i < 3; ++i)
  {
    add_items_with_values(sub, 1, 100 + i);
    wait_for_subscription_ready();
    size_t baseResponses = response_count();
    PublishRequest pubReq;
    post_handle_publish(next_request_id(), pubReq);
    wait_for_responses(baseResponses + 1, 3000ms);
  }

  // Force a non-ascending queue order (as transfer re-homing the retransmission queue can).
  SMTA::on_strand(*mMgr,
    [](auto& g)
    {
      auto& queue = g.retransmission_queue();
      std::reverse(queue.begin(), queue.end());
      return 0;
    });

  // A further publish must still report AvailableSequenceNumbers ascending.
  add_items_with_values(sub, 1, 200);
  wait_for_subscription_ready();
  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(3);
  ASSERT_NE(pr, nullptr);
  const auto& seqNums = pr->available_sequence_numbers();
  ASSERT_GE(seqNums.size(), 2u) << "need multiple entries to verify ordering";
  EXPECT_TRUE(std::is_sorted(seqNums.begin(), seqNums.end()))
    << "AvailableSequenceNumbers must be in ascending numeric order";
}

// ============================================================
// Retransmission Queue
// ============================================================

// @relation(SVR-SUB-GEN-050, SVR-SUB-GEN-126, scope=function)
TEST_F(PublishFlowTest, Publish_Gen050_SentMessageRetainedInRetransmissionQueue)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);

  auto expectedSeqNum = pr->notification_message().sequence_number();
  SMTA::on_strand(*mMgr,
    [&](auto& g)
    {
      const auto& retrans = g.retransmission_queue();
      bool found = false;
      for (const auto& entry : retrans)
      {
        if (entry.subscriptionId == subId && entry.message.sequence_number() == expectedSeqNum)
        {
          found = true;
        }
      }
      EXPECT_TRUE(found);
    });
}

// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-01-LIFETIME, scope=function)
TEST_F(PublishFlowTest, RetransmissionProjectionSidecarsShareMessageLifetimeAndCapacity)
{
  create_manager();
  const auto subscriptionId = create_subscription();

  EventFilter requestedFilter;
  SimpleAttributeOperand eventId;
  eventId.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventId.browse_path().push_back(QualifiedName{0, String{"EventId"}});
  eventId.attribute_id() = utils::to_underlying(AttributeId::Value);
  requestedFilter.select_clauses().push_back(std::move(eventId));
  auto compiled = CompiledEventFilter::compile(requestedFilter);
  ASSERT_TRUE(compiled.overallStatus.is_good());
  ASSERT_NE(compiled.filter, nullptr);
  std::shared_ptr<const CompiledEventFilter> retainedFilter{std::move(compiled.filter)};

  std::array<std::shared_ptr<std::atomic<size_t>>, 3> destructionCounts{
    std::make_shared<std::atomic<size_t>>(0),
    std::make_shared<std::atomic<size_t>>(0),
    std::make_shared<std::atomic<size_t>>(0)};
  SMTA::on_strand(*mMgr,
    [&](auto& pipeline)
    {
      pipeline.max_retransmission_queue_size() = 2;
      for (uint32_t sequenceNumber = 1; sequenceNumber <= 3; ++sequenceNumber)
      {
        NotificationMessage message;
        message.sequence_number() = sequenceNumber;
        auto data = std::make_unique<DataChangeNotification>();
        MonitoredItemNotification dataItem;
        dataItem.client_handle() = 100 + sequenceNumber;
        dataItem.value() = DataValue{Variant{int32_t{static_cast<int32_t>(900 + sequenceNumber)}}};
        data->monitored_items().push_back(std::move(dataItem));
        append_notification(message, std::move(data));

        auto events = std::make_unique<EventNotificationList>();
        EventFieldList eventFields;
        eventFields.client_handle() = 200 + sequenceNumber;
        eventFields.event_fields().push_back(Variant{ByteString{static_cast<uint8_t>(sequenceNumber)}});
        events->events().push_back(std::move(eventFields));
        append_notification(message, std::move(events));

        auto destructionCount = destructionCounts[sequenceNumber - 1];
        std::shared_ptr<BaseEvent> rawEvent{new BaseEvent,
          [destructionCount](BaseEvent* event)
          {
            delete event;
            destructionCount->fetch_add(1, std::memory_order_relaxed);
          }};
        rawEvent->eventId = ByteString{static_cast<uint8_t>(sequenceNumber)};
        rawEvent->sourceNode = mEventSourceId;
        rawEvent->eventType = mEventTypeId;

        std::vector<RetainedDataProjection> dataProjections{RetainedDataProjection{sequenceNumber,
          mMonitoredNodeId,
          AttributeId::Value,
          DataValue{Variant{int32_t{static_cast<int32_t>(100 + sequenceNumber)}}}}};
        std::vector<RetainedEventProjection> eventProjections{RetainedEventProjection{
          200 + sequenceNumber, mEventSourceId, mEventTypeId, std::move(rawEvent), {}, retainedFilter}};
        pipeline.add_to_retransmission_queue(subscriptionId,
          std::move(message),
          std::shared_ptr<const Array<String>>{},
          std::move(eventProjections),
          std::move(dataProjections));
      }

      const auto& queue = pipeline.retransmission_queue();
      ASSERT_EQ(queue.size(), 2u);
      EXPECT_EQ(queue[0].message.sequence_number(), 2u);
      EXPECT_EQ(queue[1].message.sequence_number(), 3u);
      for (const auto& entry : queue)
      {
        ASSERT_EQ(entry.message.notification_data().size(), 2u);
        ASSERT_EQ(entry.dataProjections.size(), 1u);
        ASSERT_EQ(entry.eventProjections.size(), 1u);
        ASSERT_TRUE(entry.dataProjections[0].userIndependentValue.has_value());
        EXPECT_TRUE(entry.eventProjections[0].complete());
      }
    });
  EXPECT_EQ(destructionCounts[0]->load(std::memory_order_relaxed), 1u)
    << "evicting the oldest wire message did not destroy its Event sidecar";
  EXPECT_EQ(destructionCounts[1]->load(std::memory_order_relaxed), 0u);
  EXPECT_EQ(destructionCounts[2]->load(std::memory_order_relaxed), 0u);

  SMTA::on_strand(*mMgr,
    [&](auto& pipeline)
    {
      SubscriptionAcknowledgement acknowledgement;
      acknowledgement.subscription_id() = subscriptionId;
      acknowledgement.sequence_number() = 2;
      const std::vector<SubscriptionAcknowledgement> acknowledgements{acknowledgement};
      std::vector<StatusCode> results;
      pipeline.process_acknowledgements(acknowledgements, results);
      ASSERT_EQ(results.size(), 1u);
      EXPECT_TRUE(results[0].is_good());
      ASSERT_EQ(pipeline.retransmission_queue().size(), 1u);
      EXPECT_EQ(pipeline.retransmission_queue().front().message.sequence_number(), 3u);
      EXPECT_EQ(pipeline.retransmission_queue().front().dataProjections.size(), 1u);
      EXPECT_EQ(pipeline.retransmission_queue().front().eventProjections.size(), 1u);
    });
  EXPECT_EQ(destructionCounts[1]->load(std::memory_order_relaxed), 1u)
    << "acknowledging the wire message did not destroy its Event sidecar";
  EXPECT_EQ(destructionCounts[2]->load(std::memory_order_relaxed), 0u);
}

// @relation(SVR-SUB-GEN-050, scope=function)
TEST_F(PublishFlowTest, Publish_Gen050_KeepAliveNotAddedToRetransmissionQueue)
{
  create_manager();
  auto subId = create_subscription();

  // No monitored items - publish should produce keep-alive, not a notification.
  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);

  // Wait for keep-alive response.
  wait_for_responses(baseResponses + 1, 3000ms);

  SMTA::on_strand(*mMgr,
    [&](auto& g)
    {
      const auto& retrans = g.retransmission_queue();
      for (const auto& entry : retrans)
      {
        if (entry.subscriptionId == subId)
        {
          EXPECT_FALSE(entry.message.notification_data().empty())
            << "Keep-alive messages should not be in retransmission queue";
        }
      }
    });
}

// @relation(SVR-SUB-GEN-051, SVR-SUB-GEN-126, scope=function)
TEST_F(PublishFlowTest, Publish_Gen051_RetransmissionQueueSizeRespected)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxPublishRequestsPerSession = 2;
  create_manager({}, subLimits);
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);

  for (int i = 0; i < 5; ++i)
  {
    add_items_with_values(sub, 1, 100 + i * 10);
    wait_for_subscription_ready();

    size_t baseResponses = response_count();
    PublishRequest pubReq;
    post_handle_publish(next_request_id(), pubReq);
    wait_for_responses(baseResponses + 1, 3000ms);
  }

  // retransmission queue size = 2 * maxPublishRequests = 4
  {
    size_t queueSize = 0;
    run_on_strand([this, &queueSize]() { queueSize = mMgr->retransmission_queue_size(); });
    EXPECT_LE(queueSize, 4u);
  }
}

// @relation(SVR-SUB-GEN-052, SVR-SUB-GEN-126, scope=function)
TEST_F(PublishFlowTest, Publish_Gen052_OldestDiscardedOnRetransmissionOverflow)
{
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxPublishRequestsPerSession = 2;
  create_manager({}, subLimits);
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);

  std::vector<uint32_t> seqNums;

  for (int i = 0; i < 5; ++i)
  {
    add_items_with_values(sub, 1, 100 + i * 10);
    wait_for_subscription_ready();

    size_t baseResponses = response_count();
    PublishRequest pubReq;
    post_handle_publish(next_request_id(), pubReq);
    wait_for_responses(baseResponses + 1, 3000ms);

    auto pr = find_publish_response(i);
    ASSERT_NE(pr, nullptr);
    seqNums.push_back(pr->notification_message().sequence_number());
  }

  SMTA::on_strand(*mMgr,
    [&](auto& g)
    {
      const auto& retrans = g.retransmission_queue();
      for (const auto& entry : retrans)
      {
        if (entry.subscriptionId == subId)
        {
          EXPECT_NE(entry.message.sequence_number(), seqNums[0])
            << "Oldest message should have been discarded";
        }
      }
    });
}

// ============================================================
// Republish (end-to-end)
// ============================================================

TEST_F(PublishFlowTest, Publish_Republish001_RetransmitsMessage)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  uint32_t seqNum = pr->notification_message().sequence_number();

  RepublishRequest repReq;
  repReq.subscription_id() = subId;
  repReq.retransmit_sequence_number() = seqNum;
  const auto republishResponseBase = response_count();
  {
    auto reqId = next_request_id();
    run_on_strand([this, reqId, &repReq]() { mMgr->handle_republish(reqId, repReq); });
  }
  ASSERT_TRUE(wait_for_responses(republishResponseBase + 1));

  auto resp = last_response();
  auto* repResp = dynamic_cast<RepublishResponse*>(resp.second.get());
  ASSERT_NE(repResp, nullptr);
  EXPECT_EQ(repResp->notification_message().sequence_number(), seqNum);
}

// @relation(AC-SVR-SUB-GEN-092-PUBLISHTIME-PRESERVED, scope=function)
TEST_F(PublishFlowTest, Publish_Republish003_PublishTimePreserved)
{
  create_manager();
  auto subId = create_subscription();

  auto sub = SMTA::on_strand(*mMgr,
    [subId](auto& g) -> std::shared_ptr<Subscription>
    {
      auto it = g.subscriptions().find(subId);
      if (it == g.subscriptions().end())
        return nullptr;
      return it->second;
    });
  ASSERT_NE(sub, nullptr);
  add_items_with_values(sub, 1, 100);
  wait_for_subscription_ready();

  size_t baseResponses = response_count();
  PublishRequest pubReq;
  post_handle_publish(next_request_id(), pubReq);
  wait_for_responses(baseResponses + 1, 3000ms);

  auto pr = find_publish_response(0);
  ASSERT_NE(pr, nullptr);
  uint32_t seqNum = pr->notification_message().sequence_number();
  auto originalPublishTime = pr->notification_message().publish_time();

  std::this_thread::sleep_for(50ms);

  RepublishRequest repReq;
  repReq.subscription_id() = subId;
  repReq.retransmit_sequence_number() = seqNum;
  const auto republishResponseBase = response_count();
  {
    auto reqId = next_request_id();
    run_on_strand([this, reqId, &repReq]() { mMgr->handle_republish(reqId, repReq); });
  }
  ASSERT_TRUE(wait_for_responses(republishResponseBase + 1));

  auto resp = last_response();
  auto* repResp = dynamic_cast<RepublishResponse*>(resp.second.get());
  ASSERT_NE(repResp, nullptr);
  EXPECT_EQ(repResp->notification_message().publish_time(), originalPublishTime);
}

class ComplianceSubscription : public PublishFlowTest
{};

// @relation(AC-SVR-AUTHZ-016-REPUBLISH-REAUTHORIZES, scope=function)
// @verifies(AC-SVR-AUTHZ-016-REPUBLISH-REAUTHORIZES)
TEST_F(ComplianceSubscription, RepublishReauthorizesRetainedNotification)
{
  create_manager();
  const auto subscriptionId = create_subscription();
  auto subscription = SMTA::on_strand(*mMgr,
    [subscriptionId](auto& pipeline) -> std::shared_ptr<Subscription>
    {
      auto found = pipeline.subscriptions().find(subscriptionId);
      if (found == pipeline.subscriptions().end())
        return nullptr;
      return found->second;
    });
  ASSERT_NE(subscription, nullptr);

  DataValue originalValue{Variant{int32_t{42}}};
  originalValue.status() = StatusCode{Status::Good};
  add_item_with_value_on_strand(subscription, std::move(originalValue), 77);
  wait_for_subscription_ready();

  const auto publishResponseBase = response_count();
  PublishRequest publishRequest;
  post_handle_publish(next_request_id(), publishRequest);
  ASSERT_TRUE(wait_for_responses(publishResponseBase + 1));
  auto published = find_publish_response();
  ASSERT_NE(published, nullptr);
  ASSERT_EQ(published->notification_message().notification_data().size(), 1u);
  auto* publishedData =
    dynamic_cast<DataChangeNotification*>(published->notification_message().notification_data()[0].get());
  ASSERT_NE(publishedData, nullptr);
  ASSERT_EQ(publishedData->monitored_items().size(), 1u);
  EXPECT_EQ(publishedData->monitored_items()[0].value().value(), Variant{int32_t{42}});

  auto node = mAddressSpace->try_find_node_sync(mMonitoredNodeId).value();
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::Read);
  ua::test_helpers::set_test_node_permissions(node, permissions);

  RepublishRequest republishRequest;
  republishRequest.subscription_id() = subscriptionId;
  republishRequest.retransmit_sequence_number() = published->notification_message().sequence_number();
  const auto republishResponseBase = response_count();
  const auto republishRequestId = next_request_id();
  run_on_strand([this, republishRequestId, &republishRequest]()
    { mMgr->handle_republish(republishRequestId, republishRequest); });
  ASSERT_TRUE(wait_for_responses(republishResponseBase + 1));

  auto* republished = dynamic_cast<RepublishResponse*>(last_response().second.get());
  ASSERT_NE(republished, nullptr);
  ASSERT_EQ(republished->notification_message().notification_data().size(), 1u);
  auto* republishedData =
    dynamic_cast<DataChangeNotification*>(republished->notification_message().notification_data()[0].get());
  ASSERT_NE(republishedData, nullptr);
  ASSERT_EQ(republishedData->monitored_items().size(), 1u);
  const auto& deniedValue = republishedData->monitored_items()[0].value();
  ASSERT_TRUE(deniedValue.status().has_value());
  EXPECT_EQ(*deniedValue.status(), StatusCode{Status::BadUserAccessDenied});
  EXPECT_TRUE(deniedValue.value().empty()) << "the value published before revocation leaked";
}

// @relation(AC-SVR-AUTHZ-016-REPUBLISH-REAUTHORIZES, scope=function)
// @verifies(AC-SVR-AUTHZ-016-REPUBLISH-REAUTHORIZES)
TEST_F(ComplianceSubscription, RepublishOmitsAnEventWhoseConcreteSourceWasRevoked)
{
  create_manager();
  const auto subscriptionId = create_subscription();
  auto subscription = SMTA::on_strand(*mMgr,
    [subscriptionId](auto& pipeline) -> std::shared_ptr<Subscription>
    {
      auto found = pipeline.subscriptions().find(subscriptionId);
      if (found == pipeline.subscriptions().end())
        return nullptr;
      return found->second;
    });
  ASSERT_NE(subscription, nullptr);

  EventFilter requestedFilter;
  SimpleAttributeOperand eventId;
  eventId.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventId.browse_path().push_back(QualifiedName{0, String{"EventId"}});
  eventId.attribute_id() = utils::to_underlying(AttributeId::Value);
  requestedFilter.select_clauses().push_back(std::move(eventId));
  auto compiled = CompiledEventFilter::compile(requestedFilter);
  ASSERT_TRUE(compiled.overallStatus.is_good());
  ASSERT_NE(compiled.filter, nullptr);
  std::shared_ptr<CompiledEventFilter> eventFilter{std::move(compiled.filter)};
  auto rawEvent = std::make_shared<BaseEvent>();
  rawEvent->eventId = ByteString{0x88};
  rawEvent->eventType = mEventTypeId;
  rawEvent->sourceNode = mEventSourceId;
  rawEvent->sourceName = String{"RestrictedReplaySource"};
  rawEvent->time = DateTime::now();
  rawEvent->receiveTime = rawEvent->time;
  auto fields = eventFilter->project(*rawEvent, 88);
  auto retainedFilter = eventFilter->retained_copy();

  // Resolved here, on the test thread: a blocking lookup on the Subscription's strand is refused.
  auto eventSourceNode = mAddressSpace->try_find_node_sync(mEventSourceId).value();
  STA::on_strand(*subscription,
    [&](auto& guard)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->isEventItem = true;
      item->clientHandle = 88;
      item->queueSize = 10;
      item->eventFilter = eventFilter;
      item->itemToMonitor.node_id() = mEventSourceId;
      item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
      item->accessControlNode = eventSourceNode;
      item->accessSecurityContext = mSecurityContext;
      item->accessAddressSpace = mAddressSpace->weak();

      item->enqueue_event(std::move(fields),
        false,
        RetainedEventProjection{88, mEventSourceId, mEventTypeId, rawEvent, {}, std::move(retainedFilter)});
      guard.add_monitored_item(std::move(item));
    });
  wait_for_subscription_ready();

  const auto publishResponseBase = response_count();
  PublishRequest publishRequest;
  post_handle_publish(next_request_id(), publishRequest);
  ASSERT_TRUE(wait_for_responses(publishResponseBase + 1));
  auto published = find_publish_response();
  ASSERT_NE(published, nullptr);
  ASSERT_EQ(published->notification_message().notification_data().size(), 1u);
  ASSERT_NE(
    dynamic_cast<EventNotificationList*>(published->notification_message().notification_data()[0].get()),
    nullptr);

  auto eventSource = mAddressSpace->try_find_node_sync(mEventSourceId).value();
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::ReceiveEvents);
  ua::test_helpers::set_test_node_permissions(eventSource, permissions);

  RepublishRequest republishRequest;
  republishRequest.subscription_id() = subscriptionId;
  republishRequest.retransmit_sequence_number() = published->notification_message().sequence_number();
  const auto republishResponseBase = response_count();
  const auto republishRequestId = next_request_id();
  run_on_strand([this, republishRequestId, &republishRequest]()
    { mMgr->handle_republish(republishRequestId, republishRequest); });
  ASSERT_TRUE(wait_for_responses(republishResponseBase + 1));

  auto* republished = dynamic_cast<RepublishResponse*>(last_response().second.get());
  ASSERT_NE(republished, nullptr);
  EXPECT_TRUE(republished->notification_message().notification_data().empty())
    << "the retained Event leaked after its concrete source lost ReceiveEvents";
}

// @relation(AC-COMP-SVR-REPUBLISH-PROJECTION-01-RAW-ALIGNMENT, scope=function)
// @relation(AC-SVR-AUTHZ-016-REPUBLISH-REPROJECTS-RAW-SIDECAR, scope=function)
// @verifies AC-SVR-AUTHZ-016-REPUBLISH-REPROJECTS-RAW-SIDECAR
TEST_F(ComplianceSubscription, RepublishPreservesSequenceAndNotificationOrderAfterReprojection)
{
  create_manager();
  const auto subscriptionId = create_subscription();
  auto subscription = SMTA::on_strand(*mMgr,
    [subscriptionId](auto& pipeline) -> std::shared_ptr<Subscription>
    {
      const auto found = pipeline.subscriptions().find(subscriptionId);
      return found == pipeline.subscriptions().end() ? nullptr : found->second;
    });
  ASSERT_NE(subscription, nullptr);

  add_item_with_value_on_strand(subscription, DataValue{Variant{int32_t{171}}}, 71);
  add_item_with_value_on_strand(subscription, DataValue{Variant{int32_t{172}}}, 72);

  EventFilter requestedFilter;
  SimpleAttributeOperand eventId;
  eventId.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventId.browse_path().push_back(QualifiedName{0, String{"EventId"}});
  eventId.attribute_id() = utils::to_underlying(AttributeId::Value);
  requestedFilter.select_clauses().push_back(std::move(eventId));
  auto compiled = CompiledEventFilter::compile(requestedFilter);
  ASSERT_TRUE(compiled.overallStatus.is_good());
  ASSERT_NE(compiled.filter, nullptr);
  std::shared_ptr<CompiledEventFilter> eventFilter{std::move(compiled.filter)};
  auto rawEvent = std::make_shared<BaseEvent>();
  rawEvent->eventId = ByteString{0x71, 0x72, 0x73};
  rawEvent->eventType = mEventTypeId;
  rawEvent->sourceNode = mEventSourceId;
  rawEvent->sourceName = String{"RetainedOrderSource"};
  rawEvent->time = DateTime::now();
  rawEvent->receiveTime = rawEvent->time;
  auto projectedEvent = eventFilter->project(*rawEvent, 73);
  auto retainedFilter = eventFilter->retained_copy();
  // Resolved here, on the test thread: a blocking lookup on the Subscription's strand is refused.
  auto eventSourceNode = mAddressSpace->try_find_node_sync(mEventSourceId).value();
  STA::on_strand(*subscription,
    [&](auto& guard)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->isEventItem = true;
      item->clientHandle = 73;
      item->queueSize = 10;
      item->eventFilter = eventFilter;
      item->itemToMonitor.node_id() = mEventSourceId;
      item->itemToMonitor.attribute_id() = utils::to_underlying(AttributeId::EventNotifier);
      item->accessControlNode = eventSourceNode;
      item->accessSecurityContext = mSecurityContext;
      item->accessAddressSpace = mAddressSpace->weak();
      item->enqueue_event(std::move(projectedEvent),
        false,
        RetainedEventProjection{73, mEventSourceId, mEventTypeId, rawEvent, {}, std::move(retainedFilter)});
      guard.add_monitored_item(std::move(item));
    });
  wait_for_subscription_ready();

  const auto publishResponseBase = response_count();
  PublishRequest publishRequest;
  post_handle_publish(next_request_id(), publishRequest);
  ASSERT_TRUE(wait_for_responses(publishResponseBase + 1));
  auto published = find_publish_response();
  ASSERT_NE(published, nullptr);
  const auto sequenceNumber = published->notification_message().sequence_number();
  const auto publishTime = published->notification_message().publish_time();
  ASSERT_EQ(published->notification_message().notification_data().size(), 2u);
  auto* publishedData =
    dynamic_cast<DataChangeNotification*>(published->notification_message().notification_data()[0].get());
  auto* publishedEvents =
    dynamic_cast<EventNotificationList*>(published->notification_message().notification_data()[1].get());
  ASSERT_NE(publishedData, nullptr);
  ASSERT_NE(publishedEvents, nullptr);
  ASSERT_EQ(publishedData->monitored_items().size(), 2u);
  std::array<IntegerId, 2> publishedHandles{
    publishedData->monitored_items()[0].client_handle(), publishedData->monitored_items()[1].client_handle()};
  std::ranges::sort(publishedHandles);
  EXPECT_EQ(publishedHandles, (std::array<IntegerId, 2>{71, 72}));
  ASSERT_EQ(publishedEvents->events().size(), 1u);
  EXPECT_EQ(publishedEvents->events()[0].client_handle(), 73u);

  mSecurityContext->accessIdentity = std::make_shared<AccessIdentity>(AccessIdentityKey{2},
    std::vector<NodeId>{ua::test_helpers::test_access_role_id()},
    mSecurityContext->userIdentity,
    mSecurityContext->endpointSecurity,
    String{"urn:test:replacement-client"});
  RepublishRequest republishRequest;
  republishRequest.subscription_id() = subscriptionId;
  republishRequest.retransmit_sequence_number() = sequenceNumber;
  const auto republishResponseBase = response_count();
  const auto republishRequestId = next_request_id();
  run_on_strand([this, republishRequestId, &republishRequest]()
    { mMgr->handle_republish(republishRequestId, republishRequest); });
  ASSERT_TRUE(wait_for_responses(republishResponseBase + 1));

  auto* republished = dynamic_cast<RepublishResponse*>(last_response().second.get());
  ASSERT_NE(republished, nullptr);
  const auto& replay = republished->notification_message();
  EXPECT_EQ(replay.sequence_number(), sequenceNumber);
  EXPECT_EQ(replay.publish_time(), publishTime);
  ASSERT_EQ(replay.notification_data().size(), 2u);
  const auto* replayedData = dynamic_cast<const DataChangeNotification*>(replay.notification_data()[0].get());
  const auto* replayedEvents =
    dynamic_cast<const EventNotificationList*>(replay.notification_data()[1].get());
  ASSERT_NE(replayedData, nullptr);
  ASSERT_NE(replayedEvents, nullptr);
  ASSERT_EQ(replayedData->monitored_items().size(), 2u);
  for (size_t index = 0; index < replayedData->monitored_items().size(); ++index)
  {
    EXPECT_EQ(replayedData->monitored_items()[index].client_handle(),
      publishedData->monitored_items()[index].client_handle());
    EXPECT_EQ(replayedData->monitored_items()[index].value().value(),
      publishedData->monitored_items()[index].value().value());
  }
  ASSERT_EQ(replayedEvents->events().size(), 1u);
  EXPECT_EQ(replayedEvents->events()[0].client_handle(), 73u);
  ASSERT_EQ(replayedEvents->events()[0].event_fields().size(), 1u);
  EXPECT_EQ(replayedEvents->events()[0].event_fields()[0], Variant{rawEvent->eventId});
}

// Part 4 section 5.12.2.1 and section 7.25.2: Create/Modify returnDiagnostics is sticky per item; Publish
// projects available diagnostics under the receiving Session's current policy, and Republish
// projects retained diagnostics again under the current recipient policy and rebuilds its string table.
// @relation(AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY, AC-SVR-DIAG-015-REPUBLISH-CURRENT-CONTEXT, scope=function)
TEST_F(PublishFlowTest, MonitoredItemDiagnosticsReachPublishAndRepublishWithTheirStringTable)
{
  constexpr uint32_t allDiagnostics = diag::serviceLevelMask | diag::operationLevelMask;
  create_manager();
  auto subscriptionId = create_subscription();
  auto subscription = SMTA::on_strand(*mMgr,
    [subscriptionId](auto& pipeline) -> std::shared_ptr<Subscription>
    {
      auto found = pipeline.subscriptions().find(subscriptionId);
      return found == pipeline.subscriptions().end() ? nullptr : found->second;
    });
  ASSERT_NE(subscription, nullptr);

  const StatusCode originalCause{Status::BadResourceUnavailable,
    make_error_detail("RetainedDiagnosticCause",
      "restricted nested failure summary",
      "restricted nested failure detail",
      "test.restricted.nested")};
  DataValue value;
  value.status() = StatusCode{Status::BadNodeIdUnknown,
    make_error_detail("MonitoredNodeRemoved",
      "monitored node left the address space",
      "node id 0:1000 was deleted while the item was reporting",
      "test.subscription",
      originalCause)};
  add_item_with_value_on_strand(subscription, std::move(value), 7, 5, allDiagnostics);
  wait_until_ready(subscription);

  PublishRequest publishRequest;
  publishRequest.request_header().return_diagnostics() = 0u;
  const size_t responseBase = response_count();
  post_handle_publish(next_request_id(), publishRequest);
  ASSERT_TRUE(wait_for_responses(responseBase + 1, 3000ms));

  auto publishResponse = find_publish_response();
  ASSERT_NE(publishResponse, nullptr);
  ASSERT_EQ(mDiagnosticSecurityContextCalls, 1u);
  ASSERT_FALSE(publishResponse->response_header().string_table().empty());
  ASSERT_EQ(publishResponse->notification_message().notification_data().size(), 1u);
  auto* dataChange = dynamic_cast<DataChangeNotification*>(
    publishResponse->notification_message().notification_data()[0].get());
  ASSERT_NE(dataChange, nullptr);
  ASSERT_EQ(dataChange->monitored_items().size(), 1u);
  ASSERT_EQ(dataChange->diagnostic_infos().size(), 1u);
  ASSERT_TRUE(dataChange->diagnostic_infos()[0].symbolic_id().has_value());

  const auto symbolicIndex = static_cast<size_t>(*dataChange->diagnostic_infos()[0].symbolic_id());
  ASSERT_LT(symbolicIndex, publishResponse->response_header().string_table().size());
  EXPECT_EQ(
    std::string{publishResponse->response_header().string_table()[symbolicIndex]}, "MonitoredNodeRemoved");

  const uint32_t sequenceNumber = publishResponse->notification_message().sequence_number();
  const auto originalPublishTime = publishResponse->notification_message().publish_time();
  const auto& originalDiagnostic = dataChange->diagnostic_infos()[0];
  ASSERT_TRUE(originalDiagnostic.additional_info().has_value());
  EXPECT_EQ(*originalDiagnostic.additional_info(), "node id 0:1000 was deleted while the item was reporting");
  ASSERT_TRUE(originalDiagnostic.inner_status_code().has_value());
  EXPECT_EQ(originalDiagnostic.inner_status_code()->as_status(), Status::BadResourceUnavailable);
  ASSERT_NE(originalDiagnostic.inner_diagnostic_info(), nullptr);

  using Level = ServerConfig::DiagnosticPolicy::Level;
  for (const auto level : {Level::Full, Level::None, Level::Summary, Level::Full})
  {
    SCOPED_TRACE(static_cast<int>(level));
    run_on_strand([this, level] { mDiagnosticSecurityContext.effectiveLevel = level; });

    RepublishRequest republishRequest;
    republishRequest.subscription_id() = subscriptionId;
    republishRequest.retransmit_sequence_number() = sequenceNumber;
    republishRequest.request_header().return_diagnostics() = 0u;
    const auto republishRequestId = next_request_id();
    const auto republishResponseBase = response_count();
    run_on_strand([this, republishRequestId, &republishRequest]()
      { mMgr->handle_republish(republishRequestId, republishRequest); });
    ASSERT_TRUE(wait_for_responses(republishResponseBase + 1));

    auto* republishResponse = dynamic_cast<RepublishResponse*>(last_response().second.get());
    ASSERT_NE(republishResponse, nullptr);
    const auto& message = republishResponse->notification_message();
    EXPECT_EQ(message.sequence_number(), sequenceNumber);
    EXPECT_EQ(message.publish_time(), originalPublishTime);
    ASSERT_EQ(message.notification_data().size(), 1u);
    const auto* replayedData =
      dynamic_cast<const DataChangeNotification*>(message.notification_data()[0].get());
    ASSERT_NE(replayedData, nullptr);
    ASSERT_EQ(replayedData->monitored_items().size(), 1u);
    EXPECT_EQ(replayedData->monitored_items()[0].client_handle(), 7u);
    ASSERT_TRUE(replayedData->monitored_items()[0].value().status().has_value());
    EXPECT_EQ(replayedData->monitored_items()[0].value().status()->as_status(), Status::BadNodeIdUnknown);
    const auto& table = republishResponse->response_header().string_table();
    if (level == Level::None)
    {
      EXPECT_TRUE(replayedData->diagnostic_infos().empty());
      EXPECT_TRUE(table.empty());
      continue;
    }

    ASSERT_EQ(replayedData->diagnostic_infos().size(), 1u);
    const auto& diagnostic = replayedData->diagnostic_infos()[0];
    ASSERT_TRUE(diagnostic.symbolic_id().has_value());
    ASSERT_TRUE(diagnostic.namespace_uri().has_value());
    ASSERT_TRUE(diagnostic.localized_text().has_value());
    ASSERT_LT(static_cast<size_t>(*diagnostic.symbolic_id()), table.size());
    ASSERT_LT(static_cast<size_t>(*diagnostic.namespace_uri()), table.size());
    ASSERT_LT(static_cast<size_t>(*diagnostic.localized_text()), table.size());
    EXPECT_EQ(std::string{table[*diagnostic.symbolic_id()]}, "MonitoredNodeRemoved");
    EXPECT_EQ(std::string{table[*diagnostic.namespace_uri()]}, "test.subscription");
    EXPECT_EQ(std::string{table[*diagnostic.localized_text()]}, "monitored node left the address space");
    EXPECT_FALSE(diagnostic.locale().has_value());
    if (level == Level::Summary)
    {
      EXPECT_FALSE(diagnostic.additional_info().has_value());
      EXPECT_FALSE(diagnostic.inner_status_code().has_value());
      EXPECT_EQ(diagnostic.inner_diagnostic_info(), nullptr);
      ASSERT_EQ(table.size(), 3u);
      std::vector<std::string> projectedStrings;
      for (const auto& entry : table)
        projectedStrings.emplace_back(entry);
      std::sort(projectedStrings.begin(), projectedStrings.end());
      const std::vector<std::string> permittedStrings{
        "MonitoredNodeRemoved", "monitored node left the address space", "test.subscription"};
      EXPECT_EQ(projectedStrings, permittedStrings);
    }
    else
    {
      EXPECT_EQ(diagnostic, originalDiagnostic);
      EXPECT_EQ(table, publishResponse->response_header().string_table());
      ASSERT_EQ(table.size(), 6u);
      ASSERT_NE(diagnostic.inner_diagnostic_info(), nullptr);
      const auto& nested = *diagnostic.inner_diagnostic_info();
      ASSERT_TRUE(nested.symbolic_id().has_value());
      ASSERT_TRUE(nested.namespace_uri().has_value());
      ASSERT_TRUE(nested.localized_text().has_value());
      ASSERT_LT(static_cast<size_t>(*nested.symbolic_id()), table.size());
      ASSERT_LT(static_cast<size_t>(*nested.namespace_uri()), table.size());
      ASSERT_LT(static_cast<size_t>(*nested.localized_text()), table.size());
      EXPECT_EQ(std::string{table[*nested.symbolic_id()]}, "RetainedDiagnosticCause");
      EXPECT_EQ(std::string{table[*nested.namespace_uri()]}, "test.restricted.nested");
      EXPECT_EQ(std::string{table[*nested.localized_text()]}, "restricted nested failure summary");
      ASSERT_TRUE(nested.additional_info().has_value());
      EXPECT_EQ(*nested.additional_info(), "restricted nested failure detail");
    }
  }
}

// @relation(AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY, scope=function)
TEST_F(PublishFlowTest, DiagnosticsFreePublishSkipsPolicyProjectionAndAuxiliaryTable)
{
  constexpr uint32_t allDiagnostics = diag::serviceLevelMask | diag::operationLevelMask;
  create_manager();
  auto subscriptionId = create_subscription();
  auto subscription = SMTA::on_strand(*mMgr,
    [subscriptionId](auto& pipeline) -> std::shared_ptr<Subscription>
    {
      auto found = pipeline.subscriptions().find(subscriptionId);
      return found == pipeline.subscriptions().end() ? nullptr : found->second;
    });
  ASSERT_NE(subscription, nullptr);

  DataValue detailedValue;
  detailedValue.status() = StatusCode{Status::BadInternalError,
    make_error_detail("MustStayCold", "diagnostic mask is zero", "test.subscription")};
  add_item_with_value_on_strand(subscription, std::move(detailedValue), 1, 1, 0u);

  DataValue detailFreeValue;
  detailFreeValue.value() = Variant{int32_t{42}};
  add_item_with_value_on_strand(subscription, std::move(detailFreeValue), 2, 1, allDiagnostics);
  wait_until_ready(subscription);

  const size_t responseBase = response_count();
  PublishRequest publishRequest;
  post_handle_publish(next_request_id(), publishRequest);
  ASSERT_TRUE(wait_for_responses(responseBase + 1, 3000ms));

  auto publishResponse = find_publish_response();
  ASSERT_NE(publishResponse, nullptr);
  EXPECT_EQ(mDiagnosticSecurityContextCalls, 0u) << "no diagnostic candidate may consult Session policy";
  EXPECT_TRUE(publishResponse->response_header().string_table().empty());
  ASSERT_EQ(publishResponse->notification_message().notification_data().size(), 1u);
  auto* dataChange = dynamic_cast<DataChangeNotification*>(
    publishResponse->notification_message().notification_data()[0].get());
  ASSERT_NE(dataChange, nullptr);
  EXPECT_TRUE(dataChange->diagnostic_infos().empty());

  const auto sequenceNumber = publishResponse->notification_message().sequence_number();
  SMTA::on_strand(*mMgr,
    [subscriptionId, sequenceNumber](auto& pipeline)
    {
      for (const auto& entry : pipeline.retransmission_queue())
      {
        if (entry.subscriptionId == subscriptionId && entry.message.sequence_number() == sequenceNumber)
        {
          EXPECT_EQ(entry.diagnosticStringTable, nullptr)
            << "the ordinary retransmission entry must not allocate auxiliary diagnostic storage";
          return;
        }
      }
      FAIL() << "published message was not retained for retransmission";
    });
}

class RepublishProjection : public PublishFlowTest
{
protected:
  /// One RolePermissions entry granting @p permissions to @p role.
  static RolePermissionType role_permission(NodeId role, PermissionType permissions)
  {
    RolePermissionType entry;
    entry.role_id() = std::move(role);
    entry.permissions() = permissions;
    return entry;
  }

  /// The Roles named by the RolePermissions entries @p value holds, in order; empty when it holds none.
  static std::vector<NodeId> roles_of(const Variant& value)
  {
    std::vector<NodeId> roles;
    if (!value.is_array())
      return roles;
    for (const auto& entry : value.as<Array<RefStructure<Structure>>>())
    {
      const auto* permission = dynamic_cast<const RolePermissionType*>(entry.get());
      roles.push_back(permission != nullptr ? permission->role_id() : NodeId{});
    }
    return roles;
  }

  /// The value the notification @p message carries for @p clientHandle, if it carries one.
  static std::optional<DataValue> value_for(const NotificationMessage& message, uint32_t clientHandle)
  {
    for (const auto& data : message.notification_data())
    {
      const auto* change = dynamic_cast<const DataChangeNotification*>(data.get());
      if (change == nullptr)
        continue;
      for (const auto& notification : change->monitored_items())
      {
        if (notification.client_handle() == clientHandle)
          return notification.value();
      }
    }
    return std::nullopt;
  }

  /// Every value the notification @p message carries for @p clientHandle, in order.
  static std::vector<DataValue> values_for_all(const NotificationMessage& message, uint32_t clientHandle)
  {
    std::vector<DataValue> values;
    for (const auto& data : message.notification_data())
    {
      const auto* change = dynamic_cast<const DataChangeNotification*>(data.get());
      if (change == nullptr)
        continue;
      for (const auto& notification : change->monitored_items())
      {
        if (notification.client_handle() == clientHandle)
          values.push_back(notification.value());
      }
    }
    return values;
  }

  static std::string text_of(const std::vector<DataValue>& values)
  {
    std::string text;
    for (const auto& value : values)
    {
      const StatusCode status = value.status().value_or(StatusCode{});
      const auto detail = status.shared_detail();
      text += " " + to_string(value.value()) + " [" + to_string(status) +
              (detail ? ", " + detail->code : "") + "];";
    }
    return text;
  }

  /// The Subscription the pipeline holds as @p subscriptionId.
  std::shared_ptr<Subscription> subscription_of(IntegerId subscriptionId)
  {
    return SMTA::on_strand(*mMgr,
      [subscriptionId](auto& pipeline) -> std::shared_ptr<Subscription>
      {
        const auto found = pipeline.subscriptions().find(subscriptionId);
        return found == pipeline.subscriptions().end() ? nullptr : found->second;
      });
  }

  /// An item on @p attribute of the monitored Node with @p indexRange, Reporting at interval 0.
  MonitoredItemCreateRequest attribute_item(
    AttributeId attribute, const char* indexRange, uint32_t clientHandle, uint32_t queueSize) const
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = mMonitoredNodeId;
    item.item_to_monitor().attribute_id() = utils::to_underlying(attribute);
    item.item_to_monitor().index_range() = indexRange;
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = 0;
    item.requested_parameters().queue_size() = queueSize;
    item.requested_parameters().discard_oldest() = true;
    return item;
  }

  /// Creates @p item on @p subscription for the pipeline's Session; its result.
  MonitoredItemCreateResult create_item(
    Subscription& subscription, IntegerId subscriptionId, MonitoredItemCreateRequest item)
  {
    CreateMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_create().push_back(std::move(item));
    ServerConfig::ServerCapabilities capabilities;
    capabilities.minSupportedSampleRate = 0;
    capabilities.maxMonitoredItemsQueueSize = 1000u;
    auto created = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
    auto results = created->get_future();
    subscription.create_monitored_items_async(std::move(request),
      *mAddressSpace,
      capabilities,
      ServerConfig::SubscriptionLimits{},
      mSecurityContext,
      std::weak_ptr<EventBus>{},
      nullptr,
      [created](std::vector<MonitoredItemCreateResult> answered)
      { created->set_value(std::move(answered)); });
    if (results.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the create did not answer";
      return MonitoredItemCreateResult{};
    }
    auto answered = results.get();
    EXPECT_EQ(answered.size(), 1u);
    return answered.empty() ? MonitoredItemCreateResult{} : std::move(answered.front());
  }

  /// Sends one Publish acknowledging nothing; its response, or null. When @p subscriptionId is given,
  /// Publishes are sent until one is answered for that Subscription (another Subscription's keep-alive may
  /// answer first), at most five.
  std::shared_ptr<PublishResponse> publish_without_acknowledging(std::optional<IntegerId> subscriptionId = {})
  {
    for (int attempt = 0; attempt < 5; ++attempt)
    {
      const auto base = response_count();
      PublishRequest request;
      post_handle_publish(next_request_id(), request);
      if (!wait_for_responses(base + 1))
        return nullptr;
      auto response = std::dynamic_pointer_cast<PublishResponse>(last_response().second);
      if (!subscriptionId || response == nullptr || response->subscription_id() == *subscriptionId)
        return response;
    }
    return nullptr;
  }

  /// Sends a Republish of @p sequenceNumber; its response, or null.
  std::shared_ptr<RepublishResponse> republish(IntegerId subscriptionId, uint32_t sequenceNumber)
  {
    RepublishRequest request;
    request.subscription_id() = subscriptionId;
    request.retransmit_sequence_number() = sequenceNumber;
    const auto base = response_count();
    const auto requestId = next_request_id();
    run_on_strand([this, requestId, &request]() { mMgr->handle_republish(requestId, request); });
    if (!wait_for_responses(base + 1))
      return nullptr;
    return std::dynamic_pointer_cast<RepublishResponse>(last_response().second);
  }
};

// COMP-SVR-NAMESPACE-CALLS-15 rule 4 and DL-69 (D9): a Republish returns the requested NotificationMessage
// from the retransmission queue (OPC 10000-4 5.13.1.1, 5.13.6.1), so a RolePermissions item with the
// IndexRange "0" is republished with the one entry it was published with, not the Node's whole array.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-RANGED-ROLE-PERMISSIONS-NOTIFICATION-KEEPS-ITS-RANGE-ON-REPUBLISH, scope=function)
TEST_F(RepublishProjection, ARangedRolePermissionsNotificationKeepsItsRange)
{
  constexpr uint32_t clientHandle = 91;
  create_manager();
  const auto subscriptionId = create_subscription();
  auto subscription = SMTA::on_strand(*mMgr,
    [subscriptionId](auto& pipeline) -> std::shared_ptr<Subscription>
    {
      const auto found = pipeline.subscriptions().find(subscriptionId);
      return found == pipeline.subscriptions().end() ? nullptr : found->second;
    });
  ASSERT_NE(subscription, nullptr);

  const NodeId allowedRole = ua::test_helpers::test_access_role_id();
  auto node = mAddressSpace->try_find_node_sync(mMonitoredNodeId).value();
  node.set_role_permissions(
    std::vector<RolePermissionType>{role_permission(allowedRole, ua::test_helpers::all_permissions()),
      role_permission(NodeId{1, 7301u}, PermissionType{PermissionType::Bit::Browse}),
      role_permission(NodeId{1, 7302u}, PermissionType{PermissionType::Bit::Browse})});

  CreateMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = TimestampsToReturn::Both;
  MonitoredItemCreateRequest item;
  item.item_to_monitor().node_id() = mMonitoredNodeId;
  item.item_to_monitor().attribute_id() = utils::to_underlying(AttributeId::RolePermissions);
  item.item_to_monitor().index_range() = "0";
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters().client_handle() = clientHandle;
  item.requested_parameters().sampling_interval() = 0;
  item.requested_parameters().queue_size() = 10;
  item.requested_parameters().discard_oldest() = true;
  request.items_to_create().push_back(std::move(item));
  ServerConfig::ServerCapabilities capabilities;
  capabilities.minSupportedSampleRate = 0;
  capabilities.maxMonitoredItemsQueueSize = 1000u;
  auto created = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
  auto createdFuture = created->get_future();
  subscription->create_monitored_items_async(std::move(request),
    *mAddressSpace,
    capabilities,
    ServerConfig::SubscriptionLimits{},
    mSecurityContext,
    std::weak_ptr<EventBus>{},
    nullptr,
    [created](std::vector<MonitoredItemCreateResult> results) { created->set_value(std::move(results)); });
  ASSERT_EQ(createdFuture.wait_for(5s), std::future_status::ready) << "the create did not answer";
  const auto results = createdFuture.get();
  ASSERT_EQ(results.size(), 1u);
  ASSERT_EQ(results[0].status_code(), StatusCode{Status::Good}) << to_string(results[0].status_code());
  wait_for_subscription_ready();

  const auto publishResponseBase = response_count();
  PublishRequest publishRequest;
  post_handle_publish(next_request_id(), publishRequest);
  ASSERT_TRUE(wait_for_responses(publishResponseBase + 1));
  auto published = find_publish_response();
  ASSERT_NE(published, nullptr);
  const auto publishedValue = value_for(published->notification_message(), clientHandle);
  ASSERT_TRUE(publishedValue.has_value()) << "the Publish carried no notification of the item";
  ASSERT_EQ(roles_of(publishedValue->value()), (std::vector<NodeId>{allowedRole}))
    << "the Publish carried " << to_string(publishedValue->value()) << ", not the first of the three entries";

  RepublishRequest republishRequest;
  republishRequest.subscription_id() = subscriptionId;
  republishRequest.retransmit_sequence_number() = published->notification_message().sequence_number();
  const auto republishResponseBase = response_count();
  const auto republishRequestId = next_request_id();
  run_on_strand([this, republishRequestId, &republishRequest]()
    { mMgr->handle_republish(republishRequestId, republishRequest); });
  ASSERT_TRUE(wait_for_responses(republishResponseBase + 1));
  auto* republished = dynamic_cast<RepublishResponse*>(last_response().second.get());
  ASSERT_NE(republished, nullptr) << "the Republish was not answered with a RepublishResponse";
  const auto republishedValue = value_for(republished->notification_message(), clientHandle);
  ASSERT_TRUE(republishedValue.has_value()) << "the Republish carried no notification of the item";
  EXPECT_TRUE(!republishedValue->status().has_value() || republishedValue->status()->is_good())
    << "the Republish carried " << to_string(*republishedValue->status());
  EXPECT_EQ(roles_of(republishedValue->value()), (std::vector<NodeId>{allowedRole}))
    << "the Republish carried " << to_string(republishedValue->value())
    << ", where the Publish carried one entry";
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 4: a Republish returns the NotificationMessage as it was published (OPC
// 10000-4 5.13.1.1, 5.13.6.1), so a ranged UserAccessLevel item whose queue overflowed is republished with
// the same statuses, the Overflow bit included.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-REPUBLISHED-SCALAR-OF-THE-FIVE-KEEPS-ITS-STATUS-BITS, scope=function)
TEST_F(RepublishProjection, ARepublishedScalarOfTheFiveKeepsItsStatusBits)
{
  constexpr uint32_t clientHandle = 92;
  create_manager();
  const auto subscriptionId = create_subscription();
  auto subscription = subscription_of(subscriptionId);
  ASSERT_NE(subscription, nullptr);
  auto variable = mAddressSpace->try_find_node_sync(mMonitoredNodeId).value().as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});

  auto item = attribute_item(AttributeId::UserAccessLevel, "0", clientHandle, 2);
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValueTimestamp;
  filter->deadband_type() = static_cast<uint32_t>(DeadbandType::None);
  item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);
  const auto created = create_item(*subscription, subscriptionId, std::move(item));
  ASSERT_EQ(created.status_code(), StatusCode{Status::Good}) << to_string(created.status_code());
  const IntegerId monitoredItemId = created.monitored_item_id();

  // Three changes of AccessLevel, so that the queue of two overflows.
  const std::array changes{
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite},
    AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::HistoryRead},
    AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::CurrentWrite,
      AccessLevelType::Bit::HistoryRead}};
  // Each change reaches the item through its sample sink, as its namespace delivers a change of AccessLevel,
  // and is awaited until the item has taken it.
  const std::shared_ptr<SampleSink> sink = STA::on_strand(
    *subscription, [](auto& guard) -> std::shared_ptr<SampleSinkImpl> { return guard.sample_sink(); });
  ASSERT_NE(sink, nullptr);
  for (const auto& change : changes)
  {
    std::this_thread::sleep_for(2ms);
    DataValue sample{Variant{change.as_underlying_type()}};
    sample.source_timestamp() = DateTime::now();
    sink->push({{monitoredItemId, std::move(sample)}});
    const uint8_t expected = change.as_underlying_type();
    bool taken = false;
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!taken && std::chrono::steady_clock::now() < deadline)
    {
      taken = STA::on_strand(*subscription,
        [monitoredItemId, expected](auto& guard)
        {
          const auto* monitored = guard.find_monitored_item(monitoredItemId);
          if (monitored == nullptr || !monitored->lastUserIndependentValue)
            return false;
          const auto* held = monitored->lastUserIndependentValue->value().template try_as<uint8_t>();
          return held != nullptr && *held == expected;
        });
      if (!taken)
        std::this_thread::sleep_for(2ms);
    }
    ASSERT_TRUE(taken) << "the AccessLevel " << static_cast<int>(expected) << " did not reach the item";
  }
  wait_for_subscription_ready();

  const auto published = publish_without_acknowledging();
  ASSERT_NE(published, nullptr) << "the Publish was not answered with a PublishResponse";
  const auto publishedValues = values_for_all(published->notification_message(), clientHandle);
  ASSERT_EQ(publishedValues.size(), 2u) << "the Publish carried" << text_of(publishedValues);
  ASSERT_TRUE(std::any_of(publishedValues.begin(),
    publishedValues.end(),
    [](const DataValue& value) { return value.status().has_value() && value.status()->overflow(); }))
    << "the queue did not overflow; the Publish carried" << text_of(publishedValues);

  const auto republished = republish(subscriptionId, published->notification_message().sequence_number());
  ASSERT_NE(republished, nullptr) << "the Republish was not answered with a RepublishResponse";
  const auto republishedValues = values_for_all(republished->notification_message(), clientHandle);
  ASSERT_EQ(republishedValues.size(), publishedValues.size())
    << "the Publish carried" << text_of(publishedValues) << "; the Republish" << text_of(republishedValues);
  for (std::size_t i = 0; i < publishedValues.size(); ++i)
  {
    const StatusCode publishedStatus = publishedValues[i].status().value_or(StatusCode{});
    const StatusCode republishedStatus = republishedValues[i].status().value_or(StatusCode{});
    EXPECT_EQ(republishedStatus.as_status(), Status::BadIndexRangeNoData)
      << "notification " << i + 1 << "; the Republish carried" << text_of(republishedValues);
    EXPECT_EQ(republishedStatus.overflow(), publishedStatus.overflow())
      << "notification " << i + 1 << "; the Publish carried" << text_of(publishedValues) << "; the Republish"
      << text_of(republishedValues);
    EXPECT_EQ(republishedStatus.value(), publishedStatus.value())
      << "notification " << i + 1 << "; the Publish carried" << text_of(publishedValues) << "; the Republish"
      << text_of(republishedValues);
    EXPECT_TRUE(republishedValues[i].value().empty())
      << "notification " << i + 1 << "; the Republish carried" << text_of(republishedValues);
  }
}

// COMP-SVR-NAMESPACE-CALLS-15 rule 4: a Republish returns the NotificationMessage as it was published (OPC
// 10000-4 5.13.1.1, 5.13.6.1). When a namespace marks a ranged UserRolePermissions item's semantics changed
// through its sample sink, whether the initial value is still queued (case 1) or the first Publish emptied
// the queue and the notification is made from the item's last value (case 2), the Republish carries the
// marked notification as the Publish did: Bad_IndexRangeNoData with the SemanticsChanged bit, no Value.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-15-A-SEMANTICS-CHANGED-NOTIFICATION-OF-THE-FIVE-IS-REPUBLISHED-AS-PUBLISHED, scope=function)
TEST_F(RepublishProjection, ASemanticsChangedNotificationOfTheFiveIsRepublishedAsPublished)
{
  create_manager();
  auto node = mAddressSpace->try_find_node_sync(mMonitoredNodeId).value();
  node.set_role_permissions(std::vector<RolePermissionType>{
    role_permission(ua::test_helpers::test_access_role_id(), ua::test_helpers::all_permissions()),
    role_permission(NodeId{1, 7401u}, PermissionType{PermissionType::Bit::Browse}),
    role_permission(NodeId{1, 7402u}, PermissionType{PermissionType::Bit::Browse}),
    role_permission(NodeId{1, 7403u}, PermissionType{PermissionType::Bit::Browse}),
    role_permission(NodeId{1, 7404u}, PermissionType{PermissionType::Bit::Browse})});

  const auto runCase = [this](bool markWhileQueued, uint32_t clientHandle)
  {
    const auto subscriptionId = create_subscription();
    auto subscription = subscription_of(subscriptionId);
    ASSERT_NE(subscription, nullptr);
    const auto created = create_item(
      *subscription, subscriptionId, attribute_item(AttributeId::UserRolePermissions, "3", clientHandle, 10));
    ASSERT_EQ(created.status_code(), StatusCode{Status::Good}) << to_string(created.status_code());
    const std::shared_ptr<SampleSink> sink = STA::on_strand(
      *subscription, [](auto& guard) -> std::shared_ptr<SampleSinkImpl> { return guard.sample_sink(); });
    ASSERT_NE(sink, nullptr);

    if (!markWhileQueued)
    {
      wait_for_subscription_ready();
      const auto first = publish_without_acknowledging(subscriptionId);
      ASSERT_NE(first, nullptr) << "the first Publish was not answered for the Subscription";
      const auto firstValues = values_for_all(first->notification_message(), clientHandle);
      ASSERT_EQ(firstValues.size(), 1u) << "the first Publish carried" << text_of(firstValues);
      ASSERT_EQ(firstValues[0].status().value_or(StatusCode{}).as_status(), Status::BadIndexRangeNoData)
        << "the Session's roles select four or more entries; the first Publish carried"
        << text_of(firstValues);
    }
    sink->mark_semantics_changed(created.monitored_item_id());
    STA::on_strand(*subscription, [](auto&) {});
    wait_for_subscription_ready();

    const auto marked = publish_without_acknowledging(subscriptionId);
    ASSERT_NE(marked, nullptr) << "the Publish after the mark was not answered for the Subscription";
    const auto markedValues = values_for_all(marked->notification_message(), clientHandle);
    ASSERT_EQ(markedValues.size(), 1u) << "the Publish after the mark carried" << text_of(markedValues);
    const StatusCode markedStatus = markedValues[0].status().value_or(StatusCode{});
    ASSERT_TRUE(markedStatus.as_status() == Status::BadIndexRangeNoData && markedStatus.semantics_changed())
      << "the Publish after the mark carried" << text_of(markedValues);

    const auto republished = republish(subscriptionId, marked->notification_message().sequence_number());
    ASSERT_NE(republished, nullptr) << "the Republish was not answered with a RepublishResponse";
    const auto republishedValues = values_for_all(republished->notification_message(), clientHandle);
    ASSERT_EQ(republishedValues.size(), 1u) << "the Republish carried" << text_of(republishedValues);
    const StatusCode republishedStatus = republishedValues[0].status().value_or(StatusCode{});
    EXPECT_EQ(republishedStatus.as_status(), Status::BadIndexRangeNoData)
      << "the Publish carried" << text_of(markedValues) << "; the Republish" << text_of(republishedValues);
    EXPECT_TRUE(republishedStatus.semantics_changed())
      << "the Publish carried" << text_of(markedValues) << "; the Republish" << text_of(republishedValues);
    EXPECT_TRUE(republishedValues[0].value().empty())
      << "the Republish carried" << text_of(republishedValues);
  };

  {
    SCOPED_TRACE("case 1: the mark while the initial value is still queued");
    runCase(true, 93);
  }
  {
    SCOPED_TRACE("case 2: the mark after the first Publish emptied the queue");
    runCase(false, 94);
  }
}

// COMP-SVR-NAMESPACE-CALLS-16 rule 4, DL-69 (E5): a Republish checks a retained Event's subjects again, and
// an Uncertain lookup answer for its SourceNode holds no Node, so the Event is denied, as it is for a Bad
// answer: the Republish answers, and the denied Event is left out of the message, as a revoked one is. The
// first Republish, while the SourceNode still resolves, is the control: it carries the Event.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-AN-UNCERTAIN-SUBJECT-LOOKUP-DENIES-THE-EVENT-ON-REPUBLISH, scope=function)
TEST_F(RepublishProjection, AnUncertainSubjectLookupDeniesTheEventOnRepublish)
{
  constexpr uint32_t clientHandle = 95;
  auto sourceNamespace = std::make_shared<ua::test::BatchRecordingNamespace>(
    "urn:test:republish-uncertain-source", mThreadPool.get_executor());
  const auto sourceIndex = mAddressSpace->add_namespace_sync(sourceNamespace);
  RolePermissionType granted;
  granted.role_id() = ua::test_helpers::test_access_role_id();
  granted.permissions() = ua::test_helpers::all_permissions();
  sourceNamespace->set_namespace_defaults(std::vector<RolePermissionType>{granted}, std::nullopt);
  const NodeId source{sourceIndex, 1101u};
  mAddressSpace->create_node_sync(source, NodeClass::Object);
  create_manager();
  const auto subscriptionId = create_subscription();
  auto subscription = subscription_of(subscriptionId);
  ASSERT_NE(subscription, nullptr);

  EventFilter requestedFilter;
  SimpleAttributeOperand eventId;
  eventId.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventId.browse_path().push_back(QualifiedName{0, String{"EventId"}});
  eventId.attribute_id() = utils::to_underlying(AttributeId::Value);
  requestedFilter.select_clauses().push_back(std::move(eventId));
  auto compiled = CompiledEventFilter::compile(requestedFilter);
  ASSERT_TRUE(compiled.overallStatus.is_good());
  ASSERT_NE(compiled.filter, nullptr);
  std::shared_ptr<CompiledEventFilter> eventFilter{std::move(compiled.filter)};
  auto rawEvent = std::make_shared<BaseEvent>();
  rawEvent->eventId = ByteString{0x95};
  rawEvent->eventType = mEventTypeId;
  rawEvent->sourceNode = source;
  rawEvent->sourceName = String{"UncertainReplaySource"};
  rawEvent->time = DateTime::now();
  rawEvent->receiveTime = rawEvent->time;
  auto fields = eventFilter->project(*rawEvent, clientHandle);
  auto retainedFilter = eventFilter->retained_copy();

  // Resolved here, on the test thread: a blocking lookup on the Subscription's strand is refused.
  auto sourceNode = mAddressSpace->try_find_node_sync(source).value();
  STA::on_strand(*subscription,
    [&](auto& guard)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->isEventItem = true;
      item->clientHandle = clientHandle;
      item->queueSize = 10;
      item->eventFilter = eventFilter;
      item->itemToMonitor.node_id() = source;
      item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
      item->accessControlNode = sourceNode;
      item->accessSecurityContext = mSecurityContext;
      item->accessAddressSpace = mAddressSpace->weak();
      item->enqueue_event(std::move(fields),
        false,
        RetainedEventProjection{clientHandle, source, mEventTypeId, rawEvent, {}, std::move(retainedFilter)});
      guard.add_monitored_item(std::move(item));
    });
  wait_for_subscription_ready();

  const auto eventsFor = [](const NotificationMessage& message)
  {
    std::size_t events = 0;
    for (const auto& data : message.notification_data())
    {
      if (const auto* list = dynamic_cast<const EventNotificationList*>(data.get()))
      {
        events += static_cast<std::size_t>(std::count_if(list->events().begin(),
          list->events().end(),
          [](const EventFieldList& event) { return event.client_handle() == clientHandle; }));
      }
    }
    return events;
  };

  const auto published = publish_without_acknowledging(subscriptionId);
  ASSERT_NE(published, nullptr) << "the Publish did not answer";
  ASSERT_EQ(eventsFor(published->notification_message()), 1u) << "the Event was not published";
  const uint32_t sequenceNumber = published->notification_message().sequence_number();
  const auto control = republish(subscriptionId, sequenceNumber);
  ASSERT_NE(control, nullptr) << "the control Republish was not answered with a RepublishResponse";
  ASSERT_EQ(eventsFor(control->notification_message()), 1u)
    << "the control Republish, while the SourceNode resolves, does not carry the Event";

  sourceNamespace->answer_lookup_of(source,
    StatusCode{Status::UncertainNoCommunicationLastUsableValue,
      ErrorDetail::build(
        "SourceLookupUncertain", "The namespace holds no Node it is sure of", "RepublishProjectionTest")});
  RepublishRequest request;
  request.subscription_id() = subscriptionId;
  request.retransmit_sequence_number() = sequenceNumber;
  const auto base = response_count();
  const auto requestId = next_request_id();
  run_on_strand([this, requestId, &request]() { mMgr->handle_republish(requestId, request); });

  ASSERT_TRUE(wait_for_responses(base + 1, 2000ms)) << "the Republish did not answer within 2 s";
  const auto answer = last_response().second;
  const auto* republished = dynamic_cast<const RepublishResponse*>(answer.get());
  const auto* fault = dynamic_cast<const ServiceFault*>(answer.get());
  ASSERT_NE(republished, nullptr) << "the Republish was answered with "
                                  << (fault != nullptr
                                         ? "a ServiceFault " +
                                             to_string(fault->response_header().service_result())
                                         : std::string{"another response"});
  EXPECT_EQ(republished->notification_message().sequence_number(), sequenceNumber);
  EXPECT_EQ(eventsFor(republished->notification_message()), 0u)
    << "the Event whose SourceNode lookup answered Uncertain was republished";
}

// CALLS-21 rule 1: the completion the pipeline gives a Republish's re-authorization, which a namespace
// holding the re-authorization's lookup holds, keeps no Subscription, so a Session that closes meanwhile
// releases its Subscriptions and, through them, the address space their suspended work holds.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-REPUBLISH-KEEPS-NO-SUBSCRIPTION, scope=function)
TEST_F(RepublishProjection, AHeldRepublishLookupKeepsNoSubscription)
{
  constexpr uint32_t clientHandle = 96;
  auto sourceNamespace = std::make_shared<ua::test::BatchRecordingNamespace>(
    "urn:test:republish-held-source", mThreadPool.get_executor());
  const auto sourceIndex = mAddressSpace->add_namespace_sync(sourceNamespace);
  RolePermissionType granted;
  granted.role_id() = ua::test_helpers::test_access_role_id();
  granted.permissions() = ua::test_helpers::all_permissions();
  sourceNamespace->set_namespace_defaults(std::vector<RolePermissionType>{granted}, std::nullopt);
  const NodeId source{sourceIndex, 1102u};
  mAddressSpace->create_node_sync(source, NodeClass::Object);
  create_manager();
  const auto subscriptionId = create_subscription();
  auto subscription = subscription_of(subscriptionId);
  ASSERT_NE(subscription, nullptr);

  EventFilter requestedFilter;
  SimpleAttributeOperand eventId;
  eventId.type_definition_id() = NodeId{ObjectTypeId::BaseEventType};
  eventId.browse_path().push_back(QualifiedName{0, String{"EventId"}});
  eventId.attribute_id() = utils::to_underlying(AttributeId::Value);
  requestedFilter.select_clauses().push_back(std::move(eventId));
  auto compiled = CompiledEventFilter::compile(requestedFilter);
  ASSERT_TRUE(compiled.overallStatus.is_good());
  ASSERT_NE(compiled.filter, nullptr);
  std::shared_ptr<CompiledEventFilter> eventFilter{std::move(compiled.filter)};
  auto rawEvent = std::make_shared<BaseEvent>();
  rawEvent->eventId = ByteString{0x96};
  rawEvent->eventType = mEventTypeId;
  rawEvent->sourceNode = source;
  rawEvent->sourceName = String{"HeldReplaySource"};
  rawEvent->time = DateTime::now();
  rawEvent->receiveTime = rawEvent->time;
  auto fields = eventFilter->project(*rawEvent, clientHandle);
  auto retainedFilter = eventFilter->retained_copy();
  auto sourceNode = mAddressSpace->try_find_node_sync(source).value();
  STA::on_strand(*subscription,
    [&](auto& guard)
    {
      auto item = std::make_unique<MonitoredItem>();
      item->monitoringMode = MonitoringMode::Reporting;
      item->isEventItem = true;
      item->clientHandle = clientHandle;
      item->queueSize = 10;
      item->eventFilter = eventFilter;
      item->itemToMonitor.node_id() = source;
      item->itemToMonitor.attribute_id() = static_cast<uint32_t>(AttributeId::EventNotifier);
      item->accessControlNode = sourceNode;
      item->accessSecurityContext = mSecurityContext;
      item->accessAddressSpace = mAddressSpace->weak();
      item->enqueue_event(std::move(fields),
        false,
        RetainedEventProjection{clientHandle, source, mEventTypeId, rawEvent, {}, std::move(retainedFilter)});
      guard.add_monitored_item(std::move(item));
    });
  wait_for_subscription_ready();
  const auto published = publish_without_acknowledging(subscriptionId);
  ASSERT_NE(published, nullptr) << "the Publish did not answer";
  const uint32_t sequenceNumber = published->notification_message().sequence_number();

  sourceNamespace->hold_lookups_of({source});
  RepublishRequest request;
  request.subscription_id() = subscriptionId;
  request.retransmit_sequence_number() = sequenceNumber;
  const auto requestId = next_request_id();
  run_on_strand([this, requestId, &request]() { mMgr->handle_republish(requestId, request); });
  ASSERT_TRUE(sourceNamespace->wait_for_held_lookups(1, 2000ms)) << "the Republish did not reach its lookup";

  // The Session closes while the lookup is held: its pipeline goes, and with it its Subscriptions.
  const std::weak_ptr<Subscription> weakSubscription = subscription;
  subscription.reset();
  mMgr.reset();
  for (int attempt = 0; attempt < 200 && !weakSubscription.expired(); ++attempt)
  {
    std::this_thread::sleep_for(10ms);
  }
  EXPECT_TRUE(weakSubscription.expired()) << "the held Republish keeps its Subscription";
  // The held answer arrives with no one left to take it.
  EXPECT_EQ(sourceNamespace->release_held_lookups(), 1u);
}
}  // namespace
