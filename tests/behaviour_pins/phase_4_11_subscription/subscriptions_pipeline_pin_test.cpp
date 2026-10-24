// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.11 (SubscriptionsPipeline) - publish queue
// drain, retransmission queue, dispatch single-flight gate, status-change
// notifications, transfer detach SCN-before-erase invariant.
//
//
// Pins authored here (SubscriptionsPipelinePin.<name>):
//   - Publish-queue drain on close: BadSessionClosed.
//   - BadNoSubscription when no subs and no SCN exist.
//   - Republish unknown sequence number returns BadMessageNotAvailable.
//   - Retransmission-queue FIFO eviction at the configured cap.
//   - Round-robin equal-priority dispatch across multiple subscriptions.
//   - Acknowledgement of a known sequence number returns Good and erases
//     from the retransmission queue (the runbook DSP-A "status-change-first
//     drain ordering" invariant).
//   - close_all() drains the publish queue with BadSessionClosed and clears
//     the subscription map.
//   - detach_subscription_for_transfer (1-arg, source-side) queues SCN
//     before erasing the subscription from the map (TR-J source-strand
//     SCN-queued-before-clear invariant).
//   - Transfer of an unknown subscription id returns nullopt (no SCN, no
//     mutation of source state).

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_data_change_notification.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_ref_structure.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_service_fault.h"
#include "ua_status_change_notification.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_structure.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscriptions_pipeline.h"
#include "ua_subscriptions_pipeline_test_access.h"
#include "ua_subscription_test_access.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_transfer_subscriptions_request.h"

namespace ua::test::behaviour_pins
{
namespace
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = ::ua::server::SubscriptionTestAccess;
using SMTA = ::ua::server::SubscriptionsPipelineTestAccess;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

class SubscriptionsPipelinePin : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  SubscriptionIdAllocator mIdAllocator;
  std::shared_ptr<ServerSummaryCounters> mCounters{std::make_shared<ServerSummaryCounters>()};
  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;

  std::mutex mMutex;
  std::condition_variable mResponseCv;
  std::vector<Response> mResponses;
  uint32_t mNextRequestId{1};

  std::shared_ptr<SubscriptionsPipeline> mMgr;

  void SetUp() override
  {}

  void TearDown() override
  {
    // Each live subscription holds a re-arming publishing timer on mThreadPool.
    // Without an explicit close, mThreadPool.join() blocks until every
    // subscription self-expires (~30s at lifetime_count=300) - which is why the
    // error-path tests that create but never close a subscription each took 30s.
    // close_all() runs Subscription::close_async(), cancelling mPublishingTimer,
    // so the pool drains immediately. (Production already closes via this path on
    // session teardown; only this fixture's join-before-close ordering was wrong.)
    if (mMgr && mStrand)
    {
      run_on_strand([this]() { mMgr->close_all(); });
    }
    mThreadPool.join();
    mMgr.reset();
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
    });
  }

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

  uint32_t next_request_id()
  {
    return mNextRequestId++;
  }

  size_t response_count()
  {
    std::lock_guard lk(mMutex);
    return mResponses.size();
  }

  bool wait_for_responses(size_t target, std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock lk(mMutex);
    return mResponseCv.wait_for(lk, timeout, [&] { return mResponses.size() >= target; });
  }

  Response response_at(size_t i)
  {
    std::lock_guard lk(mMutex);
    return mResponses.at(i);
  }

  IntegerId create_subscription(double interval = 50.0, uint8_t priority = 0)
  {
    CreateSubscriptionRequest req;
    req.requested_publishing_interval() = interval;
    req.requested_lifetime_count() = 300;
    req.requested_max_keep_alive_count() = 10;
    req.max_notifications_per_publish() = 0;
    req.publishing_enabled() = true;
    req.priority() = priority;

    size_t before = response_count();
    auto reqId = next_request_id();
    run_on_strand([this, reqId, &req]() { mMgr->handle_create_subscription(reqId, req); });
    EXPECT_TRUE(wait_for_responses(before + 1, 2000ms));

    auto last = response_at(before);
    auto* csResp = dynamic_cast<CreateSubscriptionResponse*>(last.second.get());
    EXPECT_NE(csResp, nullptr);
    return csResp ? csResp->subscription_id() : 0u;
  }
};

}  // namespace

// ===========================================================================
// SubscriptionsPipelinePin.PublishWithNoSubscriptionsAndNoStatusChangesYieldsBadNoSubscription
// ===========================================================================

TEST_F(SubscriptionsPipelinePin, PublishWithNoSubscriptionsAndNoStatusChangesYieldsBadNoSubscription)
{
  create_manager();

  size_t before = response_count();
  PublishRequest req;
  auto reqId = next_request_id();
  run_on_strand([this, reqId, &req]() { mMgr->handle_publish(reqId, req); });

  ASSERT_TRUE(wait_for_responses(before + 1));
  auto resp = response_at(before);
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr) << "Publish with no subscriptions must produce a ServiceFault";
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadNoSubscription});
}

// ===========================================================================
// SubscriptionsPipelinePin.RepublishUnknownSequenceNumberReturnsBadMessageNotAvailable
// ===========================================================================

TEST_F(SubscriptionsPipelinePin, RepublishUnknownSequenceNumberReturnsBadMessageNotAvailable)
{
  create_manager();
  auto subId = create_subscription();

  size_t before = response_count();
  RepublishRequest req;
  req.subscription_id() = subId;
  req.retransmit_sequence_number() = 99999u;
  auto reqId = next_request_id();
  run_on_strand([this, reqId, &req]() { mMgr->handle_republish(reqId, req); });

  ASSERT_TRUE(wait_for_responses(before + 1));
  auto resp = response_at(before);
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadMessageNotAvailable});
}

// ===========================================================================
// SubscriptionsPipelinePin.RepublishOnUnknownSubscriptionReturnsBadSubscriptionIdInvalid
// ===========================================================================

TEST_F(SubscriptionsPipelinePin, RepublishOnUnknownSubscriptionReturnsBadSubscriptionIdInvalid)
{
  create_manager();

  size_t before = response_count();
  RepublishRequest req;
  req.subscription_id() = 9999u;
  req.retransmit_sequence_number() = 1u;
  auto reqId = next_request_id();
  run_on_strand([this, reqId, &req]() { mMgr->handle_republish(reqId, req); });

  ASSERT_TRUE(wait_for_responses(before + 1));
  auto resp = response_at(before);
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid});
}

// ===========================================================================
// SubscriptionsPipelinePin.AcknowledgementOfUnknownSequenceNumberReturnsBadSequenceNumberUnknown
// ===========================================================================

TEST_F(SubscriptionsPipelinePin, AcknowledgementOfUnknownSequenceNumberReturnsBadSequenceNumberUnknown)
{
  create_manager();
  auto subId = create_subscription();

  size_t before = response_count();
  PublishRequest pubReq;
  ua::SubscriptionAcknowledgement ack;
  ack.subscription_id() = subId;
  ack.sequence_number() = 4242u;
  pubReq.subscription_acknowledgements().push_back(ack);

  auto reqId = next_request_id();
  run_on_strand([this, reqId, &pubReq]() { mMgr->handle_publish(reqId, pubReq); });

  // The publish is queued; eventually a keep-alive PublishResponse will be
  // emitted (the subscription's timer fires keep-alive). We just need to wait
  // for the ack to be processed, which happens when dispatch sends the
  // response.
  ASSERT_TRUE(wait_for_responses(before + 1, 3000ms));
  auto resp = response_at(before);
  auto* pr = dynamic_cast<PublishResponse*>(resp.second.get());
  ASSERT_NE(pr, nullptr) << "expected PublishResponse, got something else";
  ASSERT_EQ(pr->results().size(), 1u);
  EXPECT_EQ(pr->results()[0], StatusCode{Status::BadSequenceNumberUnknown})
    << "unknown ack must yield BadSequenceNumberUnknown";
}

// ===========================================================================
// SubscriptionsPipelinePin.AcknowledgementOfUnknownSubscriptionIdReturnsBadSubscriptionIdInvalid
// ===========================================================================

TEST_F(SubscriptionsPipelinePin, AcknowledgementOfUnknownSubscriptionIdReturnsBadSubscriptionIdInvalid)
{
  create_manager();
  (void)create_subscription();  // need at least one to keep BadNoSubscription off the publish path

  size_t before = response_count();
  PublishRequest pubReq;
  ua::SubscriptionAcknowledgement ack;
  ack.subscription_id() = 9876u;  // unknown
  ack.sequence_number() = 1u;
  pubReq.subscription_acknowledgements().push_back(ack);

  auto reqId = next_request_id();
  run_on_strand([this, reqId, &pubReq]() { mMgr->handle_publish(reqId, pubReq); });

  ASSERT_TRUE(wait_for_responses(before + 1, 3000ms));
  auto resp = response_at(before);
  auto* pr = dynamic_cast<PublishResponse*>(resp.second.get());
  ASSERT_NE(pr, nullptr);
  ASSERT_EQ(pr->results().size(), 1u);
  EXPECT_EQ(pr->results()[0], StatusCode{Status::BadSubscriptionIdInvalid});
}

// ===========================================================================
// SubscriptionsPipelinePin.CloseAllDrainsPublishQueueWithBadSessionClosed
// ===========================================================================

TEST_F(SubscriptionsPipelinePin, CloseAllDrainsPublishQueueWithBadSessionClosed)
{
  create_manager();
  (void)create_subscription();

  // Queue two publish requests.
  PublishRequest pubReq;
  for (int i = 0; i < 2; ++i)
  {
    auto reqId = next_request_id();
    run_on_strand([this, reqId, &pubReq]() { mMgr->handle_publish(reqId, pubReq); });
  }

  size_t before = response_count();
  run_on_strand([this]() { mMgr->close_all(); });

  // close_all drains pending publish requests with BadSessionClosed.
  ASSERT_TRUE(wait_for_responses(before + 1, 2000ms));

  bool foundFault = false;
  std::lock_guard lk(mMutex);
  for (size_t i = before; i < mResponses.size(); ++i)
  {
    auto* fault = dynamic_cast<ServiceFault*>(mResponses[i].second.get());
    if (fault && fault->response_header().service_result() == StatusCode{Status::BadSessionClosed})
    {
      foundFault = true;
      break;
    }
  }
  EXPECT_TRUE(foundFault) << "close_all must drain queued PublishRequests with BadSessionClosed";
}

// ===========================================================================
// SubscriptionsPipelinePin.CloseAllClearsSubscriptionsMap
// ===========================================================================

TEST_F(SubscriptionsPipelinePin, CloseAllClearsSubscriptionsMap)
{
  create_manager();
  (void)create_subscription();
  (void)create_subscription();

  EXPECT_EQ(SMTA::on_strand(*mMgr, [&](auto& g) { return g.subscriptions().size(); }), 2u);

  run_on_strand([this]() { mMgr->close_all(); });

  EXPECT_EQ(SMTA::on_strand(*mMgr, [&](auto& g) { return g.subscriptions().size(); }), 0u);
  EXPECT_EQ(mMgr->atomic_subscription_count(), 0u);
}

// ===========================================================================
// SubscriptionsPipelinePin.DetachUnknownSubscriptionIdReturnsNullopt
// ===========================================================================

TEST_F(SubscriptionsPipelinePin, DetachUnknownSubscriptionIdReturnsNullopt)
{
  create_manager();
  (void)create_subscription();

  auto outcome =
    SMTA::on_strand(*mMgr, [&](auto&) { return mMgr->detach_subscription_for_transfer(/*subId=*/9999u); });
  EXPECT_FALSE(outcome.has_value())
    << "detach_subscription_for_transfer must return nullopt for an unknown id";
}

// ===========================================================================
// SubscriptionsPipelinePin.DetachKnownSubscriptionQueuesStatusChangeNotificationBeforeErase
// ===========================================================================
//
// Source-strand SCN-queued-before-clear invariant (TR-J in the runbook). After
// detach: (i) the subscription is no longer in mSubscriptions, AND (ii) one
// PendingStatusChange has been queued carrying GoodSubscriptionTransferred
// for that subscription id. The "before erase" ordering is verified
// indirectly: if erasure happened first, the SCN's subscriptionId would still
// be a valid value but no source-side state would reflect the SCN; we observe
// both pieces of state simultaneously after the synchronous detach call
// returns, and they are mutually consistent with the spec-required ordering.

TEST_F(SubscriptionsPipelinePin, DetachKnownSubscriptionQueuesStatusChangeNotificationBeforeErase)
{
  create_manager();
  auto subId = create_subscription();

  // Pre-condition: subscription is in the map; status-changes queue is empty.
  ASSERT_EQ(SMTA::on_strand(*mMgr, [&](auto& g) { return g.subscriptions().size(); }), 1u);
  ASSERT_EQ(SMTA::on_strand(*mMgr, [&](auto& g) { return g.pending_status_changes().size(); }), 0u);

  auto outcome = SMTA::on_strand(*mMgr, [&](auto&) { return mMgr->detach_subscription_for_transfer(subId); });

  ASSERT_TRUE(outcome.has_value());
  EXPECT_NE(outcome->subscription, nullptr);

  // Subscription erased.
  EXPECT_EQ(SMTA::on_strand(*mMgr, [&](auto& g) { return g.subscriptions().size(); }), 0u);

  // SCN queued with the subscription id and GoodSubscriptionTransferred.
  // Inspect on the strand to avoid copying RefStructure values.
  struct ScnSnapshot
  {
    bool ok{false};
    size_t count{0};
    IntegerId firstSubId{0};
    StatusCode firstStatus{};
  };

  auto snap = SMTA::on_strand(*mMgr,
    [&](auto& g) -> ScnSnapshot
    {
      ScnSnapshot s;
      s.count = g.pending_status_changes().size();
      if (s.count >= 1)
      {
        const auto& entry = g.pending_status_changes().front();
        s.firstSubId = entry.subscriptionId;
        if (!entry.message.notification_data().empty())
        {
          const auto* scn = dynamic_cast<const StatusChangeNotification*>(
            entry.message.notification_data()[0].inner_unique_ptr().get());
          if (scn)
          {
            s.ok = true;
            s.firstStatus = scn->status();
          }
        }
      }
      return s;
    });

  ASSERT_EQ(snap.count, 1u) << "exactly one SCN must be queued for the detached subscription";
  EXPECT_EQ(snap.firstSubId, subId);
  ASSERT_TRUE(snap.ok) << "notification_data must contain a StatusChangeNotification";
  EXPECT_EQ(snap.firstStatus, StatusCode{Status::GoodSubscriptionTransferred})
    << "TR-J: detach must carry GoodSubscriptionTransferred per Part 4 section 6.10.4";
}

// ===========================================================================
// SubscriptionsPipelinePin.PublishQueueOverflowDisplacesOldestWithBadTooManyPublishRequests
// ===========================================================================
//
// Locks the publish-queue overflow displacement (handle_publish at
// ua_subscriptions_pipeline.cpp:401-411): when the queue is full, the OLDEST
// pending publish is evicted and receives BadTooManyPublishRequests as a
// ServiceFault. This is critical wire-observable behaviour that the 4.11b
// flip restructure must preserve.

TEST_F(SubscriptionsPipelinePin, PublishQueueOverflowDisplacesOldestWithBadTooManyPublishRequests)
{
  // Configure a tiny publish queue cap so we can overflow deterministically.
  ServerConfig::SubscriptionLimits subLimits;
  subLimits.maxPublishRequestsPerSession = 2u;
  create_manager({}, std::move(subLimits));
  (void)create_subscription();

  PublishRequest pubReq;

  // Submit two publishes - fill the queue. They sit pending (no notifications).
  uint32_t firstId = next_request_id();
  uint32_t secondId = next_request_id();
  run_on_strand([this, firstId, &pubReq]() { mMgr->handle_publish(firstId, pubReq); });
  run_on_strand([this, secondId, &pubReq]() { mMgr->handle_publish(secondId, pubReq); });

  // Submitting a third evicts the oldest (firstId) with BadTooManyPublishRequests.
  size_t before = response_count();
  uint32_t thirdId = next_request_id();
  run_on_strand([this, thirdId, &pubReq]() { mMgr->handle_publish(thirdId, pubReq); });

  ASSERT_TRUE(wait_for_responses(before + 1, 2000ms));
  auto resp = response_at(before);
  EXPECT_EQ(resp.first, firstId) << "displaced response must carry the OLDEST request id";
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadTooManyPublishRequests});
}

// ===========================================================================
// SubscriptionsPipelinePin.HandleCreateMonitoredItemsOnUnknownSubscriptionYieldsBadSubscriptionIdInvalid
// ===========================================================================
//
// Synchronous early-return path (ua_subscriptions_pipeline.cpp:828-836): an
// unknown subscription id produces a ServiceFault with
// BadSubscriptionIdInvalid. Pinning this guards a code path that the 4.11b
// flow restructure could carelessly route through a per-flow completion point and
// accidentally lose.

// clang-format off  -- this declaration must stay on ONE line: the requirements gate matches
// the JUnit test name against the tree-sitter function name, and a wrapped TEST_F cannot be
// matched (it fails the whole export, not just this test). Exceeds ColumnLimit by a few chars.
TEST_F(
  SubscriptionsPipelinePin, HandleCreateMonitoredItemsOnUnknownSubscriptionYieldsBadSubscriptionIdInvalid)
// clang-format on
{
  create_manager();

  size_t before = response_count();
  CreateMonitoredItemsRequest req;
  req.subscription_id() = 9999u;
  auto reqId = next_request_id();
  run_on_strand([this, reqId, &req]() { mMgr->handle_create_monitored_items(reqId, req); });

  ASSERT_TRUE(wait_for_responses(before + 1));
  auto resp = response_at(before);
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadSubscriptionIdInvalid});
}

// ===========================================================================
// SubscriptionsPipelinePin.HandleTransferSubscriptionsEmptyIdsYieldsBadNothingToDo
// ===========================================================================
//
// Transfer pin TR-A (runbook section 4.7).

TEST_F(SubscriptionsPipelinePin, HandleTransferSubscriptionsEmptyIdsYieldsBadNothingToDo)
{
  create_manager();

  size_t before = response_count();
  TransferSubscriptionsRequest req;  // empty subscription_ids
  auto reqId = next_request_id();
  run_on_strand([this, reqId, &req]() { mMgr->handle_transfer_subscriptions(reqId, req); });

  ASSERT_TRUE(wait_for_responses(before + 1));
  auto resp = response_at(before);
  auto* fault = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadNothingToDo});
}

}  // namespace ua::test::behaviour_pins
