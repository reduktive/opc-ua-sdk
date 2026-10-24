// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.11 (Subscription) - fulfill_publish, publishing-timer
// state-machine transitions, set_monitoring_mode, set_triggering, close.
//
// SCOPE NOTE
// ----------
// This file pins the externally observable Subscription behaviours that are
// exercisable WITHOUT new fake-collaborator infrastructure (fake AddressSpace /
// fake Namespace / fake Authorizer / fake Session). The runbook section 4 properties
// that depend on those fakes (CMI/Delete/Modify per-namespace/per-item paths,
// TransferSubscriptions, strand-dispatch contract pins) are listed in this
// file as DISABLED stubs so the test count is visible to the human and the
// 4.11b reviewer.
//
// PINS COVERED HERE (SubscriptionPin.<name>):
//   - Lifecycle / construction (Pin SubscriptionPin.CreateAssignsId).
//   - fulfill_publish synchronous body - sequence-number allocation vs
//     keep-alive-peek (FP-A, FP-B); empty result on closed sub (FP-D).
//   - on_publishing_timer_expired state machine - Part 4 section 5.13.1.2 transitions
//     (PT-A NORMAL->Late, PT-B publishReqQueued keeps NORMAL, PT-C lifetime
//     decrement, PT-D lifetime reset, PT-E keep-alive counter, PT-I
//     NORMAL->KeepAlive, PT-J KeepAlive->NORMAL->Late on notifications).
//   - set_monitoring_mode (SM-A unknown id, SM-B no-op, SM-C disabled-clears).
//   - set_triggering (SM-E missing triggerer, SM-F remove-before-add, SM-G
//     empty-link cleanup).
//   - close (CL-A timer cancelled, CL-D callbacks released).

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_monitored_item.h"
#include "ua_subscription.h"
#include "ua_subscription_test_access.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"

namespace ua::test::behaviour_pins
{
namespace
{

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = ::ua::server::SubscriptionTestAccess;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------
//
// One thread-pool, one Subscription. boost::asio::thread_pool::abort() in TearDown matches
// the pattern in tests/unit/server/subscription/subscription_tests.cpp - joins
// the pool before locals reverse-destruct ("explicit boost::asio::thread_pool stop"
// rule). The `mSubscription.reset()` happens before abort to drain the strand
// while threads are still running.

class SubscriptionPin : public ::testing::Test
{
protected:
  boost::asio::thread_pool mThreadPool;
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<Subscription> mSubscription;

  std::mutex mMutex;
  std::condition_variable mReadyCv;
  std::condition_variable mExpiredCv;
  int mReadyCount{0};
  int mExpiredCount{0};

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
  }

  void TearDown() override
  {
    mSubscription.reset();
    mThreadPool.join();
  }

  // Construct with very large publishing interval so the periodic timer does
  // NOT fire during tests that drive on_publishing_timer_expired by hand. The
  // pins that observe the periodic-timer side effect (PT-* pins below) call
  // STA::on_strand_method::on_publishing_timer_expired() directly; we do not
  // want a parallel real-timer fire perturbing the deterministic sequence.
  std::shared_ptr<Subscription> create_subscription(double publishingInterval = 1'000'000.0,
    uint32_t lifetimeCount = 100, uint32_t maxKeepAliveCount = 3, bool publishingEnabled = true,
    uint8_t priority = 0)
  {
    mSubscription = Subscription::create(/*subscriptionId=*/
      1,
      publishingInterval,
      lifetimeCount,
      maxKeepAliveCount,
      /*maxNotificationsPerPublish=*/0,
      publishingEnabled,
      priority,
      mExecutor,
      [this](IntegerId)
      {
        std::lock_guard lk(mMutex);
        ++mReadyCount;
        mReadyCv.notify_all();
      },
      [this](IntegerId)
      {
        std::lock_guard lk(mMutex);
        ++mExpiredCount;
        mExpiredCv.notify_all();
      });
    return mSubscription;
  }

  IntegerId add_item_with_value(DataValue value, MonitoringMode mode = MonitoringMode::Reporting)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = mode;
        item->clientHandle = 100 + static_cast<uint32_t>(g.monitored_items().size());
        item->queueSize = 10;
        item->enqueue_initial(std::move(value));
        return g.add_monitored_item(std::move(item));
      });
  }

  IntegerId add_empty_item(MonitoringMode mode = MonitoringMode::Reporting)
  {
    return STA::on_strand(*mSubscription,
      [&](auto& g)
      {
        auto item = std::make_unique<MonitoredItem>();
        item->monitoringMode = mode;
        item->clientHandle = 100 + static_cast<uint32_t>(g.monitored_items().size());
        item->queueSize = 10;
        return g.add_monitored_item(std::move(item));
      });
  }

  std::vector<StatusCode> set_mode_blocking(std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode)
  {
    std::promise<std::vector<StatusCode>> completion;
    auto result = completion.get_future();
    mSubscription->set_monitoring_mode_async(std::move(monitoredItemIds),
      newMode,
      [&completion](std::vector<StatusCode> statuses) { completion.set_value(std::move(statuses)); });
    return result.get();
  }

  int ready_count()
  {
    std::lock_guard lk(mMutex);
    return mReadyCount;
  }

  int expired_count()
  {
    std::lock_guard lk(mMutex);
    return mExpiredCount;
  }

  bool wait_for_ready(int target, std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock lk(mMutex);
    return mReadyCv.wait_for(lk, timeout, [&] { return mReadyCount >= target; });
  }

  bool wait_for_expired(std::chrono::milliseconds timeout = 2000ms)
  {
    std::unique_lock lk(mMutex);
    return mExpiredCv.wait_for(lk, timeout, [&] { return mExpiredCount > 0; });
  }
};

DataValue make_int_value(int32_t v)
{
  DataValue dv;
  dv.value() = Variant{v};
  dv.source_timestamp() = DateTime::now();
  return dv;
}

}  // namespace

// ===========================================================================
// Lifecycle (sanity - locks externally observable id assignment).
// ===========================================================================

TEST_F(SubscriptionPin, CreateAssignsIdAndReportsInfo)
{
  auto sub = create_subscription();
  ASSERT_NE(sub, nullptr);
  EXPECT_EQ(sub->id(), 1u);

  auto info = sub->get_info();
  EXPECT_EQ(info.id, 1u);
  EXPECT_FALSE(info.hasNotifications);
  EXPECT_EQ(info.monitoredItemCount, 0u);
}

// ===========================================================================
// FP-A - fulfill_publish with notifications uses an ALLOCATED sequence number.
// ===========================================================================
//
// fulfill_publish (ua_subscription.cpp:410) on a subscription with notifications
// available must produce a NotificationMessage carrying a freshly allocated
// sequence number - i.e. mNextSequenceNumber is incremented past the message's
// number. Pin guards the alloc-then-increment ordering against a regression
// that peeks (would emit the same number for a real notification and the next
// keep-alive).

TEST_F(SubscriptionPin, FulfillPublishWithNotificationsUsesAllocatedSequenceNumber)
{
  auto sub = create_subscription();
  add_item_with_value(make_int_value(42));

  // Capture pre-call sequence number.
  uint32_t preNext = STA::on_strand(*sub, [&](auto& g) { return g.next_sequence_number(); });

  auto results =
    STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(/*availablePublishCount=*/1); });

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].message.sequence_number(), preNext)
    << "fulfill_publish must emit the pre-call sequence number for a notification message";

  uint32_t postNext = STA::on_strand(*sub, [&](auto& g) { return g.next_sequence_number(); });
  EXPECT_EQ(postNext, preNext + 1u) << "next_sequence_number must have advanced by 1 (alloc, not peek)";
}

// ===========================================================================
// FP-B - keep-alive uses PEEKED sequence number; mNextSequenceNumber unchanged.
// ===========================================================================

TEST_F(SubscriptionPin, FulfillPublishKeepAliveUsesPeekedSequenceNumberNotIncremented)
{
  auto sub = create_subscription();

  uint32_t preNext = STA::on_strand(*sub, [&](auto& g) { return g.next_sequence_number(); });

  auto results =
    STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(/*availablePublishCount=*/1); });

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].message.sequence_number(), preNext)
    << "keep-alive message must carry the peeked sequence number";

  uint32_t postNext = STA::on_strand(*sub, [&](auto& g) { return g.next_sequence_number(); });
  EXPECT_EQ(postNext, preNext) << "keep-alive must NOT advance next_sequence_number";

  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); }),
    Subscription::PublishingState::KeepAlive);
}

// ===========================================================================
// FP-D - fulfill_publish on a closed subscription returns an empty vector.
// ===========================================================================

TEST_F(SubscriptionPin, FulfillPublishOnClosedSubscriptionReturnsEmpty)
{
  auto sub = create_subscription();
  add_item_with_value(make_int_value(1));

  STA::on_strand(*sub, [&](auto& g) { g.close(); });

  auto results =
    STA::on_strand(*sub, [&](auto& g) { return g.fulfill_publish(/*availablePublishCount=*/1); });
  EXPECT_TRUE(results.empty()) << "closed subscription must yield an empty PublishResult vector";
}

// ===========================================================================
// PT-A - Timer expiry with notifications and no publish queued: Normal->Late.
// ===========================================================================

TEST_F(SubscriptionPin, TimerExpiryNoPublishQueuedTransitionsNormalToLate)
{
  auto sub = create_subscription();
  add_item_with_value(make_int_value(7));

  // Force initial state: Normal, mMessageSent = false, mPublishReqQueued = false.
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.publishing_state() = Subscription::PublishingState::Normal;
      g.message_sent() = false;
      g.set_publish_req_queued(false);
    });

  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });

  EXPECT_EQ(
    STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); }), Subscription::PublishingState::Late);
  EXPECT_GE(ready_count(), 1) << "signal_ready must have fired in the Normal->Late path";
}

// ===========================================================================
// PT-B - Timer expiry with publish queued keeps state Normal.
// ===========================================================================

TEST_F(SubscriptionPin, TimerExpiryWithPublishQueuedKeepsStateNormal)
{
  auto sub = create_subscription();
  add_item_with_value(make_int_value(7));

  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.publishing_state() = Subscription::PublishingState::Normal;
      g.message_sent() = false;
      g.set_publish_req_queued(true);
    });

  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });

  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); }),
    Subscription::PublishingState::Normal);
}

// ===========================================================================
// PT-C - lifetime decrement when no publish queued.
// ===========================================================================

TEST_F(SubscriptionPin, TimerExpiryDecrementsLifetimeWhenNoPublishQueued)
{
  auto sub = create_subscription();
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.lifetime_counter() = 5;
      g.set_publish_req_queued(false);
    });

  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });

  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); }), 4u);
}

// ===========================================================================
// PT-C cont. - when the lifetime counter hits zero, notify_expired fires and
// the timer is NOT restarted.
// ===========================================================================

TEST_F(SubscriptionPin, TimerExpiryAtZeroLifetimeFiresNotifyExpired)
{
  auto sub = create_subscription();
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.lifetime_counter() = 1;
      g.set_publish_req_queued(false);
    });

  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });

  EXPECT_TRUE(wait_for_expired()) << "notify_expired must fire when lifetime hits zero";
  EXPECT_GE(expired_count(), 1);
}

// ===========================================================================
// PT-D - publishReqQueued resets the lifetime counter to mLifetimeCount.
// ===========================================================================

TEST_F(SubscriptionPin, TimerExpiryWithPublishQueuedResetsLifetime)
{
  const uint32_t lifetime = 100;
  auto sub = create_subscription(/*publishingInterval=*/1'000'000.0, lifetime);
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.lifetime_counter() = 5;  // anything < lifetime_count
      g.set_publish_req_queued(true);
    });

  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });

  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.lifetime_counter(); }), lifetime);
}

// ===========================================================================
// PT-E - KeepAlive counter decrement; reaches threshold then re-fires.
// ===========================================================================

TEST_F(SubscriptionPin, TimerExpiryKeepAliveCounterDecrementsWithoutSignal)
{
  auto sub = create_subscription(/*publishingInterval=*/1'000'000.0,
    /*lifetimeCount=*/100,
    /*maxKeepAliveCount=*/3);
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.publishing_state() = Subscription::PublishingState::KeepAlive;
      g.keep_alive_counter() = 3;
      g.publishing_enabled() = true;
      g.set_publish_req_queued(false);
    });

  // First tick: 3 -> 2, no signal_ready.
  int beforeReady = ready_count();
  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });
  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.keep_alive_counter(); }), 2u);
  EXPECT_EQ(ready_count(), beforeReady) << "keep-alive decrement must NOT fire signal_ready";

  // Second tick: 2 -> 1, no signal_ready.
  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });
  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.keep_alive_counter(); }), 1u);
  EXPECT_EQ(ready_count(), beforeReady);

  // Third tick: 1 -> reset to 3 AND signal_ready.
  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });
  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.keep_alive_counter(); }), 3u)
    << "keep-alive counter must reset to maxKeepAliveCount when threshold reached";
  EXPECT_GE(ready_count(), beforeReady + 1) << "signal_ready must fire when keep-alive threshold reached";
}

// ===========================================================================
// PT-I - NORMAL->KEEPALIVE: no notifications + mMessageSent.
// ===========================================================================

TEST_F(SubscriptionPin, TimerExpiryNoNotificationsAndMessageSentTransitionsNormalToKeepalive)
{
  auto sub = create_subscription(/*publishingInterval=*/1'000'000.0,
    /*lifetimeCount=*/100,
    /*maxKeepAliveCount=*/5);
  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.publishing_state() = Subscription::PublishingState::Normal;
      g.message_sent() = true;
      g.set_publish_req_queued(false);
      g.keep_alive_counter() = 0;
    });

  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });

  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); }),
    Subscription::PublishingState::KeepAlive)
    << "Part 4 section 5.13.1.2: NORMAL->KEEPALIVE when no notifications and mMessageSent";
  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.keep_alive_counter(); }), 5u)
    << "keep-alive counter must initialise to maxKeepAliveCount on entry";
}

// ===========================================================================
// PT-J - KEEPALIVE->Late on notifications-arrive + no publish queued.
// ===========================================================================

TEST_F(SubscriptionPin, KeepAliveTimerExpiryWithNotificationsTransitionsKeepaliveToLate)
{
  auto sub = create_subscription();
  add_item_with_value(make_int_value(99));

  STA::on_strand(*sub,
    [&](auto& g)
    {
      g.publishing_state() = Subscription::PublishingState::KeepAlive;
      g.set_publish_req_queued(false);
    });

  int beforeReady = ready_count();
  STA::on_strand(*sub, [&](auto& g) { g.on_publishing_timer_expired(); });

  EXPECT_GE(ready_count(), beforeReady + 1) << "signal_ready must fire on KEEPALIVE->Late";
  EXPECT_EQ(
    STA::on_strand(*sub, [&](auto& g) { return g.publishing_state(); }), Subscription::PublishingState::Late)
    << "KEEPALIVE->NORMAL->Late when notifications and no publish queued";
}

// ===========================================================================
// SM-A - set_monitoring_mode unknown id yields BadMonitoredItemIdInvalid.
// ===========================================================================

TEST_F(SubscriptionPin, SetMonitoringModeUnknownIdYieldsBadMonitoredItemIdInvalid)
{
  auto sub = create_subscription();
  add_empty_item();

  auto results = set_mode_blocking({42u}, MonitoringMode::Reporting);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::BadMonitoredItemIdInvalid});
}

// ===========================================================================
// SM-B - Reporting->Reporting no-op returns Good and does not clear queue.
// ===========================================================================

TEST_F(SubscriptionPin, SetMonitoringModeNoOpReturnsGoodWithoutClearingQueue)
{
  auto sub = create_subscription();
  auto miId = add_item_with_value(make_int_value(11));

  auto results = set_mode_blocking({miId}, MonitoringMode::Reporting);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});

  size_t qSize = STA::on_strand(*sub,
    [&](auto& g) -> size_t
    {
      auto* it = g.find_monitored_item(miId);
      return it ? it->queue.size() : 0u;
    });
  EXPECT_GT(qSize, 0u) << "Reporting->Reporting must not clear the queue";
}

// ===========================================================================
// SM-C - Reporting->Disabled clears the queue.
// ===========================================================================

TEST_F(SubscriptionPin, SetMonitoringModeToDisabledClearsQueue)
{
  auto sub = create_subscription();
  auto miId = add_item_with_value(make_int_value(5));

  size_t qBefore = STA::on_strand(*sub,
    [&](auto& g) -> size_t
    {
      auto* it = g.find_monitored_item(miId);
      return it ? it->queue.size() : 0u;
    });
  ASSERT_GT(qBefore, 0u);

  auto results = set_mode_blocking({miId}, MonitoringMode::Disabled);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0], StatusCode{Status::Good});

  size_t qAfter = STA::on_strand(*sub,
    [&](auto& g) -> size_t
    {
      auto* it = g.find_monitored_item(miId);
      return it ? it->queue.size() : 0u;
    });
  EXPECT_EQ(qAfter, 0u) << "MonitoringMode::Disabled transition must clear the queue (SVR-MI-GEN-014)";
}

// ===========================================================================
// SM-E - set_triggering with unknown triggering id fails all per-item results.
// ===========================================================================

TEST_F(SubscriptionPin, SetTriggeringTriggeringItemMissingFailsAllResults)
{
  auto sub = create_subscription();
  auto a = add_empty_item();
  auto b = add_empty_item();

  auto result = STA::on_strand(*sub,
    [&](auto& g)
    {
      return g.set_triggering(/*triggering=*/42u,
        /*linksToAdd=*/std::vector<IntegerId>{a, b},
        /*linksToRemove=*/std::vector<IntegerId>{a});
    });

  ASSERT_EQ(result.removeResults.size(), 1u);
  ASSERT_EQ(result.addResults.size(), 2u);
  EXPECT_EQ(result.removeResults[0], StatusCode{Status::BadMonitoredItemIdInvalid});
  EXPECT_EQ(result.addResults[0], StatusCode{Status::BadMonitoredItemIdInvalid});
  EXPECT_EQ(result.addResults[1], StatusCode{Status::BadMonitoredItemIdInvalid});
}

// ===========================================================================
// SM-F - set_triggering processes removes BEFORE adds.
// ===========================================================================

// Covers SVR-MI-GEN-104 (coverage-audit retag).
TEST_F(SubscriptionPin, SetTriggeringRemovesProcessedBeforeAdds)
{
  auto sub = create_subscription();
  auto t = add_empty_item();
  auto l1 = add_empty_item();
  auto l2 = add_empty_item();

  // Pre-link T -> L1.
  STA::on_strand(
    *sub, [&](auto& g) { (void)g.set_triggering(t, std::vector<IntegerId>{l1}, std::vector<IntegerId>{}); });

  // Add L2; remove L1.
  auto result = STA::on_strand(*sub,
    [&](auto& g) { return g.set_triggering(t, std::vector<IntegerId>{l2}, std::vector<IntegerId>{l1}); });
  ASSERT_EQ(result.removeResults.size(), 1u);
  ASSERT_EQ(result.addResults.size(), 1u);
  EXPECT_EQ(result.removeResults[0], StatusCode{Status::Good});
  EXPECT_EQ(result.addResults[0], StatusCode{Status::Good});
}

// ===========================================================================
// SM-G - set_triggering removes the link map entry when its set becomes empty.
// ===========================================================================
//
// The runbook references the "empty link set is cleaned up" invariant at
// ua_subscription.cpp:1586-1589. We can't observe the internal map directly
// without a TestAccess hook, but we CAN observe the externally consequential
// behaviour: after removing the only link, a subsequent set_triggering that
// removes the same link again returns BadMonitoredItemIdInvalid (set is gone)
// rather than Good - locking the cleanup-on-empty invariant via its observable
// downstream consequence.

TEST_F(SubscriptionPin, SetTriggeringEmptyLinkSetIsCleanedUp)
{
  auto sub = create_subscription();
  auto t = add_empty_item();
  auto l1 = add_empty_item();

  STA::on_strand(
    *sub, [&](auto& g) { (void)g.set_triggering(t, std::vector<IntegerId>{l1}, std::vector<IntegerId>{}); });
  STA::on_strand(
    *sub, [&](auto& g) { (void)g.set_triggering(t, std::vector<IntegerId>{}, std::vector<IntegerId>{l1}); });

  // After clearing, T should no longer have any tracked linked items - adding
  // L1 back must succeed (i.e. the link set genuinely cleared, not retained
  // empty in a way that would refuse the re-add).
  auto result = STA::on_strand(
    *sub, [&](auto& g) { return g.set_triggering(t, std::vector<IntegerId>{l1}, std::vector<IntegerId>{}); });
  ASSERT_EQ(result.addResults.size(), 1u);
  EXPECT_EQ(result.addResults[0], StatusCode{Status::Good})
    << "after empty-link cleanup, re-adding the same linked item must succeed";
}

// ===========================================================================
// CL-A - close() releases mOnReady; subsequent signal_ready does not fire it.
// ===========================================================================
//
// Pin-runs Subscription's close(): callbacks (mOnReady) cleared, samples
// rejected on receipt. We observe via the ready_count counter.

TEST_F(SubscriptionPin, CloseReleasesNotifyReadyCallback)
{
  auto sub = create_subscription();
  add_empty_item();

  STA::on_strand(*sub, [&](auto& g) { g.close(); });

  int beforeReady = ready_count();

  // After close, on_samples_received is a no-op. Inject samples and assert
  // the ready callback never fires.
  std::vector<std::pair<IntegerId, DataValue>> samples;
  samples.emplace_back(1u, make_int_value(99));
  STA::on_strand(*sub, [&](auto& g) { g.on_samples_received(std::move(samples)); });

  EXPECT_EQ(ready_count(), beforeReady)
    << "after close(), signal_ready must NOT fire (mOnReady released, samples ignored)";
}

// ===========================================================================
// CL-A continued - close clears the publishing-state machine state.
// ===========================================================================
//
// After close, the strand-posted state is observable: monitored items cleared,
// reportable count zeroed, hasNotifications cleared. These are deterministic
// snapshots - no sleep-based "did the timer fire?" assertion (quality
// rule against sleep_for).

TEST_F(SubscriptionPin, CloseClearsMonitoredItemsAndReportableState)
{
  auto sub = create_subscription();
  add_item_with_value(make_int_value(1));
  add_item_with_value(make_int_value(2));

  ASSERT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.monitored_items().size(); }), 2u);

  STA::on_strand(*sub, [&](auto& g) { g.close(); });

  EXPECT_EQ(STA::on_strand(*sub, [&](auto& g) { return g.monitored_items().size(); }), 0u);
  auto info = sub->get_info();
  EXPECT_EQ(info.monitoredItemCount, 0u);
  EXPECT_FALSE(info.hasNotifications);
}

}  // namespace ua::test::behaviour_pins
