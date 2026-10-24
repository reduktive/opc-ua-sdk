// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTION_TEST_ACCESS_H
#define UA_SUBSCRIPTION_TEST_ACCESS_H

#include "ua_subscription.h"
#include "ua_address_space.h"
#include "ua_base_event.h"
#include "ua_create_monitored_items_request.h"
#include "ua_modify_monitored_items_request.h"

#include "strand_test_access_base.h"

namespace ua::server
{

struct SubscriptionTestAccess : ua::test::StrandTestAccessBase<SubscriptionTestAccess, Subscription>
{
  static boost::asio::strand<boost::asio::any_io_executor>& get_strand(Subscription& sub, StrandKey)
  {
    return sub.mStrand;
  }

private:
  template<typename>
  friend class ua::test::StrandGuard;

  // --- Pointer-to-member data constants ---
  static constexpr auto sMonitoredItems = &Subscription::mMonitoredItems;
  static constexpr auto sPublishingState = &Subscription::mPublishingState;
  static constexpr auto sMessageSent = &Subscription::mMessageSent;
  static constexpr auto sLifetimeCounter = &Subscription::mLifetimeCounter;
  static constexpr auto sKeepAliveCounter = &Subscription::mKeepAliveCounter;
  static constexpr auto sPublishingEnabled = &Subscription::mPublishingEnabled;
  static constexpr auto sNextSequenceNumber = &Subscription::mNextSequenceNumber;
  static constexpr auto sPublishingInterval = &Subscription::mPublishingInterval;
  static constexpr auto sLifetimeCount = &Subscription::mLifetimeCount;
  static constexpr auto sMaxKeepAliveCount = &Subscription::mMaxKeepAliveCount;
  static constexpr auto sPriority = &Subscription::mPriority;
  static constexpr auto sSampleSink = &Subscription::mSampleSink;
  static constexpr auto sSummaryCounters = &Subscription::mSummaryCounters;
  static constexpr auto sReportableItemCount = &Subscription::mReportableItemCount;
  static constexpr auto sDurable = &Subscription::mDurable;
  static constexpr auto sDurableLifetimeHours = &Subscription::mDurableLifetimeHours;
  static constexpr auto sPendingEventDeliveries = &Subscription::mPendingEventDeliveries;
  static constexpr auto sActiveEventDeliveryOrdinal = &Subscription::mActiveEventDeliveryOrdinal;
  static constexpr auto sEventDeliveryAttemptEpoch = &Subscription::mEventDeliveryAttemptEpoch;
  static constexpr auto sEventDeliveryActive = &Subscription::mEventDeliveryActive;
  static constexpr auto sEventDeliveryDeadline = &Subscription::mEventDeliveryDeadline;
  static constexpr auto sEventDeliveryPlan = &Subscription::mEventDeliveryPlan;

  // --- Pointer-to-member method constants ---
  static constexpr auto sAddMonitoredItem =
    static_cast<IntegerId (Subscription::*)(std::unique_ptr<MonitoredItem>)>(
      &Subscription::add_monitored_item);
  static constexpr auto sRemoveMonitoredItem = &Subscription::remove_monitored_item;
  static constexpr auto sFindMonitoredItem = &Subscription::find_monitored_item;
  static constexpr auto sPeekSequenceNumber = &Subscription::peek_sequence_number;
  static constexpr auto sAllocateSequenceNumber = &Subscription::allocate_sequence_number;
  static constexpr auto sOnPublishingTimerExpired = &Subscription::on_publishing_timer_expired;
  static constexpr auto sNotificationsAvailable = &Subscription::notifications_available;
  static constexpr auto sSetPublishReqQueued = &Subscription::set_publish_req_queued;
  static constexpr auto sOnSamplesReceived = &Subscription::on_samples_received;
  static constexpr auto sOnSampleInvalidated = &Subscription::on_sample_invalidated;
  static constexpr auto sOnSemanticsChanged = &Subscription::on_semantics_changed;
  static constexpr auto sOnStructureChanged = &Subscription::on_structure_changed;
  static constexpr auto sFulfillPublish = &Subscription::fulfill_publish;
  static constexpr auto sModify = &Subscription::modify;
  static constexpr auto sSetPublishingMode = &Subscription::set_publishing_mode;
  static constexpr auto sClose = &Subscription::close;
  static constexpr auto sOnServiceCall = &Subscription::on_service_call;
  static constexpr auto sAccountCommittedItem = &Subscription::account_committed_item;
  static constexpr auto sSetTriggering = &Subscription::set_triggering;
  static constexpr auto sSetDurable = &Subscription::set_durable;
  static constexpr auto sRunAccessRecheck = &Subscription::run_access_recheck;
  static constexpr auto sOnEventDeliveryDeadline = &Subscription::on_event_delivery_deadline;
  static constexpr auto sEnqueueEventDelivery = &Subscription::enqueue_event_delivery;

  static void seed_pending_event_delivery(Subscription& subscription, IntegerId monitoredItemId)
  {
    auto event = std::make_shared<BaseEvent>();
    event->sourceNode = NodeId{0, 2253u};
    event->eventType = NodeId{0, 2041u};
    const uint64_t ordinal = subscription.mNextEventDeliveryOrdinal++;
    subscription.mPendingEventDeliveries.push_back(
      Subscription::PendingEventDelivery{ordinal, monitoredItemId, std::move(event), {}});
    // accounted as production enqueues are
    auto& accounting = subscription.mPendingEventAccounting[monitoredItemId];
    ++accounting.count;
    accounting.lastAcceptedOrdinal = ordinal;
  }
};

}  // namespace ua::server

template<>
class ua::test::StrandGuard<ua::server::SubscriptionTestAccess>
{
  using TA = ua::server::SubscriptionTestAccess;

public:
  // --- Data accessors ---
  STRAND_GUARD_DATA(monitored_items, sMonitoredItems)
  STRAND_GUARD_DATA(publishing_state, sPublishingState)
  STRAND_GUARD_DATA(message_sent, sMessageSent)
  STRAND_GUARD_DATA(lifetime_counter, sLifetimeCounter)
  STRAND_GUARD_DATA(keep_alive_counter, sKeepAliveCounter)
  STRAND_GUARD_DATA(publishing_enabled, sPublishingEnabled)
  STRAND_GUARD_DATA(next_sequence_number, sNextSequenceNumber)
  STRAND_GUARD_DATA(publishing_interval, sPublishingInterval)
  STRAND_GUARD_DATA(lifetime_count, sLifetimeCount)
  STRAND_GUARD_DATA(max_keep_alive_count, sMaxKeepAliveCount)
  STRAND_GUARD_DATA(priority, sPriority)
  STRAND_GUARD_DATA(sample_sink, sSampleSink)
  STRAND_GUARD_DATA(summary_counters, sSummaryCounters)
  STRAND_GUARD_DATA(reportable_item_count, sReportableItemCount)
  STRAND_GUARD_DATA(durable, sDurable)
  STRAND_GUARD_DATA(durable_lifetime_hours, sDurableLifetimeHours)
  STRAND_GUARD_DATA(pending_event_deliveries, sPendingEventDeliveries)
  STRAND_GUARD_DATA(active_event_delivery_ordinal, sActiveEventDeliveryOrdinal)
  STRAND_GUARD_DATA(event_delivery_attempt_epoch, sEventDeliveryAttemptEpoch)
  STRAND_GUARD_DATA(event_delivery_active, sEventDeliveryActive)
  STRAND_GUARD_DATA(event_delivery_deadline, sEventDeliveryDeadline)
  STRAND_GUARD_DATA(event_delivery_plan, sEventDeliveryPlan)

  // --- Method accessors ---

  // add_monitored_item has an overload - use explicit signature to select.
  ua::IntegerId add_monitored_item(std::unique_ptr<ua::server::MonitoredItem> item)
  {
    return (mTarget.*TA::sAddMonitoredItem)(std::move(item));
  }

  STRAND_GUARD_METHOD(remove_monitored_item, sRemoveMonitoredItem)
  STRAND_GUARD_METHOD(find_monitored_item, sFindMonitoredItem)
  STRAND_GUARD_METHOD(peek_sequence_number, sPeekSequenceNumber)
  STRAND_GUARD_METHOD(allocate_sequence_number, sAllocateSequenceNumber)
  STRAND_GUARD_METHOD(on_publishing_timer_expired, sOnPublishingTimerExpired)
  STRAND_GUARD_METHOD(notifications_available, sNotificationsAvailable)
  STRAND_GUARD_METHOD(set_publish_req_queued, sSetPublishReqQueued)
  STRAND_GUARD_METHOD(on_samples_received, sOnSamplesReceived)
  STRAND_GUARD_METHOD(on_sample_invalidated, sOnSampleInvalidated)
  STRAND_GUARD_METHOD(on_semantics_changed, sOnSemanticsChanged)
  STRAND_GUARD_METHOD(on_structure_changed, sOnStructureChanged)
  STRAND_GUARD_METHOD(fulfill_publish, sFulfillPublish)
  STRAND_GUARD_METHOD(modify, sModify)
  STRAND_GUARD_METHOD(set_publishing_mode, sSetPublishingMode)
  STRAND_GUARD_METHOD(close, sClose)
  STRAND_GUARD_METHOD(on_service_call, sOnServiceCall)
  STRAND_GUARD_METHOD(account_committed_item, sAccountCommittedItem)
  STRAND_GUARD_METHOD(set_triggering, sSetTriggering)
  STRAND_GUARD_METHOD(set_durable, sSetDurable)
  STRAND_GUARD_METHOD(run_access_recheck, sRunAccessRecheck)
  STRAND_GUARD_METHOD(on_event_delivery_deadline, sOnEventDeliveryDeadline)
  STRAND_GUARD_METHOD(enqueue_event_delivery, sEnqueueEventDelivery)

  void seed_pending_event_delivery(IntegerId monitoredItemId)
  {
    TA::seed_pending_event_delivery(mTarget, monitoredItemId);
  }

private:
  friend struct ua::test::StrandTestAccessBase<ua::server::SubscriptionTestAccess, ua::server::Subscription>;

  explicit StrandGuard(ua::server::Subscription& a) : mTarget(a)
  {}

  ua::server::Subscription& mTarget;
};

#endif  // !UA_SUBSCRIPTION_TEST_ACCESS_H
