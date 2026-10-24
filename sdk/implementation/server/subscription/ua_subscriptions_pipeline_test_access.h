// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTIONS_PIPELINE_TEST_ACCESS_H
#define UA_SUBSCRIPTIONS_PIPELINE_TEST_ACCESS_H

#include "ua_subscriptions_pipeline.h"

#include "strand_test_access_base.h"

#include <optional>

namespace ua::server
{

struct SubscriptionsPipelineTestAccess
  : ua::test::StrandTestAccessBase<SubscriptionsPipelineTestAccess, SubscriptionsPipeline>
{
  static boost::asio::strand<boost::asio::any_io_executor>& get_strand(SubscriptionsPipeline& mgr, StrandKey)
  {
    return mgr.mSessionStrand;
  }

private:
  template<typename>
  friend class ua::test::StrandGuard;

  static constexpr auto sSubscriptions = &SubscriptionsPipeline::mSubscriptions;
  static constexpr auto sRetransmissionQueue = &SubscriptionsPipeline::mRetransmissionQueue;
  static constexpr auto sMaxRetransmissionQueueSize = &SubscriptionsPipeline::mMaxRetransmissionQueueSize;
  static constexpr auto sAtomicTotalMonitoredItemCount =
    &SubscriptionsPipeline::mAtomicTotalMonitoredItemCount;
  static constexpr auto sPendingStatusChanges = &SubscriptionsPipeline::mPendingStatusChanges;
  static constexpr auto sEnqueuePendingStatusChange = &SubscriptionsPipeline::enqueue_pending_status_change;
  static constexpr auto sDispatchInFlight = &SubscriptionsPipeline::mDispatchInFlight;
  static constexpr auto sDispatchNeeded = &SubscriptionsPipeline::mDispatchNeeded;
  static constexpr auto sDispatchScheduled = &SubscriptionsPipeline::mDispatchScheduled;
  static constexpr auto sRequestDispatch = &SubscriptionsPipeline::request_dispatch;
  static constexpr auto sDeleteSubscription = &SubscriptionsPipeline::delete_subscription;
  static constexpr auto sAddToRetransmissionQueue = &SubscriptionsPipeline::add_to_retransmission_queue;
  static constexpr auto sProcessAcknowledgements = &SubscriptionsPipeline::process_acknowledgements;
};

}  // namespace ua::server

template<>
class ua::test::StrandGuard<ua::server::SubscriptionsPipelineTestAccess>
{
  using TA = ua::server::SubscriptionsPipelineTestAccess;

public:
  STRAND_GUARD_DATA(subscriptions, sSubscriptions)
  STRAND_GUARD_DATA(retransmission_queue, sRetransmissionQueue)
  STRAND_GUARD_DATA(max_retransmission_queue_size, sMaxRetransmissionQueueSize)
  STRAND_GUARD_DATA(atomic_total_monitored_item_count, sAtomicTotalMonitoredItemCount)
  STRAND_GUARD_DATA(pending_status_changes, sPendingStatusChanges)
  STRAND_GUARD_METHOD(enqueue_pending_status_change, sEnqueuePendingStatusChange)
  STRAND_GUARD_DATA(dispatch_in_flight, sDispatchInFlight)
  STRAND_GUARD_DATA(dispatch_needed, sDispatchNeeded)
  STRAND_GUARD_METHOD(request_dispatch, sRequestDispatch)
  STRAND_GUARD_METHOD(delete_subscription, sDeleteSubscription)
  STRAND_GUARD_METHOD(add_to_retransmission_queue, sAddToRetransmissionQueue)
  STRAND_GUARD_METHOD(process_acknowledgements, sProcessAcknowledgements)

  /// Pre-flip surface was `std::optional<coroutine> mDispatchTask`; the
  /// callback-canonical shape uses `bool mDispatchScheduled`. This accessor
  /// preserves the `dispatch_task().has_value()` shape so the 4.11a DSP-A pin
  /// keeps observing the same sticky "ever started" indicator.
  std::optional<bool> dispatch_task()
  {
    return (mTarget.*TA::sDispatchScheduled) ? std::optional<bool>{true} : std::nullopt;
  }

private:
  friend struct ua::test::StrandTestAccessBase<ua::server::SubscriptionsPipelineTestAccess,
    ua::server::SubscriptionsPipeline>;

  explicit StrandGuard(ua::server::SubscriptionsPipeline& a) : mTarget(a)
  {}

  ua::server::SubscriptionsPipeline& mTarget;
};

#endif  // !UA_SUBSCRIPTIONS_PIPELINE_TEST_ACCESS_H
