// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ALARM_CONDITION_TRACKER_TEST_ACCESS_H
#define UA_ALARM_CONDITION_TRACKER_TEST_ACCESS_H

/// @file
/// @brief Friend test interface for @ref ua::client::detail::AlarmConditionTrackerImpl (the design specification
/// "no public API
///        pollution for testing"). The tracker is a NO-OWN-STRAND sub-object that runs on its owning
///        @ref ua::client::detail::EventSubscriberImpl's strand (section 8.8). This interface lets a unit test:
///          - drive the tracker's on-strand hook entry points (`handle_*_on_strand`) by POSTING them onto
///            the tracker's strand, so the tracker's OWN demux/decode/observer logic is exercised the way
///            the subscriber's dispatch would drive it (no need to build a full positional Publish decode);
///          - assert the tracker's strand IS the subscriber's strand (no fabricated strand of its own);
///          - peek the strand-private refresh state (which @ref AlarmConditionTrackerInfo does not surface,
///            e.g. `mRefreshInProgress`) after the io_context has drained (single-threaded  to  safe).
/// @ingroup client

#include "ua_alarm_condition_tracker_impl.h"
#include "ua_client_monitored_item.h"  // EventNotification

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <cstddef>
#include <functional>
#include <utility>
#include "ua_on_strand.h"

namespace ua::client::detail
{

struct AlarmConditionTrackerTestAccess
{
  using Impl = AlarmConditionTrackerImpl;
  using Strand = boost::asio::strand<boost::asio::any_io_executor>;

  /// The strand the tracker runs on (the subscriber's  -  the tracker owns none of its own).
  [[nodiscard]] static const Strand& strand(const Impl& tracker)
  {
    return tracker.mStrand;
  }

  /// Posts arbitrary @p work onto the tracker's strand (a runtime probe of which strand it runs on).
  static void post_probe(Impl& tracker, std::function<void()> work)
  {
    boost::asio::post(tracker.mStrand, ua::async::guarded(ua::Logger{}, std::move(work)));
  }

  // ---- Drive the on-strand hook entry points (posted onto the tracker's strand, weak-locked) ----

  static void post_event(Impl& tracker, EventNotification notification)
  {
    post_hook(tracker,
      [notification = std::move(notification)](Impl& self) { self.handle_event_on_strand(notification); });
  }

  static void post_refresh_start(Impl& tracker, EventNotification notification)
  {
    post_hook(tracker,
      [notification = std::move(notification)](Impl& self)
      { self.handle_refresh_start_on_strand(notification); });
  }

  static void post_refresh_end(Impl& tracker, EventNotification notification)
  {
    post_hook(tracker,
      [notification = std::move(notification)](Impl& self)
      { self.handle_refresh_end_on_strand(notification); });
  }

  static void post_refresh_required(Impl& tracker, EventNotification notification)
  {
    post_hook(tracker,
      [notification = std::move(notification)](Impl& self)
      { self.handle_refresh_required_on_strand(notification); });
  }

  static void post_first_event_after_attach(Impl& tracker)
  {
    post_hook(tracker, [](Impl& self) { self.handle_first_event_after_attach_on_strand(); });
  }

  /// The tracker's SelectClause/WhereClause contribution (Slice AC1 asserts the two-segment `/Id` +
  /// `/CurrentState` sub-state clauses and the empty-path ConditionId operand). It builds a fresh EventFilter
  /// from constants and reads no mutable state, so it is safe to call directly (no strand hop needed).
  [[nodiscard]] static ua::EventFilter filter_contribution(const Impl& tracker)
  {
    return tracker.filter_contribution_on_strand();
  }

  // ---- Strand-private state peeks (call only after the io_context has drained) ----

  [[nodiscard]] static bool refresh_in_progress(const Impl& tracker)
  {
    return tracker.mRefreshInProgress;
  }

  [[nodiscard]] static bool has_pending_refresh_callback(const Impl& tracker)
  {
    return static_cast<bool>(tracker.mPendingRefreshCallback);
  }

  [[nodiscard]] static bool pending_follow_on(const Impl& tracker)
  {
    return tracker.mPendingFollowOnRefresh;
  }

  [[nodiscard]] static bool closing(const Impl& tracker)
  {
    return tracker.mClosing;
  }

  [[nodiscard]] static std::size_t active_window_count(const Impl& tracker)
  {
    return tracker.mActiveRefreshWindows.size();
  }

  [[nodiscard]] static std::size_t tracked_count(const Impl& tracker)
  {
    return tracker.mTrackedConditions.size();
  }

private:
  template<class Fn>
  static void post_hook(Impl& tracker, Fn fn)
  {
    ua::async::post_borrowing(
      &tracker, tracker.mStrand, ua::Logger{}, [fn = std::move(fn)](Impl& strong) mutable { fn(strong); })();
  }
};

}  // namespace ua::client::detail

#endif  // UA_ALARM_CONDITION_TRACKER_TEST_ACCESS_H
