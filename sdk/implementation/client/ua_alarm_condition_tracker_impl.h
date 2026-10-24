// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ALARM_CONDITION_TRACKER_IMPL_H
#define UA_ALARM_CONDITION_TRACKER_IMPL_H

/// @file
/// @brief The private @ref ua::client::detail::AlarmConditionTrackerImpl (client design section 8.8): a
///        NO-OWN-STRAND 1:1 sub-object of @ref ua::client::detail::EventSubscriberImpl. It is constructed by
///        and co-owned with the subscriber and runs on ITS strand (per section 1.3 / section 9.8 / section
///        12-S2)  -  it does NOT bear a strand of its own, and is NOT owned by `ConnectionImpl`. It maintains
///        the
///        `(ConditionId, BranchId)  to  TrackedCondition` map, drives the `ConditionRefresh` demultiplexer
///        (collect-until-`RefreshEnd`; re-entrant refresh  to  `Bad_RefreshInProgress`), and exposes the
///        typed method wrappers via `WireOps::call_async`.
/// @ingroup client

#include "ua_alarm_condition_tracker.h"
#include "ua_event_subscriber_impl.h"  // EventTrackerHook
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_redundancy_support.h"
#include "ua_result.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ua::client::detail
{

class WireOps;
class ObserverSink;

/// CL-AC-023 (LimitInequality): true iff the PRESENT limit thresholds violate the canonical ordering
/// `lowLowLimit <= lowLimit <= highLimit <= highHighLimit`. Absent limits impose no constraint (the present
/// values are projected in canonical order and required to be non-decreasing). A NaN limit is treated as
/// ABSENT for ordering (skipped, never advances the running value) so it cannot mask an inversion between the
/// real limits surrounding it; +/-Inf participate normally. Pure  -  free so the detection logic is
/// unit-testable in isolation.
[[nodiscard]] bool limit_inequality(const TrackedCondition& condition) noexcept;

/// CL-AC-025 (NonExclusiveCrossGroup): true iff a high-group NonExclusive state (`HighState` |
/// `HighHighState`) AND a low-group state (`LowState` | `LowLowState`) are simultaneously active.
/// Within-group concurrency (High+HighHigh, Low+LowLow) is LEGAL and returns false. A state is "active" iff
/// its `TwoStateValue.id` is true. Pure  -  free so the detection logic is unit-testable in isolation.
[[nodiscard]] bool non_exclusive_cross_group(const TrackedCondition& condition) noexcept;

/// The no-own-strand A&C tracker sub-object (section 8.8). Runs on the subscriber's strand (injected at
/// construction); never fabricates a strand of its own.
class AlarmConditionTrackerImpl : public std::enable_shared_from_this<AlarmConditionTrackerImpl>
{
public:
  /// The executor the tracker's operations complete on (the subscriber's); a blocking wrapper must not
  /// wait on it from one of its threads.
  [[nodiscard]] boost::asio::any_io_executor executor() const noexcept
  {
    return mExecutor;
  }

  /// Constructed BY @ref EventSubscriberImpl (which passes its own strand + executor + a weak self so the
  /// tracker can attach its hook), plus the tier-1 @ref WireOps method-call interface, a logger, and policy.
  [[nodiscard]] static std::shared_ptr<AlarmConditionTrackerImpl> create(
    boost::asio::strand<boost::asio::any_io_executor> strand, boost::asio::any_io_executor executor,
    std::weak_ptr<EventSubscriberImpl> subscriber, std::weak_ptr<WireOps> wireOps, ua::Logger logger,
    AlarmConditionTrackerPolicy policy, std::weak_ptr<ObserverSink> observerSink = {});

  AlarmConditionTrackerImpl(const AlarmConditionTrackerImpl&) = delete;
  AlarmConditionTrackerImpl& operator=(const AlarmConditionTrackerImpl&) = delete;
  AlarmConditionTrackerImpl(AlarmConditionTrackerImpl&&) = delete;
  AlarmConditionTrackerImpl& operator=(AlarmConditionTrackerImpl&&) = delete;
  ~AlarmConditionTrackerImpl() = default;

  /// Attaches the tracker hook to the subscriber (widening the composite filter) and arms initial refresh.
  void start_async(std::function<void(ua::VoidResult)> callback) noexcept;
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// A completed Cold/Warm redundant-server switch invalidates every cached condition and refresh window.
  /// Posts to the co-owned subscriber strand, clears the former server's state, and initiates one internal
  /// ConditionRefresh when enabled by policy (CL-AC-013). Other redundancy modes are a no-op.
  void on_redundancy_switch_recovered_async(ua::RedundancySupport mode) noexcept;

  void read_alarm_metrics_async(
    ua::NodeId metricsObject, std::function<void(ua::Result<AlarmMetricsSnapshot>)> callback) noexcept;
  void reset_alarm_metrics_async(
    ua::NodeId metricsObject, std::function<void(ua::VoidResult)> callback) noexcept;

  // -------- Consumer surface (mirrors the public AlarmConditionTracker handle) --------

  [[nodiscard]] std::shared_ptr<const AlarmConditionTrackerInfo> info() const noexcept;

  void on_condition_added_async(ConditionAddedCb cb, std::function<void(ua::VoidResult)> callback) noexcept;
  void on_condition_changed_async(
    ConditionChangedCb cb, std::function<void(ua::VoidResult)> callback) noexcept;
  void on_condition_removed_async(
    ConditionRemovedCb cb, std::function<void(ua::VoidResult)> callback) noexcept;

  void list_conditions_async(
    std::function<void(ua::Result<std::vector<TrackedCondition>>)> callback) noexcept;
  void get_condition_async(
    TrackedKey key, std::function<void(ua::Result<TrackedCondition>)> callback) noexcept;

  void refresh_async(std::function<void(ua::VoidResult)> callback) noexcept;

  // AcknowledgeableConditionType (CL-AC-009/010/019/020).
  void acknowledge_async(TrackedKey key, std::optional<ua::ByteString> eventId,
    std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept;
  void confirm_async(TrackedKey key, std::optional<ua::ByteString> eventId,
    std::optional<ua::LocalizedText> comment, std::function<void(ua::VoidResult)> callback) noexcept;
  void add_comment_async(TrackedKey key, ua::ByteString eventId, std::optional<ua::LocalizedText> comment,
    std::function<void(ua::VoidResult)> callback) noexcept;

  // ConditionType / AlarmConditionType / ShelvedStateMachineType (no-argument methods share one path).
  void enable_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  void disable_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  void silence_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  void suppress_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  void unsuppress_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  void timed_shelve_async(
    TrackedKey key, ua::Duration shelvingTime, std::function<void(ua::VoidResult)> callback) noexcept;
  void one_shot_shelve_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  void unshelve_async(TrackedKey key, std::function<void(ua::VoidResult)> callback) noexcept;
  void read_property_async(TrackedKey key, ua::QualifiedName property,
    std::function<void(ua::Result<ua::Variant>)> callback) noexcept;

  // -------- Tracker-hook entry points (called ON the strand by the subscriber dispatch) --------

  void handle_event_on_strand(const EventNotification& notification);
  void handle_refresh_start_on_strand(const EventNotification& notification);
  void handle_refresh_end_on_strand(const EventNotification& notification);
  void handle_refresh_required_on_strand(const EventNotification& notification);
  void handle_first_event_after_attach_on_strand();
  /// CL-AC-003 (AC003-D1a) / Finding 2 (R4): the backbone's old refresh windows were abandoned  -  either a
  /// session-CHANGED reconnect recreated the backbone (@p reason `SessionReestablished`) or a reactive
  /// Republish drain lost messages (a dropped RefreshEnd, @p reason `EventLossDetected`). Delivers any
  /// in-flight USER `refresh_async` callback its reset status/message keyed on @p reason (the ErrorDetail is
  /// source-tagged and never dropped) and clears the dead refresh state. Does NOT `issue_refresh`  -  the
  /// subscriber re-arms the first-event path, which re-issues once the backbone is delivering again.
  void handle_backbone_recovered_on_strand(BackboneRecoveryReason reason);

  /// Records the backbone's SubscriptionId and MonitoredItemId (strand-only) - the mandatory
  /// arguments of ConditionRefresh and ConditionRefresh2 respectively.
  void set_backbone_ids(std::uint32_t subscriptionId, std::uint32_t monitoredItemId);
  void handle_redundancy_switch_recovered_on_strand(ua::RedundancySupport mode);
  [[nodiscard]] ua::EventFilter filter_contribution_on_strand() const;

private:
  friend struct AlarmConditionTrackerTestAccess;

  AlarmConditionTrackerImpl(boost::asio::strand<boost::asio::any_io_executor> strand,
    boost::asio::any_io_executor executor, std::weak_ptr<EventSubscriberImpl> subscriber,
    std::weak_ptr<WireOps> wireOps, ua::Logger logger, AlarmConditionTrackerPolicy policy,
    std::weak_ptr<ObserverSink> observerSink);

  // ---- strand-private helpers ----
  [[nodiscard]] TrackedCondition* find(const TrackedKey& key);
  [[nodiscard]] const TrackedCondition* find(const TrackedKey& key) const;
  void call_condition_method(const TrackedKey& key, std::uint32_t methodId, std::vector<ua::Variant> inputs,
    std::function<void(ua::VoidResult)> callback);
  /// Calls one of the three ShelvedStateMachine methods on @p key.
  ///
  /// Shelving is the one condition method family whose Methods are NOT components of the Condition:
  /// OPC 10000-9 5.8.17 declares them on ShelvedStateMachineType, so they live on the instance's
  /// ShelvingState child. Addressing them like every other condition method - ConditionId as the
  /// ObjectId, the well-known type node as the MethodId - asks for a Method the Condition does not
  /// have, and a Server that validates the pairing answers `Bad_MethodInvalid`.
  ///
  /// So this resolves the instance's own ShelvingState object and Method node (one
  /// TranslateBrowsePaths, cached per condition) and calls the pair the spec calls normal. If the
  /// Server does not expose the Condition instance - the case 5.8.17 explicitly allows - the
  /// resolution finds nothing and the call falls back to the ConditionId form, which those Servers are
  /// required to accept.
  void call_shelving_method(const TrackedKey& key, std::string_view methodName,
    std::uint32_t wellKnownMethodId, std::vector<ua::Variant> inputs,
    std::function<void(ua::VoidResult)> callback);
  void issue_resolved_call(ua::NodeId objectId, ua::NodeId methodId, std::vector<ua::Variant> inputs,
    std::function<void(ua::VoidResult)> callback);
  void deliver_void(std::function<void(ua::VoidResult)> callback, ua::VoidResult result);
  // CL-AC-023 / CL-AC-025: run the pure data-integrity predicates over the freshly-decoded (raw) condition
  // and, on a positive detection, ADVISE  -  a source-tagged advisory log AND (if the sink is alive) the
  // AlarmObserver::on_data_integrity_warning hook. Never refuses/coerces/drops the raw value.
  void detect_and_advise_data_integrity(const TrackedCondition& condition);
  void issue_refresh();
  void fail_refresh_and_reset(ua::VoidResult outcome);
  void refresh_windows_maybe_complete();
  void refresh_info_snapshot();

  boost::asio::strand<boost::asio::any_io_executor> mStrand;  // the SUBSCRIBER's strand  -  not ours
  boost::asio::any_io_executor mExecutor;
  std::weak_ptr<EventSubscriberImpl> mSubscriber;
  std::weak_ptr<WireOps> mWireOps;
  ua::Logger mLogger;
  AlarmConditionTrackerPolicy mPolicy;
  // The per-Connection observer fan-out (section 7.8), WEAK-only  -  the tracker never owns the sink and
  // there is no strong cycle. `.lock()` before every fire; if expired, the advisory log still fires
  // (CL-AC-023/025).
  std::weak_ptr<ObserverSink> mObserverSink;

  std::shared_ptr<EventTrackerHook> mTrackerHook;

  /// SubscriptionId of the backbone this tracker is attached to, published by the subscriber on attach
  /// and whenever a reconnect recreates the MonitoredItem on a new subscription. ConditionRefresh's
  /// one MANDATORY argument (OPC 10000-9 Table 20); 0 means "not attached yet", and a refresh issued in
  /// that state is refused locally rather than sent argument-less for the server to reject.
  std::uint32_t mBackboneSubscriptionId{0};

  /// The backbone MonitoredItem's id - ConditionRefresh2's second mandatory argument (Table 23).
  std::uint32_t mBackboneMonitoredItemId{0};

  std::vector<TrackedCondition> mTrackedConditions;

  /// EventIds of the RefreshStart events whose replay windows are still open, oldest first. A
  /// RefreshEnd closes the oldest (see `handle_refresh_end_on_strand` for why the pairing is
  /// positional and not by EventId).
  std::vector<ua::ByteString> mActiveRefreshWindows;

  /// The RefreshEnd EventIds already counted, so that the copy queued into a second Notifier
  /// MonitoredItem of the same Subscription (OPC 10000-9 5.5.7 step 4 - every copy carries the same
  /// EventId) closes one window rather than two. Bounded by `sRefreshEndLedgerLimit`; a server that
  /// never repeats an EventId would otherwise grow it without limit.
  std::deque<ua::ByteString> mSeenRefreshEndEventIds;
  static constexpr std::size_t sRefreshEndLedgerLimit = 16;

  /// Per-condition ShelvingState resolution (@ref call_shelving_method). The object id is the
  /// instance's ShelvingState node; the map holds one Method node per browse name. An entry is added
  /// only on a successful resolution, so a Server that does not expose Condition instances is retried
  /// rather than remembered as unsupported. Strand-only.
  struct ShelvingNodes
  {
    ua::NodeId shelvingStateId;
    std::unordered_map<std::string, ua::NodeId> methodIds;
  };

  std::map<ua::NodeId, ShelvingNodes> mShelvingNodes;

  bool mRefreshInProgress = false;  // a client-initiated refresh is awaiting its RefreshEnd
  bool mPendingFollowOnRefresh = false;
  bool mUseRefresh2 = false;
  bool mClosing = false;
  std::function<void(ua::VoidResult)> mPendingRefreshCallback;
  /// The code the server answered the confirmed ConditionRefresh trigger with (plain Good or a Good subcode);
  /// a pending refresh callback completes with it when the RefreshEnd arrives. Strand-only.
  ua::StatusCode mRefreshTriggerStatus{ua::Status::Good};

  std::vector<ConditionAddedCb> mAddedObservers;
  std::vector<ConditionChangedCb> mChangedObservers;
  std::vector<ConditionRemovedCb> mRemovedObservers;

  std::atomic<std::shared_ptr<const AlarmConditionTrackerInfo>> mInfoSnapshot{
    std::make_shared<const AlarmConditionTrackerInfo>()};
};

}  // namespace ua::client::detail

#endif  // UA_ALARM_CONDITION_TRACKER_IMPL_H
