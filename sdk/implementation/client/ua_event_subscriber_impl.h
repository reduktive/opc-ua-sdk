// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EVENT_SUBSCRIBER_IMPL_H
#define UA_EVENT_SUBSCRIBER_IMPL_H

/// @file
/// @brief The strand-bearing private @ref ua::client::detail::EventSubscriberImpl (client design
/// section 8.13): the
///        per-`Connection` collapsing event backbone. Owns the event subsystem's OWN private strand
///        (distinct from `ConnectionImpl`'s), coalesces N logical consumers onto one (or a few) backbone
///        event MonitoredItem(s), demultiplexes inbound events client-side to each consumer's callback by
///        its registered filter, and implements @ref ua::client::detail::MonitoredItemOwner for event
///        consumers (resolving the Slice-9 `monitor_event` deferral  -  an event `MonitoredItem`'s
///        self-actions route here, NOT to the data-change owner).
/// @ingroup client

#include "ua_alarm_condition_tracker.h"  // AlarmConditionTrackerPolicy (by-value ensure_alarm_tracker param)
#include "ua_client_monitored_item.h"
#include "ua_event_backbone_ops.h"
#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_subscriber.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_redundancy_support.h"
#include "ua_result.h"
#include "ua_simple_attribute_operand.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace ua
{
struct ErrorDetail;
}  // namespace ua

namespace ua::client::detail
{

class AlarmConditionTrackerImpl;
class ObserverSink;
class WireOps;

/// Why a backbone's dead refresh state is being reset (Finding 2 / R4). The two triggers deliver DISTINCT,
/// accurate reset reasons to an in-flight user ConditionRefresh so the boundary status is never misleading
/// (ErrorDetail stays source-tagged, never dropped).
enum class BackboneRecoveryReason
{
  /// A session-CHANGED reconnect RECREATED the backbone MonitoredItem on a NEW session  -  the session the
  /// old-session refresh windows belonged to is gone (delivers `Bad_SessionClosed`).
  SessionReestablished,
  /// A REACTIVE Republish drain terminated with an unrecovered sequence gap (dropped messages, possibly a
  /// lost RefreshEnd) on a session that stayed up  -  no session closed, the condition state simply re-syncs
  /// (delivers `Bad_SequenceNumberUnknown`).
  EventLossDetected,
};

/// The hook an @ref AlarmConditionTrackerImpl registers with the subscriber to receive the A&C event feed
/// plus the three broadcast `Refresh*EventType` events (CL-AC-008  -  these bypass the per-consumer demux and
/// go to EVERY attached tracker). Held weakly by the subscriber (`weak_ptr`  -  the subscriber never owns a
/// tracker); the tracker keeps its own hook alive.
class EventTrackerHook
{
public:
  EventTrackerHook() = default;
  EventTrackerHook(const EventTrackerHook&) = delete;
  EventTrackerHook& operator=(const EventTrackerHook&) = delete;
  EventTrackerHook(EventTrackerHook&&) = delete;
  EventTrackerHook& operator=(EventTrackerHook&&) = delete;
  virtual ~EventTrackerHook() = default;

  /// Every non-Refresh event matching the tracker's interest (the subscriber broadcasts to attached
  /// trackers; the tracker filters internally).
  virtual void on_event(const EventNotification& notification) = 0;

  /// The SelectClauses + WhereClause this tracker contributes to the composite backbone filter on attach.
  [[nodiscard]] virtual ua::EventFilter filter_contribution() const = 0;

  /// Broadcast Refresh events (CL-AC-008)  -  delivered regardless of the per-consumer demux.
  virtual void on_refresh_start_event(const EventNotification& notification) = 0;
  virtual void on_refresh_end_event(const EventNotification& notification) = 0;
  virtual void on_refresh_required_event(const EventNotification& notification) = 0;

  /// Fired exactly once per attach, on the first Publish-decode after the backbone carrying this tracker's
  /// filter reports a notification (gates the tracker's initial `refresh_async`, CL-AC-003).
  virtual void on_first_event_after_attach() = 0;

  /// The backbone's dead refresh state must be reset (CL-AC-003). Two triggers reach here: a session-CHANGED
  /// reconnect that RECREATED the backbone MonitoredItem on a NEW session (its old-session
  /// RefreshStart/RefreshEnd windows can never complete  -  no Republish), or a REACTIVE Republish drain that
  /// terminated with an unrecovered gap (a lost RefreshEnd). @p reason distinguishes them so an in-flight
  /// user ConditionRefresh is delivered an accurate status/message. The subscriber re-arms
  /// `on_first_event_after_attach` so the next post-recovery event re-issues a fresh ConditionRefresh
  /// (resync).
  virtual void on_backbone_recovered(BackboneRecoveryReason reason) = 0;

  /// The SubscriptionId of the backbone this tracker is attached to, published whenever it is
  /// established or changes (attach, and after a session-CHANGED reconnect recreates the MonitoredItem
  /// on a new subscription).
  ///
  /// ConditionRefresh takes it as its one MANDATORY argument (OPC 10000-9 Table 20:
  /// `ConditionRefresh([in] IntegerId SubscriptionId)`), and the tracker has no other way to learn it -
  /// it reaches the wire through a method-call interface that knows nothing about subscriptions. Without it
  /// the tracker sent a Call with NO input arguments, which a conforming server refuses; our own server
  /// answers Bad_ArgumentsMissing.
  /// @param subscriptionId  The backbone's SubscriptionId - ConditionRefresh's mandatory argument.
  /// @param monitoredItemId The backbone MonitoredItem's id - ConditionRefresh2's second mandatory
  ///                        argument (OPC 10000-9 Table 23: `ConditionRefresh2([in] IntegerId
  ///                        SubscriptionId, [in] IntegerId MonitoredItemId)`), which scopes the replay
  ///                        to one item rather than the whole subscription.
  virtual void on_backbone_subscription_changed(
    std::uint32_t subscriptionId, std::uint32_t monitoredItemId) = 0;
};

/// Per-Connection knobs for the collapsing subscriber (section 7.7 `EventSubscriberPolicy`, drift #10).
/// Minimal in this slice; extended when `ConnectionConfig.eventSubscriber` is richer.
struct EventSubscriberPolicy
{
  std::uint32_t defaultQueueSize = 1000;
};

/// The strand-bearing event backbone (section 8.13). Owns its OWN private strand; every public method posts
/// to it once on entry. User callbacks fire on the executor (the design specification), never on the event
/// strand.
class EventSubscriberImpl : public std::enable_shared_from_this<EventSubscriberImpl>,
                            public MonitoredItemOwner
{
public:
  /// @param executor     The io_context executor the private strand is made from + user callbacks fire on.
  /// @param backboneOps  The narrow tier-1 backbone interface (weak  -  locked per use; no ownership cycle).
  /// @param logger       Logger for the guarded async boundaries.
  /// @param policy       Per-Connection knobs.
  /// @param observerSink The per-Connection observer fan-out (weak; section 7.8). Threaded into the co-owned
  /// A&C
  ///                     tracker so it can fire `AlarmObserver::on_data_integrity_warning` (CL-AC-023/025).
  [[nodiscard]] static std::shared_ptr<EventSubscriberImpl> create(boost::asio::any_io_executor executor,
    std::weak_ptr<EventBackboneOps> backboneOps, ua::Logger logger, EventSubscriberPolicy policy = {},
    std::weak_ptr<ObserverSink> observerSink = {});

  EventSubscriberImpl(const EventSubscriberImpl&) = delete;
  EventSubscriberImpl& operator=(const EventSubscriberImpl&) = delete;
  EventSubscriberImpl(EventSubscriberImpl&&) = delete;
  EventSubscriberImpl& operator=(EventSubscriberImpl&&) = delete;
  ~EventSubscriberImpl() override = default;

  // -------- Consumer API (the EventSubscriber facade forwards to these) --------

  void subscribe_async(EventSubscription subscription, EventNotificationCallback onEvent,
    std::function<void(SubscribeResult)> callback) noexcept;
  void subscribe_to_type_async(ua::NodeId eventType, EventNotificationCallback onEvent,
    std::function<void(SubscribeResult)> callback) noexcept;

  /// Like @ref subscribe_to_type_async, but ALSO requests @p fieldName (a field declared on @p eventType,
  /// e.g. GeneralModelChangeEventType's / SemanticChangeEventType's `Changes`) via an extra typed
  /// SelectClause (typeDefinitionId = @p eventType), on a DEDICATED backbone. The dedicated backbone is
  /// required because two event types can declare a field of the SAME browse-name ("Changes") but different
  /// type: on a shared backbone the two clauses would collide and `EventNotification::field(name)`
  /// (browse-name keyed) would resolve the wrong (or a null) one for the second type. Used by the @ref
  /// EventRouter to carry the per-node `Changes` payload for the model / semantic change backbones
  /// (CL-EVT-003 / CL-EVT-004). Never throws.
  void subscribe_to_type_with_field_async(ua::NodeId eventType, std::string_view fieldName,
    EventNotificationCallback onEvent, std::function<void(SubscribeResult)> callback) noexcept;

  /// Multi-field form used by routed event types with more than one additional Property (ProgressEventType).
  /// Each BrowseName is selected from @p eventType on one dedicated backbone.
  void subscribe_to_type_with_fields_async(ua::NodeId eventType, std::vector<std::string_view> fieldNames,
    EventNotificationCallback onEvent, std::function<void(SubscribeResult)> callback) noexcept;

  void unsubscribe_async(MonitoredItem item, std::function<void(ua::VoidResult)> callback) noexcept;

  // -------- MonitoredItemOwner (section 7.4)  -  event MonitoredItem self-actions, routed by clientHandle
  // --------

  void mi_modify_async(MonitoredItemId clientHandle, MonitorRequest request,
    std::function<void(ua::VoidResult)> callback) noexcept override;
  void mi_set_mode_async(MonitoredItemId clientHandle, ua::MonitoringMode mode,
    std::function<void(ua::VoidResult)> callback) noexcept override;
  void mi_delete_async(
    MonitoredItemId clientHandle, std::function<void(ua::VoidResult)> callback) noexcept override;

  // -------- Tracker hook surface (called by AlarmConditionTrackerImpl) --------

  void attach_tracker_async(
    std::shared_ptr<EventTrackerHook> hook, std::function<void(ua::VoidResult)> callback) noexcept;

  /// A tracker can widen the composite backbone filter after attach (CL-AC-016/022)  -  the subscriber
  /// recomputes the union and issues a `ModifyMonitoredItems` iff it changed. Idempotent.
  void widen_tracker_filter_async(std::function<void(ua::VoidResult)> callback) noexcept;

  // -------- Connection-internal entry points --------

  /// Delivered by the connection's Publish demux after every Publish-decode for events on a backbone this
  /// subscriber owns. @p backboneClientHandle is the CLIENT-assigned backbone handle the server echoes in
  /// `EventFieldList.client_handle` (the inbound demux key  -  the wire carries no monitored-item id).
  /// Decodes each @ref ua::EventFieldList positionally against the backbone's last-sent filter (CL-EVT-002),
  /// then demuxes to consumers / broadcasts Refresh events to trackers.
  void on_publish_events_async(std::uint32_t backboneClientHandle,
    std::vector<ua::EventFieldList> notifications, std::function<void()> callback) noexcept;

  /// Signalled by `ConnectionImpl::reconnect_commit` after a session-CHANGED reconnect RECREATED one or more
  /// backbone Subscriptions/MonitoredItems on a NEW session (CL-AC-003). @p affectedSubscriptionIds carries
  /// the OLD (create-time) subscription ids of exactly the backbones that were recreated (a transferred
  /// backbone is NOT in the set  -  the server kept it under the same id and Republish drains its old-session
  /// windows, so its tracker must NOT be reset). Posts to this subscriber's own strand, then, for ONLY the
  /// backbones whose `Backbone::subscriptionId` is in @p affectedSubscriptionIds: resets each live tracker's
  /// dead (old-session) refresh state via `EventTrackerHook::on_backbone_recovered`, prunes expired tracker
  /// weaks, and re-arms `on_first_event_after_attach` so the next post-recovery event re-issues a fresh
  /// ConditionRefresh. Preserved/transferred backbones are left untouched (Republish drains them). The
  /// connection strand never reaches into subscriber state  -  it only calls this method, which dispatches.
  ///
  /// @p reason distinguishes the trigger (a session-CHANGED reconnect vs a steady-state event-loss resync,
  /// Finding 2 / R4) so the reset delivers an accurate status/message to any in-flight user ConditionRefresh;
  /// it is threaded to each tracker's `EventTrackerHook::on_backbone_recovered`.
  void on_reconnect_recovered_async(
    std::vector<std::uint32_t> affectedSubscriptionIds, BackboneRecoveryReason reason) noexcept;

  /// Signalled after a reconnect driven by a RedundancySwitch reaches Active. Cold/Warm modes forward to
  /// the co-owned alarm tracker on this component's strand so it can discard cross-server state and issue
  /// the mandatory ConditionRefresh (CL-AC-013). All other modes are intentionally ignored.
  void on_redundancy_switch_recovered_async(ua::RedundancySupport mode) noexcept;

  /// Lazily constructs + co-owns the no-own-strand @ref AlarmConditionTrackerImpl sub-object (section 8.8),
  /// binds it to THIS strand, and starts it (attach hook + arm initial refresh once the backbone reports an
  /// event). Idempotent (guarded by a `once_flag`); returns the co-owned tracker so `Connection::alarms()`
  /// can wrap it in a public handle.
  [[nodiscard]] std::shared_ptr<AlarmConditionTrackerImpl> ensure_alarm_tracker(
    std::weak_ptr<WireOps> wireOps, AlarmConditionTrackerPolicy policy);

  /// Drains pending consumer records; the backbone Subscriptions are torn down by the pipeline, not here.
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// Cross-strand info snapshot (atomic-load; any thread).
  [[nodiscard]] std::shared_ptr<const EventSubscriberInfo> info() const noexcept;

  /// The subscriber's private executor (the co-owned tracker sub-object runs its callbacks on it).
  [[nodiscard]] boost::asio::any_io_executor executor() const noexcept override
  {
    return mExecutor;
  }

  /// The subscriber's private strand (the co-owned tracker sub-object runs ON it  -  it has no strand of its
  /// own, section 8.8 / section 1.3). NOT exposed publicly; only the co-owned tracker Impl and tests reach
  /// it.
  [[nodiscard]] const boost::asio::strand<boost::asio::any_io_executor>& event_strand() const noexcept
  {
    return mStrand;
  }

private:
  friend struct EventSubscriberTestAccess;

  EventSubscriberImpl(boost::asio::any_io_executor executor, std::weak_ptr<EventBackboneOps> backboneOps,
    ua::Logger logger, EventSubscriberPolicy policy, std::weak_ptr<ObserverSink> observerSink);

  /// One logical consumer coalesced onto a backbone (section 8.13.2). Strand-private.
  struct Consumer
  {
    MonitoredItemId handle = 0;
    std::size_t backboneIndex = 0;
    ua::EventFilter filter;  ///< the consumer's own filter (raw)
    std::vector<ua::SimpleAttributeOperand> selectClauses;  ///< the consumer's SelectClause contribution
    std::vector<ua::NodeId> ofTypes;  ///< the event types it wants; EMPTY == match-all (BaseEventType)
    /// @p ofTypes plus every transitive `HasSubtype` descendant, as the server's hierarchy declares it -
    /// resolved once at subscribe. This, not @ref ofTypes, is what the demux matches against, because
    /// `OfType` is subtype-inclusive (OPC 10000-4 7.4.4.5). Empty when the consumer is match-all, when it
    /// sits on a dedicated backbone (the server's own filter is then authoritative), or when the closure
    /// could not be resolved and the consumer was isolated instead.
    std::vector<ua::NodeId> ofTypeClosure;
    EventNotificationCallback callback;
    ua::MonitoringMode mode = ua::MonitoringMode::Reporting;
  };

  /// One backbone event MonitoredItem N consumers coalesce onto (section 8.13.2). Strand-private.
  struct Backbone
  {
    ua::NodeId notifier;
    std::uint32_t backboneClientHandle = 0;  ///< the MI's own client handle (inbound demux key)
    std::uint32_t subscriptionId = 0;
    std::uint32_t monitoredItemId = 0;
    bool created = false;  ///< the server MI exists
    bool creating = false;  ///< a create is in flight (coalesce racing first-subscribes)
    bool dedicated = false;  ///< a caller-requested isolated backbone (never coalesced into)
    bool isDefaultServerBackbone = false;  ///< kept warm on last-consumer drop (section 8.13.3)
    ua::EventFilter lastSentFilter;
    std::vector<MonitoredItemId> consumers;
    std::vector<std::weak_ptr<EventTrackerHook>> trackers;
    bool firstEventDelivered = false;  ///< on_first_event_after_attach fires once (CL-AC-003)
    std::vector<std::shared_ptr<EventTrackerHook>>
      pendingFirstEvent;  ///< trackers awaiting their first event
  };

  // ---- strand-private helpers ----
  void do_subscribe(EventSubscription subscription, EventNotificationCallback onEvent,
    std::vector<ua::SimpleAttributeOperand> selectClauses, std::vector<ua::NodeId> ofTypes,
    std::function<void(SubscribeResult)> callback);
  /// The tail of @ref do_subscribe, run once the consumer's subtype closure is known: allocates the
  /// handle, picks the backbone and pushes the composite filter.
  void finish_subscribe(EventSubscription subscription, EventNotificationCallback onEvent,
    std::vector<ua::SimpleAttributeOperand> selectClauses, std::vector<ua::NodeId> ofTypes,
    std::vector<ua::NodeId> ofTypeClosure, std::function<void(SubscribeResult)> callback);
  /// Whether this subscribe needs a client-side subtype closure: it demuxes by type (non-empty ofTypes),
  /// it is not one of the audit types (which always get a dedicated backbone), and it is not already
  /// isolated on a dedicated backbone - on a dedicated backbone the server's own OfType filter is the
  /// only filter that matters, so no client-side type test is required.
  [[nodiscard]] static bool needs_subtype_closure(
    const std::vector<ua::NodeId>& ofTypes, bool dedicatedBackbone);
  std::size_t find_or_add_backbone(const ua::NodeId& notifier, bool dedicated);
  ua::EventFilter compute_composite_filter(const Backbone& backbone) const;
  void push_filter_and_complete(
    std::size_t backboneIndex, MonitoredItemId handle, std::function<void(SubscribeResult)> callback);
  [[nodiscard]] MonitoredItem make_event_item(const Backbone& backbone, MonitoredItemId handle);
  void recompute_after_drop(std::size_t backboneIndex, std::function<void(ua::VoidResult)> callback);
  void dispatch_notifications(
    std::uint32_t backboneClientHandle, const std::vector<ua::EventFieldList>& notifications);
  [[nodiscard]] std::optional<EventNotification> decode_notification(
    const Backbone& backbone, const ua::EventFieldList& fieldList) const;
  /// Surfaces a decode-time drop (CL-EVT-001/002) as a non-fatal advisory via the weak @ref mObserverSink
  /// (`ClientObserver::on_advisory_diagnostic`), so a dropped malformed event is not silently lost. A no-op
  /// when no sink is installed / it has expired. Callable from the const decode path (locks the weak member).
  void fire_decode_advisory(std::shared_ptr<const ua::ErrorDetail> detail) const;
  /// Surfaces every bad status returned in an EventFilterResult without turning an otherwise successful
  /// Create/ModifyMonitoredItems operation into a failure (CL-MI-018).
  void fire_filter_diagnostics(const EventFilterDiagnostics& diagnostics) const;
  void dispatch_one(Backbone& backbone, const EventNotification& notification);
  [[nodiscard]] bool consumer_matches(const Consumer& consumer, const ua::NodeId& eventTypeId) const;
  void deliver_void(std::function<void(ua::VoidResult)> callback, ua::VoidResult result);
  void refresh_info_snapshot();

  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  // Dedicated FIFO delivery strand for USER event callbacks (CL-MI-026): per-item event delivery to a
  // consumer runs in arrival order and non-reentrant, off the processing strand (mirrors the pipeline's
  // mDeliveryStrand). Tracker/Refresh broadcasts do NOT use this strand  -  they run on mStrand by design
  // (section 8.8).
  boost::asio::strand<boost::asio::any_io_executor> mDeliveryStrand;
  std::weak_ptr<EventBackboneOps> mBackboneOps;
  ua::Logger mLogger;
  EventSubscriberPolicy mPolicy;
  // The per-Connection observer fan-out (section 7.8), WEAK-only. Threaded into the co-owned A&C tracker at
  // construction so it can fire AlarmObserver::on_data_integrity_warning (CL-AC-023/025). No ownership cycle.
  std::weak_ptr<ObserverSink> mObserverSink;

  std::vector<Backbone> mBackbones;
  std::unordered_map<MonitoredItemId, Consumer> mConsumers;  // keyed by consumer clientHandle
  std::vector<std::weak_ptr<EventTrackerHook>> mTrackerHooks;
  std::uint32_t mNextClientHandle = 1;
  std::size_t mLastPublishFieldListCount = 0;
  bool mClosing = false;
  // Subtype closures already resolved on this Connection, keyed by the requested root type (strand-only).
  // The hierarchy is server state that does not change within a session, so the second consumer asking for
  // a type costs no round-trip. Cleared on close with everything else.
  std::unordered_map<ua::NodeId, std::vector<ua::NodeId>> mSubtypeClosureCache;

  std::atomic<std::shared_ptr<const EventSubscriberInfo>> mInfoSnapshot{
    std::make_shared<const EventSubscriberInfo>()};

  // The co-owned no-own-strand A&C tracker sub-object (section 8.8), lazily constructed on first
  // Connection::alarms().
  std::once_flag mAlarmTrackerOnce;
  std::shared_ptr<AlarmConditionTrackerImpl> mAlarmTracker;
};

}  // namespace ua::client::detail

#endif  // UA_EVENT_SUBSCRIBER_IMPL_H
