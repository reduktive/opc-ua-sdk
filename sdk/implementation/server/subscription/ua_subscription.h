// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTION_H
#define UA_SUBSCRIPTION_H

#include "ua_access_control.h"
#include "ua_address_space.h"
#include "ua_weak_address_space.h"
#include "ua_await_callback.h"
#include "ua_result.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_value.h"
#include "ua_duration.h"
#include "ua_event_bus.h"
#include "ua_event_filter_result.h"
#include "ua_event_filter.h"
#include "ua_eu_range_resolver.h"
#include "ua_instance_tracker.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_integer_id.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_monitored_item.h"
#include "ua_monitoring_release.h"
#include "ua_monitored_item_create_result.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_notification_message.h"
#include "ua_request_info.h"
#include "ua_server_configuration.h"
#include "ua_server_counters.h"
#include "ua_subscription_router.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/dispatch.hpp>
#include <unordered_set>
#include "ua_timer.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua
{
class DeleteMonitoredItemsRequest;
}  // namespace ua

namespace ua::server
{

class Session;
class SessionSecurityContext;
class SampleSinkImpl;

/// One distinct sampling interval and how many monitored items use it (for
/// SamplingIntervalDiagnosticsArray).
struct SamplingIntervalEntry
{
  Duration samplingInterval{0};
  uint32_t monitoredItemCount{0};
  uint32_t disabledMonitoredItemCount{0};
};

/// Thread-safe snapshot of subscription state for cross-strand reads. Guarded by
/// `Subscription::mInfoMutex`. The "derived" fields are recomputed by `update_info()` on the
/// subscription strand; the cumulative "*Count" counters are bumped in place by the `record_*`
/// methods, which take the same mutex and so may be called from any strand (the publish path and
/// MI changes run on the subscription strand; republish / transfer / acknowledge run on the
/// pipeline's session strand). Backs the server-wide SubscriptionDiagnosticsArray (i=2290) and
/// SamplingIntervalDiagnosticsArray (i=2289).
struct SubscriptionInfo
{
  // Existing fields consumed by the pipeline (do not remove).
  IntegerId id{0};
  uint8_t priority{0};
  Duration publishingInterval{0};
  uint32_t monitoredItemCount{0};
  bool hasNotifications{false};  // data state: reportable notifications are queued (sample-driven)
  // Dispatch gate: the publishing timer has granted a send slot this cycle (data
  // or keep-alive). Decoupled from hasNotifications so that queued data does NOT
  // make the subscription eligible for an out-of-band Publish response - delivery
  // is paced by the publishing interval (Part 4 5.13.1), not by sample arrival.
  bool readyToPublish{false};
  uint32_t peekSequenceNumber{0};  // also serves as SubscriptionDiagnostics NextSequenceNumber

  // --- Derived diagnostic fields (recomputed by update_info on the subscription strand) ---
  uint32_t maxKeepAliveCount{0};
  uint32_t maxLifetimeCount{0};
  uint32_t maxNotificationsPerPublish{0};
  bool publishingEnabled{false};
  uint32_t currentKeepAliveCount{0};
  uint32_t currentLifetimeCount{0};
  uint32_t disabledMonitoredItemCount{0};
  std::vector<SamplingIntervalEntry> samplingIntervals;

  // --- Cumulative counters (bumped in place by record_* under mInfoMutex) ---
  uint32_t modifyCount{0};
  uint32_t enableCount{0};
  uint32_t disableCount{0};
  uint32_t republishRequestCount{0};
  uint32_t republishMessageRequestCount{0};
  uint32_t republishMessageCount{0};
  uint32_t transferRequestCount{0};
  uint32_t transferredToAltClientCount{0};
  uint32_t transferredToSameClientCount{0};
  uint32_t publishRequestCount{0};
  uint32_t dataChangeNotificationsCount{0};
  uint32_t eventNotificationsCount{0};
  uint32_t notificationsCount{0};
  uint32_t latePublishRequestCount{0};
  uint32_t discardedMessageCount{0};
  uint32_t monitoringQueueOverflowCount{0};
  uint32_t eventQueueOverflowCount{0};

  // Current (set, not accumulated): number of unacknowledged messages held in the
  // retransmission queue for this subscription. Maintained by the pipeline.
  uint32_t unacknowledgedMessageCount{0};
};

/// Parallel arrays of server/client handles for all monitored items in a subscription.
/// Returned by Subscription::get_monitored_item_handles_async.
struct MonitoredItemHandles
{
  std::vector<uint32_t> serverHandles;
  std::vector<uint32_t> clientHandles;
};

/// boost::asio::strand<boost::asio::any_io_executor>-serialized component for a single subscription. All
/// mutable state is accessed exclusively on the subscription strand. The only cross-strand read is
/// has_notifications() (atomic flag).
class Subscription : public std::enable_shared_from_this<Subscription>
{
public:
  /// Result of fulfill_publish - returned to SubscriptionsPipeline which
  /// builds the full PublishResponse (adds retransmission, availableSeqNums).
  struct PublishResult
  {
    NotificationMessage message;
    /// Empty on the ordinary hot path. Lazily sized only when a drained data-change notification has
    /// both a non-zero operation-level diagnostic mask and an ErrorDetail; entries align with the
    /// DataChangeNotification's monitoredItems array and carry each item's sticky mask.
    std::vector<uint32_t> dataChangeDiagnosticMasks;
    /// Server-only subjects aligned with the EventNotificationList fields retained for Republish.
    std::vector<RetainedEventProjection> eventProjections;
    /// Server-only raw inputs and stable subjects aligned with retained DataChange notifications.
    std::vector<RetainedDataProjection> dataProjections;
    bool moreNotifications{false};
  };

  /// Publishing state machine states (exposed for test access).
  enum class PublishingState
  {
    Normal,
    Late,
    KeepAlive
  };

  /// Callback to notify SubscriptionsPipeline that notifications are ready
  /// or that the subscription has expired.
  using NotifyReady = std::function<void(IntegerId subscriptionId)>;
  using NotifyExpired = std::function<void(IntegerId subscriptionId)>;

  /// Factory - returns shared_ptr (constructor is protected).
  static std::shared_ptr<Subscription> create(IntegerId subscriptionId, Duration publishingInterval,
    uint32_t lifetimeCount, uint32_t maxKeepAliveCount, uint32_t maxNotificationsPerPublish,
    bool publishingEnabled, uint8_t priority, boost::asio::any_io_executor executor, NotifyReady onReady,
    NotifyExpired onExpired, SubscriptionRouter::Weak registry = {},
    std::weak_ptr<Session> owningSession = {}, uint32_t maxResponseMessageSize = 0);

  ~Subscription();

  /// Seeds the logger used by this subscription's (and its sample sink's) async continuations.
  ///
  /// Called once by the owner (SubscriptionsPipeline) immediately after @ref create, before the
  /// subscription is published or sampled, so no synchronisation is needed. A ua::Logger is a value
  /// handle that survives teardown; it is passed into the post helpers at each call site. Forwards a
  /// copy to the sample sink so its cross-strand posts are guarded too.
  void set_logger(ua::Logger logger);

  /// Seeds the server-wide summary counters this subscription's MonitoredItems count against.
  ///
  /// Called once by the owning pipeline immediately after @ref create, before any service call, so no
  /// synchronisation is needed. Seeding at creation (rather than on the first CreateMonitoredItems)
  /// means a subscription can release and reacquire its slots whatever path its items arrived by.
  void set_summary_counters(std::shared_ptr<ServerSummaryCounters> counters);

  /// Sets the deadline shared by one asynchronous namespace-permission decision.
  ///
  /// Called by the owning pipeline before MonitoredItems are created. The value is retained across
  /// transfer and defaults to the ServerConfig default for directly-constructed unit fixtures.
  void set_access_control_timeout(std::chrono::milliseconds timeout);

  // Non-copyable, non-movable (shared_ptr-managed; owns a strand, mutex and timers).
  Subscription(const Subscription&) = delete;
  Subscription& operator=(const Subscription&) = delete;
  Subscription(Subscription&&) = delete;
  Subscription& operator=(Subscription&&) = delete;

  IntegerId id() const
  {
    return mId;
  }

  // --- SetTriggering result type (used in async/coro signatures) ---

  struct SetTriggeringResult
  {
    std::vector<StatusCode> removeResults;
    std::vector<StatusCode> addResults;
    // The triggeringItemId did not resolve to a MonitoredItem of this Subscription. Per Part 4
    // Table 79, Bad_MonitoredItemIdInvalid is a *service-level* SetTriggering result, so the caller
    // returns a ServiceFault rather than per-link results.
    bool triggeringItemInvalid{false};
  };

  // --- Thread-safe info query (Rule 4 info object) ---

  /// Returns a mutex-guarded snapshot of subscription state.
  /// Safe to call from any thread/strand.
  SubscriptionInfo get_info() const;

  // --- Diagnostic counter recording (mutex-guarded; safe from any strand) ---
  // The publish-path / MI counters are recorded on the subscription strand; the republish /
  // transfer / acknowledge counters are recorded by the pipeline on the session strand. All take
  // mInfoMutex, so cross-strand calls are safe.
  void record_modified();
  void record_publishing_mode(bool enabled);
  void record_publish_serviced();
  void record_notifications(uint32_t dataChangeCount, uint32_t eventCount);
  void record_late_publish();
  void record_republish_request();
  void record_republish_message();
  void record_transfer_request();
  void record_transferred(bool sameClient);
  void record_discarded_message();
  void set_unacknowledged_message_count(uint32_t count);

  // --- Fire-and-forget async methods (post to subscription strand) ---

  // ModifySubscription carries no PublishingEnabled (OPC 10000-4 5.13.3): only SetPublishingMode
  // changes it, so a modify keeps the mode the Subscription has.
  void modify_async(Duration publishingInterval, uint32_t lifetimeCount, uint32_t maxKeepAliveCount,
    uint32_t maxNotificationsPerPublish, uint8_t priority);
  void set_publishing_mode_async(bool enabled);
  void on_service_call_async();
  void close_async();
  void close_async(std::function<void()> callback);
  /// Stops counting this subscription's MonitoredItems against the server-wide gauge (a parked
  /// orphan holds no session and must not deny other clients their slots). Releases exactly the
  /// items this subscription holds, never a cached snapshot. Idempotent; callable from any strand.
  void release_server_monitored_item_slots();
  /// Counts this subscription's MonitoredItems against the server-wide gauge again (a transfer gives
  /// it a session). All or nothing: when @p serverMax is set and the items would push the gauge past
  /// it, nothing is claimed and `false` is returned, so the caller can refuse the transfer while
  /// the subscription is still parked. Idempotent (already-held slots return `true`); callable from
  /// any strand.
  [[nodiscard]] bool reacquire_server_monitored_item_slots(std::optional<uint32_t> serverMax);

  void rewire_callbacks_async(NotifyReady onReady, NotifyExpired onExpired,
    std::optional<uint32_t> maxResponseMessageSize = std::nullopt);
  void resend_initial_values_async(std::function<void(VoidResult)> callback = {});
  void update_registry_owner_async(std::weak_ptr<Session> newOwner);
  void set_publish_req_queued_async(bool queued);

  /// Configure periodic per-MonitoredItem authorization re-evaluation (Part 4 5.12.2.1).
  ///
  /// Posts to the subscription strand: stores the session security context, a weak address-space
  /// handle, and a weak EventBus used to re-resolve and re-authorize each item, then arms a periodic
  /// timer using the positive validated interval. The pipeline calls this once
  /// when the subscription is created (it owns these dependencies); the subscription owns no config of
  /// its own. Safe to call from any thread.
  void configure_access_recheck(std::chrono::milliseconds interval,
    std::shared_ptr<SessionSecurityContext> securityContext, WeakAddressSpace addressSpace,
    std::weak_ptr<EventBus> eventBus);

  /// Re-evaluate every live MonitoredItem against one explicitly supplied, freshly resolved
  /// authorization context. Unlike the periodic best-effort cycle, this mandatory identity-change
  /// path propagates infrastructure failures and completes only after the complete item snapshot was
  /// visited. Safe to call from any thread; completion is delivered exactly once.
  void reauthorize_all_async(std::function<void(VoidResult)> callback);

  /// reauthorize_all_async for a Subscription just transferred to another Session: every item is
  /// re-authorized for the new owner, and samples held while it had no Session reach the queue, but an
  /// item whose verdict is unchanged is not sent its latest value again - with sendInitialValues false a
  /// transfer delivers only changes (Part 4 5.13.7.2). Safe to call from any thread.
  void reauthorize_after_transfer_async(std::function<void(VoidResult)> callback);

  using ReauthorizeNotificationCallback = std::function<void(Result<NotificationMessage>)>;
  /// Re-check a retained NotificationMessage under the current receiving identity before Republish.
  void reauthorize_notification_async(NotificationMessage message,
    std::vector<RetainedEventProjection> eventProjections,
    std::vector<RetainedDataProjection> dataProjections, ReauthorizeNotificationCallback callback);

  // --- Callback async methods (post to strand, deliver result via callback) ---

  using FulfillPublishCallback = std::function<void(std::vector<PublishResult>)>;
  void fulfill_publish_async(
    uint32_t availablePublishCount, bool publishReqQueued, FulfillPublishCallback callback);

  using CreateMonitoredItemsCallback = std::function<void(std::vector<MonitoredItemCreateResult>)>;
  /// @p locales are the Session's, most preferred first; the namespace calls carry them (NR-8). Empty for a
  /// caller with no Session.
  void create_monitored_items_async(CreateMonitoredItemsRequest request, AddressSpace addressSpace,
    ServerConfig::ServerCapabilities capabilities, ServerConfig::SubscriptionLimits subscriptionLimits,
    std::shared_ptr<SessionSecurityContext> securityContext, std::weak_ptr<EventBus> eventBus,
    std::shared_ptr<ServerSummaryCounters> summaryCounters, CreateMonitoredItemsCallback callback,
    std::vector<LocaleId> locales = {});

  using DeleteMonitoredItemsCallback = std::function<void(std::vector<StatusCode>)>;
  void delete_monitored_items_async(std::vector<IntegerId> monitoredItemIds, AddressSpace addressSpace,
    std::weak_ptr<EventBus> eventBus, std::shared_ptr<ServerSummaryCounters> summaryCounters,
    DeleteMonitoredItemsCallback callback);

  using ModifyMonitoredItemsCallback = std::function<void(std::vector<MonitoredItemModifyResult>)>;
  /// @p locales as for @ref create_monitored_items_async.
  void modify_monitored_items_async(ModifyMonitoredItemsRequest request, AddressSpace addressSpace,
    ServerConfig::ServerCapabilities capabilities, ServerConfig::SubscriptionLimits subscriptionLimits,
    ModifyMonitoredItemsCallback callback, std::vector<LocaleId> locales = {});

  using SetMonitoringModeCallback = std::function<void(std::vector<StatusCode>)>;
  void set_monitoring_mode_async(
    std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode, SetMonitoringModeCallback callback);

  using SetTriggeringCallback = std::function<void(SetTriggeringResult)>;
  void set_triggering_async(IntegerId triggeringItemId, std::vector<IntegerId> linksToAdd,
    std::vector<IntegerId> linksToRemove, SetTriggeringCallback callback);

  using GetMonitoredItemHandlesCallback = std::function<void(MonitoredItemHandles)>;
  void get_monitored_item_handles_async(GetMonitoredItemHandlesCallback callback);

  /// Marks the subscription durable per Part 4 5.13.9 (SetSubscriptionDurable). On the subscription
  /// strand: reports Bad_ServiceUnsupported if durable subscriptions are disabled
  /// (`subscriptionLimits.durableSubscriptionsEnabled` false); reports Bad_InvalidState if the
  /// subscription already has monitored items (durable must be set before items are added); otherwise
  /// flags the subscription durable, recomputes the lifetime from `lifetimeInHours` (revised to >= 1 and
  /// capped at `subscriptionLimits.maxDurableSubscriptionLifetimeHours`) so it survives the durable
  /// window, raises the monitored-item queue ceiling (to
  /// `subscriptionLimits.maxDurableMonitoredItemQueueSize` at MI create), and reports the revised
  /// lifetime in hours. Durable state is in-memory only - it does not persist across a server restart.
  using SetDurableCallback = std::function<void(StatusCode, uint32_t revisedLifetimeInHours)>;
  void set_durable_async(uint32_t lifetimeInHours, ServerConfig::SubscriptionLimits subscriptionLimits,
    SetDurableCallback callback);

protected:
  Subscription(IntegerId subscriptionId, Duration publishingInterval, uint32_t lifetimeCount,
    uint32_t maxKeepAliveCount, uint32_t maxNotificationsPerPublish, bool publishingEnabled, uint8_t priority,
    boost::asio::any_io_executor executor, NotifyReady onReady, NotifyExpired onExpired,
    SubscriptionRouter::Weak registry, uint32_t maxResponseMessageSize);

private:
  // Identity
  const IntegerId mId;

  // State machine
  PublishingState mPublishingState{PublishingState::Normal};
  bool mMessageSent{false};
  uint32_t mKeepAliveCounter{0};
  uint32_t mLifetimeCounter;
  uint32_t mNextSequenceNumber{1};

  // Publishing parameters
  Duration mPublishingInterval;
  uint32_t mLifetimeCount;
  uint32_t mMaxKeepAliveCount;
  uint32_t mMaxNotificationsPerPublish;
  uint32_t mMaxResponseMessageSize;
  bool mPublishingEnabled;
  uint8_t mPriority;

  // Durable subscription state (Part 4 5.13.9). Set by SetSubscriptionDurable; once durable the
  // subscription uses a long lifetime and permits large monitored-item queues. In-memory only - the
  // durable flag does not persist across a server restart.
  bool mDurable{false};
  uint32_t mDurableLifetimeHours{0};

  // boost::asio::strand<boost::asio::any_io_executor> + async infrastructure
  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  /// Logger for async continuations, seeded by @ref set_logger after construction. Value handle that
  /// survives teardown; passed into the post helpers at each call site.
  ua::Logger mLogger;
  Timer mPublishingTimer;

  // Live-instance counter for leak diagnostics (RAII; see ua_instance_tracker.h).
  [[no_unique_address]] ua::diagnostics::InstanceTracker<Subscription> mInstanceTracker;

  // Monitored items (owned by shell - logic doesn't touch these).
  std::unordered_map<IntegerId, std::unique_ptr<MonitoredItem>> mMonitoredItems;
  /// Handles of create answers not yet taken by their create; created by the first create.
  std::shared_ptr<UnclaimedMonitoringHandles> mUnclaimedHandles;
  IntegerId mNextMonitoredItemId{1};

  // Triggered item links: triggeringItemId -> set of triggeredItemIds
  std::map<IntegerId, std::set<IntegerId>> mTriggerLinks;

  // Batch sink - one per subscription, shared with all namespaces.
  std::shared_ptr<SampleSinkImpl> mSampleSink;

  // Notification dirty flag (atomic - internal use only).
  std::atomic<bool> mHasNotifications{false};

  // Dispatch gate, strand-confined. Set only by signal_ready() (publishing-timer
  // expiry / Late catch-up / moreNotifications continuation) and cleared when a
  // Publish response consumes the granted send slot. select_subscription_for_publish
  // keys on this (via SubscriptionInfo::readyToPublish), so a sample arriving
  // between timer ticks does NOT trigger an out-of-band response.
  bool mReadyToPublish{false};

  // True only when mReadyToPublish was re-opened to continue draining a response whose
  // MoreNotifications field was true. Table 85 SetPublishingMode clears that continuation, but it
  // must not withdraw an independent send slot granted by the publishing timer.
  bool mMoreNotificationsContinuationPending{false};

  bool has_notifications() const
  {
    return mHasNotifications.load(std::memory_order_acquire);
  }

  void set_publish_req_queued(bool queued)
  {
    mPublishReqQueued.store(queued, std::memory_order_release);
  }

  // Count of monitored items with non-empty queues in Reporting or
  // triggered-report-pending state.
  uint32_t mReportableItemCount{0};

  // Whether Publish requests are currently queued on the session strand.
  std::atomic<bool> mPublishReqQueued{false};

  // Callbacks to SubscriptionsPipeline (post to session strand)
  NotifyReady mOnReady;
  NotifyExpired mOnExpired;

  // Whether the subscription has been closed.
  bool mClosed{false};

  // Server-wide counters for monitored item count tracking. Nullable.
  std::shared_ptr<ServerSummaryCounters> mSummaryCounters;

  /// Exact accounting of this subscription's share of the server-wide gauge
  /// (`ServerSummaryCounters::currentMonitoredItemCount`). `itemCount` is the number of live
  /// MonitoredItems, moved on the subscription strand as items commit and are deleted; `held` says
  /// whether those items are currently counted in the gauge (a parked orphan releases its share, a
  /// transfer claims it back). One mutex guards both because the release and the claim are driven
  /// from a session strand while the count moves on the subscription strand. The cached info
  /// snapshot is never used for this: it lags the live map while a create or delete is in flight.
  struct ServerSlotAccounting
  {
    bool held{true};
    uint32_t itemCount{0};
  };

  std::mutex mSlotMutex;
  ServerSlotAccounting mSlots;

  // Server-level subscription registry (for RAII register/unregister).
  SubscriptionRouter::Weak mRegistry;
  /// This Subscription's MonitoredItem counts per interval as last reported to mRegistry. Strand-confined.
  std::map<Duration, uint32_t> mReportedSamplingIntervals;

  // --- Periodic per-MonitoredItem authorization re-evaluation (Part 4 5.12.2.1) ---
  // Captured at subscription creation via configure_access_recheck. The timer periodically re-checks
  // each item's Read / ReceiveEvents authorization against the Session's current access identity and
  // the freshly-resolved node, replacing MonitoredItem::accessSnapshot so revocation stops streaming,
  // a changed mask reprojects, and a later grant resumes delivery. All fields are strand-confined.
  Timer mAccessRecheckTimer;
  std::chrono::milliseconds mAccessRecheckInterval{60000};
  std::chrono::milliseconds mAccessControlTimeout{1000};
  std::weak_ptr<SessionSecurityContext> mRecheckSecurityContext;
  WeakAddressSpace mRecheckAddressSpace;
  std::weak_ptr<EventBus> mRecheckEventBus;
  /// The bus this Subscription's event items are registered on, recorded at registration so the items
  /// can be deregistered at close whichever path registered them.
  std::weak_ptr<EventBus> mRegisteredEventBus;
  bool mAccessRecheckArmed{false};

  // --- Subscription lifecycle (must be called on subscription strand) ---

  void modify(Duration publishingInterval, uint32_t lifetimeCount, uint32_t maxKeepAliveCount,
    uint32_t maxNotificationsPerPublish, uint8_t priority);
  void set_durable(uint32_t lifetimeInHours, const ServerConfig::SubscriptionLimits& subscriptionLimits,
    SetDurableCallback callback);
  void set_publishing_mode(bool enabled);
  void on_service_call();
  void close();
  /// Releases the monitoring handles of every live item; the Subscription's end, closed or destroyed.
  void release_live_monitoring_handles() noexcept;
  /// Takes every live event item out of the EventBus it registered on; the Subscription's end, closed or
  /// destroyed. The bus is server-wide and outlives the Subscription, so a registration left behind is
  /// scanned and called for every event the server emits from then on.
  void release_event_bus_registrations() noexcept;
  /// Records one more live MonitoredItem. @p reservedInGauge is true when the item's slot came from
  /// a create-time reservation (already counted in the gauge): if the subscription is parked, that
  /// slot is handed straight back so an orphan never counts against other clients.
  void account_committed_item(bool reservedInGauge);
  /// Records @p deletedCount fewer live MonitoredItems and, while the share is held, releases them
  /// from the gauge.
  void account_deleted_items(uint32_t deletedCount, const std::shared_ptr<ServerSummaryCounters>& counters);

  void rewire_callbacks(NotifyReady onReady, NotifyExpired onExpired);
  void resend_initial_values();
  void update_registry_owner(std::weak_ptr<Session> newOwner);

  // --- Sample reception (called on subscription strand by SampleSinkImpl) ---

  void on_samples_received(std::vector<std::pair<IntegerId, DataValue>> samples);
  void on_sample_invalidated(IntegerId monitoredItemId, StatusCode reason);

  struct PendingEventDelivery
  {
    uint64_t ordinal{0};
    IntegerId monitoredItemId{0};
    std::shared_ptr<const BaseEvent> event;
    std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel;
  };

  // EventBus fan-out must never wait for one recipient's permission resolution. The subscription therefore
  // owns a FIFO of handed-off Events and serializes resolve -> bit-11 authorization -> filter -> projection
  // on its own strand. This retains a cold Event until the bounded permission lookup completes while
  // preserving per-subscription delivery order.
  std::deque<PendingEventDelivery> mPendingEventDeliveries;

  /// SVC-5: per-item accounting of mPendingEventDeliveries. The FIFO is bounded per item by the item's
  /// queueSize BEFORE authorization, with the item's own discard policy; without it an event storm queued
  /// every event for every event item ahead of the serial permission resolution, unbounded. The last
  /// accepted ordinal is where a discard-newest loss puts its overflow event (SVR-EVT-MON-008), kept in
  /// O(1) so a drop never scans the FIFO for it.
  struct PendingEventAccounting
  {
    uint32_t count{0};
    uint64_t lastAcceptedOrdinal{0};
  };

  std::unordered_map<IntegerId, PendingEventAccounting> mPendingEventAccounting;
  uint64_t mNextEventDeliveryOrdinal{1};
  uint64_t mActiveEventDeliveryOrdinal{0};
  uint64_t mEventDeliveryAttemptEpoch{0};
  bool mEventDeliveryActive{false};
  AccessIdentityKey mEventDeliveryIdentity;
  std::chrono::steady_clock::time_point mEventDeliveryDeadline;
  Timer mEventDeliveryDeadlineTimer;
  std::optional<SessionAccessControl> mEventDeliveryAccessControl;
  std::vector<CompiledEventFilter::AuthorizationSubject> mEventDeliveryPlan;
  std::vector<AccessControl::Item> mEventDeliveryResolvedItems;
  std::vector<size_t> mEventDeliveryResolvedPlanIndices;
  std::vector<AccessControl::Verdict> mEventDeliveryVerdicts;

  void enqueue_event_delivery(IntegerId monitoredItemId, std::shared_ptr<const BaseEvent> event,
    std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel);
  void discard_pending_event_deliveries(IntegerId monitoredItemId);
  void start_next_event_delivery();
  void start_event_delivery_attempt(uint64_t ordinal);
  void on_event_subjects_resolved(
    uint64_t ordinal, uint64_t attemptEpoch, BatchResult<NodeAccessorResult> batch);
  void on_event_subjects_authorized(
    uint64_t ordinal, uint64_t attemptEpoch, std::vector<AccessControl::Verdict> verdicts);
  void on_event_delivery_deadline(uint64_t ordinal);
  void restart_active_event_delivery_for_identity_change();
  bool event_delivery_attempt_matches(uint64_t ordinal, uint64_t attemptEpoch) const noexcept;
  bool event_delivery_identity_is_current() const;
  void complete_event_delivery(uint64_t ordinal, bool deliver, StatusCode terminalCause);
  void log_event_delivery_failure(const StatusCode& status) const;

  /// What one retained notification needs to be re-authorized against the CURRENT identity.
  ///
  /// Plain data held by value in the operation that walks it. Nothing here records where that walk
  /// has got to: a coroutine's position in its own body is that. The address space is held weakly, as the
  /// access control holds it: the completion the operation gives a namespace owns the operation (CALLS-21
  /// rule 1).
  struct RepublishProjection
  {
    RepublishProjection(NotificationMessage retainedMessage,
      std::vector<RetainedEventProjection> retainedEventProjections,
      std::vector<RetainedDataProjection> retainedDataProjections, AddressSpace currentAddressSpace,
      SessionAccessControl currentAccessControl)
      : message(std::move(retainedMessage)), eventProjections(std::move(retainedEventProjections)),
        dataProjections(std::move(retainedDataProjections)), addressSpace(currentAddressSpace.weak()),
        accessControl(std::move(currentAccessControl))
    {}

    NotificationMessage message;
    std::vector<RetainedEventProjection> eventProjections;
    std::vector<RetainedDataProjection> dataProjections;
    WeakAddressSpace addressSpace;
    SessionAccessControl accessControl;
    std::vector<CompiledEventFilter::AuthorizationSubject> plan;
    std::vector<AccessControl::Item> resolvedItems;
    std::vector<size_t> resolvedPlanIndices;
    std::vector<AccessControl::Verdict> verdicts;
  };

  /// One retained notification's re-authorization, start to finish. Defined in the .cpp.
  ///
  /// An operation rather than a member task: Republish is a per-request entry point, so a
  /// Subscription can have several of these in flight and has no single slot to hold one in.
  /// @see ua::async::SelfOwningOperation
  class RepublishProjectionOperation;

  void start_republish_projection(NotificationMessage message,
    std::vector<RetainedEventProjection> eventProjections,
    std::vector<RetainedDataProjection> dataProjections, ReauthorizeNotificationCallback completion);

  /// Projects the re-authorized notification and answers the caller. Synchronous: every question it
  /// needed answering was answered before it was called.
  void finish_republish_projection(
    RepublishProjection& projection, ReauthorizeNotificationCallback completion);

  /// A semantic property of the item's value changed: arm the item so its next enqueued value
  /// carries the SemanticsChanged bit and bypasses the deadband (CTT Data Access Analog 008). For a
  /// polled item the next sampling tick folds the bit into its regular sample; for an exception-
  /// reported item (no tick coming) it synthesizes one from the item's cache now. The bit clears
  /// only when a bit-carrying value is published.
  void on_semantics_changed(IntegerId monitoredItemId);

  /// The structure of the item's value changed (OPC 10000-4 7.39.1 Table 180): one notification of the item
  /// carries the StructureChanged bit - the value queued and not yet published, else one made now from the
  /// value last published, else the next value the item takes (@ref MonitoredItem::mark_structure_changed).
  /// A mark that reaches an item still being created is applied when it commits; a Disabled item, which
  /// samples nothing, and an event item are not marked.
  void on_structure_changed(IntegerId monitoredItemId);

  /// An EURange as read for a PercentDeadband item: its limits.
  struct EuRangeRead
  {
    double low{0.0};
    double high{0.0};
  };

  /// The EURange of a Variable from its EURange Property as @ref EuRangeResolver answered it.
  ///
  /// @return Its limits; or why there are none: the resolver's failure (Bad_NodeIdUnknown when the Variable
  ///         has no EURange Property), the Value's status when its quality is Bad, Bad_TypeMismatch
  ///         ("EuRangeNotARange") when the Value is not a Range.
  static Result<EuRangeRead> eu_range_from(const EuRangeProperty& property);

  /// The EURange Properties of @p variables for @p request: one @ref EuRangeResolver call, awaited on this
  /// Subscription's strand. Eager, so a caller can start it with other work and await it later.
  ua::async::Task<std::vector<EuRangeProperty>> resolve_eu_ranges(AddressSpace addressSpace,
    RequestInfo request, std::vector<NodeAccessor> variables, std::optional<uint32_t> browseLimit);

  /// Finds and reads a PercentDeadband item's EURange Property again, after a SemanticsChanged mark: the
  /// Property is looked up by its browse name, as at create, because the mark may say it is a new Node.
  /// The item joins the re-reads of this strand turn, which @ref flush_eu_range_rereads resolves together.
  void reread_eu_range(const MonitoredItem& item);

  /// Resolves every item of @ref mEuRangeRereads at once (NR-62 rule 2): one lookup of their Variables, then
  /// one @ref EuRangeResolver call, with the server's own request; each answer is applied by
  /// @ref apply_reread_eu_range with the item's generation when the flush began.
  void flush_eu_range_rereads();

  /// The PercentDeadband items marked since the last flush of their EURange re-reads, by id.
  std::set<IntegerId> mEuRangeRereads;

  /// Applies what @ref reread_eu_range read to item @p monitoredItemId, unless a later mark advanced the
  /// item's EURange generation past @p generation. A usable Range replaces the item's range. A Variable
  /// without an EURange Property, or a Value that is not a usable Range, leaves the item without one: it
  /// reports every change. A lookup or read that failed otherwise says nothing about the range, and the item
  /// keeps the one it holds. Each case but the first is logged with its status and ErrorDetail.
  ///
  /// @param value The EURange Property's Value as read, or why it could not be: Bad_NodeIdUnknown when the
  ///              Variable has no EURange Property.
  void apply_reread_eu_range(IntegerId monitoredItemId, uint64_t generation, DataValueResult value);

  /// Mark every item linked to `sourceId` as triggered (so Sampling-mode links become reportable)
  /// and update the reportable count. Called when a triggering item enqueues a notification
  /// (SVR-MI-GEN-081..087). Must run on the subscription strand.
  void flush_triggered_links(IntegerId sourceId);

  /// Projects one user-independent sample for `item`'s owner and enqueues it, updating the reportable
  /// count and the item's triggered links. The caller has established that the owner's snapshot allows
  /// the item. Must run on the subscription strand.
  void accept_sample(IntegerId monitoredItemId, MonitoredItem& item, DataValue userIndependentValue);

  /// One sample for a committed item: held while the Subscription has no Session, dropped while the
  /// item's snapshot does not allow the current identity, otherwise accepted. Must run on the subscription
  /// strand.
  void receive_sample(IntegerId monitoredItemId, MonitoredItem& item, DataValue userIndependentValue);

  /// Delivers into `item`'s queue the samples it held while the Subscription had no Session, once the
  /// item's snapshot is of the identity that now owns it; until then they stay held. Returns whether the
  /// item became reportable. Must run on the subscription strand.
  bool replay_orphaned_samples(MonitoredItem& item);

  /// replay_orphaned_samples for every item, when the new owner's context is installed.
  void replay_orphaned_samples();

  // --- Publishing (called on subscription strand) ---

  std::vector<PublishResult> fulfill_publish(uint32_t availablePublishCount);

  // --- Monitored item management (called on subscription strand) ---

  IntegerId add_monitored_item(std::unique_ptr<MonitoredItem> item);
  bool remove_monitored_item(IntegerId monitoredItemId);
  MonitoredItem* find_monitored_item(IntegerId monitoredItemId);

  // --- Service operations (called on subscription strand) ---

  // --- CreateMonitoredItems ---
  //
  // One at a time: a second create_monitored_items_async arriving while one is running is refused
  // with BadInvalidState. ~Subscription fires the in-flight callback with all-bad results (7.3
  // ergonomic firing, CL-F).
  //
  // The staged items are OWNED by the body until they commit - a `unique_ptr<MonitoredItem>` each,
  // not yet in `mMonitoredItems` - which is what makes them safe to hold across a suspension. The
  // other item operations are NOT serialised against this one: each single-flight gate refuses only
  // a second call of its own kind, so a delete runs in its own strand turn while this body waits.
  // Nothing here may borrow what one of them can destroy.

  /// Where an item's initial value stands among the samples held for the item before it committed.
  struct InitialValueMark
  {
    /// The initial value's SourceTimestamp when the source gave it one. Empty for a value this Subscription
    /// made itself (a refusal or a failed read), whose timestamp says nothing about the source.
    std::optional<DateTime> sourceTimestamp{};
    /// The value of @ref mStrandSequence taken when the initial value was asked for: a held sample that
    /// reached the strand after it may be newer than what the namespace answered.
    uint64_t issued{0};
  };

  /// One requested item that survived validation, and the item it will become.
  struct PendingItem
  {
    size_t index{0};
    std::unique_ptr<MonitoredItem> item;
    Duration revisedSamplingInterval{0};
    uint32_t revisedQueueSize{0};
    std::optional<EventFilterResult> eventFilterResult;
    std::optional<EventFilter> sourceEventFilter;
    /// The handle a namespace issued for this item, kept here because a refused item is reset before
    /// the create ends; released unless the item commits.
    IssuedMonitoringHandle issuedHandle;
    bool committed{false};
    /// The Node the create's one lookup found for the item (NR-26 step 1); every item the lookup found
    /// none for is refused there.
    std::optional<NodeAccessor> subject;
    /// What a sample held before the item committed is compared with to decide whether it is newer than the
    /// item's initial value (DL-69 (D7)). Empty for an event item.
    std::optional<InitialValueMark> initialValueMark;
    /// The code the namespace answered the item's creation with: plain Good, a Good subcode or an Uncertain
    /// code. The created item's result carries it.
    StatusCode answered{Status::Good};
  };

  /// One sample a namespace pushed for an item of the running create before the item committed, with the
  /// value of @ref mStrandSequence taken when it reached the strand.
  struct HeldSample
  {
    uint64_t arrival{0};
    DataValue value;
  };

  /// What a namespace pushed for an item of the running create before the item committed (DL-69 (D7)):
  /// its samples, oldest first and bounded like the item's queue, and its deletion notice.
  struct HeldBeforeCommit
  {
    std::deque<HeldSample> samples{};
    std::optional<StatusCode> notice{};
    size_t capacity{1};
    bool discardOldest{true};
  };

  /// What one CreateMonitoredItems was given to work with. Held by value in the body that runs it.
  struct CreateInputs
  {
    CreateMonitoredItemsRequest request;
    AddressSpace addressSpace;
    std::optional<SessionAccessControl> accessControl;
    ServerConfig::ServerCapabilities capabilities;
    ServerConfig::SubscriptionLimits subscriptionLimits;
    std::shared_ptr<SessionSecurityContext> securityContext;
    std::weak_ptr<EventBus> eventBus;
    std::shared_ptr<ServerSummaryCounters> summaryCounters;
    /// What the namespaces are called with: the deadline the request's timeoutHint sets from its arrival,
    /// and the create's cancellation flag, set when the create ends (@ref take_create_completion).
    RequestInfo requestInfo;
  };

  /// Slots claimed from the server-wide MaxMonitoredItems count for items that have not committed.
  ///
  /// The cap is claimed for a whole batch at once, atomically, so that concurrent creates on other
  /// subscriptions see each other's claims instead of all racing past the same stale count. What
  /// that leaves behind is a debt: every slot claimed for an item that then fails has to go back.
  /// Holding the debt in an object is what makes it go back on EVERY way out of the body, including
  /// the ways nobody wrote down - a body that is withdrawn, or one that throws.
  class ServerSlotReservation
  {
  public:
    ServerSlotReservation() = default;
    ServerSlotReservation(std::shared_ptr<ServerSummaryCounters> counters, uint32_t slots);
    ~ServerSlotReservation();

    /// Moves the debt, leaving nothing behind - so the claim is owned continuously from the moment
    /// the count was raised to the moment it is given back, with no instant in between where two
    /// objects would release it or none would.
    ServerSlotReservation(ServerSlotReservation&& other) noexcept;

    ServerSlotReservation(const ServerSlotReservation&) = delete;
    ServerSlotReservation& operator=(const ServerSlotReservation&) = delete;
    ServerSlotReservation& operator=(ServerSlotReservation&&) = delete;

    /// Gives one slot to an item that has just committed: the gauge counts it as a live item now.
    void hand_one_over();
    /// Returns every slot still held, now rather than at destruction. @see finish_create
    void release_now();

  private:
    std::shared_ptr<ServerSummaryCounters> mCounters;
    uint32_t mSlots{0};
  };

  /// Whether a create is running. What the engaged bit of a `unique_ptr` used to say. Read by the
  /// next create, which is refused while this one runs, and by both access rechecks.
  bool mCreateRunning{false};
  /// The one answer a create owes. Moved out by whoever ends it first.
  CreateMonitoredItemsCallback mCreateCompletion;
  /// How many results that answer carries, for the paths that end the create from outside its body.
  size_t mCreateItemCount{0};
  /// The ids of the items the running create has assigned, and those of them a SemanticsChanged or a
  /// StructureChanged mark reached before they committed; the mark is applied at commit. Declared before the
  /// create's task, whose frame may still read them while this Subscription is destroyed.
  std::unordered_set<IntegerId> mCreatingItemIds;
  std::unordered_set<IntegerId> mSemanticMarksBeforeCommit;
  std::unordered_set<IntegerId> mStructureMarksBeforeCommit;
  /// The samples and deletion notices pushed for the running create's items before they committed, by id;
  /// delivered at commit (@ref deliver_held_before_commit).
  std::unordered_map<IntegerId, HeldBeforeCommit> mHeldBeforeCommit;
  /// Advanced on the strand each time a sample is held for an item that has not committed and each time a
  /// create asks for its items' initial values, so the two can be ordered by when they reached the strand.
  uint64_t mStrandSequence{0};
  /// The running create's cancellation flag, which its RequestInfo carries; set when the create ends.
  std::shared_ptr<std::atomic_bool> mCreateCancelled;
  /// The create's own coroutine. @see start_create
  ua::async::Task<> mCreateTask;
  /// Which create the task slot belongs to. @see start_create
  uint64_t mCreateGeneration{0};

  /// Starts one create and puts it in the task slot, if the slot is still this create's to fill.
  void start_create(CreateInputs inputs);

  /// Contains whatever the create throws, and makes sure it ends exactly once.
  ua::async::Task<> run_create(CreateInputs inputs);

  /// Validates, compiles, caps, authorizes, registers and establishes every requested item, in that
  /// order, and answers when the last of them is done.
  ///
  /// By reference, because the containing task owns the inputs for the create's whole life.
  ua::async::Task<> walk_create(CreateInputs& inputs);

  /// Everything decidable from the request alone. No I/O. @see walk_create
  void validate_create_items(CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results,
    std::vector<PendingItem>& validItems);

  /// Validates each EventFilter's select clauses against the EventType model, with one resolution for the
  /// request (every EventType the filters name collected once), and compiles each in request order.
  ua::async::Task<> compile_create_event_filters(CreateInputs& inputs,
    std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems);

  /// Applies the per-subscription and server-wide item caps, and claims the slots for what is left.
  [[nodiscard]] ServerSlotReservation apply_create_caps(CreateInputs& inputs,
    std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems);

  /// Looks every item's Node up with one call per namespace, for the request (NR-26 step 1). A row whose
  /// lookup is not Good is refused and never registered: a Bad answer with its status and ErrorDetail; an
  /// Uncertain answer, with or without the Node, Bad_InternalError (`LookupAnswerUncertain`, the SDK does not
  /// act on an answer the namespace is uncertain of) with the Uncertain status as its cause (DL-69 (D2) as
  /// revised).
  ua::async::Task<> look_up_create_items(CreateInputs& inputs,
    std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems);

  /// Records each item's permission decision on the item, with one permission call for the items whose
  /// lookup found a Node. A denied item is still created.
  ua::async::Task<> authorize_create_items(CreateInputs& inputs, std::vector<PendingItem>& validItems);

  /// Refuses, before registration, each AbsoluteDeadband item whose Variable's DataType is known not to be
  /// numeric (@ref numeric_data_type_facts, once for the request's distinct DataTypes).
  ua::async::Task<> refuse_non_numeric_absolute_deadbands(CreateInputs& inputs,
    std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems);

  /// Registers every data-change item with the namespace that owns its node - one call per
  /// namespace, all namespaces at once.
  ua::async::Task<> register_create_items(CreateInputs& inputs,
    std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems);

  /// One namespace's part of @ref register_create_items.
  ua::async::Task<> register_in_namespace(CreateInputs& inputs, uint16_t namespaceIndex,
    std::vector<std::pair<size_t, MonitoringCreateItem>>& nsItems,
    std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems);

  /// Gives each surviving item what it needs to start reporting, and commits it: the PercentDeadband items'
  /// EURanges and the Variables' initial Values are read with one call of each kind per namespace, started
  /// together; every other initial value comes from the Node's description; then the items commit in
  /// request order, in one strand turn.
  ua::async::Task<> establish_create_items(CreateInputs& inputs,
    std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems,
    ServerSlotReservation& reservation);

  /// The initial Values of @p reads, read for @p caller with maxAge 0 and a SourceTimestamp: one
  /// `NodeAccessorRoute::read_values` call, awaited on this Subscription's strand. Eager.
  ua::async::Task<std::vector<DataValueResult>> read_initial_values(
    RequestInfo request, std::shared_ptr<const CallerInfo> caller, std::vector<ua::detail::ValueRead> reads);

  /// Delivers to the just-committed item @p monitoredItemId what was held for it before it committed:
  /// the samples newer than its initial value (by SourceTimestamp when both carry one, otherwise by whether
  /// the sample reached the strand after the initial value was asked for), then the deletion notice. A
  /// sample not newer is dropped.
  void deliver_held_before_commit(IntegerId monitoredItemId, HeldBeforeCommit held,
    const std::optional<InitialValueMark>& initialValueMark);

  /// Checks the event item's Node for SubscribeToEvents, from its description, and registers the item with
  /// the EventBus. A description that is not Good answers the item with its status and ErrorDetail; a Node
  /// whose EventNotifier is absent or lacks SubscribeToEvents, `Bad_FilterNotAllowed`.
  /// @param node The event item's notifier Node, as the create's lookup found it.
  /// @return Whether the item may go on to be committed.
  bool establish_event_item(CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results,
    PendingItem& pending, const NodeAccessor& node);

  /// Moves one finished item into `mMonitoredItems` and fills in its result row.
  void finalise_create_item(PendingItem& pending, std::vector<MonitoredItemCreateResult>& results,
    ServerSlotReservation& reservation);

  /// Ends the create and hands back the one answer it owes, or null if something else ended it first.
  CreateMonitoredItemsCallback take_create_completion();
  void finish_create(std::vector<MonitoredItemCreateResult> results, ServerSlotReservation& reservation);
  void fail_create(StatusCode status);

  // --- DeleteMonitoredItems ---
  //
  // One delete at a time: a second delete_monitored_items_async arriving while one is running is
  // refused with BadInvalidState. The body holds its own inputs and its own working state; what
  // stays here is only what something OTHER than the body needs - whether one is running, the answer
  // it owes, and how many results that answer must carry. ~Subscription fires that answer with
  // all-bad results (7.3 ergonomic firing).

  /// Whether a delete is running. What the engaged bit of a `unique_ptr` used to say. Read by the
  /// next delete, which is refused while this one runs, and by both access rechecks, which will not
  /// re-authorize items that a delete is in the middle of removing.
  bool mDeleteRunning{false};
  /// The one answer a delete owes. Moved out by whoever ends the delete first.
  DeleteMonitoredItemsCallback mDeleteCompletion;
  /// How many results that answer carries. Held outside the body because the body's own copy of the
  /// ids goes with its frame, and ~Subscription has to answer when the body can no longer be asked.
  size_t mDeleteItemCount{0};
  /// The delete's own coroutine. Single-flight, so one slot is enough - and @ref start_delete is
  /// what makes sure the one in it is the one still running.
  ua::async::Task<> mDeleteTask;
  /// Which delete the task slot belongs to. @see start_delete
  uint64_t mDeleteGeneration{0};

  /// Starts one delete and puts it in the task slot, if the slot is still this delete's to fill.
  void start_delete(std::vector<IntegerId> monitoredItemIds, AddressSpace addressSpace,
    std::weak_ptr<EventBus> eventBus, std::shared_ptr<ServerSummaryCounters> summaryCounters);

  /// Contains whatever the delete throws, and makes sure it ends exactly once.
  ua::async::Task<> run_delete(std::vector<IntegerId> monitoredItemIds, AddressSpace addressSpace,
    std::weak_ptr<EventBus> eventBus, std::shared_ptr<ServerSummaryCounters> summaryCounters);

  /// Removes every named item from this subscription, then asks every namespace that issued a monitoring
  /// handle for one of them to release it (@ref delete_in_namespace, all at once), and answers when each
  /// has answered.
  ///
  /// By reference, because the containing task owns them for the delete's whole life and a nested
  /// task that copied them would hold a second AddressSpace handle and a second id list.
  ua::async::Task<> walk_delete(const std::vector<IntegerId>& monitoredItemIds, AddressSpace& addressSpace,
    const std::weak_ptr<EventBus>& eventBus, const std::shared_ptr<ServerSummaryCounters>& summaryCounters);

  /// One namespace's part of the delete: its `delete_monitoring_async` for the handles of @p nsItems (each a
  /// row of @p results and the handle of the item that row deleted), then each row answers the namespace's
  /// answer for its handle: plain Good, a Good subcode, an Uncertain or a Bad code. A Bad batch status is
  /// every row's answer. The handles live until the namespace answers, so a release outlives a Subscription
  /// destroyed meanwhile; a namespace that is no longer registered leaves its rows Good.
  ua::async::Task<> delete_in_namespace(AddressSpace& addressSpace, uint16_t namespaceIndex,
    const std::vector<std::pair<size_t, MonitoringHandle>>& nsItems, std::vector<StatusCode>& results);

  /// Ends the delete and hands back the one answer it owes, or null if something else ended it first.
  DeleteMonitoredItemsCallback take_delete_completion();
  /// Answers the delete with @p results, after accounting for the @p removedCount items it removed from this
  /// subscription.
  void finish_delete(std::vector<StatusCode> results, uint32_t removedCount,
    const std::shared_ptr<ServerSummaryCounters>& summaryCounters);
  void fail_delete(StatusCode status);

  // --- ModifyMonitoredItems ---
  //
  // One at a time, and the single-flight gate refuses only a second MODIFY. What used to stand here
  // said the staged changes "survive every namespace callback because the strand serialises with
  // respect to CMI/Delete on the same Subscription": that was the reasoning behind a raw
  // `MonitoredItem*` in each staged row, and it was wrong. A strand serialises TURNS, not
  // operations - a delete runs in its own turn while a modify is suspended between two of its own,
  // and it erases the items the modify staged. Nothing here may borrow what another operation can
  // destroy while this one waits.
  //
  // ~Subscription fires the in-flight callback with all-bad MonitoredItemModifyResults.
  /// One requested change that survived validation, and what its parameters were revised to.
  ///
  /// Held by value in a vector local to the body that builds it. It names its item by ID rather than
  /// pointing at it: a delete is NOT refused while a modify is running, and it erases the very
  /// MonitoredItems a modify was told to change - so between staging a change and a namespace
  /// answering for it, the item can be gone.
  struct PendingModify
  {
    size_t index{0};
    IntegerId monitoredItemId{0};
    Duration revisedSamplingInterval{0};
    uint32_t revisedQueueSize{0};
    bool discardOldest{true};
    DataChangeTrigger trigger{DataChangeTrigger::StatusValue};
    DeadbandType deadbandType{DeadbandType::None};
    double deadbandValue{0.0};
    IntegerId clientHandle{0};
    uint32_t diagnosticInfoMask{0};
    /// For a PercentDeadband, the EURange read for it.
    double euRangeLow{0.0};
    double euRangeHigh{0.0};
    /// The item's EURange generation when the EURange was read for this modify.
    uint64_t euRangeGeneration{0};
    /// The EURange was read for this modify (the item had no usable range of its own).
    bool euRangeRead{false};
    /// The item keeps the range it holds at commit, which its marks keep current: it already has a
    /// PercentDeadband with a usable range. Nothing is copied, so a re-read applied meanwhile is kept.
    bool keepHeldEuRange{false};
    /// The code the namespace answered the change with: plain Good, a Good subcode or an Uncertain code.
    /// The changed item's result carries it.
    StatusCode answered{Status::Good};
  };

  /// Whether a modify is running. What the engaged bit of a `shared_ptr` used to say. Read by the
  /// next modify, which is refused while this one runs, and by both access rechecks.
  bool mModifyRunning{false};
  /// The running modify's cancellation flag, which its RequestInfo carries; set when the modify ends.
  std::shared_ptr<std::atomic_bool> mModifyCancelled;
  /// The one answer a modify owes. Moved out by whoever ends it first.
  ModifyMonitoredItemsCallback mModifyCompletion;
  /// How many results that answer carries, for the paths that end the modify from outside its body.
  size_t mModifyItemCount{0};
  /// The modify's own coroutine. @see start_modify
  ua::async::Task<> mModifyTask;
  /// Which modify the task slot belongs to. @see start_modify
  uint64_t mModifyGeneration{0};

  /// Starts one modify and puts it in the task slot, if the slot is still this modify's to fill.
  void start_modify(ModifyMonitoredItemsRequest request, AddressSpace addressSpace,
    ServerConfig::ServerCapabilities capabilities, ServerConfig::SubscriptionLimits subscriptionLimits,
    RequestInfo requestInfo);

  /// Contains whatever the modify throws, and makes sure it ends exactly once.
  ua::async::Task<> run_modify(ModifyMonitoredItemsRequest request, AddressSpace addressSpace,
    ServerConfig::ServerCapabilities capabilities, ServerConfig::SubscriptionLimits subscriptionLimits,
    RequestInfo requestInfo);

  /// Validates and revises every requested change, applies the ones that need no namespace, and
  /// tells each namespace about the ones that do - one call per namespace, every namespace at once.
  /// The rows asking for an AbsoluteDeadband, and the PercentDeadband rows whose item holds no usable
  /// range, are first looked up with one call per namespace; their DataTypes are then decided and their
  /// EURanges read together, one call of each kind per namespace.
  ///
  /// By reference, because the containing task owns them for the modify's whole life.
  ua::async::Task<> walk_modify(const ModifyMonitoredItemsRequest& request, AddressSpace& addressSpace,
    const ServerConfig::ServerCapabilities& capabilities,
    const ServerConfig::SubscriptionLimits& subscriptionLimits, const RequestInfo& requestInfo);

  /// One namespace's part of the modify: its `modify_monitoring_async`, then the answers applied to the
  /// rows of @p nsItems, each item looked up again since a delete may have removed it meanwhile.
  ua::async::Task<> modify_in_namespace(AddressSpace& addressSpace, const RequestInfo& requestInfo,
    uint16_t namespaceIndex, const std::vector<std::pair<size_t, MonitoringModifyItem>>& nsItems,
    std::vector<MonitoredItemModifyResult>& results, std::vector<PendingModify>& validModifies);

  /// Whether each of @p types is known not to be numeric (@ref numeric_data_type_facts), awaited on this
  /// Subscription's strand. Eager.
  ua::async::Task<std::vector<bool>> decide_numeric_data_types(
    AddressSpace addressSpace, RequestInfo request, std::vector<NodeId> types);

  /// Writes one accepted change onto the item it names, which the caller has just looked up.
  void apply_pending_modify(MonitoredItem& item, const PendingModify& pending);

  /// Ends the modify and hands back the one answer it owes, or null if something else ended it first.
  ModifyMonitoredItemsCallback take_modify_completion();
  void finish_modify(
    std::vector<MonitoredItemModifyResult> results, const std::vector<PendingModify>& validModifies);
  void fail_modify(StatusCode status);

  /// Gives the strand back for one turn, for a step that answered without ever suspending.
  /// @see await_step
  ua::async::Task<> yield_strand();

  // --- SetMonitoringMode ---
  //
  // Disable, no-op and transitions between enabled modes are answered immediately. A
  // Disabled-to-enabled transition stays Disabled while every affected Node is freshly resolved and
  // authorized, both in one batch. One at a time: a second change arriving while one is running is
  // refused. What stays here is only what something OTHER than the body needs - whether one is
  // running, the answer it owes, and how many results that answer carries.
  /// One item that is being taken out of Disabled, and therefore needs a fresh permission decision.
  ///
  /// Held by value in a vector local to the body that builds it. It carries the item's own data and
  /// nothing about where the body has got to: the item is looked up again by id when the decision
  /// comes back, because a concurrent delete is ordinary rather than exceptional.
  struct PendingEnable
  {
    size_t resultIndex{0};
    IntegerId monitoredItemId{0};
    NodeId nodeId;
    AccessOperation operation{AccessOperation::Browse};
    std::optional<NodeAccessor> resolvedNode;
    AccessControl::Verdict verdict;
  };

  /// Whether a monitoring-mode change is running. One at a time; a second is refused
  /// BadInvalidState. Read by both access rechecks, which will not re-authorize items while one of
  /// these is deciding their permissions.
  bool mSetMonitoringModeRunning{false};
  /// The one answer a monitoring-mode change owes. Moved out by whoever ends it first.
  SetMonitoringModeCallback mSetMonitoringModeCompletion;
  /// How many results that answer carries, for the paths that end the change from outside its body.
  size_t mSetMonitoringModeItemCount{0};
  /// The change's own coroutine. @see start_set_monitoring_mode
  ua::async::Task<> mSetMonitoringModeTask;
  /// Which change the task slot belongs to. @see start_set_monitoring_mode
  uint64_t mSetMonitoringModeGeneration{0};

  /// Starts one change and puts it in the task slot, if the slot is still this change's to fill.
  void start_set_monitoring_mode(std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode);

  /// Contains whatever the change throws, and makes sure it ends exactly once.
  ua::async::Task<> run_set_monitoring_mode(std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode);

  /// Applies the new mode to every named item: immediately for the modes that need no permission
  /// decision, and after one batched resolve and one batched authorization for the items being taken
  /// out of Disabled.
  ///
  /// By reference, because the containing task owns the ids for the change's whole life.
  ua::async::Task<> walk_set_monitoring_mode(
    const std::vector<IntegerId>& monitoredItemIds, MonitoringMode newMode);

  /// Commits the decisions for the items being re-enabled, one item at a time, re-looking each up.
  void apply_set_monitoring_mode(std::vector<PendingEnable>& pendingEnables, MonitoringMode newMode,
    const std::optional<SessionAccessControl>& accessControl, std::vector<StatusCode>& results);

  /// Ends the change and hands back the one answer it owes, or null if something else ended it first.
  SetMonitoringModeCallback take_set_monitoring_mode_completion();
  void finish_set_monitoring_mode(std::vector<StatusCode> results);
  void fail_set_monitoring_mode(StatusCode status);

  // --- Periodic authorization re-evaluation flow (single-flight, like create/modify/delete) ---
  // One cycle snapshots the live item ids and the session's AccessIdentity (queried fresh per cycle,
  // so node-permission and identity changes are picked up), then re-resolves every item in one batched
  // lookup and re-authorizes them in one batched authorization. Items are re-looked-up by id at every
  // hop so a concurrent delete is tolerated.
  /// What one re-evaluation cycle was given to work with. Held by value in the cycle's own body;
  /// the snapshot of item ids, and where the walk has got to in it, are locals of that body.
  struct AccessRecheckInputs
  {
    // AddressSpace has no default constructor (it is a value handle), so the inputs are constructed
    // with the locked handle.
    explicit AccessRecheckInputs(AddressSpace addressSpaceIn) : addressSpace(std::move(addressSpaceIn))
    {}

    std::optional<SessionAccessControl> accessControl;
    AddressSpace addressSpace;  ///< strong handle held for the duration of the cycle
    std::weak_ptr<EventBus> eventBus;
  };

  /// Whether a cycle is running. One at a time, and mutually exclusive with the item flows - which is
  /// what the engaged bit of a `unique_ptr` used to say, and what an in-flight body now asks at every
  /// resumption to discover that something else ended it.
  bool mAccessRecheckRunning{false};
  /// A mandatory cycle owes its caller an answer even if the subscription closes underneath it; a
  /// periodic one does not. Read from outside the cycle, so it outlives the body.
  bool mAccessRecheckMandatory{false};
  // False while a transfer's re-authorization runs: an unchanged verdict then re-sends nothing.
  bool mReprojectUnchangedOnRecheck{true};
  /// The one answer a cycle owes. Moved out by whoever finishes the cycle first.
  std::function<void(VoidResult)> mAccessRecheckCompletion;
  /// The cycle's own coroutine. Single-flight, so one slot is enough - and
  /// @ref start_access_recheck_cycle is what makes sure the one in it is the one still running.
  ua::async::Task<> mAccessRecheckTask;
  /// Which cycle the task slot belongs to. @see start_access_recheck_cycle
  uint64_t mAccessRecheckGeneration{0};

  void arm_access_recheck_timer();
  // Runs one re-evaluation cycle on the strand. `onComplete` (may be null) fires when the cycle
  // finishes or is skipped; the timer path passes null, test access passes a completion signal.
  void run_access_recheck(std::function<void()> onComplete);

  /// Starts one cycle and puts it in the task slot, if the slot is still this cycle's to fill.
  void start_access_recheck_cycle(AccessRecheckInputs inputs, std::vector<IntegerId> itemIds, bool mandatory);

  /// Contains whatever the cycle throws, and makes sure it ends exactly once.
  ua::async::Task<> run_access_recheck_cycle(
    AccessRecheckInputs inputs, std::vector<IntegerId> itemIds, bool mandatory);

  /// One re-evaluation cycle: every item in the snapshot re-resolved in one call and re-authorized in one
  /// call, so each namespace is asked once per step (NR-23), then the verdicts applied in snapshot order.
  ///
  /// By reference, because the containing task owns both for the cycle's whole life and a nested task
  /// that copied them would hold a second AddressSpace handle and a second identity snapshot.
  ua::async::Task<> walk_access_recheck_cycle(
    AccessRecheckInputs& inputs, const std::vector<IntegerId>& itemIds, bool mandatory);

  /// Awaits one collaborator call of one of this subscription's own bodies, on its strand.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    // The answer is POSTED rather than dispatched. A collaborator on this path can answer on the
    // calling stack - a local address space always does - and `await_callback` resumes inline when
    // the answer arrives on the strand it is already running on, so a body of N steps would run from
    // its first to its last inside ONE strand turn, holding this subscription's strand against
    // publishing and every other item flow for as long as the client's item count. The chains these
    // bodies replace posted after every step, for exactly that reason (R18).
    //
    // `post_borrowing`, not `post_owning`: this subscription owns these Tasks, so a subscription that
    // has gone has taken them with it and there is nothing left to answer.
    return ua::async::await_callback<T>(mStrand,
      mLogger,
      weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          mStrand,
          mLogger,
          [completion = std::move(completion)](Subscription&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  void start_mandatory_access_recheck(std::function<void(VoidResult)> callback);
  VoidResult apply_recheck_transition(MonitoredItem& item, MonitoredAccessSnapshot snapshot);
  /// @param cycleAccessControl The running cycle's identity, when one is running. A failure recorded
  ///                            before a cycle has an identity keeps the item's own.
  void apply_periodic_recheck_failure(MonitoredItem& item, StatusCode failure,
    const std::optional<SessionAccessControl>& cycleAccessControl = std::nullopt);
  void apply_periodic_recheck_failure_to_all(StatusCode failure);
  void log_periodic_recheck_failure(IntegerId monitoredItemId, const StatusCode& failure) const;
  void finish_access_recheck(VoidResult result = {});

  // Subscribe an event MonitoredItem to the EventBus and record its handle (shared by create Phase-3
  // and the deny->allow recheck transition).
  void register_event_monitored_item(MonitoredItem& item, EventBus& eventBus);

  SetTriggeringResult set_triggering(IntegerId triggeringItemId, const std::vector<IntegerId>& linksToAdd,
    const std::vector<IntegerId>& linksToRemove);

  // --- Internal: state machine helpers ---
  uint32_t allocate_sequence_number();
  uint32_t peek_sequence_number() const;
  void signal_ready();
  void notify_expired();
  void reset_lifetime();
  void start_publishing_timer();
  void on_publishing_timer_expired();
  NotificationMessage create_notification_message(uint32_t maxNotifications,
    std::vector<uint32_t>& dataChangeDiagnosticMasks, std::vector<RetainedEventProjection>& eventProjections,
    std::vector<RetainedDataProjection>& dataProjections);

  bool notifications_available() const
  {
    return mReportableItemCount > 0;
  }

  void update_reportable_count();

  // --- Info snapshot (Rule 4: mutex-guarded, not part of strand) ---
  mutable std::mutex mInfoMutex;
  SubscriptionInfo mCachedInfo;

  // Cumulative queue-overflow counts carried over from monitored items that have since been
  // removed, so the subscription's overflow totals stay monotonic as items come and go.
  uint32_t mRemovedDataOverflowCount{0};
  uint32_t mRemovedEventOverflowCount{0};

  /// Update the cached info snapshot. Must be called on strand after state mutations.
  void update_info();

  /// Transition into the Late publishing state, counting LatePublishRequestCount only on a genuine
  /// entry (not when already Late). Subscription strand.
  void enter_late_state();

  friend class SampleSinkImpl;
  friend struct SubscriptionTestAccess;
};

}  // namespace ua::server

#endif  // !UA_SUBSCRIPTION_H
