// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTIONS_PIPELINE_H
#define UA_SUBSCRIPTIONS_PIPELINE_H

#include "ua_await_callback.h"
#include "ua_defines.h"
#include "ua_duration.h"
#include "ua_diagnostic_security_context.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_integer_id.h"
#include "ua_logger.h"
#include "ua_notification_message.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_request_header.h"
#include "ua_server_configuration.h"
#include "ua_server_counters.h"
#include "ua_status_code.h"
#include "ua_subscription.h"
#include "ua_subscription_id_allocator.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_subscription_acknowledgement.h"
#include "ua_timer.h"

#include "ua_session_security.h"
#include "security/ua_server_authentication.h"
#include "ua_transfer_subscriptions_response.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace ua
{
class AddressSpace;
class CreateSubscriptionRequest;
class CreateMonitoredItemsRequest;
class DeleteMonitoredItemsRequest;
class ModifyMonitoredItemsRequest;
class ModifySubscriptionRequest;
class DeleteSubscriptionsRequest;
class SetPublishingModeRequest;
class SetMonitoringModeRequest;
class SetTriggeringRequest;
class TransferSubscriptionsRequest;
class PublishRequest;
class RepublishRequest;
}  // namespace ua

namespace ua::server
{

class Session;
class SubscriptionRouter;
// NOT `struct UserIdentity;` here. The type is ua::UserIdentity, and ua_server_authentication.h
// brings it into this namespace with `using ::ua::UserIdentity;` - so declaring it again here
// creates a SECOND, distinct ua::server::UserIdentity that conflicts with that using-declaration.
// Every clang from 16 to 20 rejects it; GCC tolerates it, which is why the primary toolchain never
// saw it. The using-declaration below names the one real type.
using ::ua::UserIdentity;

/// Per-session subscription manager.
/// Lives on the session strand - all methods are called from the session strand.
/// Manages subscription lifecycle, publish request queue, and retransmission queue.
///
/// Lifetime: shared_ptr-managed via enable_shared_from_this. Async continuations
/// capture weak_from_this() and lock() on resumption (weak-capture default), so a
/// dispatch in flight when the owning Session is destroyed simply no-ops on the
/// next strand turn rather than touching a dead manager.
class SubscriptionsPipeline : public std::enable_shared_from_this<SubscriptionsPipeline>
{
public:
  /// Dependencies injected at construction time.
  struct Config
  {
    boost::asio::any_io_executor executor;
    boost::asio::strand<boost::asio::any_io_executor> sessionStrand;
    Logger logger;
    SubscriptionIdAllocator& idAllocator;
    std::shared_ptr<ServerSummaryCounters> summaryCounters;
    ServerConfig::ServerCapabilities capabilities;
    ServerConfig::SubscriptionLimits subscriptionLimits;
    /// Positive period on which each MonitoredItem's authorization is re-evaluated. Sourced from
    /// `ServerConfig::monitoredItemAccessRecheckInterval`; threaded to each subscription.
    std::chrono::milliseconds monitoredItemAccessRecheckInterval{60000};
    /// Deadline shared by one access-control operation's namespace permission resolution.
    std::chrono::milliseconds accessControlTimeout{1000};
    std::function<void(Response)> sendResponse;
    WeakAddressSpace addressSpace;
    SubscriptionRouter::Weak subscriptionRouter;
    OrphanedSubscriptionStore::Weak orphanedSubscriptionStore;
    std::weak_ptr<Session> owningSession;
    std::shared_ptr<SessionSecurityContext> securityContext;
    /// Lazily invoked only when a published item both requested diagnostics and carries ErrorDetail.
    /// The provider snapshots the receiving Session's current authenticated diagnostic policy.
    std::function<DiagnosticSecurityContext()> diagnosticSecurityContext;
    /// The NodeId of the receiving Session's SessionDiagnostics Object while that Object exists, or nullopt
    /// (diagnostics off, or the Object still being created). Called on the Session strand when a transfer's
    /// audit Event is raised; unset, the audit names the Server Object.
    std::function<std::optional<NodeId>()> diagnosticsObject;
    std::weak_ptr<EventBus> eventBus;
    uint32_t maxResponseMessageSize{0};
    bool auditingEnabled{false};
    std::string applicationUri;
    /// Monotonic time source used to validate queued Publish timeoutHints. Injectable for deterministic
    /// unit tests; production uses steady_clock so wall-clock adjustments cannot revive/expire requests.
    std::function<std::chrono::steady_clock::time_point()> monotonicNow{[]
      {
        return std::chrono::steady_clock::now();
      }};
  };

  static std::shared_ptr<SubscriptionsPipeline> create(Config config);

  /// Answers an in-flight reauthorization walk before it goes. @see mReauthorizeAllCompletion
  ~SubscriptionsPipeline();

  SubscriptionsPipeline(const SubscriptionsPipeline&) = delete;
  SubscriptionsPipeline& operator=(const SubscriptionsPipeline&) = delete;
  SubscriptionsPipeline(SubscriptionsPipeline&&) = delete;
  SubscriptionsPipeline& operator=(SubscriptionsPipeline&&) = delete;

  // --- Subscription service calls (run on session strand) ---
  void handle_create_subscription(uint32_t requestId, const CreateSubscriptionRequest& request);
  void handle_modify_subscription(uint32_t requestId, const ModifySubscriptionRequest& request);
  void handle_delete_subscriptions(uint32_t requestId, const DeleteSubscriptionsRequest& request);
  void handle_set_publishing_mode(uint32_t requestId, const SetPublishingModeRequest& request);

  // --- Publish service (run on session strand) ---
  void handle_publish(uint32_t requestId, const PublishRequest& request);
  void handle_republish(uint32_t requestId, const RepublishRequest& request);

  /// Discards every queued Publish request (run on the session strand) and RETURNS their requestIds so the
  /// caller (the session) can release the matching per-request bookkeeping - those requests will never
  /// reach the response path that normally reaps it. Call when the session's SecureChannel is lost: the
  /// requests arrived on the now-dead channel, the client abandons them and resends fresh ones on the
  /// reconnect channel (Part 4 6.7), and a response can no longer be delivered for them. Crucially, leaving
  /// them queued would cause a post-reconnect NotificationMessage to be dispatched in reply to a stale
  /// requestId the client no longer has outstanding, so the client drops the response and the notification
  /// is lost. Unlike @ref drain_publish_queue this sends nothing (the channel is gone) - it simply drops
  /// the requests and reports their ids.
  [[nodiscard]] std::vector<uint32_t> discard_pending_publish_requests();

  // --- MonitoredItem services (run on session strand) ---
  /// @p locales are the Session's, which the namespace calls of Create and ModifyMonitoredItems carry (NR-8).
  void handle_create_monitored_items(
    uint32_t requestId, const CreateMonitoredItemsRequest& request, std::vector<LocaleId> locales = {});
  void handle_delete_monitored_items(uint32_t requestId, const DeleteMonitoredItemsRequest& request);
  void handle_modify_monitored_items(
    uint32_t requestId, const ModifyMonitoredItemsRequest& request, std::vector<LocaleId> locales = {});
  void handle_set_monitoring_mode(uint32_t requestId, const SetMonitoringModeRequest& request);
  void handle_set_triggering(uint32_t requestId, const SetTriggeringRequest& request);

  /// Mandatory cold-path permission re-evaluation used by ActivateSession identity changes. The
  /// supplied context is the freshly resolved context for the new identity. Every Subscription is
  /// awaited serially; the first infrastructure failure is forwarded losslessly.
  void reauthorize_all_async(std::function<void(VoidResult)> callback);

  // --- TransferSubscriptions (run on session strand) ---
  void handle_transfer_subscriptions(uint32_t requestId, const TransferSubscriptionsRequest& request);

  /// Retransmission queue entry - public alias for transfer support.
  using RetransmissionEntry = ::ua::server::RetransmissionEntry;

  /// Result of detaching a subscription for transfer.
  struct DetachResult
  {
    std::shared_ptr<Subscription> subscription;
    std::vector<RetransmissionEntry> retransmissionEntries;
  };

  /// Detach a subscription for transfer. Called on THIS session's strand.
  /// Sends StatusChangeNotification to old session's publish pipeline.
  /// Returns the subscription + extracted retransmission entries, or nullopt if not found.
  std::optional<DetachResult> detach_subscription_for_transfer(IntegerId subscriptionId);

  /// Attach a previously transferred subscription. Called on THIS session's strand.
  void attach_transferred_subscription(std::shared_ptr<Subscription> subscription,
    std::vector<RetransmissionEntry> retransmissionEntries, bool sendInitialValues);

  // --- Session lifecycle ---
  void close_all();

  /// CloseSession(deleteSubscriptions=false): detach every subscription into the server-level
  /// OrphanedSubscriptionStore (kept alive on its own lifetime for a later TransferSubscriptions)
  /// instead of closing it. The immutable source context is retained for the complete 5.13.7
  /// transfer authorization check. Falls back to close_all() if no store is configured.
  void orphan_all(SubscriptionTransferContext transferContext);

  // --- Notification dispatch (called when subscription signals readiness/expiry) ---
  void on_subscription_ready(IntegerId subscriptionId);
  void on_subscription_expired(IntegerId subscriptionId);

  // --- Query ---
  size_t subscription_count() const
  {
    return mSubscriptions.size();
  }

  bool has_subscription(IntegerId subscriptionId) const
  {
    return mSubscriptions.find(subscriptionId) != mSubscriptions.end();
  }

  std::shared_ptr<Subscription> find_subscription(IntegerId subscriptionId) const
  {
    auto it = mSubscriptions.find(subscriptionId);
    return (it != mSubscriptions.end()) ? it->second : nullptr;
  }

  size_t total_monitored_item_count() const
  {
    size_t total = 0;
    for (const auto& [id, sub] : mSubscriptions)
    {
      total += sub->get_info().monitoredItemCount;
    }
    return total;
  }

  size_t pending_publish_count() const
  {
    return mPendingPublishRequests.size();
  }

  size_t retransmission_queue_size() const
  {
    return mRetransmissionQueue.size();
  }

  /// Cross-strand observable subscription count (safe from any thread).
  uint32_t atomic_subscription_count() const
  {
    return mAtomicSubscriptionCount.load(std::memory_order_relaxed);
  }

  /// Cross-strand observable total monitored item count (safe from any thread).
  uint32_t atomic_total_monitored_item_count() const
  {
    return mAtomicTotalMonitoredItemCount.load(std::memory_order_relaxed);
  }

  friend struct SubscriptionsPipelineTestAccess;

private:
  /// Sends a Create/Modify/DeleteMonitoredItems response once the diagnostics describing MonitoredItems
  /// (the per-interval SamplingIntervalDiagnostics nodes) reflect the change, so a client browsing them
  /// straight after the response finds them current. Must run on the session strand.
  void send_after_monitoring_reflected(Response response);

  /// The bodies of the service entry points above, which those entry points reach only once they
  /// are on the session strand - inline if the caller was already there, after a hop otherwise.
  /// Private because being on the strand is the precondition, and the only way to satisfy it is to
  /// go through the public name.

  void handle_create_subscription_on_strand(uint32_t requestId, const CreateSubscriptionRequest& request);
  void handle_modify_subscription_on_strand(uint32_t requestId, const ModifySubscriptionRequest& request);
  void handle_delete_subscriptions_on_strand(uint32_t requestId, const DeleteSubscriptionsRequest& request);
  void handle_set_publishing_mode_on_strand(uint32_t requestId, const SetPublishingModeRequest& request);
  void handle_publish_on_strand(uint32_t requestId, const PublishRequest& request);
  void handle_republish_on_strand(uint32_t requestId, const RepublishRequest& request);
  void handle_create_monitored_items_on_strand(
    uint32_t requestId, const CreateMonitoredItemsRequest& request, std::vector<LocaleId> locales);
  void handle_delete_monitored_items_on_strand(
    uint32_t requestId, const DeleteMonitoredItemsRequest& request);
  void handle_modify_monitored_items_on_strand(
    uint32_t requestId, const ModifyMonitoredItemsRequest& request, std::vector<LocaleId> locales);
  void handle_set_monitoring_mode_on_strand(uint32_t requestId, const SetMonitoringModeRequest& request);
  void handle_set_triggering_on_strand(uint32_t requestId, const SetTriggeringRequest& request);
  void handle_transfer_subscriptions_on_strand(
    uint32_t requestId, const TransferSubscriptionsRequest& request);
  explicit SubscriptionsPipeline(Config config);

  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mSessionStrand;
  Logger mLogger;
  // A copy of the server's allocator, sharing its counter: the pipeline can outlive the server.
  SubscriptionIdAllocator mIdAllocator;
  std::shared_ptr<ServerSummaryCounters> mSummaryCounters;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
  std::chrono::milliseconds mAccessRecheckInterval{0};
  std::chrono::milliseconds mAccessControlTimeout{1000};
  std::function<void(Response)> mSendResponse;
  WeakAddressSpace mAddressSpace;
  SubscriptionRouter::Weak mSubscriptionRouter;
  OrphanedSubscriptionStore::Weak mOrphanedSubscriptionStore;
  std::weak_ptr<Session> mOwningSession;
  std::weak_ptr<SessionSecurityContext> mSecurityContext;
  std::function<DiagnosticSecurityContext()> mDiagnosticSecurityContext;
  std::function<std::optional<NodeId>()> mDiagnosticsObject;
  std::weak_ptr<EventBus> mEventBus;
  uint32_t mMaxResponseMessageSize{0};
  bool mAuditingEnabled{false};
  std::string mApplicationUri;
  std::function<std::chrono::steady_clock::time_point()> mMonotonicNow;

  // Subscription registry
  std::map<IntegerId, std::shared_ptr<Subscription>> mSubscriptions;

  // --- Reauthorize every subscription of this Session ---
  //
  // One at a time: a second walk arriving while one is running is refused BadServerTooBusy. What
  // stays here is only what something OTHER than the body needs - whether one is running and the
  // answer it owes. ~SubscriptionsPipeline answers an in-flight walk, which is what the posted hops
  // of the chain this replaces used to do for it: every hop carried the caller's completion through
  // a completion-owning post, so a pipeline that went away answered BadSessionClosed on its way out.
  // A body that holds its answer in a member has to say that itself.

  /// Whether a reauthorization walk is running. What the engaged bit of a `unique_ptr` used to say.
  bool mReauthorizeAllRunning{false};
  /// The one answer a walk owes. Moved out by whoever ends it first.
  std::function<void(VoidResult)> mReauthorizeAllCompletion;
  /// The walk's own coroutine. @see start_reauthorize_all
  ua::async::Task<> mReauthorizeAllTask;
  /// Which walk the task slot belongs to. @see start_reauthorize_all
  uint64_t mReauthorizeAllGeneration{0};

  /// Starts one walk and puts it in the task slot, if the slot is still this walk's to fill.
  void start_reauthorize_all(std::vector<std::shared_ptr<Subscription>> subscriptions);

  /// Contains whatever the walk throws, and makes sure it ends exactly once.
  ua::async::Task<> run_reauthorize_all(std::vector<std::shared_ptr<Subscription>> subscriptions);

  /// Reauthorizes each subscription in turn, stopping at the first that refuses.
  ///
  /// By reference, because the containing task owns the snapshot for the walk's whole life. The
  /// subscriptions are held STRONGLY for that time, which is what the chain this replaces did too:
  /// the walk is about them, and one closing underneath it would otherwise leave the walk asking a
  /// destroyed subscription.
  ua::async::Task<> walk_reauthorize_all(const std::vector<std::shared_ptr<Subscription>>& subscriptions);

  /// Ends the walk and hands back the one answer it owes, or null if something else ended it first.
  std::function<void(VoidResult)> take_reauthorize_all_completion();
  void finish_reauthorize_all(VoidResult result);

  /// Awaits one collaborator call of one of this pipeline's own bodies, on its session strand.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    // The answer is POSTED rather than dispatched. A collaborator can answer on the calling stack,
    // and `await_callback` resumes inline when the answer arrives on the strand it is already
    // running on - so a walk over N subscriptions would run from its first to its last inside ONE
    // strand turn, holding this session's strand against every Publish it owes for as long as the
    // client's subscription count. The chain this replaces posted after every step (R18).
    //
    // `post_borrowing`, not `post_owning`: this pipeline owns the walk's Task, so a pipeline that
    // has gone has taken the walk with it and there is nothing left to answer.
    return ua::async::await_callback<T>(mSessionStrand,
      mLogger,
      weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          mSessionStrand,
          mLogger,
          [completion = std::move(completion)](SubscriptionsPipeline&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  // Publish request queue (FIFO)
  struct PendingPublish
  {
    uint32_t requestId{};
    std::vector<ua::SubscriptionAcknowledgement> acknowledgements;
    std::chrono::steady_clock::time_point receivedAt;
    uint32_t timeoutHint{};
    ua::RequestHeader requestHeader;
  };

  std::deque<PendingPublish> mPendingPublishRequests;
  uint32_t mMaxPendingPublishRequests{10};

  // Retransmission queue (per-session, keyed by subscriptionId + sequenceNumber)
  std::deque<RetransmissionEntry> mRetransmissionQueue;
  uint32_t mMaxRetransmissionQueueSize{20};

  // Pending StatusChangeNotifications (e.g., BadTimeout on lifetime expiry).
  // Queued here until a Publish request is available to carry them.
  struct PendingStatusChange
  {
    IntegerId subscriptionId;
    NotificationMessage message;
  };

  std::deque<PendingStatusChange> mPendingStatusChanges;
  uint32_t mMaxPendingStatusChanges{100};  ///< Cap on the parked-status-change backlog; evict-oldest.

  // Round-robin tracking for equal-priority dispatch
  IntegerId mLastDispatchedSubscriptionId{0};

  // --- Parameter revision ---
  struct RevisedParams
  {
    Duration publishingInterval;
    uint32_t lifetimeCount;
    uint32_t maxKeepAliveCount;
    uint32_t maxNotificationsPerPublish;
  };

  RevisedParams revise_parameters(Duration requestedInterval, uint32_t requestedLifetimeCount,
    uint32_t requestedMaxKeepAliveCount, uint32_t requestedMaxNotificationsPerPublish) const;

  // --- Publish dispatch (callback-canonical self-tail-call drain) ---
  //
  // request_dispatch() is the entry point; if no dispatch is in flight it
  // marks mDispatchInFlight and posts dispatch_one_iteration to mSessionStrand.
  // dispatch_one_iteration runs the synchronous portion (drain pending status
  // changes + drain BadNoSubscription + try one publish round); if a publish
  // is issued it suspends until on_fulfill_complete fires, which then re-posts
  // dispatch_one_iteration as a self-tail-call (post, not dispatch - yields the
  // strand turn).
  void request_dispatch();
  void dispatch_one_iteration();
  void on_fulfill_complete(std::shared_ptr<Subscription> subscription, uint32_t pendingRequestId,
    RequestHeader pendingRequestHeader, std::vector<StatusCode> ackResults,
    std::vector<Subscription::PublishResult> results);
  void finish_dispatch_iteration();
  // Sticky "a dispatch was ever requested" bit. Pre-flip this was indicated by
  // std::optional<coroutine> mDispatchTask being engaged; the callback-canonical
  // shape has no Task field, but the runbook 3.2 Flow 4 reserves a bool for
  // post-flip parity with the dispatch_pin_test corpus (DSP-A).
  bool mDispatchScheduled{false};
  bool mDispatchInFlight{false};
  bool mDispatchNeeded{false};
  bool mClosed{false};

  std::shared_ptr<Subscription> select_subscription_for_publish();
  bool publish_request_timed_out(const PendingPublish& pending) const;
  void send_publish_fault(PendingPublish&& pending, StatusCode reason);
  std::optional<PendingPublish> dequeue_valid_publish_request();
  void process_acknowledgements(
    const std::vector<ua::SubscriptionAcknowledgement>& acks, std::vector<StatusCode>& results);
  void drain_publish_queue(StatusCode reason);
  void on_republish_reauthorized(uint32_t requestId, RequestHeader requestHeader,
    const std::weak_ptr<Subscription>& subscription, Result<NotificationMessage> result);
  void add_to_retransmission_queue(IntegerId subscriptionId, NotificationMessage&& message,
    std::shared_ptr<const Array<String>> diagnosticStringTable = {},
    std::vector<RetainedEventProjection> eventProjections = {},
    std::vector<RetainedDataProjection> dataProjections = {});
  /// Recount this subscription's entries in the retransmission queue and publish the value to the
  /// subscription's diagnostics (UnacknowledgedMessageCount). Call after any queue mutation.
  void refresh_unacknowledged(IntegerId subscriptionId);
  bool close_and_remove_subscription(IntegerId subscriptionId, std::function<void()> closeCompletion = {});
  void delete_subscription(IntegerId subscriptionId);
  NotificationMessage build_status_change_notification(Counter sequenceNumber, Status status);

  /// Parks a StatusChangeNotification for later delivery, evicting the oldest when the per-session
  /// backlog (`mMaxPendingStatusChanges`) is full. Bounds memory against a client that never publishes.
  void enqueue_pending_status_change(IntegerId subscriptionId, NotificationMessage message);

  // --- TransferSubscriptions ---
  //
  // Cross-strand: each subscription's detach hops to the SOURCE session's strand via
  // Session::detach_subscription_for_transfer and the answer hops back to `mSessionStrand`, where
  // the attach happens. One transfer at a time: a second arriving while one is running is refused
  // BadInvalidState (TR-K). `close()` answers an in-flight transfer with a BadSessionClosed fault.
  //
  // What the source session answers with is `Session::SubscriptionDetachResult`, and this header
  // cannot name it - `Session` is forward-declared, and including its header would close a cycle.
  // The chain this replaces paid for that with a `TransferDetachOutcome` struct that decomposed the
  // answer into raw fields purely so a HANDLER DECLARATION could carry it. A body has no handler
  // declaration: the answer is a local in the .cpp, where `Session` is complete, so the struct is
  // gone and with it the decomposition.

  /// What one TransferSubscriptions was given to work with. Held by value in the body that runs it.
  struct TransferInputs
  {
    std::vector<IntegerId> subIds;
    UserIdentity requestingUser;
    EndpointSecurityContext requestingSecurity;
    bool sendInitialValues{false};
    std::shared_ptr<TransferSubscriptionsResponse> response;
    uint32_t requestId{0};
    RequestHeader requestHeader;
  };

  /// Whether a transfer is running. What the engaged bit of a `unique_ptr` used to say.
  bool mTransferRunning{false};
  /// What a transfer failed from OUTSIDE its body needs to answer with. Held here because the body's
  /// own copy goes with its frame, and `close()` has to send a fault when the body can no longer be
  /// asked. @see fail_transfer
  uint32_t mTransferRequestId{0};
  RequestHeader mTransferRequestHeader;
  /// The transfer's own coroutine. @see start_transfer
  ua::async::Task<> mTransferTask;
  /// Which transfer the task slot belongs to. @see start_transfer
  uint64_t mTransferGeneration{0};

  /// Starts one transfer and puts it in the task slot, if the slot is still this transfer's to fill.
  void start_transfer(TransferInputs inputs);

  /// Contains whatever the transfer throws, and makes sure it ends exactly once.
  ua::async::Task<> run_transfer(TransferInputs inputs);

  /// Takes each named subscription from wherever it lives - a live session, or the orphan store -
  /// and attaches it here, in request order, recording one result per id.
  ///
  /// By reference, because the containing task owns the inputs for the transfer's whole life.
  ua::async::Task<> walk_transfer(TransferInputs& inputs);

  /// Transfer a subscription that has no live owner out of the OrphanedSubscriptionStore (orphaned
  /// by CloseSession deleteSubscriptions=false). Records Good or BadUserAccessDenied into the
  /// response at `cursor`; returns false (no result recorded) only when no such orphan exists.
  bool try_transfer_from_orphan_store(TransferInputs& inputs, size_t cursor, IntegerId subId);

  /// Ends the transfer and stops anything else from answering it.
  void release_transfer_slot();
  void finish_transfer(TransferInputs& inputs);
  void fail_transfer(StatusCode status);

  // Cross-strand observable gauges (updated on session strand, read from any thread).
  std::atomic<uint32_t> mAtomicSubscriptionCount{0};
  std::atomic<uint32_t> mAtomicTotalMonitoredItemCount{0};
};

}  // namespace ua::server

#endif  // !UA_SUBSCRIPTIONS_PIPELINE_H
