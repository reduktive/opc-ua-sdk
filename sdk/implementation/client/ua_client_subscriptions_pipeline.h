// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_SUBSCRIPTIONS_PIPELINE_H
#define UA_CLIENT_SUBSCRIPTIONS_PIPELINE_H

/// @file
/// @brief Client SubscriptionsPipeline strand component - publish pump + demux (section 8.4).
/// @ingroup client

#include "ua_ack_queue.h"
#include "ua_attribute_id.h"
#include "ua_connection_ops.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_aggregate_filter.h"
#include "ua_data_change_filter.h"
#include "ua_monitoring_mode.h"
#include "ua_node_id.h"
#include "ua_publish_pump.h"
#include "ua_read_value_id.h"
#include "ua_result.h"
#include "ua_sequence_tracker.h"
#include "ua_timer.h"
#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <variant>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua::client::detail
{

// The tier-0 send interface the pipeline drives its Publish pump through is now @ref SubscriptionOps (the
// renamed former `SubscriptionsPipelineHost`), one of the three upward-interface roles in
// ua_connection_ops.h.

/// Cross-strand snapshot of the pipeline (Rule 4).
struct PipelineInfo
{
  PumpState pumpState = PumpState::Idle;
  std::size_t subscriptionCount = 0;
  std::size_t outstandingPublishes = 0;
  std::size_t pumpTarget =
    0;  // the pump's sized outstanding-Publish target = max(2, ceil(items/100)) (CL-SUB-015)
  std::size_t monitoredItemCount = 0;
  std::size_t unknownHandleDrops = 0;  // notifications for an unregistered clientHandle (CL-MI-003)
};

/// The wire params a monitored item needs to be recreated on a fresh Subscription (CALLBACK-FREE, so it can
/// cross a strand boundary). The data-change callback is deliberately NOT included - it never leaves the
/// pipeline strand; only the pipeline re-registers it under the new Subscription id via a re-key.
///
/// The tuning fields are retained so a session-CHANGED recreate rebuilds the item with the SAME tuning the
/// caller requested at create, not the builder's defaults (they mirror the create path's
/// build_create_monitored_items_request inputs). This includes discardOldest (CL-MI-020) so a recreate does
/// not silently revert a caller's requested overflow policy, AND the DataChangeFilter / AggregateFilter
/// (CL-MI-011 / OPEN-MI-011) so a recreate re-sends the caller's deadband/trigger rather than dropping it.
struct MonitoredItemDescriptor
{
  ua::NodeId nodeId;  // the node the item monitors (build_create_monitored_items_request input)
  std::uint32_t clientHandle = 0;  // the Connection-unique client handle to preserve across the recreate
  ua::AttributeId attribute = ua::AttributeId::Value;  // retained tuning: monitored attribute
  std::optional<std::string> indexRange;  // retained tuning: NumericRange (empty when unset)
  double samplingIntervalMs = 0.0;  // retained tuning: requested sampling interval
  std::uint32_t queueSize = 1;  // retained tuning: server-side queue depth
  ua::MonitoringMode monitoringMode = ua::MonitoringMode::Reporting;  // retained tuning: monitoring mode
  bool discardOldest = true;  // retained tuning: queue-overflow policy (CL-MI-020)
  // retained tuning: the DataChangeFilter / AggregateFilter (CL-MI-011), so a session-CHANGED recreate
  // re-sends it rather than silently dropping the caller's deadband/trigger (OPEN-MI-011). A copyable value.
  std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter> filter;
};

/// The wire params one Subscription needs to be transferred-or-recreated on a fresh Session, plus the
/// recreate params for every monitored item it owns (CALLBACK-FREE snapshot, Q5). The connection-strand
/// recovery orchestration (piece 3) snapshots these, issues the wire ops, and then tells the pipeline to
/// re-key. Non-configurable create params (lifetime/keepalive/priority) are omitted: they are hardcoded
/// constants in build_create_subscription_request, so recreate reuses those same constants.
struct RecoveryDescriptor
{
  std::uint32_t subscriptionId = 0;
  double publishingInterval = 0.0;
  std::vector<MonitoredItemDescriptor> monitoredItems;
  std::uint32_t maxNotificationsPerPublish = 0;
};

/// Client-side SubscriptionsPipeline: the single per-Connection Publish pump plus per-Subscription
/// sequence tracking and acknowledgement batching (section 8.4).
///
/// Strand-serialized. `start_async` runs the pump (always-on pipelining via @ref PublishPump); each
/// Publish carries the batched acks (@ref AckQueue); each response is demuxed to its Subscription,
/// sequence-classified (@ref SequenceTracker), and acknowledged. Gap recovery (Republish) and the
/// monitored-item demux/dispatch layer on top in later slices.
class SubscriptionsPipeline : public std::enable_shared_from_this<SubscriptionsPipeline>,
                              private PublishPumpHost
{
public:
  /// Creates an idle pipeline over the three upward-interface role handles (section 8.2A.13).
  ///
  /// @param executor The io_context executor for the private strand.
  /// @param subOps   The Publish/Republish send interface (strong ref; a subobject of the one
  /// ConnectionOpsShim,
  ///                 which holds only a weak ConnectionImpl - so this strong ref forms no cycle).
  /// @param wireOps  The wire-op interface used by the polled-Read fallback (`read_async` +
  /// `max_nodes_per_read`,
  ///                 CL-SUB-019..022). Same shim.
  /// @param support  The support interface (`namespace_table` / `post_to_executor` / `state`). Same shim.
  /// @param logger   Logger for the guarded async boundaries.
  /// @param onSubscriptionEventLoss Signalled (on this pipeline's strand) with a Subscription id when a
  ///                 REACTIVE Republish drain terminates with an UNRECOVERED sequence gap (dropped messages,
  ///                 possibly a lost ConditionRefresh RefreshEnd) or hits its iteration cap (Finding 2 /
  ///                 CL-AC-003). Immutable after construction; the empty default is a no-op (used by the
  ///                 unit fixtures that only drive the pump). The Connection wires a `weak_from_this()`
  ///                 lambda that forwards to `ConnectionImpl::on_subscription_event_loss` to trigger the
  ///                 scoped A&C-tracker resync.
  /// @param onSemanticsChanged Signalled (on this pipeline's strand) with the monitored node's `NodeId` when
  /// a
  ///                 delivered DataChange carries the in-band `SemanticsChanged` StatusCode bit (Part 8
  ///                 section 5.2 / Part 3 section 6.5.4 / CL-DA-010). Immutable after construction; the empty
  ///                 default is a no-op (the unit fixtures that do not exercise semantic-change
  ///                 invalidation). The Connection wires a `weak_from_this()` lambda that forwards the node
  ///                 into `SemanticChangeCache::invalidate_async` so the DA typed-accessor Property cache
  ///                 re-resolves fresh Properties on the next read.
  /// @param onPublishGap Signalled (on this pipeline's strand) with the Subscription id, the first missed
  ///                 sequence number, and the sequence number of the live Publish that revealed the gap,
  ///                 when a reactive Republish drain STARTS (CL-SUB-002). Fired once per drain, so a
  ///                 later Publish arriving mid-drain does not re-report the same gap. Immutable after
  ///                 construction; the empty default is a no-op.
  /// @return A shared pipeline.
  [[nodiscard]] static std::shared_ptr<SubscriptionsPipeline> create(boost::asio::any_io_executor executor,
    std::shared_ptr<SubscriptionOps> subOps, std::shared_ptr<WireOps> wireOps,
    std::shared_ptr<SupportOps> support, ua::Logger logger,
    std::function<void(std::uint32_t)> onSubscriptionEventLoss = {},
    std::function<void(ua::NodeId)> onSemanticsChanged = {},
    std::function<void(std::uint32_t, ua::StatusCode)> onSubscriptionTerminated = {},
    std::function<void(std::uint32_t, ua::StatusCode, std::uint32_t)> onOversizedRecoveryExhausted = {},
    std::function<void(std::uint32_t, std::uint32_t, std::uint32_t)> onPublishGap = {});

  SubscriptionsPipeline(const SubscriptionsPipeline&) = delete;
  SubscriptionsPipeline& operator=(const SubscriptionsPipeline&) = delete;
  SubscriptionsPipeline(SubscriptionsPipeline&&) = delete;
  SubscriptionsPipeline& operator=(SubscriptionsPipeline&&) = delete;
  ~SubscriptionsPipeline() override = default;

  /// Registers a Subscription (from a `CreateSubscription` success), starting its sequence tracking.
  ///
  /// Retains @p publishingInterval so the Subscription can be recreated on a fresh Session after a
  /// reconnect that changed the Session (section 6.7 - the single-owner record, Q5).
  ///
  /// @param subscriptionId    The server-assigned Subscription id.
  /// @param publishingInterval The requested publishing interval (retained for recreate).
  void add_subscription_async(std::uint32_t subscriptionId, double publishingInterval,
    std::uint32_t maxNotificationsPerPublish = 0) noexcept;
  void add_subscription_async(std::uint32_t subscriptionId, double publishingInterval,
    std::uint32_t maxNotificationsPerPublish, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Engages a POLLED-READ fallback Subscription (CL-SUB-019): registers a client-side Subscription that has
  /// NO server-side counterpart (its `CreateSubscription` failed and the fallback policy permitted a swap)
  /// and arms a periodic driver that, every @p publishingInterval ms, bulk-`Read`s the Subscription's
  /// Reporting monitored items (paged at `MaxNodesPerRead`, CL-SUB-020) and delivers each value to its
  /// callback via the delivery strand. The ConnectionImpl decides engagement (it holds the policy + the
  /// create outcome) and assigns @p subscriptionId from a synthetic, server-id-disjoint range; monitored
  /// items are added under it via @ref add_monitored_item_async WITHOUT a wire `CreateMonitoredItems`.
  /// Removing the Subscription
  /// (@ref remove_subscription_async) or stopping the pipeline (@ref stop_async) cancels the driver.
  ///
  /// @param subscriptionId    The synthetic client-side Subscription id.
  /// @param publishingInterval The polling period (ms); a non-positive value floors to a single tick cadence.
  /// @param publishingEnabled  Whether the driver delivers polled values (a disabled Subscription polls
  /// nothing).
  void engage_fallback_subscription_async(
    std::uint32_t subscriptionId, double publishingInterval, bool publishingEnabled) noexcept;
  void engage_fallback_subscription_async(std::uint32_t subscriptionId, double publishingInterval,
    bool publishingEnabled, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Refreshes a registered Subscription's RETAINED publishing interval after a successful ModifySubscription
  /// (CL-SUB-013), so a session-CHANGED recreate rebuilds it at the modified interval rather than the stale
  /// create-time one. Update-only: a no-op if @p subscriptionId is not registered (never creates a record).
  void update_publishing_interval_async(std::uint32_t subscriptionId, double publishingInterval) noexcept;

  /// Deregisters a Subscription (on DeleteSubscription / termination), dropping its sequence tracking.
  ///
  /// @param subscriptionId The Subscription to remove.
  void remove_subscription_async(std::uint32_t subscriptionId) noexcept;

  /// Deregisters a monitored item (on DeleteMonitoredItems), so later notifications for its handle drop.
  ///
  /// @param clientHandle The item's client handle.
  void remove_monitored_item_async(std::uint32_t clientHandle) noexcept;

  /// Deregisters a monitored item and completes only after its state and published diagnostics are updated.
  ///
  /// @param clientHandle The item's client handle.
  /// @param callback Receives Good after removal, or Bad_Shutdown if the pipeline is gone before its strand
  ///                 turn.
  void remove_monitored_item_async(
    std::uint32_t clientHandle, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Starts the Publish pump (always-on pipelining).
  void start_async() noexcept;

  /// Stops the Publish pump (no further Publish requests are issued).
  void stop_async() noexcept;

  /// Resumes the Publish pump after a reconnect, on a freshly-rebound session.
  ///
  /// Clears the stale outstanding-Publish accounting (the in-flight Publishes died with the dropped
  /// channel) and refills on the new channel, so a subscription's notifications resume after a reconnect
  /// (CL-RECONN-004). A no-op when there are no registered subscriptions.
  void resume_async() noexcept;

  /// Feeds a received Publish response into the pipeline.
  ///
  /// Maintains the pump (pause/resume on @p tooManyPublishRequests), then demuxes to @p subscriptionId,
  /// classifies @p sequenceNumber, and queues an acknowledgement (per the retransmission latch).
  ///
  /// A keep-alive (an empty NotificationMessage, @p hasNotifications == false) is handled distinctly: per
  /// OPC UA 10000-4 section 5.13.5 a keep-alive carries the sequence number of the NEXT NotificationMessage
  /// to be sent (the server peeks, it does not allocate). So an in-order keep-alive must NOT advance the
  /// sequence tracker and must NOT be acknowledged - otherwise the next REAL message reuses that same number
  /// and would classify Duplicate and be dropped (silent data loss). Only a real message
  /// (@p hasNotifications == true) advances/acks. A keep-alive AHEAD of the expected number is left to the
  /// gap path (it still, correctly, reveals a gap and drives Republish).
  ///
  /// Reports the message's @ref SequenceClass to @p onClassified (on this pipeline's strand) once the demux
  /// has classified it, so the delivery site can gate dispatch on the classification and honour the
  /// "Duplicate / Invalid -> no dispatch" contract (CL-SUB-002): the caller delivers only for @ref
  /// SequenceClass::InOrder or @ref SequenceClass::Gap and drops otherwise. When @p subscriptionId matches no
  /// registered Subscription the classification defaults to @ref SequenceClass::Invalid, so an
  /// unknown/spoofed subscriptionId reports Invalid and its payload is dropped by the caller.
  ///
  /// @param subscriptionId          The response's Subscription id.
  /// @param sequenceNumber          The notification message's sequence number.
  /// @param hasNotifications        Whether the NotificationMessage carried any notifications (false == a
  ///                                keep-alive, i.e. an empty NotificationMessage).
  /// @param hasAvailableSequenceNumbers Whether the response carried a non-empty `availableSequenceNumbers`.
  /// @param tooManyPublishRequests  Whether the service result was `Bad_TooManyPublishRequests`.
  /// @param onClassified            Invoked (on this pipeline's strand) with the message's @ref SequenceClass
  ///                                after the demux; the default empty completion reports nothing (used by
  ///                                callers that only drive the tracker/ack/pump and need no classification).
  ///                                The delivery site gates dispatch on it via @ref should_deliver.
  /// @param terminalStatus          The status of a StatusChangeNotification the message carried that ends
  ///                                the Subscription on this Session: Bad_Timeout or
  ///                                Good_SubscriptionTransferred (OPC 10000-4 7.25.4). A deliverable message
  ///                                with one removes the Subscription and reports the code, unchanged, to the
  ///                                Subscription-terminated callback.
  void on_publish_response_async(std::uint32_t subscriptionId, std::uint32_t sequenceNumber,
    bool hasNotifications, bool hasAvailableSequenceNumbers, bool tooManyPublishRequests,
    std::function<void(SequenceClass)> onClassified = {},
    std::optional<ua::StatusCode> terminalStatus = std::nullopt) noexcept;

  /// Feeds a whole-service Publish failure into the pump. `Bad_ResponseTooLarge` enters CL-SUB-005
  /// oversized recovery for every live server-backed Subscription because a failed Publish carries no
  /// decodable Subscription id. Other failures only release/refill the Publish pump.
  void on_publish_failure_async(ua::StatusCode status) noexcept;

  /// Signals that a Publish returned `Bad_NoSubscription`  -  the last Subscription on the Session was
  /// deleted and the server de-queued the outstanding Publishes (CL-SUB-009, Part 4 section 5.13.8.1). Enters
  /// a drain-and- HOLD: stops the pump (no retry; still-in-flight responses drain without re-pumping) and
  /// holds future Publishes until a new Subscription is added (@ref add_subscription_async resumes the pump).
  /// NOT a fault
  ///  -  the caller must not reconnect or surface an error. Idempotent (repeated Bad_NoSubscription responses
  /// just re-confirm the hold).
  void on_publish_no_subscription_async() noexcept;

  /// Registers a monitored item's data-change callback under its unique client handle (CL-MI-003).
  ///
  /// The item is associated with @p subscriptionId so deleting that Subscription
  /// (@ref remove_subscription_async) cascades to remove its items (a subscription delete implicitly
  /// deletes all its monitored items server-side, OPC UA 10000-4 section 5.13.8).
  ///
  /// Retains @p nodeId AND the five NON-FILTER tuning params so the item can be recreated on a fresh
  /// Subscription after a reconnect that changed the Session (section 6.7 - the single-owner record, Q5). The
  /// recovery record carries the caller's tuning (attribute / indexRange / samplingIntervalMs / queueSize /
  /// monitoringMode) so recreate rebuilds the item with the SAME parameters the caller requested at create,
  /// not the builder's defaults; discardOldest stays hardcoded true and the DataChangeFilter is out of scope
  /// (a separate, still-batched piece). The id-only / event callers pass the defaults.
  ///
  /// @param subscriptionId    The owning Subscription id (for cascade removal on subscription delete).
  /// @param clientHandle      The Connection-unique client handle allocated for the item.
  /// @param nodeId            The node the item monitors (retained for recreate).
  /// @param callback          Invoked with each notification for the item, serialized on the pipeline's
  ///                          dedicated delivery strand (see @ref deliver_notification_async):
  ///                          per-clientHandle in arrival order, never re-entered concurrently (CL-MI-026).
  /// @param attribute         The monitored attribute (retained for recreate).
  /// @param indexRange        The NumericRange (retained for recreate; empty when unset).
  /// @param samplingIntervalMs The requested sampling interval (retained for recreate).
  /// @param queueSize         The server-side queue depth (retained for recreate).
  /// @param monitoringMode    The monitoring mode (retained for recreate).
  void add_monitored_item_async(std::uint32_t subscriptionId, std::uint32_t clientHandle, ua::NodeId nodeId,
    std::function<void(ua::DataValue)> callback, ua::AttributeId attribute = ua::AttributeId::Value,
    std::optional<std::string> indexRange = std::nullopt, double samplingIntervalMs = 0.0,
    std::uint32_t queueSize = 1, ua::MonitoringMode monitoringMode = ua::MonitoringMode::Reporting,
    bool discardOldest = true,
    std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter> filter = {}) noexcept;

  /// Delivers one demuxed notification to its monitored item's callback (CL-MI-016 / CL-MI-026).
  ///
  /// Routes @p value to the item registered under @p clientHandle. The lookup runs on the processing strand
  /// (in arrival order); the user callback is then hopped onto the dedicated DELIVERY strand (@ref
  /// mDeliveryStrand)  -  NOT the bare executor and NOT the processing strand  -  so per-clientHandle
  /// delivery is in arrival order and never re-entered concurrently, for ANY executor thread count
  /// (CL-MI-026). An unknown handle is dropped and counted as an advisory (CL-MI-003).
  ///
  /// @param clientHandle The notification's client handle.
  /// @param value        The notification's DataValue.
  void deliver_notification_async(std::uint32_t clientHandle, ua::DataValue value) noexcept;

  /// Feeds a received Republish response into a Subscription's gap-recovery drain (section 8.4.5).
  ///
  /// A retained message (@p status Good) is acknowledged and advances the drain to the next sequence
  /// number. The drain then ends on its terminator @p status, each handled distinctly (CL-RECONN-004):
  ///   - `Bad_MessageNotAvailable`  -  the retransmission queue is drained (the normal, clean terminator);
  ///   - `Bad_SubscriptionIdInvalid`  -  the Subscription is gone server-side; the drain stops and the fault
  ///     is logged (recreate is a separate concern);
  ///   - any other bad status  -  a transient/transport failure; the drain stops and the fault is logged
  ///     (never silently discarded, per the design specification).
  /// A per-Subscription iteration budget bounds a non-conforming server that never returns the terminator.
  ///
  /// @param subscriptionId The Subscription being drained.
  /// @param sequenceNumber The Republish request's target sequence number.
  /// @param status         The Republish outcome (the effective service status).
  void on_republish_response_async(
    std::uint32_t subscriptionId, std::uint32_t sequenceNumber, ua::StatusCode status) noexcept;

  /// Drives the reconnect Republish-on-reconnect drain across every registered Subscription (section 6.7 /
  /// CL-RECONN-004): the recover step of the reconnect FSM calls this after the Session is re-activated
  /// but before the Publish pump resumes, so retained notifications queued during the outage are recovered
  /// in-order before live publishing continues.
  ///
  /// Runs a per-Subscription barrier: for each Subscription a FRESH, current-epoch gap drain is (re)started
  /// from its next expected sequence number and @p done fires only once every drain reaches a terminal.
  /// Any drain already in flight for a Subscription (a pre-drop reactive one) is RESET and re-issued, NOT
  /// adopted: its Republish was issued under the superseded channel, so the connection-strand epoch guard
  /// drops that response - an adopted drain's terminal would never arrive and the barrier would stall
  /// forever, failing the reconnect against a healthy server. A prior in-flight recovery is cancelled first
  /// (its stored callback is discarded WITHOUT firing). @p done carries `Good` iff every drain ended clean -
  /// the normative terminators (`Bad_MessageNotAvailable` / `Bad_SubscriptionIdInvalid`) OR a Good-status
  /// terminal (an iteration-cap-hit / off-sequence reply, proceed rather than DoS the reconnect into
  /// Failed); a genuinely bad status makes @p done carry it so the FSM recover step backs off and retries
  /// (no-loss, section 6.7). With no registered Subscription @p done fires `Good` immediately. A
  /// `Bad_SubscriptionIdInvalid` drain also REMOVES its (gone) Subscription from the pipeline (recreate is
  /// the deferred session-CHANGED branch).
  ///
  /// @param done Fired once (on this pipeline's strand) when the whole recovery completes.
  void recover_subscriptions_async(std::function<void(ua::VoidResult)> done) noexcept;

  /// Snapshots the CALLBACK-FREE recreate descriptors for every registered Subscription (session-CHANGED
  /// recovery, section 6.7 - Q5 single-owner query). Posts to the pipeline strand, builds one @ref
  /// RecoveryDescriptor per Subscription (its retained publishing interval/current notification limit plus
  /// every owned monitored item's node + client handle), and fires @p callback with the vector on the strand.
  /// The data-change callbacks
  /// are NOT included
  /// - they never cross the strand; the pipeline re-registers them under the new id via @ref
  /// rekey_subscription_async. The connection-strand orchestration re-posts the result to its own strand.
  ///
  /// @param callback Receives the descriptor snapshot (on this pipeline's strand).
  void recovery_descriptors_async(std::function<void(std::vector<RecoveryDescriptor>)> callback) noexcept;

  /// Atomically applies a batch of RECREATE re-keys (session-CHANGED recovery commit, section 6.7 / #24).
  ///
  /// Every entry is a RECREATED Subscription: the connection-strand recovery recreated it on the fresh
  /// Session (new server id) and now re-keys the pipeline `{oldId -> newId}`. Transferred Subscriptions are
  /// deliberately NOT in this batch (they keep their id + sequence counter and are left untouched), so EVERY
  /// entry here resets the tracker to a fresh sequence space (next_expected = 1) - a recreated Subscription
  /// starts its numbering at 1, so keeping the old high water-mark would classify the first Publish (seq 1)
  /// as a Duplicate and silently stall (spec Q3). This holds EVEN when @p newId == @p oldId: a server that
  /// reassigned the freed id to the recreated Subscription still restarted its sequence space, so the tracker
  /// must reset regardless of whether the id changed.
  ///
  /// Applied ATOMICALLY against the pre-image on the pipeline strand: every old Subscription's state is
  /// extracted (and the old id erased) BEFORE any new id is inserted, and each monitored item is repointed
  /// exactly once by its ORIGINAL owning id. This is collision-safe - a recreated Subscription's @p newId may
  /// legitimately equal another still-pending Subscription's @p oldId (all old ids were freed when the old
  /// Session died), and a naive one-at-a-time move would clobber the pristine entry. An entry whose @p oldId
  /// is no longer registered is skipped.
  ///
  /// @param rekeys The `{oldId, newId}` recreate re-keys to apply as one atomic remap.
  void apply_recreate_rekeys_async(std::vector<std::pair<std::uint32_t, std::uint32_t>> rekeys) noexcept;

  /// Polled-Read fallback foundation (section 8.4, CL-SUB-019..022): reads @p reads in bulk, paged at
  /// @ref WireOps::max_nodes_per_read, and delivers the per-node @ref ua::DataValue results stitched back
  /// in request order.
  ///
  /// Runs on the pipeline strand. The bulk read is split into pages of at most `max_nodes_per_read()`
  /// nodes (CL-SUB-020; a zero limit is floored to 1), and each page is issued in order via
  /// @ref WireOps::read_async on the strand - the next page starts only when the previous one completes,
  /// so the stitched result preserves request order. Any page failure short-circuits and delivers that
  /// page's bad Result (its @ref ua::ErrorDetail is never discarded). An empty @p reads delivers an empty
  /// vector without issuing a read. @p callback fires on the executor (via
  /// @ref SupportOps::post_to_executor), never on the strand.
  ///
  /// @param reads    The nodes/attributes to read (may be empty).
  /// @param callback Receives the stitched DataValues on success, or the first page's bad Result.
  void poll_read_async(std::vector<ua::ReadValueId> reads,
    std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) noexcept;

  /// Returns the cross-strand snapshot (atomic-load; any thread).
  ///
  /// @return The latest published @ref PipelineInfo.
  [[nodiscard]] std::shared_ptr<const PipelineInfo> info() const noexcept;

private:
  friend class SubscriptionsPipelineTestAccess;

  SubscriptionsPipeline(boost::asio::any_io_executor executor, std::shared_ptr<SubscriptionOps> subOps,
    std::shared_ptr<WireOps> wireOps, std::shared_ptr<SupportOps> support, ua::Logger logger,
    std::function<void(std::uint32_t)> onSubscriptionEventLoss,
    std::function<void(ua::NodeId)> onSemanticsChanged,
    std::function<void(std::uint32_t, ua::StatusCode)> onSubscriptionTerminated,
    std::function<void(std::uint32_t, ua::StatusCode, std::uint32_t)> onOversizedRecoveryExhausted,
    std::function<void(std::uint32_t, std::uint32_t, std::uint32_t)> onPublishGap);

  void issue_publish() override;  // PublishPumpHost - runs on the strand (from the pump)
  void publish_info();

  /// Re-sizes the single per-Connection Publish pump to the current total monitored-item count
  /// (`target = max(2, ceil(items / 100))`, CL-SUB-015) and re-publishes the diagnostics snapshot. Call on
  /// the strand after ANY `mMonitoredItems` mutation. Replaces the bare `publish_info()` at those sites; a
  /// Running pump tops up to the new (grown) target in-line, and a shrunk target simply drains naturally.
  void resize_pump();

  /// Transient per-call barrier for @ref poll_read_async (strand-only). Held by `shared_ptr` so it lives
  /// across the sequential per-page @ref WireOps::read_async completions until the last page terminates.
  struct PollReadState
  {
    std::vector<ua::ReadValueId> reads;  ///< The full node list being paged.
    std::size_t nextIndex = 0;  ///< Offset of the next unread page in @ref reads.
    std::size_t requested = 0;  ///< ReadValueId count of the in-flight page (for the per-page count check).
    std::uint32_t pageSize = 1;  ///< Nodes per page (== max_nodes_per_read, floored to 1).
    std::vector<ua::DataValue> results;  ///< Stitched per-node results, in request order.
    std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback;  ///< Fired once, on the executor.
  };

  /// Issues the next polled-Read page (strand-only). When @p state is drained, delivers the stitched
  /// results on the executor; otherwise reads the next page via @ref WireOps::read_async and, on its
  /// completion, re-hops to the strand to continue (or short-circuits a page failure). Fires
  /// @ref PollReadState::callback exactly once.
  void issue_next_poll_page(std::shared_ptr<PollReadState> state);

  /// Arms (or re-arms) the periodic fallback-poll timer for the fallback Subscription @p subscriptionId
  /// (strand-only). A weak-self notifier runs on `mStrand`; each non-aborted fire calls @ref
  /// poll_fallback_tick. A no-op if the Subscription is absent or not a fallback. Stored in its
  /// `FallbackSubscription.timer` (a prior armed timer is cancelled by the move-assignment).
  void arm_fallback_timer(std::uint32_t subscriptionId);

  /// One polling cycle for the fallback Subscription @p subscriptionId (strand-only): gathers its Reporting
  /// monitored items, bulk-`Read`s them via @ref poll_read_async (paged at MaxNodesPerRead), and delivers
  /// each recovered DataValue to its item's callback via @ref deliver_notification_async. A no-op if the
  /// Subscription is gone / not a fallback / has no Reporting items. A poll failure is dropped (advisory)  -
  /// the next tick retries; never delivers a partial/misaligned page.
  void poll_fallback_tick(std::uint32_t subscriptionId);

  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  // Dedicated delivery strand for hopping USER notification callbacks off the processing strand (mStrand).
  // Serializing delivery here  -  rather than bare-posting to mExecutor  -  guarantees per-clientHandle
  // in-order, non-concurrent delivery (CL-MI-026) even when mExecutor is a multi-threaded pool, WITHOUT
  // running user code under the processing strand (a slow user callback stalls only delivery, never the
  // publish pump).
  boost::asio::strand<boost::asio::any_io_executor> mDeliveryStrand;
  std::shared_ptr<SubscriptionOps> mSubOps;  // Publish/Republish send interface (const after ctor)
  std::shared_ptr<WireOps> mWireOps;  // polled-Read fallback interface (const after ctor)
  std::shared_ptr<SupportOps> mSupport;  // namespace / executor / state interface (const after ctor)
  ua::Logger mLogger;
  // Subscription-event-loss signal (Finding 2 / CL-AC-003): fired on THIS strand when a reactive Republish
  // drain terminates with an unrecovered gap or hits its cap. Immutable after ctor (like mSubOps).
  std::function<void(std::uint32_t)> mOnSubscriptionEventLoss;
  // CL-DA-010: fired on the strand with a monitored node's NodeId when a delivered DataChange carries the
  // in-band SemanticsChanged StatusCode bit. Immutable after ctor; empty = no-op.
  std::function<void(ua::NodeId)> mOnSemanticsChanged;
  // CL-SUB-008: fired after atomic Bad_Timeout or Good_SubscriptionTransferred cleanup, still on the
  // pipeline strand.
  std::function<void(std::uint32_t, ua::StatusCode)> mOnSubscriptionTerminated;
  // CL-SUB-005: observer handoff after the automatic maxNotificationsPerPublish recovery cannot make
  // further progress. Fires on this strand; ConnectionImpl forwards through ObserverSink.
  std::function<void(std::uint32_t, ua::StatusCode, std::uint32_t)> mOnOversizedRecoveryExhausted;
  // CL-SUB-002: fired on this strand when a live Publish reveals a sequence gap and a Republish drain
  // starts, with (subscriptionId, first missed sequence, sequence that revealed it). Once per drain, not
  // per late Publish. ConnectionImpl forwards through ObserverSink.
  std::function<void(std::uint32_t, std::uint32_t, std::uint32_t)> mOnPublishGap;

  /// Per-Subscription pipeline state (strand only).
  struct SubscriptionState
  {
    SequenceTracker tracker;
    double publishingInterval = 0.0;  // retained create param for session-CHANGED recreate (section 6.7, Q5)
    std::uint32_t maxNotificationsPerPublish = 0;  // retained current request value; 0 == unbounded
    std::size_t oversizedRecoveryAttempts = 0;
    std::uint64_t oversizedRecoveryGeneration = 0;
    bool oversizedRecoveryInFlight = false;
    bool oversizedRecoveryHandedOff = false;
    bool republishing = false;  // draining a sequence gap via Republish (CL-SUB-002 / CL-RECONN-004)
    std::size_t republishIterations = 0;  // iteration budget guard for the current drain (reset on start)
    bool inRecovery =
      false;  // this drain participates in a reconnect recovery barrier (recover_subscriptions_async)
    // High-water sequence target of the live Publish that revealed the current gap (Finding 2 / CL-AC-003).
    // 0 = unset (SequenceTracker::classify(0) == Invalid, so it never reads as a gap). Bumped by the reactive
    // Publish Gap branch; a terminal whose classify(gapTarget) is still Gap means the drain left an
    // unrecovered hole (dropped messages) and fires the event-loss signal. Reset to 0 by the RECOVERY drain
    // (recover_subscriptions_async / clear_recovery) so a blind recovery walk never false-fires.
    std::uint32_t gapTarget = 0;
  };

  /// A polled-Read fallback Subscription (CL-SUB-019): a CLIENT-SIDE Subscription with NO server counterpart
  /// (its CreateSubscription failed and the fallback policy engaged a poll instead). Kept in a SEPARATE map
  /// (@ref mFallbackSubs), NOT the server-backed @ref mSubscriptions keyspace, so a synthetic id can never
  /// collide with a server-assigned Subscription id AND a fallback Subscription is naturally excluded from
  /// the Publish pump, sequence tracking, and reconnect recovery (which all walk @ref mSubscriptions only).
  struct FallbackSubscription
  {
    double interval = 0.0;  // polling period (ms), retained so a resume can re-arm the driver
    bool deliver = true;  // create-time publishingEnabled  -  a disabled Subscription polls nothing
    bool pollInFlight = false;  // single-flight guard: skip a tick while a prior poll's Read is outstanding
    ua::Timer
      timer;  // the periodic driver; erasing this entry cancels it (a queued fire is operation_aborted)
  };

  /// A registered monitored item: its owning Subscription (for cascade removal), its retained recreate node
  /// AND the five NON-FILTER tuning params (session-CHANGED recovery, section 6.7, Q5), and its data-change
  /// callback.
  struct MonitoredItemEntry
  {
    std::uint32_t subscriptionId = 0;
    ua::NodeId nodeId;  // retained create param for session-CHANGED recreate
    ua::AttributeId attribute = ua::AttributeId::Value;  // retained tuning
    std::optional<std::string> indexRange;  // retained tuning (empty when unset)
    double samplingIntervalMs = 0.0;  // retained tuning
    std::uint32_t queueSize = 1;  // retained tuning
    ua::MonitoringMode monitoringMode = ua::MonitoringMode::Reporting;  // retained tuning
    bool discardOldest = true;  // retained tuning: queue-overflow policy (CL-MI-020)
    std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter> filter;  // retained (CL-MI-011)
    std::function<void(ua::DataValue)> callback;
    // CL-SUB-021: the last value DISPATCHED to the callback by the polled-Read fallback driver, so the driver
    // can evaluate the item's DataChangeFilter (Trigger + AbsoluteDeadband) client-side and dispatch only
    // changes. Unset until the first dispatch; only used by fallback items (a server-backed item is filtered
    // server-side).
    std::optional<ua::DataValue> lastPolledValue;
  };

  /// Services a recovery barrier when a drain reaches a terminal (strand only). Call AFTER clearing
  /// `state.republishing`. A no-op for a purely reactive drain (`state.inRecovery` false). Otherwise folds
  /// @p terminalStatus into the worst recovery outcome (F6) and, when the last drain terminates, fires the
  /// stored recovery callback exactly once.
  void finish_drain_terminal(SubscriptionState& state, ua::StatusCode terminalStatus);

  /// Discards any in-flight recovery WITHOUT firing its callback and resets every Subscription's
  /// `inRecovery` flag (strand only). Used to cancel a superseded/abandoned recovery (F2) and to purge
  /// recovery state on stop/close.
  void clear_recovery();

  /// Starts or continues CL-SUB-005 automatic halving for one Subscription (strand-only).
  void begin_oversized_recovery(
    std::uint32_t subscriptionId, SubscriptionState& state, ua::StatusCode failure);

  // Strand-only state.
  PublishPump mPump;
  AckQueue mAckQueue;
  std::unordered_map<std::uint32_t, SubscriptionState> mSubscriptions;
  // Polled-Read fallback Subscriptions (CL-SUB-019), keyed by synthetic id  -  SEPARATE from mSubscriptions
  // so a fallback never shares the server-id keyspace and is never swept into the Publish pump or reconnect
  // recovery.
  std::unordered_map<std::uint32_t, FallbackSubscription> mFallbackSubs;
  std::unordered_map<std::uint32_t, MonitoredItemEntry> mMonitoredItems;  // by clientHandle
  // CL-SUB-009: true while the pump is HELD after a Bad_NoSubscription Publish response (the last
  // Subscription was deleted). Cleared + the pump resumed when a new Subscription is added, and on a
  // reconnect resume / stop (which supersede the hold). Strand-confined.
  bool mPublishHeldNoSubscription = false;
  std::size_t mUnknownHandleDrops = 0;

  // Reconnect recovery barrier (strand only): the recover step (re)starts a gap drain per Subscription and
  // fires mRecoveryDone once every drain terminates. mRecoveryWorstStatus threads the worst terminal so
  // done reports Bad (=> FSM backoff + retry) unless every drain ended cleanly (F6).
  std::size_t mRecoveryPending = 0;
  std::function<void(ua::VoidResult)> mRecoveryDone;
  bool mRecoveryActive = false;
  ua::StatusCode mRecoveryWorstStatus{ua::Status::Good};

  std::atomic<std::shared_ptr<const PipelineInfo>> mInfoSnapshot;
};

}  // namespace ua::client::detail

#endif  // UA_CLIENT_SUBSCRIPTIONS_PIPELINE_H
