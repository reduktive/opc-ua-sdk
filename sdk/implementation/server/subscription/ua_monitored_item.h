// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_MONITORED_ITEM_H
#define UA_MONITORED_ITEM_H

#include "ua_access_control.h"
#include "ua_instance_tracker.h"
#include "ua_address_space.h"
#include "ua_compiled_event_filter.h"
#include "ua_data_change_trigger.h"
#include "ua_data_value.h"
#include "ua_deadband_type.h"
#include "ua_duration.h"
#include "ua_event_field_list.h"
#include "ua_integer_id.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_namespace_monitoring.h"
#include "ua_node_accessor.h"
#include "ua_read_value_id.h"
#include "ua_retained_notification_authorization.h"
#include "ua_timestamps_to_return.h"

#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <vector>

namespace ua::server
{

class SessionSecurityContext;

/// Complete authorization input retained between MonitoredItem refreshes.
///
/// The AccessIdentityKey binds the verdict to every identity fact, including endpoint and selected
/// token-policy context. The verdict itself binds the permission mask to its exact node and operation.
/// Both are values so sampling never owns an identity lifetime and never waits for permission I/O.
struct MonitoredAccessSnapshot
{
  AccessIdentityKey identity;
  AccessControl::Verdict verdict;
};

/// Per-monitored-item data and queue/filter logic.
/// Lives inside a Subscription - all access is on the subscription strand.
/// No async, no strands, no I/O - pure data + logic.
struct MonitoredItem
{
  // Identity
  IntegerId id{0};
  IntegerId clientHandle{0};
  ReadValueId itemToMonitor;
  MonitoringMode monitoringMode{MonitoringMode::Reporting};
  TimestampsToReturn timestampsToReturn{TimestampsToReturn::Both};

  // Revised parameters
  Duration samplingInterval{};
  uint32_t queueSize{1};
  bool discardOldest{true};

  // Filter (data change)
  DataChangeTrigger trigger{DataChangeTrigger::StatusValue};
  DeadbandType deadbandType{DeadbandType::None};
  double deadbandValue{0.0};

  // EURange for percent deadband: read at CreateMonitoredItems, or at a ModifyMonitoredItems that sets
  // PercentDeadband, and again whenever the item is marked SemanticsChanged (Part 8 6.2).
  bool hasEuRange{false};
  double euRangeLow{0.0};
  double euRangeHigh{0.0};
  /// Advanced by each SemanticsChanged mark: a read of the EURange applies only if no mark came after it.
  uint64_t euRangeGeneration{0};

  // Whether this item monitors a non-Value attribute.
  // Non-Value attributes bypass the DataChangeFilter (SVR-MI-GEN-071).
  bool isNonValueAttribute{false};

  // Notification queue
  std::deque<DataValue> queue;

  // Last value pushed to queue (for deadband comparison per spec)
  std::optional<DataValue> lastQueuedValue;

  // Last value sent in a Publish response (for TransferSubscriptions sendInitialValues)
  std::optional<DataValue> lastSentValue;

  /// The user-independent value retained with @ref lastSentValue, so that a notification made from
  /// lastSentValue (@ref enqueue_semantic_from_cache) retains the input it was made from and a Republish
  /// of it projects that input again (COMP-SVR-NAMESPACE-CALLS-15 rule 4).
  std::optional<DataValue> lastSentUserIndependentValue;

  // Triggered item state
  bool triggeredReportPending{false};

  // SemanticsChanged (CTT Data Access Analog 008). When a semantic property of the monitored value
  // changes (e.g. an AnalogItem's EURange), the namespace arms this flag via the subscription. While
  // armed, every value this item enqueues carries the SemanticsChanged StatusCode bit and bypasses
  // the DataChangeFilter (a semantics change must reach the client regardless of deadband). The flag
  // clears only when a bit-carrying value is actually drained into a Publish (clear-on-publish), so
  // it survives queue overwrite/overflow until then.
  bool pendingSemanticChange{false};

  /// StructureChanged owed to the next value this item enqueues (OPC 10000-4 7.39.1 Table 180): set by
  /// @ref mark_structure_changed when no queued value can carry the bit, cleared by the value that takes it.
  /// Unlike @ref pendingSemanticChange, one notification carries the bit, and an overflow that discards it
  /// moves it to the next notification in the queue (@ref enqueue).
  bool pendingStructureChange{false};

  // Namespace monitoring handle (returned by Namespace::create_monitoring).
  // Used to delete monitoring when the item is removed.
  MonitoringHandle namespaceHandle{0};
  uint16_t namespaceIndex{0};

  // Diagnostic info (SVC-CreateMI-008, SVC-Publish-012)
  uint32_t diagnosticInfoMask{0};

  // --- Event-specific fields ---

  /// True if this item monitors EventNotifier (event monitoring, not data-change).
  bool isEventItem{false};

  /// Identity-bound complete authorization snapshot. Absence and a denied verdict both fail closed;
  /// a permitted snapshot is usable only while its key still matches the Session's current identity.
  std::optional<MonitoredAccessSnapshot> accessSnapshot;

  /// Latest value as it arrived, before any identity-derived projection. For an item on an Attribute whose
  /// value the server produces (`AccessControl::produces_value`), the whole value of the Attribute the
  /// namespace holds, which the item narrows after projecting it; for any other item, the value as its
  /// producer narrowed it to the IndexRange. Reauthorization, ResendData and re-enable paths reproject this
  /// value with the replacement snapshot; they never try to recover capabilities from a value already
  /// filtered for an earlier identity.
  std::optional<DataValue> lastUserIndependentValue;

  /// Server-only inputs aligned one-for-one with `queue`, held as `lastUserIndependentValue` is. The
  /// public/wire queue remains unchanged; this parallel queue moves into the same retransmission entry when
  /// a notification is drained.
  std::deque<std::optional<DataValue>> queuedUserIndependentValues;

  /// Samples taken while the Subscription had no Session - closed with deleteSubscriptions false and
  /// not yet transferred (Part 4 5.13.7). Held before any identity-derived projection, because there is
  /// no identity to project for, and bounded like `queue` by queueSize and discardOldest. The next owner's
  /// context replays them through the same authorization as a live sample (Subscription::
  /// replay_orphaned_samples); whatever that identity may not see is dropped there.
  std::deque<DataValue> orphanedSamples;

  /// Compiled event filter (null for data-change items).
  std::shared_ptr<CompiledEventFilter> eventFilter;

  /// Resolved subject and live Session/address-space view used to project every initial value, sample,
  /// Event field and replay through the same canonical access-control helper as Read.
  std::optional<NodeAccessor> accessControlNode;
  std::weak_ptr<SessionSecurityContext> accessSecurityContext;
  WeakAddressSpace accessAddressSpace;

  /// Entry in the event notification queue, tagging whether the event was a condition event.
  struct QueuedEvent
  {
    EventFieldList fields;
    bool conditionEvent{false};
    RetainedEventProjection projection;
    bool overflowEvent{false};  ///< the EventQueueOverflowEvent, which takes no slot of the queue
  };

  /// Event notification queue (separate from data-change queue).
  std::deque<QueuedEvent> eventQueue;

  /// Whether an overflow event has been inserted in the current overflow episode.
  /// Resets when the queue is fully drained.
  bool overflowEventInserted{false};

  /// Whether the EventQueueOverflowEvent is in @ref eventQueue now. Part 4 5.12.1.5 puts it there "in
  /// addition to the size of the Queue", so the queue is full at queueSize events besides it.
  bool overflowEventQueued{false};

  /// Cumulative count of queue overflows on this item (a notification discarded because the
  /// queue was full). `dataQueueOverflowCount` feeds the subscription's MonitoringQueueOverflowCount
  /// and `eventQueueOverflowCount` feeds its EventQueueOverflowCount (Part 5 SubscriptionDiagnostics).
  uint32_t dataQueueOverflowCount{0};
  uint32_t eventQueueOverflowCount{0};

  /// Accounts one event lost BEFORE the delivered queue (the subscription's pre-authorization hand-off
  /// FIFO, SVR-MI-GEN-020..023): the diagnostic counter now, and the EventQueueOverflowEvent once, on
  /// the next delivery, through enqueue_event so the queue's slot rules and the subscription's
  /// reportable bookkeeping are the delivered path's (Part 4 5.12.1.5).
  void note_event_queue_overflow();
  /// Inserts the EventQueueOverflowEvent if it is not already queued (SVR-EVT-MON-006..008).
  void insert_overflow_event_once();
  /// A pre-authorization loss whose overflow event has not been queued yet.
  bool overflowEventPending{false};
  /// discardOldest == false only: the FIFO ordinal of the newest event kept at the loss. The overflow
  /// event goes AFTER it (SVR-EVT-MON-008 puts the marker where the missing events would have been),
  /// so it is queued once that entry has left the hand-off FIFO.
  uint64_t overflowEventAfterOrdinal{0};

  /// Set when a condition event is lost due to queue overflow.
  /// The owning Subscription checks this flag during publish and emits
  /// RefreshRequiredEvent (Part 9 5.7.2, COND-920).
  bool refreshRequired{false};

  /// EventBus registration handle (for deregistration on delete).
  /// Zero means not registered.
  uint64_t eventBusHandle{0};

  // --- Methods ---

  /// Apply filter and enqueue if accepted. Returns true if enqueued.
  /// For the initial sample, call enqueue_initial() instead (bypasses filter).
  bool evaluate_and_enqueue(DataValue value, std::optional<DataValue> userIndependentValue = std::nullopt);

  /// Enqueue without applying filter (SVR-MI-GEN-060: first sample after creation
  /// or after Disabled->Sampling/Reporting transition).
  void enqueue_initial(DataValue value, std::optional<DataValue> userIndependentValue = std::nullopt);

  /// Enqueue a security reprojection only when it differs from the last queued client value.
  /// Applies the IndexRange step first (@ref apply_index_range) and deliberately bypasses the configured
  /// DataChangeFilter: an access capability change is observable even when the underlying source Attribute
  /// did not change.
  bool enqueue_reprojection_if_changed(
    DataValue value, std::optional<DataValue> userIndependentValue = std::nullopt);

  /// Whether the retained complete verdict currently denies delivery.
  bool access_denied() const noexcept
  {
    return !accessSnapshot || !accessSnapshot->verdict.permitted;
  }

  /// Whether the snapshot belongs to the AccessIdentity currently receiving samples.
  bool access_snapshot_matches(const AccessIdentityKey& identity) const noexcept
  {
    return accessSnapshot && accessSnapshot->identity == identity;
  }

  /// Synthesize a sample from the last value the client saw (lastSentValue), carrying the
  /// SemanticsChanged bit, for an armed exception-reported item where no further tick is coming
  /// (CTT Data Access Analog 008). Skips index-range (the cached value is already sliced) and the
  /// DataChangeFilter. The user-independent value retained with lastSentValue is retained with the
  /// sample, with the SemanticsChanged bit set on its own status. No-op (returns false) if there is no
  /// cache yet or monitoring is Disabled - the item stays armed and the first real value carries the bit.
  /// Returns true if it enqueued.
  bool enqueue_semantic_from_cache();

  /// Sets the SemanticsChanged bit on the newest queued, not yet published data value, which is the next
  /// DataChange the Client will receive. Returns false when nothing is queued or monitoring is Disabled.
  bool mark_queued_semantics_changed();

  /// The structure of the item's value changed (OPC 10000-4 7.39.1 Table 180): sets the StructureChanged bit
  /// on the newest queued, not yet published data value; with none queued, enqueues one made from
  /// lastSentValue with the bit, as @ref enqueue_semantic_from_cache does; with no value sent either, leaves
  /// the bit owed to the next value enqueued (@ref pendingStructureChange), which the DataChangeFilter does
  /// not hold back. The user-independent value retained with the value carries the bit too. Does nothing for
  /// an event item or a Disabled one, which samples nothing.
  /// @return true when it enqueued a notification.
  bool mark_structure_changed();

  /// Drain up to maxCount notifications into the caller's output vector.
  /// The caller pre-reserves the vector to mMaxNotificationsPerPublish,
  /// reusing it across publish cycles to avoid per-publish allocation.
  /// Sets lastSentValue to the last drained value.
  void drain(uint32_t maxCount, std::vector<MonitoredItemNotification>& out);

  /// Drain data notifications together with their aligned server-only retained projection inputs.
  void drain(uint32_t maxCount, std::vector<MonitoredItemNotification>& out,
    std::vector<RetainedDataProjection>& retainedProjections);

  /// Enqueue an event notification that has already been filtered and projected.
  /// Called from the subscription strand when the EventBus delivers an event.
  /// isConditionEvent indicates whether the original event was a condition event
  /// (used for RefreshRequired detection on overflow).
  void enqueue_event(EventFieldList fields, bool isConditionEvent = false);

  /// Enqueue a projected Event together with its concrete authorization subjects for Republish.
  void enqueue_event(EventFieldList fields, bool isConditionEvent, NodeId sourceNode, NodeId eventType);

  /// Enqueue a projected Event with its complete user-independent Republish sidecar.
  void enqueue_event(EventFieldList fields, bool isConditionEvent, RetainedEventProjection projection);

  /// Drain up to maxCount event notifications into the caller's output vector.
  void drain_events(uint32_t maxCount, std::vector<EventFieldList>& out);

  /// Drain Events without discarding their server-only Republish authorization subjects.
  void drain_events(uint32_t maxCount, std::vector<QueuedEvent>& out);

  /// Check if this item has notifications ready for reporting.
  bool has_reportable_notifications() const;

private:
  /// The IndexRange step for a value entering the queue (COMP-SVR-NAMESPACE-CALLS-15 rules 3 and 5). No-op
  /// when the range is empty. Applied before the DataChangeFilter, so that deadband and trigger comparisons
  /// operate on what the client actually sees.
  ///
  /// For an item on an Attribute whose value the server produces (`AccessControl::produces_value`), the
  /// projected @p value is narrowed, as the Read service narrows it: a value whose shape does not match
  /// the range becomes Bad_IndexRangeNoData. @p userIndependentValue, the projection's input, stays whole.
  ///
  /// Every other value was narrowed by whoever produced it and is only checked (NR-10 rule 8): @p value
  /// and @p userIndependentValue, each when its status is not Bad and its Value is larger than the range
  /// in a dimension, are replaced by `Bad_InternalError` with the ErrorDetail `NamespaceValueExceedsRange`
  /// and the value's timestamps. Neither is narrowed.
  void apply_index_range(DataValue& value, std::optional<DataValue>& userIndependentValue) const;

  /// Core enqueue logic - handles overflow and Overflow bit.
  void enqueue(DataValue value, std::optional<DataValue> userIndependentValue);

  /// Test whether a new value passes the DataChangeFilter relative to lastQueuedValue.
  bool passes_filter(const DataValue& newValue) const;

  /// Value-level deadband comparison.
  bool passes_value_deadband(const DataValue& oldValue, const DataValue& newValue) const;

  /// Extract the numeric value from a Variant as a double for deadband comparison.
  /// Returns nullopt if the variant is not a numeric scalar.
  static std::optional<double> to_numeric(const Variant& variant);

  /// Live-instance counter for leak diagnostics. Zero-sized and inert in a release build; in
  /// debug and sanitizer builds a test can assert `InstanceTracker<ServerMonitoredItemTag>::live() == 0`
  /// after churning monitored items, which names the type that leaked instead of a byte count.
  [[no_unique_address]] ua::diagnostics::InstanceTracker<ua::diagnostics::ServerMonitoredItemTag>
    mInstanceTracker;
};

}  // namespace ua::server

#endif  // !UA_MONITORED_ITEM_H
