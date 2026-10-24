// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EVENT_BUS_H
#define UA_EVENT_BUS_H

#include "ua_address_space.h"
#include "ua_base_event.h"
#include "ua_event_type_model.h"
#include "ua_sinks.h"
#include "ua_node_id.h"
#include "ua_node_utilities.h"
#include "ua_result.h"
#include "ua_server_observer.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua::server
{

/// Opaque handle for event monitoring registration. Used for deregistration.
using EventMonitoringHandle = uint64_t;

/// Callback to deliver an event to a subscription's event monitored item.
/// Invoked on the EventBus dispatch strand; the subscription must post to its own strand.
/// Parameters: monitoredItemId, shared event (immutable after auto-fill), and the shared immutable
/// InstanceDeclaration model cached for the concrete EventType.
using EventDeliveryCallback =
  std::function<void(IntegerId monitoredItemId, std::shared_ptr<const BaseEvent> event,
    std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel)>;

// Source-compatible adapter for existing two-argument EventBus observers that do not consume
// declaration metadata. New subscription delivery uses EventDeliveryCallback directly.
using LegacyEventDeliveryCallback =
  std::function<void(IntegerId monitoredItemId, std::shared_ptr<const BaseEvent> event)>;

/// Server-level event routing component.
///
/// Strand-serialised component:
/// the dispatch strand owns all mutable state. `emit()` is non-blocking -
/// `auto_fill` and the event clone run on the caller's thread; subscriber
/// dispatch and the local listener invocation are posted to the dispatch
/// strand.
///
/// Emits are processed **one at a time** in submission order. Each dispatch
/// task (listener invocation + notifier-set walk + per-MI callback hand-off)
/// runs to completion before the next emit's task starts. This serialisation
/// is enforced via a per-bus pending-task queue gated by a `mDispatching`
/// flag - without it, a strand-only model would let multiple in-flight flows
/// interleave their async hops on the bus strand and complete in
/// shortest-path-first order rather than emit-order. The serialisation
/// guarantees per-MonitoredItem FIFO ordering (Part 4 5.12.1.5, 7.25.1)
/// even across emits with different source nodes / notifier-walk depths.
/// Which application ReferenceTypes are subtypes of HasEventSource, for one model generation.
struct EventSourceTypeCache
{
  /// Internally synchronised; shared with the subtype walks in flight.
  std::shared_ptr<node_utils::RefTypeCache> subtypes{std::make_shared<node_utils::RefTypeCache>()};
  /// Types whose lookup failure has been logged. Dispatch strand only.
  std::unordered_set<NodeId> failuresLogged;
};

class EventBus : public EventSink, public std::enable_shared_from_this<EventBus>
{
public:
  /// @param addressSpace          Address space the bus reads type hierarchy / notifier links from.
  /// @param maxPendingDispatches  Hard cap on queued-but-not-yet-started dispatch tasks. When a new
  ///                              task would exceed it, the oldest pending task is dropped (and the
  ///                              dropped-dispatch counter bumped) so a burst of events cannot grow
  ///                              the bus's working set without limit. Clamped to >= 1.
  explicit EventBus(AddressSpace addressSpace, size_t maxPendingDispatches = 10000);

  /// Number of dispatch tasks dropped due to the pending-queue overflow cap (observability).
  /// Reads an atomic; safe from any thread.
  uint64_t dropped_dispatch_count() const;

  /// EventSink interface - may be called from any thread.
  /// auto_fill + clone happen on the caller's thread (so `event.event_id` is
  /// populated before this returns); listener + subscriber dispatch are
  /// posted to the dispatch strand.
  void emit(BaseEvent& event) override;

  /// Emit an event to all event monitored items on a specific subscription,
  /// bypassing notifier resolution and WhereClause filtering.
  /// Used by ConditionRefresh to deliver retained condition snapshots.
  /// May be called from any thread; subscriber dispatch is posted to the
  /// dispatch strand. The local listener is not invoked for this path.
  void emit_to_subscription(uint32_t subscriptionId, BaseEvent& event);

  /// Emit an event to a single event monitored item identified by
  /// (subscriptionId, monitoredItemId), bypassing notifier resolution and
  /// WhereClause filtering. Used by ConditionRefresh2 (Part 9 5.5.8) to
  /// deliver retained condition snapshots to exactly one MonitoredItem.
  /// May be called from any thread; subscriber dispatch is posted to the
  /// dispatch strand. The local listener is not invoked for this path.
  void emit_to_monitored_item(uint32_t subscriptionId, IntegerId monitoredItemId, BaseEvent& event);

  /// Resolve the monitored NodeId of the event monitored item identified by
  /// (subscriptionId, monitoredItemId). The lookup is posted to the dispatch
  /// strand (the registry is strand-owned); the callback receives the
  /// monitored NodeId, or std::nullopt when no such event monitored item is
  /// registered. "Not found" is a normal outcome (the MonitoredItem may not be
  /// an event item or may not exist), so it is reported as nullopt rather than
  /// an error status - no ErrorDetail is discarded.
  void resolve_event_item_node_async(
    uint32_t subscriptionId, IntegerId monitoredItemId, std::function<void(std::optional<NodeId>)> callback);

  /// Reports whether a Subscription currently contains at least one event
  /// MonitoredItem. The registry lookup is serialized on the dispatch strand.
  /// A destroyed EventBus completes with `BadShutdown`; a live, empty
  /// Subscription completes Good with `false`.
  void has_event_items_async(uint32_t subscriptionId, std::function<void(Result<bool>)> callback);

  /// Register an event monitoring callback for a given node.
  /// Returns the handle synchronously on the caller's thread; the registry
  /// insert is posted to the dispatch strand (eventually consistent). The
  /// brief window between handle allocation and insert is harmless - an MI
  /// that is still being created cannot receive events.
  EventMonitoringHandle register_event_item(
    NodeId monitoredNode, IntegerId monitoredItemId, uint32_t subscriptionId, EventDeliveryCallback callback);
  EventMonitoringHandle register_event_item(NodeId monitoredNode, IntegerId monitoredItemId,
    uint32_t subscriptionId, EventDeliveryCallback callback, bool requiresDeclarationModel);

  EventMonitoringHandle register_event_item(NodeId monitoredNode, IntegerId monitoredItemId,
    uint32_t subscriptionId, LegacyEventDeliveryCallback callback);

  /// Deregister a previously registered event monitoring callback.
  /// Posted to the dispatch strand. In-flight callbacks already past the
  /// strand are tolerated by the subscription-side MI lookup (it bails if
  /// the MI is gone).
  void deregister_event_item(EventMonitoringHandle handle);

  /// Set a local event listener invoked on the dispatch strand, before
  /// subscriber dispatch, for every event passed to `emit()`. Pass nullptr
  /// to clear.
  using EventListener = std::function<void(const BaseEvent&)>;
  void set_event_listener(EventListener listener);

  /// Clears the local listener on the dispatch strand - so after it no event reaches the listener, an
  /// in-flight one included - and refuses any later set_event_listener; then invokes @p done. The server's
  /// shutdown completes only after this, so the application's listener is never called once shutdown has
  /// completed. Cost: one strand post per shutdown.
  void close_listener_async(std::function<void()> done);

  /// Returns true if any MonitoredItem is registered OR a local listener is set.
  /// Lightweight atomic gate for high-frequency event emission (e.g. Write audit events).
  bool has_event_interest() const noexcept;

  /// Callback invoked (on the dispatch strand) for each event dropped by the pending-dispatch cap.
  using DispatchDroppedObserver = std::function<void(const DroppedEventInfo&)>;

  /// Install the dropped-event observer. Set once at startup, before the server begins dispatching;
  /// the assignment is posted to the dispatch strand so the strand remains the sole owner of the
  /// callback. Pass nullptr to clear.
  void set_dispatch_dropped_observer(DispatchDroppedObserver observer);

private:
  friend struct EventBusTestAccess;

  using DeclarationResolver = std::function<void(AddressSpace, NodeId, event_type_model::CollectCallback)>;

  struct RegisteredItem
  {
    NodeId monitoredNode;
    IntegerId monitoredItemId;
    uint32_t subscriptionId;
    EventDeliveryCallback callback;
    bool requiresDeclarationModel{false};
    EventMonitoringHandle handle;
  };

  EventMonitoringHandle register_event_item_impl(NodeId monitoredNode, IntegerId monitoredItemId,
    uint32_t subscriptionId, bool requiresDeclarationModel, EventDeliveryCallback callback);

  /// Auto-fill EventId, ReceiveTime, Time on the event. Called on the caller's thread.
  void auto_fill(BaseEvent& event);

  /// Resolve an EventType's supertype chain (``[eventType, parent, ...,
  /// BaseEventType]``) from the address-space ``HasSubtype`` hierarchy and invoke
  /// ``done`` with it. Used to populate ``BaseEvent::event_type_hierarchy`` before
  /// delivery so the subscription layer's EventFilter ``OfType`` test (Part 4
  /// 7.7.3) is a pure synchronous membership check.
  ///
  /// Must be called on the dispatch strand. Results are cached per EventType in
  /// ``mEventTypeHierarchyCache`` (the cache is strand-confined). Cache entries
  /// are reused only while the AddressSpace model generation is unchanged.
  void resolve_event_type_hierarchy_async(
    NodeId eventType, std::function<void(std::shared_ptr<const std::vector<NodeId>>)> done);

  /// Resolve and cache all inherited InstanceDeclarations for one concrete EventType.
  void resolve_event_type_declarations_async(
    NodeId eventType, std::function<void(std::shared_ptr<const event_type_model::DeclarationsResult>)> done);

  /// Recompute hasEventInterest_ from registry size and listener presence.
  /// Must only be called on the dispatch strand.
  void update_interest_flag();

  /// A dispatch task - invoked with a completion callback that triggers the
  /// next task. The task must call `onComplete()` exactly once, on the
  /// dispatch strand, when the task is fully done (i.e. listener invoked,
  /// notifier walk finished, and per-MI callbacks have all been handed off).
  using DispatchTask = std::function<void(std::function<void()> onComplete)>;

  /// A queued dispatch plus the identity of its event, so that if this entry is dropped by the
  /// pending-dispatch cap we can report what was lost (the task itself is type-erased).
  struct PendingDispatch
  {
    DispatchTask task;
    DroppedEventInfo info;
  };

  /// Push a dispatch task (with its event's identity, for drop reporting) onto the pending queue.
  /// Must be called on the dispatch strand. If no task is currently in flight, starts the queue.
  void enqueue_dispatch_on_strand(DispatchTask task, DroppedEventInfo info);

  /// Pop the next pending dispatch task and start it. Must be called on the
  /// dispatch strand. No-op if a task is already in flight or the queue is
  /// empty.
  void start_next_dispatch_on_strand();

  /// Called by a completed task's onComplete callback (always on the
  /// dispatch strand). Triggers the next task via a strand-post to break
  /// stack growth for chains of synchronous tasks.
  void on_dispatch_complete();

  AddressSpace mAddressSpace;
  boost::asio::strand<boost::asio::any_io_executor> mDispatchStrand;

  // All state below is owned by mDispatchStrand and accessed only on it.
  std::unordered_map<EventMonitoringHandle, RegisteredItem> mRegistry;
  EventListener mEventListener;
  bool mListenerClosed = false;  ///< Set by close_listener_async; strand-owned.
  std::queue<PendingDispatch> mPendingDispatches;
  DispatchDroppedObserver mOnDispatchDropped;  // invoked on the strand per dropped event
  bool mDispatching{false};
  // Hard cap on queued-but-not-started dispatch tasks; drop-oldest on overflow (strand-confined).
  const size_t mMaxPendingDispatches;

  struct HierarchyCacheEntry
  {
    uint64_t modelGeneration{0};
    std::shared_ptr<const std::vector<NodeId>> hierarchy;
  };

  struct DeclarationCacheEntry
  {
    uint64_t modelGeneration{0};
    std::shared_ptr<const event_type_model::DeclarationsResult> declarations;
  };

  // Derived EventType models are reusable only while the AddressSpace mutation generation is
  // unchanged. Both caches are confined to mDispatchStrand.
  std::unordered_map<NodeId, HierarchyCacheEntry> mEventTypeHierarchyCache;

  /// Application ReferenceTypes already found to be, or not to be, subtypes of HasEventSource; renewed
  /// when the model generation moves. Read and replaced on the dispatch strand.
  std::shared_ptr<EventSourceTypeCache> mEventSourceTypes;
  uint64_t mEventSourceTypesGeneration{0};

  /// The cache of event-source ReferenceTypes for the current model generation. Dispatch strand only.
  std::shared_ptr<EventSourceTypeCache> event_source_types();

  // Per-concrete-EventType InstanceDeclaration cache used by field authorization.
  std::unordered_map<NodeId, DeclarationCacheEntry> mEventTypeDeclarationsCache;

  // Empty in production. Criterion-bound fault injector confined to the dispatch strand.
  DeclarationResolver mDeclarationResolver;

  // Atomics - cross-thread observable / caller-thread allocated.
  std::atomic<uint64_t> mDroppedDispatchCount{0};  // overflow status: tasks dropped by the cap
  std::atomic<uint64_t> mNextHandle{1};
  std::atomic<uint64_t> mNextEventId{1};
  std::atomic<bool> mHasEventInterest{false};
};

}  // namespace ua::server

#endif  // !UA_EVENT_BUS_H
