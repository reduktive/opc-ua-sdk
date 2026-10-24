// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-2 public @ref ua::client::EventSubscriber value handle (client design section 8.13): the
///        per-`Connection` collapsing event backbone. N logical consumers coalesce onto one (small number
///        of) server-side event MonitoredItem(s); inbound events are demultiplexed client-side to each
///        consumer's callback by its registered filter. The strand-bearing
///        `ua::client::detail::EventSubscriberImpl` (which owns the event subsystem's OWN private strand
///        and implements @ref ua::client::detail::MonitoredItemOwner for event consumers) lives in the
///        implementation; this handle forwards its consumer surface one-hop.
/// @ingroup client

#ifndef UA_EVENT_SUBSCRIBER_H
#define UA_EVENT_SUBSCRIBER_H

#include "ua_client_monitored_item.h"
#include "ua_duration.h"
#include "ua_event_filter.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_result.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace ua::client
{

namespace detail
{
class EventSubscriberImpl;
struct EventSubscriberHandleFactory;
}  // namespace detail

/// The parameters for one event-consumer subscription (section 8.13.1). The @ref notifier defaults to the
/// `Server` Object; an absent @ref filter means "events of `BaseEventType`" (i.e. everything the server emits
/// on the notifier). All N consumers on the same notifier COALESCE onto one backbone MonitoredItem  -  the
/// union of their filters is what hits the wire; each consumer's callback fires only for events matching ITS
/// filter.
/// @ingroup client
struct EventSubscription
{
  ua::NodeId notifier{ua::ObjectId::Server};  ///< default: the Server Object
  std::optional<ua::EventFilter> filter;  ///< nullopt == OfType(BaseEventType) (match-all on the notifier)
  std::optional<std::uint32_t> queueSize;  ///< default: policy default (1000)
  std::optional<ua::Duration> publishingInterval;  ///< default: backbone-shared
  /// The discard oldest.
  bool discardOldest = true;
  bool requestDedicatedBackbone = false;  ///< force a fresh backbone MI on its own Subscription
};

/// The "subscribe and get a handle" result  -  the unified @ref MonitoredItem (kind() == Event), T13.
using SubscribeResult = MonitoredItemResult;

/// Cross-strand observability snapshot of the subscriber (Rule 3 info-snapshot).
/// @ingroup client
struct EventSubscriberInfo
{
  /// The backbone count.
  std::size_t backboneCount = 0;
  /// The consumer count.
  std::size_t consumerCount = 0;
  /// The tracker count.
  std::size_t trackerCount = 0;
  /// The last publish event field list count.
  std::size_t lastPublishEventFieldListCount = 0;
};

/// The public value handle (move-only shared_ptr pimpl) users obtain from `Connection::events()` (returned
/// BY VALUE, section 7.2). It forwards its consumer API one-hop to the private strand component
/// `detail::EventSubscriberImpl` (T23), which owns the event subsystem's OWN private strand and
/// implements @ref detail::MonitoredItemOwner (section 7.4)  -  so an event @ref MonitoredItem's self-actions
/// route there. Only the consumer methods live here; the tracker hooks, publish-demux, reconnect, and session
/// feeds live on the Impl. `ConnectionImpl` and the (future) pipeline co-own the same Impl.
/// @ingroup client
class EventSubscriber
{
public:
  /// Returns or updates the event subscriber.
  EventSubscriber(EventSubscriber&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  EventSubscriber& operator=(EventSubscriber&&) noexcept = default;
  EventSubscriber(const EventSubscriber&) = delete;  // move-only
  EventSubscriber& operator=(const EventSubscriber&) = delete;
  ~EventSubscriber() = default;

  // -------- Public consumer API (subscribe / unsubscribe  to  Result<MonitoredItem>) --------

  /// @param subscription The subscription.
  /// @param onEvent The on event.
  /// @param callback Completion callback that receives the operation result.
  /// Subscribes @p onEvent to events matching @p subscription's filter on its notifier. Coalesces onto the
  /// shared backbone; the returned @ref MonitoredItem (kind() == Event) self-acts through the owner
  /// interface. Rejects an empty (non-null but zero-SelectClause) filter with `Bad_EventFilterInvalid`
  /// (CL-MI-016). Rejects `InView`, `RelatedTo`, and unknown `whereClause` operators locally with
  /// `Bad_FilterOperatorInvalid`; basic operators and `OfType` are permitted (CL-MI-023).
  /// The callback runs on the executor. Never throws.
  void subscribe_async(EventSubscription subscription, EventNotificationCallback onEvent,
    std::function<void(SubscribeResult)> callback) noexcept;

  /// Convenience: subscribe to events of type @p eventType (and its subtypes), with the standard
  /// @param eventType The event type.
  /// @param onEvent The on event.
  /// @param callback Completion callback that receives the operation result.
  /// `BaseEventType` mandatory SelectClauses already populated. Never throws.
  void subscribe_to_type_async(ua::NodeId eventType, EventNotificationCallback onEvent,
    std::function<void(SubscribeResult)> callback) noexcept;
  /// @param eventType The eventtype.
  /// @param onEvent The onevent.
  /// @return The requested value.
  /// Synchronously subscribe to type. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  /// A Good subcode on the answer is not returned; try_subscribe_to_type_sync() returns it.
  ua::client::MonitoredItem subscribe_to_type_sync(ua::NodeId eventType, EventNotificationCallback onEvent);
  /// @param eventType The eventtype.
  /// @param onEvent The onevent.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to subscribe to type sync without throwing.
  ua::Result<ua::client::MonitoredItem> try_subscribe_to_type_sync(
    ua::NodeId eventType, EventNotificationCallback onEvent) noexcept;

  /// @param item The item.
  /// @param callback Completion callback that receives the operation result.
  /// Event-consumer teardown. Equivalent to `item.delete_async()` on the returned handle (both route through
  /// @ref detail::MonitoredItemOwner::mi_delete_async on the Impl): drop THIS consumer and recompute the
  /// composite backbone filter (a `ModifyMonitoredItems` iff it changed)  -  it must NOT
  /// `DeleteMonitoredItems` the shared backbone and kill the other consumers. Never throws.
  void unsubscribe_async(MonitoredItem item, std::function<void(ua::VoidResult)> callback) noexcept;

  // -------- Sync convenience (section 7.0) --------

  /// @param subscription The subscription.
  /// @param onEvent The on event.
  /// @return The requested value.
  /// Blocking @ref subscribe_async. @throws ua::UaException on a bad Result.
  /// A Good subcode on the answer is not returned; try_subscribe_sync() returns it.
  MonitoredItem subscribe_sync(EventSubscription subscription, EventNotificationCallback onEvent);
  /// @param subscription The subscription.
  /// @param onEvent The on event.
  /// @return The requested value.
  /// Blocking @ref subscribe_async. Never throws.
  SubscribeResult try_subscribe_sync(
    EventSubscription subscription, EventNotificationCallback onEvent) noexcept;

  /// @param item The item.
  /// Blocking @ref unsubscribe_async. @throws ua::UaException on a bad Result.
  void unsubscribe_sync(MonitoredItem item);
  /// @param item The item.
  /// @return The requested value.
  /// Blocking @ref unsubscribe_async. Never throws.
  ua::VoidResult try_unsubscribe_sync(MonitoredItem item) noexcept;

  /// @return An immutable snapshot of the current state.
  /// Cross-strand info snapshot (atomic-load; any thread).
  [[nodiscard]] std::shared_ptr<const EventSubscriberInfo> info() const noexcept;

private:
  friend class Connection;
  friend class AlarmConditionTracker;
  friend struct detail::EventSubscriberHandleFactory;

  explicit EventSubscriber(std::shared_ptr<detail::EventSubscriberImpl> impl) noexcept
    : mImpl(std::move(impl))
  {}

  std::shared_ptr<detail::EventSubscriberImpl> mImpl;  // pimpl; ConnectionImpl co-owns the same Impl
};

namespace detail
{

/// Construction interface for @ref EventSubscriber (the Connection machinery and tests build handles through
/// it, keeping the public constructor private).
/// @ingroup client
struct EventSubscriberHandleFactory
{
  [[nodiscard]] static EventSubscriber create(std::shared_ptr<detail::EventSubscriberImpl> impl) noexcept
  {
    return EventSubscriber{std::move(impl)};
  }
};

}  // namespace detail

}  // namespace ua::client

#endif  // UA_EVENT_SUBSCRIBER_H
