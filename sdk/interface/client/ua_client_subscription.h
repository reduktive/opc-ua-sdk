// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-1 public `Subscription` handle (client design section 7.4): item lifecycle (monitor /
/// monitor_event
///        / monitor_many / set_triggering), subscription lifecycle (modify / set_publishing_mode / close),
///        and state queries, over the reconnect-surviving `SubscriptionsPipeline`.
/// @ingroup client

#ifndef UA_CLIENT_SUBSCRIPTION_H
#define UA_CLIENT_SUBSCRIPTION_H

#include "ua_client_monitored_item.h"
#include "ua_duration.h"
#include "ua_integer_id.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace ua::client
{

namespace detail
{
class ConnectionImpl;
struct SubscriptionImpl;
struct SubscriptionFactory;
}  // namespace detail

/// The parameters for creating a Subscription (OPC 10000-4 5.13.2, Table 85). Every field reaches the
/// CreateSubscription request; an unset optional takes the SDK default named on it. The values are also
/// retained for the two operations that replace the whole parameter set later - @ref
/// Subscription::modify_async and the rebuild after a reconnect that had to create a fresh Session - so
/// neither silently reverts them.
///
/// Note the one place the SDK adjusts a request: setting @ref maxKeepAliveCount WITHOUT
/// @ref lifetimeCount raises the lifetime to three times the keep-alive, the floor Table 90 requires. Left
/// alone, the default lifetime would sit below that floor for any raised keep-alive and the server would
/// revise BOTH, handing back a Subscription tuned like neither the request nor the default. Set both to be
/// sent verbatim.
/// @ingroup client
struct SubscriptionConfig
{
  /// The requested publishing interval in milliseconds; 0 asks the server for its fastest supported rate.
  double publishingIntervalMs = 0.0;
  /// Whether the Subscription starts publishing. False creates it dormant, to be enabled later.
  bool publishingEnabled = true;
  /// Publishing intervals without an acknowledged Publish before the server deletes the Subscription.
  /// Defaults to 30. With @ref maxKeepAliveCount this is what decides how quickly a dead client releases
  /// server resources - and how long a live one may be silent before the server gives up on it.
  std::optional<std::uint32_t> lifetimeCount;
  /// Publishing intervals with nothing to report before the server sends a keep-alive. Defaults to 10.
  /// This is what bounds how long a client can take to notice a dead server.
  std::optional<std::uint32_t> maxKeepAliveCount;
  /// The maximum notifications the server may pack into one Publish response; unset (0) means no limit.
  std::optional<std::uint32_t> maxNotificationsPerPublish;
  /// Relative publishing priority when the server has several Subscriptions to service. Defaults to 0, the
  /// lowest; a higher value is published first.
  std::optional<std::uint8_t> priority;
};

/// The parameters for modifying a Subscription (OPC 10000-4 5.13.3, Table 88).
///
/// ModifySubscription replaces the WHOLE parameter set, so a field left unset here is NOT left alone by the
/// server - it would be reset. The SDK therefore re-sends every unset field from the values retained at
/// create (or at the last successful modify), and only the fields stated here change.
/// @ingroup client
struct SubscriptionModifyConfig
{
  /// The requested publishing interval in milliseconds.
  double publishingIntervalMs = 0.0;
  /// The requested lifetime count, or unset to keep the value the server currently holds.
  std::optional<std::uint32_t> lifetimeCount;
  /// The requested keep-alive count, or unset to keep the value the server currently holds.
  std::optional<std::uint32_t> maxKeepAliveCount;
  /// The requested per-Publish notification cap, or unset to keep the value the server currently holds.
  std::optional<std::uint32_t> maxNotificationsPerPublish;
  /// The requested priority, or unset to keep the value the server currently holds.
  std::optional<std::uint8_t> priority;
};

/// The per-link outcome of a SetTriggering call (CL-MI-029, OPC UA Part 4 section 5.12.5.2 Table 78). The
/// server returns a StatusCode array for the links added and a StatusCode array for the links removed; each
/// array is positionally paired with its input list, so `addResults[i]` is the outcome of `linksToAdd[i]` and
/// `removeResults[i]` the outcome of `linksToRemove[i]`. A per-link Bad is surfaced here at its index WITHOUT
/// failing the call as a whole  -  the call is bad only on a transport/service-level fault.
/// @ingroup client
struct SetTriggeringResult
{
  std::vector<ua::StatusCode> addResults;  ///< per-link results, paired with the linksToAdd input order.
  std::vector<ua::StatusCode>
    removeResults;  ///< per-link results, paired with the linksToRemove input order.
};

/// Parallel ServerHandle / ClientHandle arrays returned by Server.GetMonitoredItems (Part 5 section 9.1).
/// `serverHandles[i]` and `clientHandles[i]` describe the same monitored item.
/// @ingroup client
struct MonitoredItemHandles
{
  /// The server handles.
  std::vector<ua::IntegerId> serverHandles;
  /// The client handles.
  std::vector<ua::IntegerId> clientHandles;
};

/// A move-only handle to a client-side Subscription (section 7.4). The `SubscriptionsPipeline` owns the
/// underlying state and survives reconnect via TransferSubscriptions (default) or recreate (per policy).
/// Item-level modify / set-mode / delete are SELF-ACTING on the returned @ref MonitoredItem (T14)  -  they
/// are not methods here.
/// @ingroup client
class Subscription
{
public:
  Subscription(const Subscription&) = delete;
  Subscription& operator=(const Subscription&) = delete;
  /// Returns or updates the subscription.
  Subscription(Subscription&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  Subscription& operator=(Subscription&&) noexcept = default;
  ~Subscription() = default;

  // ============ Item lifecycle ============

  /// Attaches a data-change monitor; the callback delivers the returned @ref MonitoredItem (or a bad Result)
  /// @param request The request.
  /// @param onData The on data.
  /// @param callback Completion callback that receives the operation result.
  /// on the executor. Notifications for the item are delivered to @p onData on the executor. Never throws.
  void monitor_async(MonitorRequest request, DataChangeCallback onData,
    std::function<void(MonitoredItemResult)> callback) noexcept;
  /// @param request The request.
  /// @param onData The on data.
  /// @return The requested value.
  /// Blocking @ref monitor_async. @throws ua::UaException on a bad Result.
  /// A Good subcode on the answer is not returned; try_monitor_sync() returns it.
  MonitoredItem monitor_sync(MonitorRequest request, DataChangeCallback onData);
  /// @param request The request.
  /// @param onData The on data.
  /// @return The requested value.
  /// Blocking @ref monitor_async. Never throws.
  MonitoredItemResult try_monitor_sync(MonitorRequest request, DataChangeCallback onData) noexcept;

  /// Attaches an event monitor (dedicated @ref EventMonitorRequest with its REQUIRED @ref ua::EventFilter,
  /// T17).
  ///
  /// @param request The request.
  /// @param onEvent The on event.
  /// @param callback Completion callback that receives the operation result.
  /// @note DEFERRED to Slice 10a. Event-notification demux + composite-filter routing is owned by the
  ///       tier-2 `EventSubscriber` (section 8.13); this handle surfaces the API now and completes with
  ///       `Bad_NotSupported` until 10a wires the event owner into the @ref detail::MonitoredItemOwner
  ///       interface.
  void monitor_event_async(EventMonitorRequest request, EventCallback onEvent,
    std::function<void(MonitoredItemResult)> callback) noexcept;
  /// @param request The request.
  /// @param onEvent The on event.
  /// @return The requested value.
  /// Blocking @ref monitor_event_async. @throws ua::UaException on a bad Result.
  /// A Good subcode on the answer is not returned; try_monitor_event_sync() returns it.
  MonitoredItem monitor_event_sync(EventMonitorRequest request, EventCallback onEvent);
  /// @param request The request.
  /// @param onEvent The on event.
  /// @return The requested value.
  /// Blocking @ref monitor_event_async. Never throws.
  MonitoredItemResult try_monitor_event_sync(EventMonitorRequest request, EventCallback onEvent) noexcept;

  /// A bulk-add result: per-item results in the same order as the input vector.
  using BulkMonitorResult = ua::Result<std::vector<MonitoredItemResult>>;

  /// @param requests The requests.
  /// @param onData The on data.
  /// @param callback Completion callback that receives the operation result.
  /// Attaches many data-change monitors; per-item results are returned in input order. Never throws.
  ///
  /// @note v1 issues the creates sequentially (each its own `CreateMonitoredItems`); the single-round-trip
  ///       bulk wire op is a ConnectionImpl-richness follow-up. The per-item result ordering contract holds.
  void monitor_many_async(std::vector<MonitorRequest> requests, DataChangeCallback onData,
    std::function<void(BulkMonitorResult)> callback) noexcept;
  /// @param requests The requests.
  /// @param onData The on data.
  /// @return The requested value.
  /// Blocking @ref monitor_many_async. @throws ua::UaException on a bad outer Result.
  /// A Good subcode on the answer is not returned; try_monitor_many_sync() returns it.
  std::vector<MonitoredItemResult> monitor_many_sync(
    std::vector<MonitorRequest> requests, DataChangeCallback onData);
  /// @param requests The requests.
  /// @param onData The on data.
  /// @return The requested value.
  /// Blocking @ref monitor_many_async. Never throws.
  BulkMonitorResult try_monitor_many_sync(
    std::vector<MonitorRequest> requests, DataChangeCallback onData) noexcept;

  // ============ Triggering (Monitor Client Trigger CU, T18) ============

  /// Configures the trigger relationship between @p trigger and the linked items. The async form takes the
  /// handles BY VALUE (a `MonitoredItem&` would dangle once the body is posted to the strand); the sync
  /// forms live for the whole call and take `const&` (T18  -  the raw-pointer forms are dropped). Never
  /// throws.
  ///
  /// The callback receives a @ref SetTriggeringResult carrying the per-link add/remove StatusCode arrays,
  /// positionally paired with @p linksToAdd / @p linksToRemove (CL-MI-029, Part 4 section 5.12.5.2 Table 78).
  /// @param trigger MonitoredItem that triggers linked-item reporting.
  /// @param linksToAdd Items to add to the trigger relationship.
  /// @param linksToRemove Items to remove from the trigger relationship.
  /// @param callback Completion callback receiving the per-link results.
  /// A per-link Bad is surfaced at its index without making the outer Result bad; the Result is bad only on a
  /// local precondition failure or a transport/service-level fault.
  void set_triggering_async(MonitoredItem trigger, std::vector<MonitoredItem> linksToAdd,
    std::vector<MonitoredItem> linksToRemove,
    std::function<void(ua::Result<SetTriggeringResult>)> callback) noexcept;
  /// @param trigger The trigger.
  /// @param linksToAdd The links to add.
  /// @param linksToRemove The links to remove.
  /// @return The requested value.
  /// Blocking @ref set_triggering_async. @throws ua::UaException on a bad Result.
  /// A Good subcode on the answer is not returned; try_set_triggering_sync() returns it.
  SetTriggeringResult set_triggering_sync(const MonitoredItem& trigger,
    const std::vector<MonitoredItem>& linksToAdd, const std::vector<MonitoredItem>& linksToRemove);
  /// @param trigger The trigger.
  /// @param linksToAdd The links to add.
  /// @param linksToRemove The links to remove.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Blocking @ref set_triggering_async. Never throws.
  ua::Result<SetTriggeringResult> try_set_triggering_sync(const MonitoredItem& trigger,
    const std::vector<MonitoredItem>& linksToAdd, const std::vector<MonitoredItem>& linksToRemove) noexcept;

  // ============ Server-object methods ============

  /// Calls Server.GetMonitoredItems through the Connection/Session that owns this Subscription and returns
  /// @param callback Completion callback that receives the operation result.
  /// the parallel server/client handle arrays. Never throws.
  void get_monitored_items_async(std::function<void(ua::Result<MonitoredItemHandles>)> callback) noexcept;
  /// @return The requested value.
  /// Blocking @ref get_monitored_items_async. @throws ua::UaException on a bad Result.
  /// A Good subcode on the answer is not returned; try_get_monitored_items_sync() returns it.
  MonitoredItemHandles get_monitored_items_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Blocking @ref get_monitored_items_async. Never throws.
  ua::Result<MonitoredItemHandles> try_get_monitored_items_sync() noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Calls Server.ResendData through the Connection/Session that owns this Subscription. Never throws.
  void resend_data_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Blocking @ref resend_data_async. @throws ua::UaException on a bad Result.
  void resend_data_sync();
  /// @return The requested value.
  /// Blocking @ref resend_data_async. Never throws.
  ua::VoidResult try_resend_data_sync() noexcept;

  // ============ Subscription lifecycle ============

  /// @param config The config.
  /// @param callback Completion callback that receives the operation result.
  /// Modifies the Subscription (publishing interval). Never throws.
  void modify_async(SubscriptionModifyConfig config, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param config The config.
  /// Blocking @ref modify_async. @throws ua::UaException on a bad Result.
  void modify_sync(SubscriptionModifyConfig config);
  /// @param config The config.
  /// @return The requested value.
  /// Blocking @ref modify_async. Never throws.
  ua::VoidResult try_modify_sync(SubscriptionModifyConfig config) noexcept;

  /// @param enabled The enabled.
  /// @param callback Completion callback that receives the operation result.
  /// Enables / disables publishing for the Subscription. Never throws.
  void set_publishing_mode_async(bool enabled, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param enabled The enabled.
  /// Blocking @ref set_publishing_mode_async. @throws ua::UaException on a bad Result.
  void set_publishing_mode_sync(bool enabled);
  /// @param enabled The enabled.
  /// @return The requested value.
  /// Blocking @ref set_publishing_mode_async. Never throws.
  ua::VoidResult try_set_publishing_mode_sync(bool enabled) noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// Deletes the Subscription server-side (DeleteSubscriptions) and deregisters it from the pipeline. Never
  /// throws.
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Blocking @ref close_async. @throws ua::UaException on a bad Result.
  void close_sync();
  /// @return The requested value.
  /// Blocking @ref close_async. Never throws.
  ua::VoidResult try_close_sync() noexcept;

  // ============ Queries / state ============

  /// @return The requested value.
  /// The server-assigned Subscription id.
  [[nodiscard]] ua::IntegerId server_subscription_id() const noexcept;
  /// @return The requested value.
  /// The server-revised publishing interval (ms). Captured at create and UPDATED on every
  /// @ref modify_async the server answers Good or Uncertain with its response, to the modify's revised value
  /// (CL-SUB-011), so it always reflects the current
  /// server cadence. Thread-safe; shared across handle copies.
  [[nodiscard]] ua::Duration publishing_interval() const noexcept;
  /// @return True when the requested condition is satisfied.
  /// Whether publishing is currently enabled (updated when the server answers @ref set_publishing_mode_async
  /// Good or Uncertain with the Subscription's result).
  [[nodiscard]] bool is_publishing_enabled() const noexcept;
  /// @return The requested value.
  /// The number of monitored items created through this handle (v1: not decremented on item delete).
  [[nodiscard]] std::size_t item_count() const noexcept;

private:
  friend struct detail::SubscriptionFactory;

  explicit Subscription(std::shared_ptr<detail::SubscriptionImpl> impl) noexcept : mImpl(std::move(impl))
  {}

  std::shared_ptr<detail::SubscriptionImpl> mImpl;
};

namespace detail
{

/// Construction interface for @ref Subscription (the connection machinery and tests build handles through it,
/// keeping the public constructor private). Primitive params keep the impl-side `SubscriptionCreated` out of
/// this public header.
/// @ingroup client
struct SubscriptionFactory
{
  [[nodiscard]] static Subscription create(std::shared_ptr<ConnectionImpl> connection,
    std::uint32_t subscriptionId, double publishingInterval, bool publishingEnabled);
};

}  // namespace detail

}  // namespace ua::client

#endif  // UA_CLIENT_SUBSCRIPTION_H
