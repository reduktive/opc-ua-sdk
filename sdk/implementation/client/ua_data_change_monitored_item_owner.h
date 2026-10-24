// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_CHANGE_MONITORED_ITEM_OWNER_H
#define UA_DATA_CHANGE_MONITORED_ITEM_OWNER_H

/// @file
/// @brief The connection-lifetime data-change implementation of the @ref
/// ua::client::detail::MonitoredItemOwner
///        interface (client design section 7.4 / tier_remediation_design section 2.3): resolves a data-change
///        @ref ua::client::MonitoredItem's `clientHandle` to its server-side action and forwards through the
///        owning @ref ua::client::detail::ConnectionImpl.
/// @ingroup client

#include "ua_client_monitored_item.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace ua::client::detail
{

class ConnectionImpl;

/// The data-change @ref MonitoredItemOwner (T13/T14). One per @ref ConnectionImpl, held strongly by it and
/// weak-referencing it back, so `owner alive <=> Connection alive`. A self-acting @ref MonitoredItem holds a
/// `weak_ptr` to this owner; its lock failing == the Connection is gone ( to  `Bad_ConnectionClosed`,
/// section 7.4).
///
/// It keeps the self-action routing index (`clientHandle  to  {subscriptionId, serverMonitoredItemId}`)  -
/// the section 7.4 owner-routing map, extended with the server monitored-item id that modify / set-mode /
/// delete need. This is distinct from the pipeline's demux map (`clientHandle  to  callback`): different
/// concern, populated on monitor success and erased on delete success / subscription close. A registry-lookup
/// MISS (the item was deleted) completes `Bad_SubscriptionIdInvalid`; a failed back-lock to the Connection
/// completes `Bad_ConnectionClosed` (section 7.4  -  the two are distinct, not both
/// `Bad_SubscriptionIdInvalid`).
///
/// The event-consumer owner (`EventSubscriberImpl`, section 8.13) is a SEPARATE implementation of the same
/// interface and lands in Slice 10a; it is deliberately not built here.
class DataChangeMonitoredItemOwner final : public MonitoredItemOwner,
                                           public std::enable_shared_from_this<DataChangeMonitoredItemOwner>
{
public:
  /// @param connection The orchestrator this owner forwards wire ops to (weak; the owner must not own it).
  [[nodiscard]] static std::shared_ptr<DataChangeMonitoredItemOwner> create(
    std::weak_ptr<ConnectionImpl> connection);

  /// Records the routing for a freshly-created data-change item (called on monitor success). @p state is the
  /// SHARED @ref MonitoredItemState the returned handle also holds, retained here so this owner (the sole
  /// updater) can refresh it on a later modify / set-mode success (D5, CL-MI-019/020/021). A null @p state
  /// (routing-only test / rekey callers) simply skips the shared-state refresh.
  void register_item(std::uint32_t clientHandle, std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
    std::shared_ptr<MonitoredItemState> state = nullptr) noexcept;

  /// Drops an item's routing (called on delete success / subscription close). Idempotent.
  void unregister_item(std::uint32_t clientHandle) noexcept;

  /// Drops EVERY routing entry owned by @p subscriptionId (called on DeleteSubscriptions success, so a closed
  /// Subscription does not leak its items' owner-routing entries  -  WARNING 3). Takes @ref mMutex once.
  void unregister_subscription(std::uint32_t subscriptionId) noexcept;

  /// One `clientHandle  to  {subscriptionId, serverMonitoredItemId}` re-key applied atomically after a
  /// session-CHANGED reconnect recreated the item under a NEW Subscription id + NEW server monitored-item id
  /// while preserving its `clientHandle` (CRITICAL 1). The owner map is the SOLE holder of this routing, so
  /// it must be re-keyed in lock-step with the pipeline re-key or every subsequent self-action mis-targets
  /// the stale server ids.
  struct ItemRekey
  {
    std::uint32_t clientHandle = 0;
    std::uint32_t subscriptionId = 0;
    std::uint32_t monitoredItemId = 0;
  };

  /// Re-keys the routing for every entry in @p rekeys (session-CHANGED recreate commit, CRITICAL 1). Each
  /// entry's `clientHandle` is repointed to its new `{subscriptionId, monitoredItemId}`. Takes @ref mMutex
  /// ONCE for the whole batch, so the re-key is atomic with respect to concurrent self-actions.
  void rekey_items(const std::vector<ItemRekey>& rekeys) noexcept;

  /// Resolves @p clientHandle to its server monitored-item id (for `SetTriggering`), or `nullopt` on a miss.
  [[nodiscard]] std::optional<std::uint32_t> server_item_id(std::uint32_t clientHandle) const noexcept;

  /// Resolves @p clientHandle to its owning subscription id, or `nullopt` on a miss.
  [[nodiscard]] std::optional<std::uint32_t> subscription_of(std::uint32_t clientHandle) const noexcept;

  // --- MonitoredItemOwner (section 7.4)  -  self-actions routed by clientHandle ---
  void mi_modify_async(MonitoredItemId clientHandle, MonitorRequest request,
    std::function<void(ua::VoidResult)> callback) noexcept override;
  void mi_set_mode_async(MonitoredItemId clientHandle, ua::MonitoringMode mode,
    std::function<void(ua::VoidResult)> callback) noexcept override;
  void mi_delete_async(
    MonitoredItemId clientHandle, std::function<void(ua::VoidResult)> callback) noexcept override;

private:
  explicit DataChangeMonitoredItemOwner(std::weak_ptr<ConnectionImpl> connection);

  /// The connection's executor, or empty once the connection has gone.
  [[nodiscard]] boost::asio::any_io_executor executor() const noexcept override;

  /// The routing an item's self-actions need. Strand-agnostic  -  guarded by @ref mMutex.
  struct Routing
  {
    std::uint32_t subscriptionId = 0;
    std::uint32_t monitoredItemId = 0;
    /// The shared mutable state of the handle(s) for this item  -  the owner refreshes it on a modify /
    /// set-mode SUCCESS so every handle copy observes the current revised values (D5, CL-MI-019/020/021).
    /// May be null (routing-only / rekey entries)  -  the refresh is then skipped.
    std::shared_ptr<MonitoredItemState> state;
  };

  [[nodiscard]] std::optional<Routing> lookup(std::uint32_t clientHandle) const noexcept;

  std::weak_ptr<ConnectionImpl> mConnection;
  mutable std::mutex mMutex;
  std::unordered_map<std::uint32_t, Routing> mRouting;  // clientHandle -> routing (guarded)
};

}  // namespace ua::client::detail

#endif  // UA_DATA_CHANGE_MONITORED_ITEM_OWNER_H
