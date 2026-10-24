// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side accessor for the OPC UA MonitoredItem Service Set.
/// @ingroup client

#ifndef UA_SESSION_MONITORED_ITEM_SERVICES_H
#define UA_SESSION_MONITORED_ITEM_SERVICES_H

#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_result.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"

#include <functional>
#include <memory>

namespace ua::client
{

class Session;
class SessionImpl;

/// Non-owning accessor for the OPC UA MonitoredItem Service Set on a Session.
///
/// Exposes the CreateMonitoredItems, ModifyMonitoredItems, SetMonitoringMode,
/// SetTriggering, and DeleteMonitoredItems services. Obtained from the owning
/// @ref Session, which retains ownership; this accessor holds only a weak
/// reference to the session implementation. Operations invoked after the
/// owning session has been destroyed complete with a bad @ref Result rather
/// than dereferencing a dangling pointer.
///
/// Each service is offered as a three-variant trio: a callback-canonical
/// `*_async` form and the `*_sync` / `try_*_sync` blocking convenience
/// wrappers for external consumers.
/// @ingroup client
class SessionMonitoredItemServices
{
public:
  // CreateMonitoredItems

  /// Result delivered for a CreateMonitoredItems request.
  using CreateMonitoredItemsResponseResult = ua::Result<ua::CreateMonitoredItemsResponse>;

  /// Callback receiving the outcome of a CreateMonitoredItems request.
  using CreateMonitoredItemsCallback = std::function<void(CreateMonitoredItemsResponseResult)>;

  /// Creates monitored items within an existing subscription.
  ///
  /// Sends the request to the server and completes asynchronously. The
  /// callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  The CreateMonitoredItems request to send.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref CreateMonitoredItemsResponse (whose per-item results
  ///                 report each item's individual status); on failure it
  ///                 carries an @ref ErrorDetail. This overload never throws.
  /// @see create_monitored_items_sync, try_create_monitored_items_sync
  void create_monitored_items_async(
    ua::CreateMonitoredItemsRequest request, CreateMonitoredItemsCallback callback) noexcept;

  /// Creates monitored items within an existing subscription, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The CreateMonitoredItems request to send.
  /// @return The CreateMonitoredItems response.
  /// @throws UaException if the service call fails at the request level.
  /// @see create_monitored_items_async, try_create_monitored_items_sync
  /// A Good subcode on the answer is not returned; try_create_monitored_items_sync() returns it.
  ua::CreateMonitoredItemsResponse create_monitored_items_sync(ua::CreateMonitoredItemsRequest request);

  /// Creates monitored items within an existing subscription, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The CreateMonitoredItems request to send.
  /// @return The CreateMonitoredItems response, or an @ref ErrorDetail on
  ///         failure. Never throws.
  /// @see create_monitored_items_async, create_monitored_items_sync
  CreateMonitoredItemsResponseResult try_create_monitored_items_sync(
    ua::CreateMonitoredItemsRequest request) noexcept;

  // ModifyMonitoredItems

  /// Result delivered for a ModifyMonitoredItems request.
  using ModifyMonitoredItemsResponseResult = ua::Result<ua::ModifyMonitoredItemsResponse>;

  /// Callback receiving the outcome of a ModifyMonitoredItems request.
  using ModifyMonitoredItemsCallback = std::function<void(ModifyMonitoredItemsResponseResult)>;

  /// Modifies the monitoring parameters of existing monitored items.
  ///
  /// Sends the request to the server and completes asynchronously. The
  /// callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  The ModifyMonitoredItems request to send.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref ModifyMonitoredItemsResponse (whose per-item results
  ///                 report each item's individual status); on failure it
  ///                 carries an @ref ErrorDetail. This overload never throws.
  /// @see modify_monitored_items_sync, try_modify_monitored_items_sync
  void modify_monitored_items_async(
    ua::ModifyMonitoredItemsRequest request, ModifyMonitoredItemsCallback callback) noexcept;

  /// Modifies the monitoring parameters of existing monitored items, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The ModifyMonitoredItems request to send.
  /// @return The ModifyMonitoredItems response.
  /// @throws UaException if the service call fails at the request level.
  /// @see modify_monitored_items_async, try_modify_monitored_items_sync
  /// A Good subcode on the answer is not returned; try_modify_monitored_items_sync() returns it.
  ua::ModifyMonitoredItemsResponse modify_monitored_items_sync(ua::ModifyMonitoredItemsRequest request);

  /// Modifies the monitoring parameters of existing monitored items, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The ModifyMonitoredItems request to send.
  /// @return The ModifyMonitoredItems response, or an @ref ErrorDetail on
  ///         failure. Never throws.
  /// @see modify_monitored_items_async, modify_monitored_items_sync
  ModifyMonitoredItemsResponseResult try_modify_monitored_items_sync(
    ua::ModifyMonitoredItemsRequest request) noexcept;

  // SetMonitoringMode

  /// Result delivered for a SetMonitoringMode request.
  using SetMonitoringModeResponseResult = ua::Result<ua::SetMonitoringModeResponse>;

  /// Callback receiving the outcome of a SetMonitoringMode request.
  using SetMonitoringModeCallback = std::function<void(SetMonitoringModeResponseResult)>;

  /// Sets the monitoring mode (Disabled, Sampling, or Reporting) of monitored items.
  ///
  /// Sends the request to the server and completes asynchronously. The
  /// callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  The SetMonitoringMode request to send.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref SetMonitoringModeResponse (whose per-item results
  ///                 report each item's individual status); on failure it
  ///                 carries an @ref ErrorDetail. This overload never throws.
  /// @see set_monitoring_mode_sync, try_set_monitoring_mode_sync
  void set_monitoring_mode_async(
    ua::SetMonitoringModeRequest request, SetMonitoringModeCallback callback) noexcept;

  /// Sets the monitoring mode of monitored items, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The SetMonitoringMode request to send.
  /// @return The SetMonitoringMode response.
  /// @throws UaException if the service call fails at the request level.
  /// @see set_monitoring_mode_async, try_set_monitoring_mode_sync
  /// A Good subcode on the answer is not returned; try_set_monitoring_mode_sync() returns it.
  ua::SetMonitoringModeResponse set_monitoring_mode_sync(ua::SetMonitoringModeRequest request);

  /// Sets the monitoring mode of monitored items, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The SetMonitoringMode request to send.
  /// @return The SetMonitoringMode response, or an @ref ErrorDetail on failure.
  ///         Never throws.
  /// @see set_monitoring_mode_async, set_monitoring_mode_sync
  SetMonitoringModeResponseResult try_set_monitoring_mode_sync(ua::SetMonitoringModeRequest request) noexcept;

  // SetTriggering

  /// Result delivered for a SetTriggering request.
  using SetTriggeringResponseResult = ua::Result<ua::SetTriggeringResponse>;

  /// Callback receiving the outcome of a SetTriggering request.
  using SetTriggeringCallback = std::function<void(SetTriggeringResponseResult)>;

  /// Configures the triggering links between a triggering item and its triggered items.
  ///
  /// Sends the request to the server and completes asynchronously. The
  /// callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  The SetTriggering request to send.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref SetTriggeringResponse (whose per-link results report
  ///                 each add/remove link's individual status); on failure it
  ///                 carries an @ref ErrorDetail. This overload never throws.
  /// @see set_triggering_sync, try_set_triggering_sync
  void set_triggering_async(ua::SetTriggeringRequest request, SetTriggeringCallback callback) noexcept;

  /// Configures triggering links between monitored items, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The SetTriggering request to send.
  /// @return The SetTriggering response.
  /// @throws UaException if the service call fails at the request level.
  /// @see set_triggering_async, try_set_triggering_sync
  /// A Good subcode on the answer is not returned; try_set_triggering_sync() returns it.
  ua::SetTriggeringResponse set_triggering_sync(ua::SetTriggeringRequest request);

  /// Configures triggering links between monitored items, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The SetTriggering request to send.
  /// @return The SetTriggering response, or an @ref ErrorDetail on failure.
  ///         Never throws.
  /// @see set_triggering_async, set_triggering_sync
  SetTriggeringResponseResult try_set_triggering_sync(ua::SetTriggeringRequest request) noexcept;

  // DeleteMonitoredItems

  /// Result delivered for a DeleteMonitoredItems request.
  using DeleteMonitoredItemsResponseResult = ua::Result<ua::DeleteMonitoredItemsResponse>;

  /// Callback receiving the outcome of a DeleteMonitoredItems request.
  using DeleteMonitoredItemsCallback = std::function<void(DeleteMonitoredItemsResponseResult)>;

  /// Deletes monitored items from a subscription.
  ///
  /// Sends the request to the server and completes asynchronously. The
  /// callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  The DeleteMonitoredItems request to send.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref DeleteMonitoredItemsResponse (whose per-item results
  ///                 report each item's individual status); on failure it
  ///                 carries an @ref ErrorDetail. This overload never throws.
  /// @see delete_monitored_items_sync, try_delete_monitored_items_sync
  void delete_monitored_items_async(
    ua::DeleteMonitoredItemsRequest request, DeleteMonitoredItemsCallback callback) noexcept;

  /// Deletes monitored items from a subscription, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The DeleteMonitoredItems request to send.
  /// @return The DeleteMonitoredItems response.
  /// @throws UaException if the service call fails at the request level.
  /// @see delete_monitored_items_async, try_delete_monitored_items_sync
  /// A Good subcode on the answer is not returned; try_delete_monitored_items_sync() returns it.
  ua::DeleteMonitoredItemsResponse delete_monitored_items_sync(ua::DeleteMonitoredItemsRequest request);

  /// Deletes monitored items from a subscription, blocking until complete.
  ///
  /// Convenience wrapper for external callers; never call from inside the SDK,
  /// as it blocks the calling thread.
  ///
  /// @param request The DeleteMonitoredItems request to send.
  /// @return The DeleteMonitoredItems response, or an @ref ErrorDetail on
  ///         failure. Never throws.
  /// @see delete_monitored_items_async, delete_monitored_items_sync
  DeleteMonitoredItemsResponseResult try_delete_monitored_items_sync(
    ua::DeleteMonitoredItemsRequest request) noexcept;

private:
  friend class Session;
  explicit SessionMonitoredItemServices(std::weak_ptr<SessionImpl> impl);

  std::weak_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_SESSION_MONITORED_ITEM_SERVICES_H
