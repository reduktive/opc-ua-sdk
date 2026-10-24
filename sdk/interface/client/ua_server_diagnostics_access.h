// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_DIAGNOSTICS_ACCESS_H
#define UA_SERVER_DIAGNOSTICS_ACCESS_H

/// @file
/// @brief Tier-2 public `ServerDiagnostics` typed-read accessor (client design section 8.18.1.c): the
/// per-`Connection`
///        accessor for the ns0 `Server.ServerDiagnostics` diagnostic node hierarchy. Reached via
///        `Connection::server_diagnostics()`. This slice (10d-3) builds the READ cluster only:
///        - `summary_async`  -  the one-shot `ServerDiagnosticsSummary` read (CL-BASEDIAG-002).
///        - `sessions_async` / `sessions_security_async` / `subscriptions_async` /
///          `sampling_intervals_async`  -  the diagnostic-array reads with a cached `EnabledFlag` +
///          disabled-advisory (CL-BASEDIAG-003).
///        - `set_enabled_flag_async`  -  the `EnabledFlag` mutator (server may reject verbatim).
/// @ingroup client
///
/// The accessor is a cheap, copyable value handle over the same tier-1 wire interface as its parent
/// @ref ua::client::Connection (`detail::WireOps` + `detail::SupportOps`, both `weak_ptr`, never a
/// `weak_ptr<ConnectionImpl>`, section 8.2A.13). Every op locks the interface per call and completes
/// `Bad_ConnectionClosed` if the Connection is gone. The `EnabledFlag` TTL cache (section 8.18.2) is held
/// behind a `shared_ptr` so every copy of the accessor shares one cache.
///
/// CL-BASEDIAG-004 `subscribe_sessions_async` / `subscribe_subscriptions_async` (subscribe-over-poll) ride a
/// managed Subscription + data-change MonitoredItem created through the `detail::SupportOps` subscription
/// factory interface.

#include "ua_client_monitored_item.h"
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_sampling_interval_diagnostics_data_type.h"
#include "ua_server_diagnostics_summary_data_type.h"
#include "ua_session_diagnostics_data_type.h"
#include "ua_session_security_diagnostics_data_type.h"
#include "ua_subscription_diagnostics_data_type.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <memory>
#include <vector>

namespace ua::client
{

namespace detail
{
class WireOps;
class SupportOps;
struct ServerDiagnosticsCacheState;
struct ServerDiagnosticsClientTestAccess;
}  // namespace detail

class Connection;

/// Callback invoked for server diagnostics summary result notifications.
using ServerDiagnosticsSummaryResult = ua::Result<ua::ServerDiagnosticsSummaryDataType>;
/// Callback invoked for session diagnostics array result notifications.
using SessionDiagnosticsArrayResult = ua::Result<std::vector<ua::SessionDiagnosticsDataType>>;
/// Callback invoked for session security diagnostics array result notifications.
using SessionSecurityDiagnosticsArrayResult = ua::Result<std::vector<ua::SessionSecurityDiagnosticsDataType>>;
/// Callback invoked for subscription diagnostics array result notifications.
using SubscriptionDiagnosticsArrayResult = ua::Result<std::vector<ua::SubscriptionDiagnosticsDataType>>;
/// Callback invoked for sampling interval diagnostics array result notifications.
using SamplingIntervalDiagnosticsArrayResult =
  ua::Result<std::vector<ua::SamplingIntervalDiagnosticsDataType>>;

/// The callback a @ref ServerDiagnosticsAccessor::subscribe_sessions_async consumer registers; invoked (on
/// the executor) with the decoded `SessionDiagnosticsArray` on every data-change notification
/// (CL-BASEDIAG-004).
using SessionsArrayCallback = std::function<void(std::vector<ua::SessionDiagnosticsDataType>)>;

/// The callback a @ref ServerDiagnosticsAccessor::subscribe_subscriptions_async consumer registers; invoked
/// (on the executor) with the decoded `SubscriptionDiagnosticsArray` on every data-change notification.
using SubscriptionsArrayCallback = std::function<void(std::vector<ua::SubscriptionDiagnosticsDataType>)>;

/// The per-`Connection` tier-2 accessor for `Server.ServerDiagnostics` (client design section 8.18.1.c). A
/// lightweight, copyable value handle over the same tier-1 wire interface as its parent @ref
/// ua::client::Connection, reached via `Connection::server_diagnostics()`.
///
/// **Cycle-safe (section 9.8.3).** The accessor holds only `weak_ptr` interface roles (`detail::WireOps` +
/// `detail::SupportOps`), never a `weak_ptr<ConnectionImpl>` (section 8.2A.13). Locks are taken per op and
/// a boundary failure is delivered on the executor if the Connection is gone.
///
/// **Cache lifetime (section 8.18.2).** The `EnabledFlag` TTL cache lives on the accessor value handle, so
/// the 60 s staleness benefit accrues only while the caller HOLDS one accessor across calls. The throwaway
/// idiom `connection.server_diagnostics().sessions_async(cb)` builds a fresh accessor (fresh cache) per call,
/// so it re-reads the flag every time; hold an accessor (`auto diag = connection.server_diagnostics();`) to
/// reuse the cache.
///
/// **Status codes.** A read's Result (the summary and the four arrays) carries the Read's ServiceResult and
/// the DataValue's status combined (`ua::detail::combined_status`), so a Good subcode or an Uncertain code
/// the server answers reaches the caller with the value; a Bad status fails the read, and a status that is
/// not Good on a null value is answered without a value. The `EnabledFlag` read beside an array is used (for
/// the cache and the advisory) only when the server answers it Good. set_enabled_flag's Result is the
/// ServiceResult and the write's status combined; only a Good write refreshes the cache. A subscribe's Result
/// carries the Subscription's code and the MonitoredItem's combined. Each plain-value `*_sync` form throws
/// unless the Result is Good; a Good subcode on the answer is returned only by its `try_*_sync` form.
/// @ingroup client
class ServerDiagnosticsAccessor
{
public:
  /// Returns or updates the server diagnostics accessor.
  ServerDiagnosticsAccessor(const ServerDiagnosticsAccessor&) = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  ServerDiagnosticsAccessor& operator=(const ServerDiagnosticsAccessor&) = default;
  /// Returns or updates the server diagnostics accessor.
  ServerDiagnosticsAccessor(ServerDiagnosticsAccessor&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  ServerDiagnosticsAccessor& operator=(ServerDiagnosticsAccessor&&) noexcept = default;
  ~ServerDiagnosticsAccessor() = default;

  /// CL-BASEDIAG-002  -  Reads `Server.ServerDiagnostics.ServerDiagnosticsSummary` (a Variant holding an
  /// ExtensionObject of `ServerDiagnosticsSummaryDataType`) and decodes it with the generated decoder (no
  /// @param callback Completion callback that receives the operation result.
  /// projection / renaming). A Bad service response or a Bad `DataValue` quality surfaces via the `Result`
  /// with source `client.tier2.server_diagnostics.summary`.
  void summary_async(std::function<void(ServerDiagnosticsSummaryResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously summary. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_summary_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  ua::ServerDiagnosticsSummaryDataType summary_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to summary sync without throwing.
  ua::Result<ua::ServerDiagnosticsSummaryDataType> try_summary_sync() noexcept;

  /// CL-BASEDIAG-003  -  Reads the `SessionDiagnosticsArray` (a Variant array of `SessionDiagnosticsDataType`
  /// @param callback Completion callback that receives the operation result.
  /// ExtensionObjects). If the cached `EnabledFlag` is absent / stale (>60 s) the flag is batch-Read
  /// alongside; when it resolves `false` a disabled-advisory is logged (source
  /// `client.tier2.server_diagnostics.diagnostics_disabled`). The array result is delivered regardless of the
  /// flag (data + advisory, not a blocked call).
  void sessions_async(std::function<void(SessionDiagnosticsArrayResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously sessions. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_sessions_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  std::vector<ua::SessionDiagnosticsDataType> sessions_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to sessions sync without throwing.
  ua::Result<std::vector<ua::SessionDiagnosticsDataType>> try_sessions_sync() noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// CL-BASEDIAG-003  -  Reads the `SessionSecurityDiagnosticsArray`. Same EnabledFlag / advisory contract as
  /// @ref sessions_async.
  void sessions_security_async(std::function<void(SessionSecurityDiagnosticsArrayResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously sessions security. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_sessions_security_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  std::vector<ua::SessionSecurityDiagnosticsDataType> sessions_security_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to sessions security sync without throwing.
  ua::Result<std::vector<ua::SessionSecurityDiagnosticsDataType>> try_sessions_security_sync() noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// CL-BASEDIAG-003  -  Reads the `SubscriptionDiagnosticsArray`. Same EnabledFlag / advisory contract as
  /// @ref sessions_async.
  void subscriptions_async(std::function<void(SubscriptionDiagnosticsArrayResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously subscriptions. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_subscriptions_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  std::vector<ua::SubscriptionDiagnosticsDataType> subscriptions_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to subscriptions sync without throwing.
  ua::Result<std::vector<ua::SubscriptionDiagnosticsDataType>> try_subscriptions_sync() noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// CL-BASEDIAG-003  -  Reads the `SamplingIntervalDiagnosticsArray`. Same EnabledFlag / advisory contract
  /// as
  /// @ref sessions_async.
  void sampling_intervals_async(
    std::function<void(SamplingIntervalDiagnosticsArrayResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously sampling intervals. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_sampling_intervals_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  std::vector<ua::SamplingIntervalDiagnosticsDataType> sampling_intervals_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to sampling intervals sync without throwing.
  ua::Result<std::vector<ua::SamplingIntervalDiagnosticsDataType>> try_sampling_intervals_sync() noexcept;

  /// @param enabled The enabled.
  /// @param callback Completion callback that receives the operation result.
  /// Writes `Server.ServerDiagnostics.EnabledFlag`. The server may reject with `Bad_UserAccessDenied` when
  /// the caller's identity lacks privilege  -  that status is surfaced verbatim (chained beneath source
  /// `client.tier2.server_diagnostics.set_enabled_flag`). The Result is the ServiceResult and the write's
  /// status combined, so a Good subcode or an Uncertain code reaches the caller. On a Good write the local
  /// TTL cache is refreshed with the written value; an Uncertain one leaves it as it was.
  void set_enabled_flag_async(bool enabled, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param enabled The enabled.
  /// Synchronously set enabled flag. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void set_enabled_flag_sync(bool enabled);
  /// @param enabled The enabled.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to set enabled flag sync without throwing.
  ua::VoidResult try_set_enabled_flag_sync(bool enabled) noexcept;

  /// CL-BASEDIAG-004  -  subscribe-over-poll for the `SessionDiagnosticsArray`. Creates a managed
  /// Subscription and a data-change MonitoredItem on the array Variable (default `samplingIntervalMs = 0.0`
  /// server-chosen, `StatusValueTimestamp` `DataChangeFilter`) through the `detail::SupportOps`
  /// subscription-factory interface, decodes each notification into the `SessionDiagnosticsArray` and
  /// delivers it to @p onSessions; @p onSessions has no place for a status, so it receives the array of every
  /// notification that holds one, an Uncertain one included, and a Bad notification (whose value is null) is
  /// not delivered. Returns the unified @ref ua::client::MonitoredItem (kind() ==
  /// DataChange), which is persist-on-drop (D-DIAG-1)  -  the caller stops the stream explicitly via
  /// `item.delete_async()`. A gone Connection completes `Bad_ConnectionClosed`. Both callbacks run on the
  /// executor.
  /// @param onSessions Callback receiving each decoded diagnostics-array update.
  /// @param callback Completion callback receiving the created MonitoredItem.
  void subscribe_sessions_async(
    SessionsArrayCallback onSessions, std::function<void(ua::client::MonitoredItemResult)> callback) noexcept;
  /// @param onSessions The onsessions.
  /// @return The requested value.
  /// Synchronously subscribe sessions. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_subscribe_sessions_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  ua::client::MonitoredItem subscribe_sessions_sync(SessionsArrayCallback onSessions);
  /// @param onSessions The onsessions.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to subscribe sessions sync without throwing.
  ua::Result<ua::client::MonitoredItem> try_subscribe_sessions_sync(
    SessionsArrayCallback onSessions) noexcept;

  /// @param onSubscriptions The on subscriptions.
  /// @param callback Completion callback that receives the operation result.
  /// CL-BASEDIAG-004  -  subscribe-over-poll for the `SubscriptionDiagnosticsArray`. Same contract as
  /// @ref subscribe_sessions_async, decoding each notification into the `SubscriptionDiagnosticsArray`.
  void subscribe_subscriptions_async(SubscriptionsArrayCallback onSubscriptions,
    std::function<void(ua::client::MonitoredItemResult)> callback) noexcept;
  /// @param onSubscriptions The onsubscriptions.
  /// @return The requested value.
  /// Synchronously subscribe subscriptions. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_subscribe_subscriptions_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  ua::client::MonitoredItem subscribe_subscriptions_sync(SubscriptionsArrayCallback onSubscriptions);
  /// @param onSubscriptions The onsubscriptions.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to subscribe subscriptions sync without throwing.
  ua::Result<ua::client::MonitoredItem> try_subscribe_subscriptions_sync(
    SubscriptionsArrayCallback onSubscriptions) noexcept;

private:
  friend class Connection;
  friend struct ua::client::detail::ServerDiagnosticsClientTestAccess;

  ServerDiagnosticsAccessor(std::weak_ptr<detail::WireOps> wireOps,
    std::weak_ptr<detail::SupportOps> supportOps, boost::asio::any_io_executor executor, ua::Logger logger,
    std::shared_ptr<detail::ServerDiagnosticsCacheState> cacheState,
    std::function<void(std::shared_ptr<const ua::ErrorDetail>)> emitAdvisory);

  std::weak_ptr<detail::WireOps>
    mWireOps;  ///< upward wire interface (section 8.2A.13); locked per op, bail if gone
  std::weak_ptr<detail::SupportOps>
    mSupportOps;  ///< upward support interface (section 8.2A.13); locked per op
  boost::asio::any_io_executor mExecutor;  ///< where results / boundary failures are delivered
  ua::Logger mLogger;  ///< logs the disabled-advisory at the wire boundary (CL-BASEDIAG-003)
  std::shared_ptr<detail::ServerDiagnosticsCacheState> mCacheState;  ///< the EnabledFlag TTL cache (shared)
  std::function<void(std::shared_ptr<const ua::ErrorDetail>)>
    mEmitAdvisory;  ///< weak ConnectionObserver fan-out; empty for inert/test accessors
};

}  // namespace ua::client

#endif  // UA_SERVER_DIAGNOSTICS_ACCESS_H
