// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side OPC UA Session handle: activation, service-set access, and graceful close.
/// @ingroup client

#ifndef UA_CLIENT_SESSION_H
#define UA_CLIENT_SESSION_H

#include "ua_user_identity.h"

#include "ua_cancel_request.h"
#include "ua_cancel_response.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_structure_factory.h"
#include "ua_session_attribute_services.h"
#include "ua_session_discovery_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_node_management_services.h"
#include "ua_session_query_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"

#include <functional>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua::client
{

namespace detail
{
class RealSessionOps;
}

class SecureChannel;
class SessionImpl;

/// Move-only public handle for a client-side OPC UA Session.
///
/// Wraps a strand-serialized component (`SessionImpl`) behind a `shared_ptr`
/// pimpl. Not directly constructable: a Session is produced by the client
/// machinery (e.g. `SecureChannel::create_session`). Service operations are not
/// invoked on the Session directly; they are reached through the lightweight
/// service-set accessors returned by discovery(), view(), attributes(),
/// node_management(), methods(), subscriptions(), monitored_items(), and
/// query().
///
/// ## Lifecycle and ownership
///
/// At creation the session takes shared ownership of the SecureChannel it was
/// created from and holds it for as long as it uses it. Callers do not need to
/// retain their own SecureChannel handle to keep the session functional; the
/// session keeps the channel alive on its own.
///
/// Per OPC UA Part 4 5.6.2 a session survives channel loss. If the transport
/// drops, the session transitions to Disconnected, releases its channel
/// reference, and waits for the caller to rebind it via the
/// activate(SecureChannel, ...) overload. The server keeps the session alive
/// until its session timeout expires.
///
/// Graceful close is explicit: destroying the handle does NOT send CloseSession
/// to the server. To close cleanly, call close_async() / close_sync() and wait
/// for the callback / return before dropping the handle. Dropping the handle
/// without closing leaves the server to time the session out (default 60s of
/// inactivity, server-configurable).
///
/// @note Public methods may be called from any thread; each internally posts to
///       the session's private strand.
/// @ingroup client
class Session
{
public:
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  /// Move-constructs from @p other, transferring the underlying session reference.
  /// @post @p other is left empty; its destructor becomes a no-op (it no longer references a
  ///       session, so it sends no CloseSession). The moved-from handle must not be used.
  Session(Session&&) noexcept = default;

  /// Move-assigns from @p other, transferring the underlying session reference.
  ///
  /// Dropping this handle's prior reference does NOT close that session: as with the destructor,
  /// a graceful close is only sent via close_async() / close_sync(). If the prior session was the
  /// last strong reference, its impl is destroyed without notifying the server.
  /// @return Reference to this handle (`*this`).
  /// @post @p other is left empty; its destructor becomes a no-op. The moved-from handle must not
  ///       be used.
  Session& operator=(Session&&) noexcept = default;

  /// Releases this handle's reference to the underlying session.
  ///
  /// Does not send CloseSession to the server. If you want a graceful close,
  /// call close_async() / close_sync() and await completion before the handle
  /// is destroyed; otherwise the server times the session out on inactivity.
  ~Session();

  // ==================== Service Set Accessors ====================

  /// Returns the discovery service set (GetEndpoints, FindServers, ...) for this session.
  /// @return The discovery service set bound to this session.
  SessionDiscoveryServices discovery() const;

  /// Returns the view service set (Browse, BrowseNext, TranslateBrowsePaths, ...) for this session.
  /// @return The view service set bound to this session.
  SessionViewServices view() const;

  /// Returns the attribute service set (Read, Write, HistoryRead, ...) for this session.
  /// @return The attribute service set bound to this session.
  SessionAttributeServices attributes() const;

  /// Returns the node-management service set (AddNodes, AddReferences, DeleteNodes, ...).
  /// @return The node-management service set bound to this session.
  SessionNodeManagementServices node_management() const;

  /// Returns the method service set (Call) for this session.
  /// @return The method service set bound to this session.
  SessionMethodServices methods() const;

  /// Returns the subscription service set (CreateSubscription, Publish, ...) for this session.
  /// @return The subscription service set bound to this session.
  SessionSubscriptionServices subscriptions() const;

  /// Returns the monitored-item service set (CreateMonitoredItems, ModifyMonitoredItems, ...).
  /// @return The monitored-item service set bound to this session.
  SessionMonitoredItemServices monitored_items() const;

  /// Returns the query service set (QueryFirst, QueryNext) for this session.
  /// @return The query service set bound to this session.
  SessionQueryServices query() const;

  // ==================== Session Lifecycle ====================

  /// Parameters for an ActivateSession request.
  struct ActivateConfig
  {
    /// Identifier of the UserTokenPolicy to use, taken from the endpoint's
    /// UserTokenPolicies. Empty selects the anonymous policy automatically.
    std::string policyId;
    /// User identity to authenticate with. Defaults to `AnonymousIdentity{}`.
    UserIdentity identity;
    /// Preferred locale identifiers, in priority order, for server-returned
    /// localised text. Empty leaves the server default in effect.
    std::vector<ua::String> localeIds;
  };

  /// Callback invoked with the outcome of an activate operation.
  using ActivateCallback = std::function<void(ua::VoidResult)>;

  /// Activates the session on its currently-bound channel.
  ///
  /// Sends ActivateSessionRequest on the channel the session was created from
  /// (or the most recent channel passed to the activate(SecureChannel, ...)
  /// overload) and transitions the session Created -> Active. Completes
  /// asynchronously; the callback runs on the client's executor and must not
  /// block.
  ///
  /// @param config   Activation parameters (token policy, identity, locales).
  /// @param callback Receives the outcome: a successful @ref VoidResult on
  ///                 activation, otherwise a Result carrying an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see activate_sync, try_activate_sync
  void activate_async(ActivateConfig config, ActivateCallback callback) noexcept;

  /// Activates the session on its currently-bound channel, blocking until complete.
  ///
  /// @param config Activation parameters (token policy, identity, locales).
  /// @throws UaException if activation fails.
  /// @see activate_async, try_activate_sync
  void activate_sync(ActivateConfig config = {});

  /// Activates the session on its currently-bound channel, blocking until complete.
  ///
  /// @param config Activation parameters (token policy, identity, locales).
  /// @return A successful @ref VoidResult, or an @ref ErrorDetail on failure. Never throws.
  /// @see activate_async, activate_sync
  ua::VoidResult try_activate_sync(ActivateConfig config = {}) noexcept;

  /// Activates (or re-activates) the session on a different channel.
  ///
  /// Used both for the reconnection flow (after a transport drop) and to switch
  /// a session onto a new channel for any reason. Valid from the Disconnected,
  /// Created, or Active states. Completes asynchronously; the callback runs on
  /// the client's executor and must not block.
  ///
  /// The session takes shared ownership of @p channel, so the caller need not
  /// retain its own SecureChannel handle to keep the session functional. The
  /// previously-bound channel (if any) is released; if no other strong
  /// reference exists, that channel's impl is destroyed.
  ///
  /// @param channel  Channel to bind and activate on; ownership is shared by the session.
  /// @param config   Activation parameters (token policy, identity, locales).
  /// @param callback Receives the outcome: a successful @ref VoidResult on
  ///                 activation, otherwise a Result carrying an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see activate_sync, try_activate_sync
  void activate_async(SecureChannel channel, ActivateConfig config, ActivateCallback callback) noexcept;

  /// Activates (or re-activates) the session on a different channel, blocking until complete.
  ///
  /// @param channel Channel to bind and activate on; ownership is shared by the session.
  /// @param config  Activation parameters (token policy, identity, locales).
  /// @throws UaException if activation fails.
  /// @see activate_async, try_activate_sync
  void activate_sync(SecureChannel channel, ActivateConfig config = {});

  /// Activates (or re-activates) the session on a different channel, blocking until complete.
  ///
  /// @param channel Channel to bind and activate on; ownership is shared by the session.
  /// @param config  Activation parameters (token policy, identity, locales).
  /// @return A successful @ref VoidResult, or an @ref ErrorDetail on failure. Never throws.
  /// @see activate_async, activate_sync
  ua::VoidResult try_activate_sync(SecureChannel channel, ActivateConfig config = {}) noexcept;

  // ==================== Session Service Set ====================

  // Cancel

  /// Result of a Cancel operation: the @ref CancelResponse, or an @ref ErrorDetail.
  using CancelResponseResult = ua::Result<ua::CancelResponse>;

  /// Callback invoked with the outcome of a cancel operation.
  using CancelCallback = std::function<void(CancelResponseResult)>;

  /// Requests cancellation of outstanding service requests.
  ///
  /// Sends a Cancel request that asks the server to cancel any in-progress
  /// requests carrying the request handle named in @p request. Completes
  /// asynchronously; the callback runs on the client's executor and must not
  /// block.
  ///
  /// @param request  The Cancel request identifying the work to cancel.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref CancelResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see cancel_sync, try_cancel_sync
  void cancel_async(ua::CancelRequest request, CancelCallback callback) noexcept;

  /// Requests cancellation of outstanding service requests, blocking until complete.
  ///
  /// @param request The Cancel request identifying the work to cancel.
  /// @return The server's @ref CancelResponse.
  /// @throws UaException if the request fails.
  /// @see cancel_async, try_cancel_sync
  /// A Good subcode on the answer is not returned; try_cancel_sync() returns it.
  ua::CancelResponse cancel_sync(ua::CancelRequest request);

  /// Requests cancellation of outstanding service requests, blocking until complete.
  ///
  /// @param request The Cancel request identifying the work to cancel.
  /// @return The @ref CancelResponse, or an @ref ErrorDetail on failure. Never throws.
  /// @see cancel_async, cancel_sync
  CancelResponseResult try_cancel_sync(ua::CancelRequest request) noexcept;

  // ==================== Close ====================

  /// Callback invoked with the outcome of a close operation.
  using CloseCallback = std::function<void(ua::VoidResult)>;

  /// Options for closing a Session.
  struct CloseOptions
  {
    /// Whether the server destroys this Session's Subscriptions on close (OPC 10000-4 5.6.4).
    ///
    /// `true` (the default, and the historical behaviour) destroys them. `false` leaves them PARKED on
    /// the server so a later Session can reclaim them with TransferSubscriptions - the documented way to
    /// survive a Session change without losing subscriptions. Parked Subscriptions are bounded by the
    /// server's `ResourceLimits::orphanedSubscriptionStore` and still expire on their own lifetime, so
    /// a client that parks and never returns does not strand them indefinitely.
    bool deleteSubscriptions = true;
  };

  /// Gracefully closes the session.
  ///
  /// Sends CloseSessionRequest, transitions the session to Closed, and releases
  /// the bound channel reference (which may then destroy the channel impl if no
  /// other strong reference exists). Completes asynchronously; the callback runs
  /// on the client's executor and must not block.
  ///
  /// Call this (or close_sync() / try_close_sync()) before dropping the Session
  /// handle if you want the server to observe CloseSession: the destructor does
  /// not close, so dropping the handle without an explicit close leaves the
  /// server to time the session out (typically within 60s). Idempotent: closing
  /// an already-closed session is a no-op success.
  ///
  /// @param callback Receives the outcome: a successful @ref VoidResult on
  ///                 close, otherwise a Result carrying an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see close_sync, try_close_sync
  void close_async(CloseCallback callback) noexcept;

  /// Closes the session with explicit options.
  ///
  /// @param config   Close options; see @ref CloseOptions::deleteSubscriptions.
  /// @param callback Receives the outcome. This overload never throws.
  void close_async(CloseOptions config, CloseCallback callback) noexcept;

  /// Gracefully closes the session, blocking until complete.
  ///
  /// Idempotent: closing an already-closed session is a no-op success.
  ///
  /// @throws UaException if the close fails.
  /// @see close_async, try_close_sync
  void close_sync();

  /// Gracefully closes the session, blocking until complete.
  ///
  /// Idempotent: closing an already-closed session is a no-op success.
  ///
  /// @return A successful @ref VoidResult, or an @ref ErrorDetail on failure. Never throws.
  /// @see close_async, close_sync
  ua::VoidResult try_close_sync() noexcept;

  /// Closes the session with explicit options, blocking until complete.
  ///
  /// @param config Close options; see @ref CloseOptions::deleteSubscriptions.
  /// @throws UaException if the close fails.
  /// @see close_async, try_close_sync
  void close_sync(CloseOptions config);

  /// Closes the session with explicit options, blocking until complete.
  ///
  /// @param config Close options; see @ref CloseOptions::deleteSubscriptions.
  /// @return A successful @ref VoidResult, or an @ref ErrorDetail on failure. Never throws.
  ua::VoidResult try_close_sync(CloseOptions config) noexcept;

  // ==================== Queries ====================

  /// Returns the server-assigned session identifier.
  ///
  /// Meaningful once the session has been created on the server; a null
  /// @ref NodeId before then.
  /// @return The server-assigned session identifier, or a null @ref NodeId before the session
  ///         has been created on the server.
  ua::NodeId session_id() const;

  /// Returns the server's revised session timeout in milliseconds, as agreed in the CreateSession response.
  ///
  /// The server MAY revise the requested session timeout up or down; this returns the value in effect for
  /// this session. Meaningful once the session has been created on the server; `0.0` before then.
  /// @return The revised session timeout in milliseconds, or `0.0` before the session has been created.
  double revised_session_timeout_ms() const;

  /// Returns whether the session is in the Created state (created but not yet activated).
  /// @return `true` if the session is Created but not yet activated; otherwise `false`.
  bool is_created() const;

  /// Returns whether the session is in the Active state (activated and usable for service calls).
  /// @return `true` if the session is Active and usable for service calls; otherwise `false`.
  bool is_active() const;

  /// Returns whether the session is in the Disconnected state (its channel was lost).
  ///
  /// A disconnected session can be brought back by re-binding it through the
  /// activate(SecureChannel, ...) overload.
  /// @return `true` if the session is Disconnected (its channel was lost); otherwise `false`.
  bool is_disconnected() const;

private:
  /// Shared body of the two close_async overloads.
  void close_impl(bool deleteSubscriptions, CloseCallback callback) noexcept;

  friend class detail::RealSessionOps;
  friend class SessionImpl;
  friend class SecureChannel;
  friend class SessionTestAccess;
  explicit Session(std::shared_ptr<SessionImpl> impl);
  void set_return_diagnostics_override(std::optional<std::uint32_t> mask) noexcept;

  std::shared_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_CLIENT_SESSION_H
