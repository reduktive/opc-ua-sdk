// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side OPC UA Secure Channel handle and its discovery,
///        session-creation, and LDS-registration surface.
/// @ingroup client

#ifndef UA_CLIENT_SECURE_CHANNEL_H
#define UA_CLIENT_SECURE_CHANNEL_H

#include "ua_client_session.h"

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_endpoint_description.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_find_servers_on_network_request.h"
#include "ua_find_servers_on_network_response.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_logger.h"
#include "ua_register_server2_request.h"
#include "ua_register_server2_response.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_result.h"
#include "ua_structure_factory.h"

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua::client
{

class SecureChannelImpl;

namespace detail
{
struct OpenChannelOrchestrator;
}

/// Public handle for a client-side OPC UA Secure Channel.
///
/// Wraps a strand-serialized component (`SecureChannelImpl`) through a
/// `shared_ptr` pimpl, so every method may be called from any thread; the
/// implementation serializes work on its own internal strand. The handle is
/// not directly constructable - instances are produced by `CoreClientImpl` or by
/// `SecureChannelImpl::create()`.
///
/// This is a move-only handle. Move-only is what guarantees that
/// `close_async`'s move-into-lambda plus reset releases the *last* strong
/// reference, so the owning thread pool's `join()` can return.
///
/// ## Lifecycle and ownership
///
/// A SecureChannel can be used standalone (for the discovery services
/// below - GetEndpoints, FindServers, FindServersOnNetwork) or as the
/// transport for one or more Sessions.
///
/// When the channel is used to create a Session (via `create_session_async`),
/// or when the channel is passed to `Session::activate(channel, ...)`, the
/// session takes shared ownership of the channel. The caller does not need to
/// retain this `SecureChannel` handle to keep the session functional; the
/// session keeps the channel alive on its own.
///
/// Graceful close is explicit. Destroying the SecureChannel handle does NOT
/// send a CloseSecureChannel message to the server. To close gracefully, call
/// `close_async` / `close_sync` and wait for the callback / return before
/// dropping the handle. If you drop the handle without calling close, the
/// server will eventually time the channel out per its configured channel
/// lifetime.
///
/// @ingroup client
class SecureChannel
{
public:
  /// Copying is disabled; the handle owns a unique share of the channel impl.
  SecureChannel(const SecureChannel&) = delete;
  /// Copy assignment is disabled; the handle owns a unique share of the impl.
  SecureChannel& operator=(const SecureChannel&) = delete;
  /// Transfers ownership of the underlying channel impl; the source is left empty.
  SecureChannel(SecureChannel&&) noexcept = default;
  /// Transfers ownership of the underlying channel impl; the source is left empty.
  /// @return Reference to this handle (`*this`).
  SecureChannel& operator=(SecureChannel&&) noexcept = default;

  /// Releases this handle's share of the channel impl.
  ///
  /// Does not send a CloseSecureChannel message and does not close the
  /// transport. Call `close_async` / `close_sync` / `try_close_sync` first for
  /// a graceful close.
  ~SecureChannel();

  // --- Session creation ---

  /// Parameters controlling the session created by `create_session_async`.
  struct CreateSessionConfig
  {
    /// Requested session timeout; `nullopt` uses the ClientConfig default.
    std::optional<std::chrono::milliseconds> requestedSessionTimeout;
    std::string sessionName;  ///< Human-readable session name reported to the server.

    /// EndpointDescriptions obtained from the unauthenticated DiscoveryEndpoint and used to select this
    /// SecureChannel. When non-empty, CreateSession verifies them against the authenticated response before
    /// accepting the Session (OPC 10000-4 section 5.4.1). Leave empty only when no discovery result was used
    /// (for example an explicit ExactUrl connection).
    std::vector<ua::EndpointDescription> discoveryEndpoints;

    /// ECC SecurityPolicyUri planned for the first encrypted UserIdentityToken. When set, CreateSession
    /// sends it as ECDHPolicyUri so the Server returns an EphemeralKey for that token policy
    /// (OPC 10000-6 section 6.8.3). Managed connections populate this from the selected UserTokenPolicy.
    std::string ecdhPolicyUri;

    /// Whether CreateSession on a key-agreement channel (ECC, RSA_DH) asks for an EphemeralKey, naming
    /// @ref ecdhPolicyUri or else the channel's policy. Default `true`; ignored on other channels. The key
    /// encrypts a UserName or IssuedToken secret (OPC 10000-6 section 6.8.2), so with `false` a later
    /// ActivateSession whose token needs one is refused by the client (Bad_SecurityChecksFailed, ErrorDetail
    /// `EphemeralKeyNotSolicited`). A managed connect that knows the endpoint's token policies (endpoint
    /// selection from discovery, easy_connect) sets `false` when the endpoint offers neither token type, and
    /// its reconnects keep that choice: no activation could use the key, and a Server may fault the request.
    bool requestEphemeralKey = true;

    /// Downgrades a server-certificate/endpointUrl HostName mismatch to a logged advisory. False is the
    /// fail-closed default.
    bool relaxHostNameCheck = false;

    /// Provider threaded from managed ConnectionConfig for RequestHeader.auditEntryId stamping.
    std::function<ua::String()> auditEntryIdProvider;

    /// Internal/advanced override for every Session RequestHeader, including CreateSession and activation.
    std::optional<std::uint32_t> returnDiagnosticsOverride;

    /// Called when the session closes unexpectedly after activation.
    ///
    /// Receives the full error chain, including any server diagnostics, as a
    /// `VoidResult`. Posted to the client's executor (not the session's
    /// internal strand). At-most-once. Must not block.
    std::function<void(ua::VoidResult)> onSessionError;
  };

  /// Outcome of session creation: the created (NOT yet activated) @ref Session, or an
  /// @ref ErrorDetail.
  using SessionResult = ua::Result<Session>;
  /// Callback receiving the outcome of `create_session_async`.
  using CreateSessionCallback = std::function<void(SessionResult)>;

  /// Creates a session on this channel. **Does not activate it.**
  ///
  /// This sends `CreateSession` only. The returned Session is in the Created state and is not
  /// usable for any service until you call @ref Session::activate_async (or its blocking
  /// variants): a service issued on a Created-but-not-Activated session is refused by the
  /// server. The split is deliberate - it is what lets a caller activate with a chosen user
  /// identity, and re-activate an existing Session on a new channel after a reconnect.
  ///
  /// The returned Session takes shared ownership of the channel; after this
  /// call the caller does not need to retain this `SecureChannel` handle to
  /// keep the session usable. May be called from any thread.
  ///
  /// @param config   Session parameters; see @ref CreateSessionConfig.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 created @ref Session, which still requires activation; on failure it
  ///                 carries an @ref ErrorDetail. This overload never throws.
  /// @see Session::activate_async, create_session_sync, try_create_session_sync
  void create_session_async(CreateSessionConfig config, CreateSessionCallback callback) noexcept;

  /// Creates a session on this channel, blocking until complete. **Does not activate it.**
  ///
  /// See @ref create_session_async for the create/activate split.
  ///
  /// @param config Session parameters; see @ref CreateSessionConfig.
  /// @return The created session, which still requires @ref Session::activate_sync.
  /// @throws ua::UaException if session creation fails.
  /// @see Session::activate_sync, create_session_async, try_create_session_sync
  /// A Good subcode on the answer is not returned; try_create_session_sync() returns it.
  Session create_session_sync(CreateSessionConfig config);

  /// Creates a session on this channel, blocking until complete. **Does not activate it.**
  ///
  /// See @ref create_session_async for the create/activate split.
  ///
  /// @param config Session parameters; see @ref CreateSessionConfig.
  /// @return The created session (still requiring activation), or an @ref ErrorDetail on
  ///         failure. Never throws.
  /// @see Session::activate_async, create_session_async, create_session_sync
  SessionResult try_create_session_sync(CreateSessionConfig config) noexcept;

  // --- Discovery services (no session required) ---

  // GetEndpoints
  /// Outcome of GetEndpoints: the @ref GetEndpointsResponse, or an @ref ErrorDetail.
  using GetEndpointsResponseResult = ua::Result<ua::GetEndpointsResponse>;
  /// Callback receiving the outcome of `get_endpoints_async`.
  using GetEndpointsCallback = std::function<void(GetEndpointsResponseResult)>;

  /// Invokes the GetEndpoints discovery service on this channel.
  ///
  /// No session is required. May be called from any thread.
  ///
  /// @param request  The GetEndpoints request.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref GetEndpointsResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see get_endpoints_sync, try_get_endpoints_sync
  void get_endpoints_async(ua::GetEndpointsRequest request, GetEndpointsCallback callback) noexcept;

  /// Invokes the GetEndpoints discovery service, blocking until complete.
  ///
  /// @param request The GetEndpoints request.
  /// @return The GetEndpoints response.
  /// @throws ua::UaException if the call fails.
  /// @see get_endpoints_async, try_get_endpoints_sync
  /// A Good subcode on the answer is not returned; try_get_endpoints_sync() returns it.
  ua::GetEndpointsResponse get_endpoints_sync(ua::GetEndpointsRequest request);

  /// Invokes the GetEndpoints discovery service, blocking until complete.
  ///
  /// @param request The GetEndpoints request.
  /// @return The GetEndpoints response, or an @ref ErrorDetail on failure. Never throws.
  /// @see get_endpoints_async, get_endpoints_sync
  GetEndpointsResponseResult try_get_endpoints_sync(ua::GetEndpointsRequest request) noexcept;

  // FindServers
  /// Outcome of FindServers: the @ref FindServersResponse, or an @ref ErrorDetail.
  using FindServersResponseResult = ua::Result<ua::FindServersResponse>;
  /// Callback receiving the outcome of `find_servers_async`.
  using FindServersCallback = std::function<void(FindServersResponseResult)>;

  /// Invokes the FindServers discovery service on this channel.
  ///
  /// No session is required. May be called from any thread.
  ///
  /// @param request  The FindServers request.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref FindServersResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see find_servers_sync, try_find_servers_sync
  void find_servers_async(ua::FindServersRequest request, FindServersCallback callback) noexcept;

  /// Invokes the FindServers discovery service, blocking until complete.
  ///
  /// @param request The FindServers request.
  /// @return The FindServers response.
  /// @throws ua::UaException if the call fails.
  /// @see find_servers_async, try_find_servers_sync
  /// A Good subcode on the answer is not returned; try_find_servers_sync() returns it.
  ua::FindServersResponse find_servers_sync(ua::FindServersRequest request);

  /// Invokes the FindServers discovery service, blocking until complete.
  ///
  /// @param request The FindServers request.
  /// @return The FindServers response, or an @ref ErrorDetail on failure. Never throws.
  /// @see find_servers_async, find_servers_sync
  FindServersResponseResult try_find_servers_sync(ua::FindServersRequest request) noexcept;

  // FindServersOnNetwork
  /// Outcome of FindServersOnNetwork: the response, or an @ref ErrorDetail.
  using FindServersOnNetworkResponseResult = ua::Result<ua::FindServersOnNetworkResponse>;
  /// Callback receiving the outcome of `find_servers_on_network_async`.
  using FindServersOnNetworkCallback = std::function<void(FindServersOnNetworkResponseResult)>;

  /// Invokes the FindServersOnNetwork discovery service on this channel.
  ///
  /// No session is required. May be called from any thread.
  ///
  /// @param request  The FindServersOnNetwork request.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref FindServersOnNetworkResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see find_servers_on_network_sync, try_find_servers_on_network_sync
  void find_servers_on_network_async(
    ua::FindServersOnNetworkRequest request, FindServersOnNetworkCallback callback) noexcept;

  /// Invokes the FindServersOnNetwork discovery service, blocking until complete.
  ///
  /// @param request The FindServersOnNetwork request.
  /// @return The FindServersOnNetwork response.
  /// @throws ua::UaException if the call fails.
  /// @see find_servers_on_network_async, try_find_servers_on_network_sync
  /// A Good subcode on the answer is not returned; try_find_servers_on_network_sync() returns it.
  ua::FindServersOnNetworkResponse find_servers_on_network_sync(ua::FindServersOnNetworkRequest request);

  /// Invokes the FindServersOnNetwork discovery service, blocking until complete.
  ///
  /// @param request The FindServersOnNetwork request.
  /// @return The FindServersOnNetwork response, or an @ref ErrorDetail on failure.
  ///         Never throws.
  /// @see find_servers_on_network_async, find_servers_on_network_sync
  FindServersOnNetworkResponseResult try_find_servers_on_network_sync(
    ua::FindServersOnNetworkRequest request) noexcept;

  // --- LDS registration (no session required) - KEYSTONE ---

  /// Outcome of RegisterServer: the @ref RegisterServerResponse, or an @ref ErrorDetail.
  using RegisterServerResponseResult = ua::Result<ua::RegisterServerResponse>;
  /// Callback receiving the outcome of `register_server_async`.
  using RegisterServerCallback = std::function<void(RegisterServerResponseResult)>;

  /// Registers a server with a Local Discovery Server over this channel.
  ///
  /// No session is required. May be called from any thread.
  ///
  /// @param request  The RegisterServer request.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref RegisterServerResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see register_server_sync, try_register_server_sync
  void register_server_async(ua::RegisterServerRequest request, RegisterServerCallback callback) noexcept;

  /// Registers a server with a Local Discovery Server, blocking until complete.
  ///
  /// @param request The RegisterServer request.
  /// @return The RegisterServer response.
  /// @throws ua::UaException if the call fails.
  /// @see register_server_async, try_register_server_sync
  /// A Good subcode on the answer is not returned; try_register_server_sync() returns it.
  ua::RegisterServerResponse register_server_sync(ua::RegisterServerRequest request);

  /// Registers a server with a Local Discovery Server, blocking until complete.
  ///
  /// @param request The RegisterServer request.
  /// @return The RegisterServer response, or an @ref ErrorDetail on failure. Never throws.
  /// @see register_server_async, register_server_sync
  RegisterServerResponseResult try_register_server_sync(ua::RegisterServerRequest request) noexcept;

  /// Outcome of RegisterServer2: the @ref RegisterServer2Response, or an @ref ErrorDetail.
  using RegisterServer2ResponseResult = ua::Result<ua::RegisterServer2Response>;
  /// Callback receiving the outcome of `register_server2_async`.
  using RegisterServer2Callback = std::function<void(RegisterServer2ResponseResult)>;

  /// Registers a server with a Local Discovery Server using RegisterServer2.
  ///
  /// RegisterServer2 extends RegisterServer with mDNS discovery configuration.
  /// No session is required. May be called from any thread.
  ///
  /// @param request  The RegisterServer2 request.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref RegisterServer2Response; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see register_server2_sync, try_register_server2_sync
  void register_server2_async(ua::RegisterServer2Request request, RegisterServer2Callback callback) noexcept;

  /// Registers a server with a Local Discovery Server using RegisterServer2,
  /// blocking until complete.
  ///
  /// @param request The RegisterServer2 request.
  /// @return The RegisterServer2 response.
  /// @throws ua::UaException if the call fails.
  /// @see register_server2_async, try_register_server2_sync
  /// A Good subcode on the answer is not returned; try_register_server2_sync() returns it.
  ua::RegisterServer2Response register_server2_sync(ua::RegisterServer2Request request);

  /// Registers a server with a Local Discovery Server using RegisterServer2,
  /// blocking until complete.
  ///
  /// @param request The RegisterServer2 request.
  /// @return The RegisterServer2 response, or an @ref ErrorDetail on failure. Never throws.
  /// @see register_server2_async, register_server2_sync
  RegisterServer2ResponseResult try_register_server2_sync(ua::RegisterServer2Request request) noexcept;

  // --- Close ---

  /// Callback receiving the success-or-error outcome of `close_async`.
  using CloseCallback = std::function<void(ua::VoidResult)>;

  /// Gracefully closes the channel.
  ///
  /// Sends a CloseSecureChannelRequest, closes the transport, and releases the
  /// channel impl owned by this handle (any session that still references the
  /// impl keeps it alive until it also releases). You must call this (or
  /// `close_sync` / `try_close_sync`) before dropping the SecureChannel handle
  /// if you want the server to see a CLO; the destructor does not close.
  /// Idempotent: closing an already-closed channel is a no-op success. May be
  /// called from any thread.
  ///
  /// @param callback Receives the outcome as a `VoidResult`: success, or an
  ///                 @ref ErrorDetail on failure. This overload never throws.
  /// @see close_sync, try_close_sync
  void close_async(CloseCallback callback) noexcept;

  /// Gracefully closes the channel, blocking until complete.
  ///
  /// @throws ua::UaException if the close fails.
  /// @see close_async, try_close_sync
  void close_sync();

  /// Gracefully closes the channel, blocking until complete.
  ///
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see close_async, close_sync
  ua::VoidResult try_close_sync() noexcept;

  // --- Queries ---

  /// Returns the server-assigned secure channel identifier.
  ///
  /// @return The secure channel id, or 0 if the channel has not yet opened.
  /// @throws ua::UaException with @ref Status::BadInvalidState if this handle is
  ///         empty - i.e. it has been moved from or already passed through
  ///         `close_async` (which releases the impl). Unlike `is_open`, this
  ///         accessor does not tolerate an empty handle.
  uint32_t secure_channel_id() const;

  /// Reports whether the channel is currently open.
  ///
  /// Safe to call on an empty handle (moved-from or post-`close_async`): such a
  /// handle reports `false` rather than throwing.
  ///
  /// @return `true` while the secure channel is established; `false` once it is
  ///         closed, has not yet opened, or this handle is empty.
  bool is_open() const;

private:
  friend class SecureChannelImpl;
  friend class CoreClientImpl;
  friend class Session;
  friend class SecureChannelTestAccess;
  friend struct ::ua::client::detail::OpenChannelOrchestrator;
  explicit SecureChannel(std::shared_ptr<SecureChannelImpl> impl);

  std::shared_ptr<SecureChannelImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_CLIENT_SECURE_CHANNEL_H
