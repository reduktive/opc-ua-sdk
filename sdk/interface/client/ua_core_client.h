// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-0 OPC UA client root: SecureChannel open, reverse-connect, and shutdown.
///
/// @ref ua::client::CoreClient is the **tier-0** root (client design section 7.1) - unmanaged,
/// wire-shaped request/response. It opens raw @ref ua::client::SecureChannel handles, owns
/// reverse-connect listeners, and carries the create-time configuration, crypto and logging knobs.
///
/// It deliberately carries **none** of the managed-session semantics: no NodeId namespace remap, no
/// queue-on-reconnect, no default timeout, no `ErrorDetail` wrap. Code holding a `CoreClient` owns
/// those problems itself. For the managed surface use the tier-1 @ref ua::client::Client
/// (`ua_client.h`), which composes a `CoreClient` and reaches it back via `Client::core()`.
///
/// @ingroup client

#ifndef UA_CORE_CLIENT_H
#define UA_CORE_CLIENT_H

#include "ua_client_components.h"
#include "ua_client_config_bundle.h"
#include "ua_client_secure_channel.h"
#include "ua_reverse_connect_config.h"

#include "ua_crypto.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_structure_factory.h"
#include "ua_log_level.h"
#include "ua_message_security_mode.h"
#include "ua_result.h"
#include "ua_to_result.h"
#include "ua_crypto_types.h"
#include "ua_x509_certificate.h"
#include "ua_runtime.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace ua
{
class CertificateStore;
class LogSink;
}  // namespace ua

namespace ua::client::detail
{
class ValidatedServerRequest;
}  // namespace ua::client::detail

namespace ua::client
{

class CoreClientImpl;
/// The tier-1 root (`ua_client.h`); it composes a CoreClient and is a friend of it.
class Client;

/// @ingroup client
/// Determines how the TCP connection for the SecureChannel is established.
enum class ConnectMode
{
  Normal,  ///< Client initiates the TCP connection (default, normal behaviour).
  Reverse,  ///< Client waits for a Server to reverse-connect.
};

/// Tier-0 root of the OPC UA Client SDK - unmanaged, wire-shaped request/response.
///
/// Provides factory methods and the `open_channel` operation that orchestrates
/// TCP connect -> HEL/ACK -> OPN to produce an open @ref SecureChannel handle. Also
/// owns reverse-connect listeners and drives cascading shutdown of every channel
/// and listener it created.
///
/// A `CoreClient` gives you the wire and nothing else: none of the managed-session
/// semantics (NodeId namespace remap, queue-on-reconnect, default request timeout,
/// `ErrorDetail` wrapping) apply to anything reached through it. That is the point -
/// certification harnesses, protocol-level debugging and bespoke flows need the
/// unmanaged surface. Application code normally wants the tier-1 @ref Client instead,
/// and can still drop down here via `Client::core()`.
///
/// Move-only handle wrapping a shared `CoreClientImpl`. Methods are safe to call from
/// any thread; each posts its work to the executor supplied at @ref create.
///
/// @ingroup client
/// @see SecureChannel, CreateConfig, CombinedConfig
class CoreClient
{
public:
  /// Move-constructs from @p other, transferring ownership of the shared `CoreClientImpl`.
  /// @post @p other is left empty; only its destruction is valid.
  CoreClient(CoreClient&&) noexcept = default;

  /// Move-assigns from @p other, transferring ownership of the shared `CoreClientImpl`.
  /// @return Reference to this Client.
  /// @post @p other is left empty; only its destruction is valid.
  CoreClient& operator=(CoreClient&&) noexcept = default;
  CoreClient(const CoreClient&) = delete;
  CoreClient& operator=(const CoreClient&) = delete;
  ~CoreClient();

  // --- Open channel (TCP -> HEL/ACK -> OPN) ---

  /// Parameters describing the SecureChannel to open against a server endpoint.
  struct OpenChannelConfig
  {
    std::string endpointUrl;  ///< OPC UA endpoint URL to connect to (e.g. `opc.tcp://host:4840`).
    /// Relaxes the HostName binding of the server certificate to @ref endpointUrl when the channel opens:
    /// the mismatch is then reported by CreateSession as a warning instead of refusing (`ConnectionConfig::
    /// relaxHostNameCheck`). Every other check of the certificate still applies.
    bool relaxHostNameCheck = false;
    ua::MessageSecurityMode securityMode{
      ua::MessageSecurityMode::None};  ///< Sign/SignAndEncrypt/None for the channel.
    ua::SecurityPolicyId securityPolicyId{
      ua::SecurityPolicyId::None};  ///< Security policy governing the channel's crypto.

    /// Requested secure channel lifetime. `nullopt` uses the @ref CombinedConfig default.
    std::optional<std::chrono::milliseconds> requestedLifetime;

    /// Optional audit-log id provider for OpenSecureChannel, renew, and CloseSecureChannel requests.
    /// Managed Connection setup supplies the same provider used by its Session.
    std::function<ua::String()> auditEntryIdProvider;

    /// Server certificate (from a prior GetEndpoints call). Required for authenticated policies;
    /// ignored for @ref ua::SecurityPolicyId::None. May be null. Parse it via @ref crypto.
    std::shared_ptr<const ua::X509Certificate> serverCertificate;

    /// Optional per-open trust-store override - when set, the OPN server-certificate validation uses
    /// THIS store instead of the client's runtime certificate store (bootstrap-trust for a GDS Pull
    /// connection, CL-PULLCRT-001). `nullptr` (the default) validates against the runtime store. The
    /// channel holds it for its whole lifetime so it outlives the channel's weak reference to it.
    ///
    /// SECURITY - this override is PER-OPEN and does NOT automatically survive a channel RECONNECT: the
    /// reconnect path rebuilds the channel config, so a bootstrap-trust connection that must reconnect
    /// requires the reconnect wiring to re-supply this override, otherwise the reconnected channel reverts
    /// to the runtime store (a trust downgrade). It is also a no-op under @ref ua::SecurityPolicyId::None
    /// (no server-certificate validation runs there).
    std::shared_ptr<ua::CertificateStore> trustStoreOverride;

    /// SDK-internal: where the channel records the exact request it validated the server certificate with,
    /// so the connection's revalidation resubmits it. Set by the connection establisher; leave null.
    std::shared_ptr<detail::ValidatedServerRequest> validatedServerRequest;

    /// Invoked when the channel closes unexpectedly after a successful open.
    ///
    /// Receives the full error chain including any server diagnostics. Posted to the client's
    /// executor (not the channel's internal strand), fires at most once, and must not block.
    /// May be empty (no notification).
    std::function<void(ua::VoidResult)> onChannelError;

    /// How to establish the underlying TCP connection (normal or reverse).
    ConnectMode connectMode{ConnectMode::Normal};

    /// Overall timeout for the open_channel operation. `nullopt` uses the configured default.
    std::optional<std::chrono::milliseconds> timeout;
  };

  /// Result of an open-channel operation: the open @ref SecureChannel or an @ref ErrorDetail.
  using SecureChannelResult = ua::Result<SecureChannel>;
  /// Callback receiving the outcome of @ref open_channel_async.
  using OpenChannelCallback = std::function<void(SecureChannelResult)>;

  /// Opens a SecureChannel to the configured endpoint.
  ///
  /// Orchestrates TCP connect -> HEL/ACK -> OPN and completes asynchronously. The work
  /// is posted to the client's executor; the callback runs on a worker thread and must
  /// not block.
  ///
  /// @param config   Endpoint, security, lifetime, and timeout parameters.
  /// @param callback Receives the outcome: on success the @ref SecureChannelResult holds
  ///                 the open @ref SecureChannel; on failure it carries an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see open_channel_sync, try_open_channel_sync
  void open_channel_async(OpenChannelConfig config, OpenChannelCallback callback) noexcept;

  /// Opens a SecureChannel, blocking until the operation completes.
  ///
  /// @param config Endpoint, security, lifetime, and timeout parameters.
  /// @return The open @ref SecureChannel.
  /// @throws UaException if the channel fails to open.
  /// @see open_channel_async, try_open_channel_sync
  /// A Good subcode on the answer is not returned; try_open_channel_sync() returns it.
  SecureChannel open_channel_sync(OpenChannelConfig config);

  /// Opens a SecureChannel, blocking until the operation completes.
  ///
  /// @param config Endpoint, security, lifetime, and timeout parameters.
  /// @return The open @ref SecureChannel, or an @ref ErrorDetail on failure. Never throws.
  /// @see open_channel_async, open_channel_sync
  SecureChannelResult try_open_channel_sync(OpenChannelConfig config) noexcept;

  // --- Type registration ---

  /// Registers a custom structure type with the client's UA Binary decoder.
  ///
  /// When the client subsequently receives an ExtensionObject carrying @p encodingId on the
  /// wire, it invokes @p factory to create an instance and decodes the body into it.
  ///
  /// @param encodingId Binary encoding NodeId that identifies the structure on the wire.
  /// @param factory    Creates a fresh instance of the structure to decode into.
  void register_structure_type(const ua::NodeId& encodingId, ua::StructureFactory::CreateMethod factory);

  // --- Reverse Connect ---

  /// Starts a reverse-connect listener that accepts inbound server connections.
  ///
  /// The work is posted to the client's executor; the callback runs on a worker thread and
  /// must not block.
  ///
  /// @param config   Listener address and acceptance parameters.
  /// @param callback Receives the outcome: on success a @ref ReverseConnectHandle identifying
  ///                 the listener; on failure an @ref ErrorDetail. This overload never throws.
  /// @see start_reverse_connect_sync, try_start_reverse_connect_sync, stop_reverse_connect_async
  void start_reverse_connect_async(client::ReverseConnectListenerConfig config,
    std::function<void(client::ReverseConnectHandleResult)> callback) noexcept;

  /// Starts a reverse-connect listener, blocking until it is established.
  ///
  /// @param config Listener address and acceptance parameters.
  /// @return A @ref ReverseConnectHandle identifying the new listener.
  /// @throws UaException if the listener cannot be started.
  /// @see start_reverse_connect_async, try_start_reverse_connect_sync
  /// A Good subcode on the answer is not returned; try_start_reverse_connect_sync() returns it.
  [[nodiscard]] client::ReverseConnectHandle start_reverse_connect_sync(
    client::ReverseConnectListenerConfig config);

  /// Starts a reverse-connect listener, blocking until it is established.
  ///
  /// @param config Listener address and acceptance parameters.
  /// @return A @ref ReverseConnectHandle, or an @ref ErrorDetail on failure. Never throws.
  /// @see start_reverse_connect_async, start_reverse_connect_sync
  [[nodiscard]] client::ReverseConnectHandleResult try_start_reverse_connect_sync(
    client::ReverseConnectListenerConfig config) noexcept;

  /// Stops a single reverse-connect listener.
  ///
  /// The work is posted to the client's executor; the callback runs on a worker thread and
  /// must not block.
  ///
  /// @param handle   Listener to stop, as returned by `start_reverse_connect_*`.
  /// @param callback Receives a @ref VoidResult - success, or an @ref ErrorDetail (e.g. if the
  ///                 handle is unknown). This overload never throws.
  /// @see stop_reverse_connect_sync, try_stop_reverse_connect_sync, stop_all_reverse_connects_async
  void stop_reverse_connect_async(
    client::ReverseConnectHandle handle, std::function<void(VoidResult)> callback) noexcept;

  /// Stops a single reverse-connect listener, blocking until complete.
  ///
  /// @param handle Listener to stop.
  /// @throws UaException if the listener cannot be stopped (e.g. the handle is unknown).
  /// @see stop_reverse_connect_async, try_stop_reverse_connect_sync
  void stop_reverse_connect_sync(client::ReverseConnectHandle handle);

  /// Stops a single reverse-connect listener, blocking until complete.
  ///
  /// @param handle Listener to stop.
  /// @return A @ref VoidResult - success, or an @ref ErrorDetail on failure. Never throws.
  /// @see stop_reverse_connect_async, stop_reverse_connect_sync
  [[nodiscard]] VoidResult try_stop_reverse_connect_sync(client::ReverseConnectHandle handle) noexcept;

  /// Stops every reverse-connect listener owned by this client.
  ///
  /// The work is posted to the client's executor; the callback runs on a worker thread and
  /// must not block.
  ///
  /// @param callback Receives a @ref VoidResult once all listeners are stopped. Never throws.
  /// @see stop_all_reverse_connects_sync, try_stop_all_reverse_connects_sync
  void stop_all_reverse_connects_async(std::function<void(VoidResult)> callback) noexcept;

  /// Stops every reverse-connect listener owned by this client, blocking until complete.
  ///
  /// @throws UaException if any listener cannot be stopped.
  /// @see stop_all_reverse_connects_async, try_stop_all_reverse_connects_sync
  void stop_all_reverse_connects_sync();

  /// Stops every reverse-connect listener owned by this client, blocking until complete.
  ///
  /// @return A @ref VoidResult - success, or an @ref ErrorDetail on failure. Never throws.
  /// @see stop_all_reverse_connects_async, stop_all_reverse_connects_sync
  [[nodiscard]] VoidResult try_stop_all_reverse_connects_sync() noexcept;

  // --- Shutdown ---

  /// Callback receiving the outcome of @ref shutdown_async.
  using ShutdownCallback = std::function<void(ua::VoidResult)>;

  /// Initiates cascading client shutdown.
  ///
  /// Stops all reverse-connect listeners and closes every open @ref SecureChannel owned by
  /// this Client. The callback fires after every local resource has been released. Peer-side
  /// errors (TCP RST, timeout during the courtesy CloseSecureChannel exchange) are tolerated;
  /// the result is always Good unless the Client is already shut down. The callback is posted
  /// to the client's executor and must not block.
  ///
  /// @param callback Receives a @ref VoidResult once shutdown completes. Never throws.
  /// @post The Client facade is empty; only destruction is valid. Construct a new Client to
  ///       reconnect.
  /// @see shutdown_sync, try_shutdown_sync
  void shutdown_async(ShutdownCallback callback) noexcept;

  /// Performs cascading shutdown, blocking until complete.
  ///
  /// @throws UaException on failure (e.g. BadInvalidState if already shut down).
  /// @post The Client facade is empty; only destruction is valid.
  /// @see shutdown_async, try_shutdown_sync
  void shutdown_sync();

  /// Performs cascading shutdown, blocking until complete.
  ///
  /// @return A @ref VoidResult - success, or an @ref ErrorDetail on failure. Never throws.
  /// @post The Client facade is empty; only destruction is valid.
  /// @see shutdown_async, shutdown_sync
  [[nodiscard]] ua::VoidResult try_shutdown_sync() noexcept;

  // --- Configuration ---

  /// Returns the frozen combined configuration for this client instance.
  ///
  /// @return Reference valid for the lifetime of this Client.
  const CombinedConfig& config() const;

  /// Returns the crypto provider backing this client.
  ///
  /// Used, for example, to parse a server certificate obtained from a GetEndpoints response
  /// before opening an authenticated channel.
  ///
  /// @return Shared crypto provider; never null.
  std::shared_ptr<const ua::Crypto> crypto() const;

  // --- Logging ---

  /// Sets the minimum severity at which records are emitted to the current log sink.
  ///
  /// The log *sink* is fixed at construction (see the `logSink` parameter of create()); only the
  /// level is mutable at runtime.
  ///
  /// @param level Minimum severity to emit; records below this level are dropped.
  void set_log_level(ua::LogLevel level);

  // --- Factory ---

  /// Creates a Client from its configuration and the components the application supplies.
  ///
  /// @param executor   Asio executor on which the client posts all of its work; must outlive
  ///                   the returned Client.
  /// @param config     Client creation configuration.
  /// @param components The crypto provider (required), certificate store and log sink; see
  ///                   @ref ClientComponents.
  /// @return A ready-to-use Client.
  /// @throws UaException `BadConfigurationError` when @p components has no crypto provider or the
  ///         configuration is invalid, or when the loaded own ApplicationInstance certificate fails a
  ///         create-time security precondition (see @ref try_create).
  /// @pre @p executor must already be serviced by a running thread at the moment of this call: the
  ///      create-time own-certificate validation performs a synchronous certificate-store read that
  ///      posts to the store's strand on @p executor and blocks for its completion. Called on a thread
  ///      of @p executor, the call is refused at once with `Status::BadWouldBlock`. On an executor no
  ///      thread runs (an `io_context` constructed but not yet `run()`), it waits at most 10 seconds and
  ///      then FAILS with `Status::BadTimeout` (ErrorDetail `ExecutorNotRunning`) rather than blocking
  ///      forever. The canonical `thread_pool` usage (a pool whose worker threads are already running)
  ///      satisfies this precondition.
  static CoreClient create(
    boost::asio::any_io_executor executor, CreateConfig config, ClientComponents components);

  /// The created @ref Client on success, or an @ref ErrorDetail on failure.
  using CreateResult = ua::Result<CoreClient>;

  /// Creates a Client, returning a bad @ref CreateResult instead of throwing on failure.
  ///
  /// In addition to configuration validation, this validates the client's own ApplicationInstance
  /// certificate  -  when one is present in @p certStore  -  against the configuration before the Client
  /// is returned (client design section 10.2 / OPC UA Part 6 section 6.2.2). A malformed own certificate
  /// (missing SAN URI, SAN URI not matching the applicationUri, missing a required keyUsage bit, an RSA key
  /// below the policy minimum, or a self-signed certificate lacking keyCertSign) fails create here
  /// with a source-tagged @ref ErrorDetail naming the offending field, rather than surfacing later as
  /// a cryptic server-side certificate rejection at channel open. A client with no own certificate
  /// (legitimate for a @ref ua::SecurityPolicyId::None connection) is exempt.
  ///
  /// @param executor   Asio executor on which the client posts all of its work; must outlive the Client.
  /// @param config     Client creation configuration.
  /// @param components The crypto provider (required), certificate store and log sink; see
  ///                   @ref ClientComponents.
  /// @return The created @ref Client, or an @ref ErrorDetail on failure (including a missing crypto
  ///         provider). Never throws.
  /// @pre @p executor must already be serviced by a running thread at the moment of this call: the
  ///      create-time own-certificate validation performs a synchronous certificate-store read that
  ///      posts to the store's strand on @p executor and blocks for its completion. Called on a thread
  ///      of @p executor, the call is refused at once with `Status::BadWouldBlock`. On an executor no
  ///      thread runs (an `io_context` constructed but not yet `run()`), it waits at most 10 seconds and
  ///      then FAILS with `Status::BadTimeout` (ErrorDetail `ExecutorNotRunning`) rather than blocking
  ///      forever. The canonical `thread_pool` usage (a pool whose worker threads are already running)
  ///      satisfies this precondition.
  /// @see create
  [[nodiscard]] static CreateResult try_create(
    boost::asio::any_io_executor executor, CreateConfig config, ClientComponents components) noexcept;

private:
  friend class CoreClientTestAccess;
  /// The tier-1 root composes a CoreClient by value (client design section 7.1) and forwards its
  /// managed entry points into the same impl, so it needs the private construction interface.
  friend class Client;
  explicit CoreClient(std::shared_ptr<CoreClientImpl> impl);

  std::shared_ptr<CoreClientImpl> mImpl;
};

/// Stops a @ref ua::client::CoreClient as part of a @ref ua::Runtime shutdown: @ref
/// ua::client::CoreClient::shutdown_sync.
///
/// Declared in `ua::client` so argument-dependent lookup finds it from @ref ua::Runtime::attach.
///
/// @param client The client being stopped.
inline void runtime_shutdown(CoreClient& client, const ua::ShutdownContext&)
{
  client.shutdown_sync();
}

}  // namespace ua::client

#endif  // !UA_CORE_CLIENT_H
