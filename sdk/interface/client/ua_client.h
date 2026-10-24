// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-1 OPC UA client root: managed connections, discovery, observers, shutdown.
///
/// @ref ua::client::Client is the **tier-1** root (client design section 7.1) - the managed
/// surface. It composes a tier-0 @ref ua::client::CoreClient **by value** and adds lifecycle
/// automation: `connect_*` returns a managed @ref ua::client::Connection that owns an
/// auto-reconnect FSM, a keep-alive, and a subscription pipeline, and whose wire-shaped
/// operations carry managed-session semantics (NodeId namespace remap, queue-on-reconnect,
/// default request timeout, `ErrorDetail` wrap).
///
/// The two types you construct yourself exist so that a reader can point at a class and name its
/// tier without prose.
/// Everything reachable from `Client` is managed; everything reachable from `CoreClient` is not.
/// Advanced callers drop to the unmanaged surface explicitly via `Client::core()` - which is a
/// deliberate, visible step, not an accident of overload resolution.
///
/// @ingroup client

#ifndef UA_CLIENT_H
#define UA_CLIENT_H

#include "ua_core_client.h"
#include "ua_easy_connect_policy.h"
#include "ua_pull_certificate_manager.h"

#include "ua_log_level.h"
#include "ua_result.h"
#include "ua_to_result.h"
#include "ua_runtime.h"
#include "ua_connection.h"
#include "ua_fmt.h"
#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <memory>

namespace ua
{
class CertificateStore;
class Crypto;
class LogSink;
}  // namespace ua

namespace ua::mdns
{
class MdnsTransport;
}  // namespace ua::mdns

namespace ua::client
{

class Discovery;
struct ConnectionConfig;

// The eight role-cohesive observer interfaces (section 7.8). Forward-declared: the Client-level setters take
// `shared_ptr<...>`, so the definitions (`ua_client_observers.h`) are pulled into the .cpp, not this header.
class ConnectionObserver;
class SubscriptionObserver;
class SecurityObserver;
class TypeObserver;
class AddressSpaceObserver;
class ServerStateObserver;
class AlarmObserver;

/// Tier-1 root of the OPC UA Client SDK - the managed surface (client design section 7.1).
///
/// Composes a @ref CoreClient by value and surfaces the managed entry points over it. Move-only
/// handle; methods are safe to call from any thread and post their work to the executor supplied
/// at @ref create.
///
/// @ingroup client
/// @see CoreClient, Connection, Discovery
class Client
{
public:
  /// Move-constructs from @p other, transferring ownership of the composed CoreClient.
  /// @post @p other is left empty; only its destruction is valid.
  Client(Client&&) noexcept = default;

  /// Move-assigns from @p other, transferring ownership of the composed CoreClient.
  /// @return Reference to this Client.
  /// @post @p other is left empty; only its destruction is valid.
  Client& operator=(Client&&) noexcept = default;
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;
  ~Client();

  // --- Managed connect (tier-1: TCP -> OPN -> CreateSession -> ActivateSession -> bootstrap) ---

  /// Result of a managed connect: the open @ref Connection or an @ref ErrorDetail.
  using ConnectResult = ua::Result<Connection>;
  /// Callback receiving the outcome of @ref connect_async.
  using ConnectCallback = std::function<void(ConnectResult)>;

  /// Establishes a fully-managed @ref Connection to a server endpoint (client design section 7.3).
  ///
  /// Orchestrates the whole tier-1 connect: open the SecureChannel, CreateSession + ActivateSession with the
  /// configured identity, then run the NamespaceArray bootstrap. On success the callback receives an `Active`
  /// @ref Connection that owns the managed channel/session pair and (unless opted out via
  /// @ref ConnectionConfig::reconnect) an automatic-reconnect FSM + keep-alive. This is the power-user entry:
  /// it takes a pre-built @ref ConnectionConfig and assumes any discovery + trust decision is already done
  /// (contrast the discovery-driven easy-connect facade). The work is posted to the client's executor; the
  /// callback runs on a worker thread and must not block.
  ///
  /// @param config   Endpoint, security, identity, session, and lifecycle-automation parameters.
  /// @param callback Receives the outcome: on success the open @ref Connection; on failure an
  ///                 @ref ErrorDetail naming the failing step. This overload never throws.
  /// @see connect_sync, try_connect_sync
  void connect_async(ConnectionConfig config, ConnectCallback callback) noexcept;

  /// Establishes a managed @ref Connection, blocking until the connect completes.
  ///
  /// @param config Endpoint, security, identity, session, and lifecycle-automation parameters.
  /// @return The open @ref Connection.
  /// @throws UaException if the connect fails at any step.
  /// @note MUST NOT be called from the client's executor thread (it blocks on the async completion, which
  ///       runs on that executor  -  a self-wait would deadlock).
  /// @see connect_async, try_connect_sync
  /// A Good subcode on the answer is not returned; try_connect_sync() returns it.
  Connection connect_sync(ConnectionConfig config);

  /// Establishes a managed @ref Connection, blocking until the connect completes.
  ///
  /// @param config Endpoint, security, identity, session, and lifecycle-automation parameters.
  /// @return The open @ref Connection, or an @ref ErrorDetail on failure. Never throws.
  /// @note MUST NOT be called from the client's executor thread (see @ref connect_sync).
  /// @see connect_async, connect_sync
  [[nodiscard]] ConnectResult try_connect_sync(ConnectionConfig config) noexcept;

  // --- Managed connect, discovery-driven (tier-1: GetEndpoints -> rank -> trust -> connect) ---

  /// Establishes a managed @ref Connection from a URL alone (client design section 7.3A).
  ///
  /// The counterpart to @ref connect_async - instead of a pre-built @ref ConnectionConfig, name a URL
  /// and the SDK performs GetEndpoints, ranks the endpoints by security strength
  /// (@ref default_easy_connect_ranker, or `policy.ranker`), decodes and validates the chosen
  /// server certificate, and - if it is untrusted - asks the application via
  /// @ref EasyConnectConfig::trustPrompt before continuing. The resolved configuration is then
  /// handed to `connect_async`, so everything downstream is an ordinary managed Connection.
  ///
  /// With a trusted server and no prompt configured this is a one-call connect. With an untrusted
  /// server and no prompt configured it FAILS rather than trusting silently - see
  /// @ref EasyConnectConfig::trustPrompt.
  ///
  /// @param policy   Endpoint URL, identity, trust prompt, ranker, and the `customize` hook.
  /// @param callback Receives the open @ref Connection, or an @ref ErrorDetail whose source names
  ///                 the failing step (`client.tier1.easy_connect.*`). Never throws.
  /// @see connect_async, easy_connect_sync, try_easy_connect_sync, EasyConnectConfig
  void easy_connect_async(EasyConnectConfig policy, ConnectCallback callback) noexcept;

  /// Discovery-driven managed connect, blocking until it completes.
  ///
  /// @param policy Endpoint URL, identity, trust prompt, ranker, and the `customize` hook.
  /// @return The open @ref Connection.
  /// @throws UaException if discovery, endpoint selection, the trust decision, or the connect fails.
  /// @note MUST NOT be called from the client's executor thread (it blocks on the async completion,
  ///       which runs on that executor - a self-wait would deadlock).
  /// @see easy_connect_async, try_easy_connect_sync
  /// A Good subcode on the answer is not returned; try_easy_connect_sync() returns it.
  Connection easy_connect_sync(EasyConnectConfig policy);

  /// Discovery-driven managed connect, blocking until it completes.
  ///
  /// @param policy Endpoint URL, identity, trust prompt, ranker, and the `customize` hook.
  /// @return The open @ref Connection, or an @ref ErrorDetail on failure. Never throws.
  /// @note MUST NOT be called from the client's executor thread (see @ref easy_connect_sync).
  /// @see easy_connect_async, easy_connect_sync
  [[nodiscard]] ConnectResult try_easy_connect_sync(EasyConnectConfig policy) noexcept;

  // --- Discovery ---

  /// Returns the Client-level Discovery facade (client design section 7.6).
  ///
  /// Each returned handle snapshots the current ephemeral-channel factory and the installed mDNS
  /// transport. Discovery is stateless per call: it opens (and closes) its own ephemeral None-policy
  /// channels, so repeat invocation is always safe. See @ref ua::client::Discovery.
  ///
  /// @return A Discovery value handle. Empty (all calls fail fast) if this Client has been shut down.
  Discovery discovery();

  /// Installs an alternative mDNS transport used by @ref Discovery::start_mdns_browse (client design
  /// section 8.12). Passing null restores the bundled default. Takes effect for Discovery handles obtained
  /// after this call.
  ///
  /// @param transport The mDNS transport to install, or null to restore the default.
  void set_mdns_transport(std::shared_ptr<ua::mdns::MdnsTransport> transport);

  // --- Observer registration (section 7.8) ---
  // Client-level (process-wide) default observers, one setter per role-cohesive family. Each is independently
  // optional; passing `nullptr` clears the slot. A per-Connection observer (`Connection::set_*_observer` /
  // `ConnectionConfig`) overrides the Client-level default for that family on that Connection
  // (section 7.3/section 7.7). A Client-level default applies to every Connection subsequently produced by
  // this Client's connect path.

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Sets the Client-level default connection / session lifecycle observer (section 7.8).
  void set_connection_observer(std::shared_ptr<ConnectionObserver> observer);

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Sets the Client-level default Subscription / MonitoredItem lifecycle observer (section 7.8).
  void set_subscription_observer(std::shared_ptr<SubscriptionObserver> observer);

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Sets the Client-level default certificate security observer (section 7.8).
  void set_security_observer(std::shared_ptr<SecurityObserver> observer);

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Sets the Client-level default type-system observer (section 7.8).
  void set_type_observer(std::shared_ptr<TypeObserver> observer);

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Sets the Client-level default address-space model / semantic-change observer (section 7.8).
  void set_address_space_observer(std::shared_ptr<AddressSpaceObserver> observer);

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Sets the Client-level default server-state / progress / device-failure observer (section 7.8).
  void set_server_state_observer(std::shared_ptr<ServerStateObserver> observer);

  /// @param observer Observer to install; an empty pointer removes the observer.
  /// Sets the Client-level default Alarms & Conditions observer (section 7.8).
  void set_alarm_observer(std::shared_ptr<AlarmObserver> observer);

  // --- Pull-Model certificate management (client design section 8.1A) ---

  /// The @ref PullCertificateManager handle on success, or an @ref ErrorDetail on failure (e.g.
  /// `Bad_AlreadyExists` for a second live start, CL-MULTI-001).
  using PullCertificateManagerResult = ua::Result<std::shared_ptr<PullCertificateManager>>;

  /// Callback receiving the outcome of @ref start_pull_cert_management_async.
  using StartPullCertManagementCallback = std::function<void(PullCertificateManagerResult)>;

  /// Starts the per-Client Pull-Model certificate + trust-list refresh engine (client design section 8.1A).
  ///
  /// Constructs the manager once and hands back the shared @ref PullCertificateManager handle; dropping the
  /// handle stops the manager. Write-once: a second live start completes `Bad_AlreadyExists` (CL-MULTI-001).
  /// The callback is posted to the client's executor. Never throws.
  ///
  /// @param config   Pull-Model configuration (GDS endpoint, bootstrap + runtime trust stores, cadence).
  /// @param callback Receives the manager handle, or an @ref ErrorDetail on failure.
  /// @see start_pull_cert_management, try_start_pull_cert_management_sync
  void start_pull_cert_management_async(
    PullCertManagementConfig config, StartPullCertManagementCallback callback) noexcept;

  /// Starts Pull-Model certificate management, blocking until the manager is constructed.
  ///
  /// @param config Pull-Model configuration.
  /// @return The shared @ref PullCertificateManager handle.
  /// @throws UaException on failure (e.g. `Bad_AlreadyExists` for a second live start).
  /// @see start_pull_cert_management_async, try_start_pull_cert_management_sync
  /// A Good subcode on the answer is not returned; try_start_pull_cert_management_sync() returns it.
  std::shared_ptr<PullCertificateManager> start_pull_cert_management_sync(PullCertManagementConfig config);

  /// Starts Pull-Model certificate management, blocking until the manager is constructed.
  ///
  /// @param config Pull-Model configuration.
  /// @return The manager handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see start_pull_cert_management_async, start_pull_cert_management
  [[nodiscard]] PullCertificateManagerResult try_start_pull_cert_management_sync(
    PullCertManagementConfig config) noexcept;

  // --- Tier-0 drop-down ---

  /// Returns the composed tier-0 @ref CoreClient (client design section 7.1).
  ///
  /// The explicit override for work the managed surface does not cover: opening a raw
  /// @ref SecureChannel, driving reverse-connect listeners, or reaching the create-time
  /// configuration, crypto provider and log-level knob. Nothing reached through the returned
  /// handle carries managed-session semantics.
  ///
  /// @return Reference to the composed CoreClient; valid for this Client's lifetime. Never a
  ///         `shared_ptr` - ownership stays with this Client.
  [[nodiscard]] CoreClient& core() noexcept;

  /// @copydoc core()
  [[nodiscard]] const CoreClient& core() const noexcept;

  // --- Shutdown ---

  /// Callback receiving the outcome of @ref shutdown_async.
  using ShutdownCallback = std::function<void(ua::VoidResult)>;

  /// Initiates cascading client shutdown.
  ///
  /// Closes every managed @ref Connection, then delegates to @ref CoreClient::shutdown_async to
  /// stop reverse-connect listeners and close every open @ref SecureChannel. The callback fires
  /// after every local resource has been released. Peer-side errors (TCP RST, timeout during the
  /// courtesy CloseSecureChannel exchange) are tolerated. Posted to the client's executor; must
  /// not block.
  ///
  /// @param callback Receives a @ref VoidResult once shutdown completes. Never throws.
  /// @post The Client facade is empty; only destruction is valid.
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

  // --- Factory ---

  /// Creates a tier-1 Client from its configuration and the components the application supplies.
  ///
  /// Same create-time validation as @ref CoreClient::create, which this delegates to.
  ///
  /// @param executor   Asio executor on which the client posts all of its work; must outlive the Client.
  /// @param config     Client creation configuration.
  /// @param components The crypto provider (required), certificate store and log sink; see
  ///                   @ref ClientComponents.
  /// @return A ready-to-use Client.
  /// @throws UaException `BadConfigurationError` when @p components has no crypto provider or the
  ///         configuration is invalid, or when the loaded own ApplicationInstance certificate fails a
  ///         create-time security precondition (see @ref try_create).
  /// @pre @p executor must already be serviced by a running thread at the moment of this call
  ///      (see @ref CoreClient::create for why).
  static Client create(
    boost::asio::any_io_executor executor, CreateConfig config, ClientComponents components);

  /// The created @ref Client on success, or an @ref ErrorDetail on failure.
  using CreateResult = ua::Result<Client>;

  /// Creates a tier-1 Client, returning a bad @ref CreateResult instead of throwing on failure.
  ///
  /// @param executor   Asio executor on which the client posts all of its work; must outlive the Client.
  /// @param config     Client creation configuration.
  /// @param components The crypto provider (required), certificate store and log sink; see
  ///                   @ref ClientComponents.
  /// @return The created @ref Client, or an @ref ErrorDetail on failure. Never throws.
  /// @pre @p executor must already be serviced by a running thread (see @ref CoreClient::try_create).
  /// @see create
  [[nodiscard]] static CreateResult try_create(
    boost::asio::any_io_executor executor, CreateConfig config, ClientComponents components) noexcept;

private:
  friend class ClientTestAccess;
  explicit Client(CoreClient core);

  CoreClient mCore;
};

/// Stops a @ref ua::client::Client as part of a @ref ua::Runtime shutdown: @ref
/// ua::client::Client::shutdown_sync.
///
/// Declared in `ua::client` so argument-dependent lookup finds it from @ref ua::Runtime::attach.
///
/// @param client The client being stopped.
inline void runtime_shutdown(Client& client, const ua::ShutdownContext&)
{
  client.shutdown_sync();
}

}  // namespace ua::client

#endif  // !UA_CLIENT_H
