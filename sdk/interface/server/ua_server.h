// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Configuration, lifecycle, and address-space entry point for an OPC UA server.
/// @ingroup server

#ifndef UA_SERVER_H
#define UA_SERVER_H

#include "ua_application_description.h"
#include "ua_base_event.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_sinks.h"
#include "ua_listen_options.h"
#include "ua_localized_text.h"
#include "ua_result.h"
#include "ua_to_result.h"
#include "ua_structure_factory.h"
#include "ua_nodeset_import.h"
#include "ua_type_loader.h"
#include "ua_transport_address.h"

#include <chrono>
#include <boost/asio/any_io_executor.hpp>
#include "ua_application_configuration.h"
#include "ua_server_config_bundle.h"
#include "ua_user_token_type.h"
#include "ua_crypto_types.h"
#include "ua_message_security_mode.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_reverse_connect_handle.h"
#include "ua_server_configuration.h"

#include "ua_log_level.h"
#include "ua_server_health.h"
#include "ua_server_observer.h"
#include "ua_server_components.h"
#include "ua_runtime.h"
#include "ua_fmt.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ua::test_helpers
{
class ServerTestAccess;
}

namespace ua
{

class Timer;
class AddressSpace;
class CertificateStore;
class LogSink;
class UaBinaryDataValueCodec;

namespace server
{

class NodeManagementDelegate;
class ServerImpl;
}  // namespace server

class Conditions;

namespace server
{

/// Opaque handle identifying a single bound listener.
///
/// Returned by the listen operations and passed back to per-listener queries
/// (endpoints, bound address, advertised URLs). Value-comparable; the wrapped
/// integer is an opaque token, not a stable address or index.
/// @ingroup server
struct ListenerHandle
{
  std::uint64_t value{};  ///< Opaque listener token. Do not interpret.

  /// Compares two handles for identity.
  friend bool operator==(ListenerHandle, ListenerHandle) = default;
};

/// A single @ref ListenerHandle or an @ref ErrorDetail on failure.
using ListenerHandleResult = Result<ListenerHandle>;

/// A list of listener handles, one per bound endpoint.
using ListenerHandleList = std::vector<ListenerHandle>;

/// A @ref ListenerHandleList or an @ref ErrorDetail on failure.
using ListenerHandleListResult = Result<ListenerHandleList>;

/// Options for one graceful server shutdown. `grace` and `reason` have the names and types of the same
/// two values on @ref ShutdownPolicy, which the runtime hands to an attached server.
/// @ingroup server
struct ShutdownOptions
{
  /// How long sessions are given before they are closed; advertised to clients as
  /// `ServerStatus.SecondsTillShutdown`.
  ///
  /// `std::nullopt` uses `ServerConfig::defaultShutdownGracePeriodSeconds`. An explicit value, `0` for an
  /// immediate shutdown included, overrides it.
  std::optional<std::chrono::seconds> grace;

  /// Reason for shutdown, exposed to clients via `ServerStatus.ShutdownReason`.
  LocalizedText reason;
};

/// The main entry point for the OPC UA Server SDK.
///
/// Configures, starts, and manages an OPC UA server: listeners and endpoints,
/// address-space access, cryptographic configuration, event emission, and
/// lifecycle. This is a move-only handle that shares ownership of the
/// underlying server implementation; the server runs while at least one handle
/// is alive.
/// @ingroup server
class Server
{
public:
  /// Callback signaling completion of an asynchronous operation.
  ///
  /// Receives a @ref VoidResult that is success or carries an @ref ErrorDetail.
  using CompleteCallback = std::function<void(VoidResult)>;

  /// Callback for a listen operation that produces a single listener handle.
  using ListenCompleteOneCallback = std::function<void(ListenerHandleResult)>;

  /// Callback for a listen operation that may produce several listener handles.
  using ListenCompleteManyCallback = std::function<void(ListenerHandleListResult)>;

  /// Move-constructs, transferring the moved-from handle's share of the server.
  ///
  /// The moved-from handle is left empty and must not be used except to destroy or reassign; the
  /// server keeps running as long as any other handle remains alive.
  Server(Server&&) noexcept = default;

  /// Move-assigns, releasing this handle's current share before taking @p other's.
  ///
  /// The moved-from handle is left empty. If this was the last handle to its previous server, that
  /// server is released as part of the assignment.
  ///
  /// @return A reference to this handle.
  Server& operator=(Server&&) noexcept = default;

  Server(const Server&) = delete;  ///< Non-copyable: the handle is move-only.
  Server& operator=(const Server&) = delete;  ///< Non-copyable: the handle is move-only.

  /// Destroys this handle and releases its share of the server implementation.
  ~Server();

  /// Returns a handle to the server's address space.
  ///
  /// The returned handle shares the server's address space and is valid only
  /// while this server is alive.
  ///
  /// @return A handle to the server's address space.
  AddressSpace address_space();

  /// Returns the server's cryptographic provider.
  ///
  /// The reference is valid only while this server is alive.
  ///
  /// @return The server's cryptographic provider.
  const Crypto& crypto() const;

  /// Returns the combined (effective) server configuration.
  ///
  /// The reference is valid only while this server is alive.
  ///
  /// @return The combined (effective) server configuration.
  const ::ua::server::CombinedConfig& config() const;

  /// Starts the server through the callback-canonical lifecycle.
  ///
  /// Namespace metadata preparation completes before any configured listener becomes accepting.
  /// The callback runs exactly once and never while the server mutex is held. As with other callback-
  /// canonical SDK APIs, an immediate lifecycle rejection may complete inline; continuations resume on
  /// the server executor. This method never blocks and never throws.
  ///
  /// @param callback Receives startup success or the exact metadata, lifecycle or network failure. With
  ///                 a null callback the server still starts and a failure is logged.
  /// @see try_start_sync, start_sync
  void start_async(CompleteCallback callback) noexcept;

  /// Starts the server, opening configured listeners and activating endpoints.
  ///
  /// @throws UaException if startup fails.
  /// @see start_async, try_start_sync
  void start_sync();

  /// Starts the server, opening configured listeners and activating endpoints.
  ///
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see start_async, start_sync
  [[nodiscard]] VoidResult try_start_sync() noexcept;

  /// Starts listening on a transport profile, host, and port.
  ///
  /// May produce more than one bound endpoint (for example when the hostname
  /// resolves to multiple addresses), hence a list of handles.
  ///
  /// @param transportProfileId Transport profile URI (e.g. TCP UA Binary).
  /// @param hostname           Hostname or IP address to bind to.
  /// @param port               TCP port number.
  /// @param options            Additional listening options.
  /// @return One handle per bound endpoint, or an @ref ErrorDetail on failure.
  ///         Never throws.
  /// @see listen_sync, listen_async
  [[nodiscard]] ListenerHandleListResult try_listen_sync(TransportProfileId transportProfileId,
    string_view hostname, uint16_t port, ListenOptions options = {}) noexcept;

  /// Starts listening on a transport profile, host, and port, blocking until done.
  ///
  /// @param transportProfileId Transport profile URI (e.g. TCP UA Binary).
  /// @param hostname           Hostname or IP address to bind to.
  /// @param port               TCP port number.
  /// @param options            Additional listening options.
  /// @return One handle per bound endpoint. A Good subcode on the answer is not returned; try_listen_sync()
  ///         returns it.
  /// @throws UaException if the listener fails to start.
  /// @see try_listen_sync, listen_async
  [[nodiscard]] ListenerHandleList listen_sync(
    TransportProfileId transportProfileId, string_view hostname, uint16_t port, ListenOptions options = {});

  /// Starts listening on a transport-qualified bind address.
  ///
  /// @param bindAddress Transport-qualified, transport-defined bind address.
  /// @param options     Additional listening options.
  /// @return The listener handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see listen_sync, listen_async
  [[nodiscard]] ListenerHandleResult try_listen_sync(
    ua::transport::BindAddress bindAddress, ListenOptions options = {}) noexcept;

  /// Starts listening on a transport-qualified bind address, blocking until done.
  ///
  /// @param bindAddress Transport-qualified, transport-defined bind address.
  /// @param options     Additional listening options.
  /// @return The listener handle. A Good subcode on the answer is not returned; try_listen_sync() returns it.
  /// @throws UaException if the listener fails to start.
  /// @see try_listen_sync, listen_async
  [[nodiscard]] ListenerHandle listen_sync(
    ua::transport::BindAddress bindAddress, ListenOptions options = {});

  /// Asynchronously starts listening on a transport profile, host, and port.
  ///
  /// @param transportProfileId Transport profile URI (e.g. TCP UA Binary).
  /// @param hostname           Hostname or IP address to bind to.
  /// @param port               TCP port number.
  /// @param options            Additional listening options.
  /// @param callback           Receives one handle per bound endpoint on success,
  ///                           or an @ref ErrorDetail on failure. Never throws.
  /// @see listen_sync, try_listen_sync
  void listen_async(TransportProfileId transportProfileId, string_view hostname, uint16_t port,
    ListenOptions options, ListenCompleteManyCallback callback) noexcept;

  /// Asynchronously starts listening on a transport-qualified bind address.
  ///
  /// @param bindAddress Transport-qualified, transport-defined bind address.
  /// @param options     Additional listening options.
  /// @param callback    Receives the listener handle on success, or an
  ///                    @ref ErrorDetail on failure. Never throws.
  /// @see listen_sync, try_listen_sync
  void listen_async(ua::transport::BindAddress bindAddress, ListenOptions options,
    ListenCompleteOneCallback callback) noexcept;

  /// Adds an endpoint configuration to a listener.
  ///
  /// @param listener The listener to attach the endpoint to.
  /// @param endpoint The endpoint configuration to add.
  void add_endpoint(ListenerHandle listener, ServerEndpointConfig endpoint);

  /// Removes an endpoint configuration from a listener.
  ///
  /// @param listener The listener to remove the endpoint from.
  /// @param endpoint The endpoint configuration to remove.
  void remove_endpoint(ListenerHandle listener, ServerEndpointConfig endpoint);

  /// Returns the endpoint configurations currently attached to a listener.
  ///
  /// @param listener The listener to query.
  /// @return The endpoint configurations currently attached to @p listener.
  std::vector<ServerEndpointConfig> endpoints(ListenerHandle listener) const;

  /// Returns the bind address originally requested for a listener.
  ///
  /// Reflects the caller's request, which may differ from the bound address
  /// (for example when a port of `0` was requested).
  ///
  /// @param listener The listener to query.
  /// @return The bind address originally requested for @p listener.
  /// @see bound_bind_address
  ua::transport::BindAddress requested_bind_address(ListenerHandle listener) const;

  /// Returns the bind address a listener is actually bound to.
  ///
  /// Resolves any wildcard or ephemeral values in the requested address.
  /// Meaningful only after the listener has started.
  ///
  /// @param listener The listener to query.
  /// @return The bind address @p listener is actually bound to.
  /// @see requested_bind_address
  ua::transport::BindAddress bound_bind_address(ListenerHandle listener) const;

  /// Returns the endpoint URLs advertised for a listener.
  ///
  /// @param listener The listener to query.
  /// @return The endpoint URLs advertised for @p listener.
  std::vector<ua::transport::EndpointUrl> advertised_urls(ListenerHandle listener) const;

  /// Returns the certificate store for the default application group.
  ///
  /// The reference is valid only while this server is alive. With push management on
  /// (`ServerConfig::pushCertificateManagementEnabled`), a change written to the store directly
  /// bypasses the server's TrustList: it is not serialised with the TrustList's own changes and is not
  /// part of a push transaction, so it may overwrite one or be overwritten by one.
  ///
  /// @return The certificate store for the default application group.
  CertificateStore& default_application_group_certificate_store() const;

  /// Returns the post-bind discovery URLs, one per bound listener endpoint.
  ///
  /// Valid only after @ref start_sync succeeds; empty beforehand.
  ///
  /// @return The discovery URLs, one per bound listener endpoint; empty before @ref start_sync.
  std::vector<std::string> discovery_urls() const;

  /// Returns the ApplicationDescription this server advertises.
  ///
  /// Built post-bind from the server identity and @ref discovery_urls;
  /// meaningful only after @ref start_sync.
  ///
  /// @return The ApplicationDescription this server advertises.
  ApplicationDescription application_description() const;

  /// Returns the certificate store the registration channel uses by default.
  ///
  /// Backs the shared-with-override trust used when registering with a
  /// discovery server. Never null while this server is alive.
  ///
  /// @return The registration channel's default certificate store; never null.
  std::shared_ptr<CertificateStore> application_certificate_store() const;

  /// Sets the observer for server lifecycle notifications.
  ///
  /// Notifications fire on SDK-internal strands; the observer must not block.
  ///
  /// The server RETAINS the supplied `shared_ptr`, so it co-owns the observer for as long
  /// as one is registered; the observer cannot be destroyed underneath a hook. The lifetime
  /// error to avoid is therefore the reverse cycle: an observer that captures this `Server`
  /// handle, or anything the server owns, keeps the server alive past its intended
  /// shutdown. Capture weakly, or capture only what a hook needs.
  ///
  /// @param observer The observer to install, or `nullptr` to unset (releasing the server's
  ///                 reference to any previously installed observer).
  /// @warning The observer is invoked on internal threads and must not block.
  void set_observer(std::shared_ptr<ServerObserver> observer);

  /// Changes the minimum log level at runtime.
  ///
  /// All existing loggers observe the change immediately via an atomic store. The log *sink* itself
  /// is fixed at construction (see the `logSink` parameter of create()); only the level is mutable.
  ///
  /// @param level The new minimum level to emit.
  void set_log_level(LogLevel level);

  /// Returns a snapshot of server-wide health metrics.
  ///
  /// Counter values are approximate: read from relaxed atomics with no
  /// cross-field consistency guarantee.
  ///
  /// @return A snapshot of server-wide health metrics.
  /// @see session_health_snapshots
  ServerHealthSnapshot health_snapshot() const;

  /// Returns one health snapshot per active session.
  ///
  /// Each snapshot carries per-service request and error counters for its
  /// session.
  ///
  /// @return One health snapshot per active session.
  /// @see health_snapshot
  std::vector<SessionHealthSnapshot> session_health_snapshots() const;

  /// Sets the application delegate for the Node Management services.
  ///
  /// Handles AddNodes, AddReferences, DeleteNodes, and DeleteReferences. With no
  /// delegate set, all four services return `BadServiceUnsupported`. The SDK
  /// performs per-item authorization before delegating, so the delegate sees
  /// only authorized items.
  ///
  /// @param delegate The delegate to install, or `nullptr` to disable node
  ///                 management.
  void set_node_management_delegate(std::shared_ptr<NodeManagementDelegate> delegate);

  /// Sets a local listener that receives every emitted event synchronously.
  ///
  /// The listener is invoked inline during @ref emit_event, before subscription
  /// dispatch. The application is responsible for offloading any non-trivial
  /// work the listener performs.
  ///
  /// @param listener The listener callback, or `nullptr` to clear.
  void set_event_listener(std::function<void(const BaseEvent&)> listener);

  /// Emits an OPC UA event into the server's event pipeline.
  ///
  /// Thread-safe. Auto-fills `EventId`, `ReceiveTime`, and `Time` when unset,
  /// then routes the event to all matching event-monitoring subscriptions based
  /// on the HasNotifier topology from the event's SourceNode.
  ///
  /// @param[in,out] event The event to emit; modified in place to populate the
  ///                      auto-filled fields.
  void emit_event(BaseEvent& event);

  /// Returns the server-level registry of live condition instances.
  ///
  /// Use it to create, find, and manage conditions. The reference is valid only
  /// while this server is alive.
  ///
  /// @return The server-level registry of live condition instances.
  Conditions& conditions();

  /// Returns the server's event sink for event emission.
  ///
  /// The same sink used by @ref emit_event; useful for passing to namespace
  /// implementations that need to inject events. The reference is valid only
  /// while this server is alive.
  ///
  /// @return The server's event sink for event emission.
  EventSink& event_sink();

  /// Creates a UA Binary codec for encoding and decoding DataValues.
  ///
  /// The returned codec is self-contained: it holds shared ownership of the
  /// server's StructureFactory and namespace configuration, so it remains valid
  /// even after the server is destroyed. A typical use is to pass it to a
  /// NamespaceHistoryDelegate that persists DataValues to a database.
  ///
  /// @return A shared pointer to an immutable codec instance.
  shared_ptr<const UaBinaryDataValueCodec> ua_binary_data_value_codec();

  /// Registers a custom structure type with the server's UA Binary decoder.
  ///
  /// When the server receives an ExtensionObject carrying this encoding NodeId
  /// on the wire, it calls the factory to create an instance and decodes into
  /// it.
  ///
  /// @param encodingId The binary encoding NodeId for the type.
  /// @param factory    A callable producing a new default-constructed instance.
  void register_structure_type(const NodeId& encodingId, StructureFactory::CreateMethod factory);

  // --- NodeSet import ---
  //
  // Import an OPC-UA NodeSet2 XML into the server's own address space. Unless
  // `options.structure_resolver` is set, it defaults to the server's structure factory, so values
  // whose ExtensionObject types the server already knows (standard NS0 structures and any types
  // registered via `register_structure_type`) decode without the caller supplying a resolver.
  //
  // Required-model dependencies (`<RequiredModel>`): the server satisfies the standard OPC UA base
  // model (`http://opcfoundation.org/UA/`) from its own built-in NS0, so a companion spec that
  // requires only the base model imports with no caller-supplied base NodeSet. A caller MAY still
  // set `options.resolve_required_model` to supply additional required models (for example a spec
  // that also requires a companion spec such as DI); the caller's resolver is consulted first and
  // the server's built-in NS0 is used only as a fallback, so the caller supplies just the extra
  // models it has. A required model that neither resolves fails the import with a clean
  // `Bad_NotFound` (`MissingRequiredModel`) error.

  /// Imports a parsed NodeSet document into the address space, blocking until done.
  ///
  /// @param document The parsed, immutable NodeSet document to import.
  /// @param options  Import options; the structure resolver defaults to the
  ///                 server's structure factory.
  /// @return The import summary, or an @ref ErrorDetail on failure. Never throws.
  /// @see import_nodeset_sync, import_nodeset_async
  Result<NodeSetImportSummary> try_import_nodeset_sync(
    shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options = {});

  /// Parses and imports a NodeSet2 XML stream into the address space, blocking until done.
  ///
  /// @param nodeset  The NodeSet2 XML stream to parse and import.
  /// @param options  Import options; the structure resolver defaults to the
  ///                 server's structure factory.
  /// @return The import summary, or an @ref ErrorDetail on failure. Never throws.
  /// @see import_nodeset_sync, import_nodeset_async
  Result<NodeSetImportSummary> try_import_nodeset_sync(
    const Stream& nodeset, NodeSetImportOptions options = {});

  /// Imports a parsed NodeSet document into the address space, blocking until done.
  ///
  /// @param document The parsed, immutable NodeSet document to import.
  /// @param options  Import options; the structure resolver defaults to the
  ///                 server's structure factory.
  /// @return The import summary. A Good subcode on the answer is not returned; try_import_nodeset_sync()
  ///         returns it.
  /// @throws UaException if the import's answer is not Good.
  /// @see try_import_nodeset_sync, import_nodeset_async
  NodeSetImportSummary import_nodeset_sync(
    shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options = {});

  /// Parses and imports a NodeSet2 XML stream into the address space, blocking until done.
  ///
  /// @param nodeset The NodeSet2 XML stream to parse and import.
  /// @param options Import options; the structure resolver defaults to the
  ///                server's structure factory.
  /// @return The import summary. A Good subcode on the answer is not returned; try_import_nodeset_sync()
  ///         returns it.
  /// @throws UaException if the import's answer is not Good.
  /// @see try_import_nodeset_sync, import_nodeset_async
  NodeSetImportSummary import_nodeset_sync(const Stream& nodeset, NodeSetImportOptions options = {});

  /// Asynchronously imports a parsed NodeSet document into the address space.
  ///
  /// Async-canonical. There is no `Stream` overload on the async form: parse
  /// with `parse_nodeset` first, then import the resulting document.
  ///
  /// @param document   The parsed, immutable NodeSet document to import.
  /// @param options    Import options; the structure resolver defaults to the
  ///                   server's structure factory.
  /// @param completion Invoked on the server's executor with the import summary
  ///                   on success, or an @ref ErrorDetail on failure. Never throws.
  /// @see import_nodeset_sync, try_import_nodeset_sync
  void import_nodeset_async(shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options,
    std::function<void(Result<NodeSetImportSummary>)> completion);

  // --- Custom DataType registration ---
  //
  // Discover the custom DataTypes already present in the server's own address space (for example
  // from a previously imported NodeSet) and register their structure/union types with the
  // server's UA Binary decoder. After the call, inbound ExtensionObjects of those types decode as
  // typed `DynamicStructure`s with full field access instead of preserved-verbatim
  // `UnknownStructure`s. Opt-in: a pass-through/gateway server relying on verbatim round-trip
  // should not call it for the affected namespaces. Run it after the owning namespace exists.

  /// Discovers and registers the address space's custom DataTypes, blocking until complete.
  ///
  /// @param filter Selects which discovered DataTypes to register; an empty filter selects all.
  ///               Field dependencies of a selected type are always registered.
  /// @return The registration statistics, or an @ref ErrorDetail on a top-level failure. Never throws.
  /// @see register_address_space_types_sync, register_address_space_types_async
  Result<dynamic_types::LoaderRegistrationStats> try_register_address_space_types_sync(
    dynamic_types::TypeFilter filter = {});

  /// Discovers and registers the address space's custom DataTypes, blocking until complete.
  ///
  /// @param filter Selects which discovered DataTypes to register; an empty filter selects all.
  /// @return The registration statistics. A Good subcode on the answer is not returned;
  ///         try_register_address_space_types_sync() returns it.
  /// @throws UaException if the load's answer is not Good at the top level.
  /// @see try_register_address_space_types_sync, register_address_space_types_async
  dynamic_types::LoaderRegistrationStats register_address_space_types_sync(
    dynamic_types::TypeFilter filter = {});

  /// Asynchronously discovers and registers the address space's custom DataTypes.
  ///
  /// @param filter     Selects which discovered DataTypes to register; an empty filter selects all.
  /// @param completion Invoked with the registration statistics on success, or an
  ///                   @ref ErrorDetail on a top-level failure. Never throws.
  /// @see register_address_space_types_sync, try_register_address_space_types_sync
  void register_address_space_types_async(dynamic_types::TypeFilter filter,
    std::function<void(Result<dynamic_types::LoaderRegistrationStats>)> completion);

  // --- Reverse Connect ---

  /// Asynchronously starts a reverse connection to a client-side listener.
  ///
  /// @param target   The reverse-connect target to dial.
  /// @param callback Receives the handle for the started reverse connection on
  ///                 success, or an @ref ErrorDetail on failure. Never throws.
  /// @see start_reverse_connect_sync, try_start_reverse_connect_sync
  void start_reverse_connect_async(ServerConfig::ReverseConnectTarget target,
    std::function<void(ReverseConnectHandleResult)> callback) noexcept;

  /// Starts a reverse connection to a client-side listener, blocking until started.
  ///
  /// @param target The reverse-connect target to dial.
  /// @return A handle identifying the started reverse connection. A Good subcode on the answer is not
  ///         returned; try_start_reverse_connect_sync() returns it.
  /// @throws UaException if the reverse connection cannot be started.
  /// @see start_reverse_connect_async, try_start_reverse_connect_sync
  [[nodiscard]] ReverseConnectHandle start_reverse_connect_sync(ServerConfig::ReverseConnectTarget target);

  /// Starts a reverse connection to a client-side listener, blocking until started.
  ///
  /// @param target The reverse-connect target to dial.
  /// @return A handle for the started reverse connection, or an @ref ErrorDetail
  ///         on failure. Never throws.
  /// @see start_reverse_connect_async, start_reverse_connect_sync
  [[nodiscard]] ReverseConnectHandleResult try_start_reverse_connect_sync(
    ServerConfig::ReverseConnectTarget target) noexcept;

  /// Asynchronously stops a reverse connection.
  ///
  /// @param handle   The reverse connection to stop.
  /// @param callback Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see stop_reverse_connect_sync, try_stop_reverse_connect_sync
  void stop_reverse_connect_async(
    ReverseConnectHandle handle, std::function<void(VoidResult)> callback) noexcept;

  /// Stops a reverse connection, blocking until stopped.
  ///
  /// @param handle The reverse connection to stop.
  /// @throws UaException if the reverse connection cannot be stopped.
  /// @see stop_reverse_connect_async, try_stop_reverse_connect_sync
  void stop_reverse_connect_sync(ReverseConnectHandle handle);

  /// Stops a reverse connection, blocking until stopped.
  ///
  /// @param handle The reverse connection to stop.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see stop_reverse_connect_async, stop_reverse_connect_sync
  [[nodiscard]] VoidResult try_stop_reverse_connect_sync(ReverseConnectHandle handle) noexcept;

  /// Asynchronously stops all active reverse connections.
  ///
  /// @param callback Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see stop_all_reverse_connects_sync, try_stop_all_reverse_connects_sync
  void stop_all_reverse_connects_async(std::function<void(VoidResult)> callback) noexcept;

  /// Stops all active reverse connections, blocking until stopped.
  ///
  /// @throws UaException if stopping fails.
  /// @see stop_all_reverse_connects_async, try_stop_all_reverse_connects_sync
  void stop_all_reverse_connects_sync();

  /// Stops all active reverse connections, blocking until stopped.
  ///
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see stop_all_reverse_connects_async, stop_all_reverse_connects_sync
  [[nodiscard]] VoidResult try_stop_all_reverse_connects_sync() noexcept;

  /// Asynchronously initiates a graceful server shutdown.
  ///
  /// Transitions ServerState to Shutdown, sets `SecondsTillShutdown` and
  /// `ShutdownReason`, emits a `SystemStatusChangeEvent`, stops accepting new
  /// connections, and starts a countdown. When the countdown expires, all
  /// sessions are terminated (with queued responses drained) and secure
  /// channels are closed.
  ///
  /// @param params   Shutdown parameters (grace period, reason).
  /// @param callback Invoked when shutdown is complete, with success or an
  ///                 @ref ErrorDetail. Never throws.
  /// @see shutdown_sync, try_shutdown_sync
  void shutdown_async(ShutdownOptions params, CompleteCallback callback) noexcept;

  /// Initiates a graceful server shutdown, blocking until complete.
  ///
  /// @param params Shutdown parameters (grace period, reason).
  /// @throws UaException if shutdown fails.
  /// @see shutdown_async, try_shutdown_sync
  void shutdown_sync(ShutdownOptions params = {});

  /// Initiates a graceful server shutdown, blocking until complete.
  ///
  /// @param params Shutdown parameters (grace period, reason).
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see shutdown_async, shutdown_sync
  [[nodiscard]] VoidResult try_shutdown_sync(ShutdownOptions params = {}) noexcept;

  /// Creates a server from its configuration and the components the application supplies.
  ///
  /// Synchronous: validates the configuration and the security gates of every endpoint it declares,
  /// builds the address space from the compiled-in NS0 model, and opens any certificate store not
  /// supplied (reading its trust-list directories). No network work happens here; listening starts
  /// with @ref listen_sync / @ref listen_async.
  ///
  /// @param executor   The executor that runs the server's asynchronous work.
  /// @param config     The server creation configuration (identity and settings).
  /// @param components The crypto provider (required), certificate stores, authenticator, Role
  ///                   configuration and log sink. See @ref ServerComponents.
  /// @return A new server handle.
  /// @throws UaException `BadConfigurationError` when @p components has no crypto provider, when the
  ///         configuration is invalid, or when a declared endpoint fails the security gates.
  /// @throws UaException `BadWouldBlock` when called on a thread of @p executor: building the Server waits
  ///         for work that runs on that executor, so it must be called from an application thread.
  /// @see try_create
  static Server create(
    boost::asio::any_io_executor executor, ::ua::server::CreateConfig config, ServerComponents components);

  /// The created @ref Server on success, or an @ref ErrorDetail on failure.
  using CreateResult = Result<Server>;

  /// Creates a server, returning a bad @ref CreateResult instead of throwing on failure.
  ///
  /// @param executor   The executor that runs the server's asynchronous work.
  /// @param config     The server creation configuration (identity and settings).
  /// @param components The crypto provider (required), certificate stores, authenticator, Role
  ///                   configuration and log sink. See @ref ServerComponents.
  /// @return The created @ref Server, or an @ref ErrorDetail on failure (including `BadWouldBlock` when
  ///         called on a thread of @p executor). Never throws.
  /// @see create
  [[nodiscard]] static CreateResult try_create(boost::asio::any_io_executor executor,
    ::ua::server::CreateConfig config, ServerComponents components) noexcept;

private:
  friend class ::ua::test_helpers::ServerTestAccess;

  explicit Server(shared_ptr<ServerImpl> impl);

  shared_ptr<ServerImpl> mImpl;
};

/// Stops a @ref ua::server::Server as part of a @ref ua::Runtime shutdown.
///
/// Declared in `ua::server` so argument-dependent lookup finds it from @ref ua::Runtime::attach.
/// Passes the policy's grace period and reason through unchanged as ShutdownOptions::grace and
/// ShutdownOptions::reason (the same names and types), so clients see the countdown the application
/// asked for in `ServerStatus.SecondsTillShutdown`.
///
/// The pass-through preserves `std::nullopt`, and that is the point: an unset
/// @ref ua::ShutdownPolicy::grace reaches `shutdown_sync` unset, so the server uses its own
/// `ServerConfig::defaultShutdownGracePeriodSeconds`. Substituting a number here - even
/// zero - would quietly disable that field for every server owned by a runtime.
///
/// @param server  The server being stopped.
/// @param context The resolved policy, deadline and logger for this shutdown.
inline void runtime_shutdown(Server& server, const ua::ShutdownContext& context)
{
  server.shutdown_sync(ShutdownOptions{.grace = context.policy.grace, .reason = context.policy.reason});
}

}  // namespace server

}  // namespace ua

#endif  // !UA_SERVER_H
