// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_IMPL_H
#define UA_SERVER_IMPL_H

#include "ua_identity_attempt_outcome.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_server.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_server_config_bundle.h"
#include "ua_server_configuration.h"
#include "ua_endpoint_description.h"
#include "ua_binary_data_value_codec.h"
#include "ua_structure_factory.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "session/ua_client_id.h"
#include "ua_create_session_request.h"
#include "ua_activate_session_request.h"
#include "ua_server_secure_channel_info.h"
#include "ua_server_model.h"
#include "ua_server_observer.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_method_response_correlation.h"
#include "ua_server_counters.h"
#include "ua_server_health.h"
#include "ua_request_latency_tracker.h"
#include "ua_event_bus.h"
#include "ua_server_state.h"
#include "ua_namespace_delegates.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_timer.h"

#include "security/ua_push_management_wiring.h"
#include "ua_server_authentication.h"
#include "ua_server_components.h"

#include "ua_server_reverse_connect_listener.h"
#include "ua_tcp_endpoint.h"

#include <optional>
#include <span>
#include <set>

#include <ua_certificate_store.h>
#include "secure_channel/ua_server_secure_channel.h"

namespace ua
{

namespace xml::nodeset
{
class ImportEngine;
class NodeSet;
}  // namespace xml::nodeset

class Conditions;
class Timer;
class TcpTransportAcceptor;
class TcpTransportConnection;

namespace server
{

class SecureChannel;
class Session;

class SessionDependencies;
class SecureChannelDependencies;
class DiscoveryDependencies;
class ServerDependencies;
class RegisteredServerStore;

}  // namespace server
}  // namespace ua

namespace ua::test_helpers
{
class ServerImplTestAccess;
}

namespace ua
{
namespace server
{

class RoleConfiguration;
class SamplingIntervalDiagnosticsNodeManager;
class SubscriptionDiagnosticsNodeManager;
class NamespaceMetadataPublication;

class ServerImpl : public std::enable_shared_from_this<ServerImpl>
{
  friend class Server;
  friend class ::ua::test_helpers::ServerImplTestAccess;

public:
  ServerImpl() = delete;
  ServerImpl(const ServerImpl&) = delete;
  ServerImpl(ServerImpl&& other) noexcept = delete;
  ServerImpl& operator=(const ServerImpl& other) = delete;
  ServerImpl& operator=(ServerImpl&& other) noexcept = delete;

  ~ServerImpl();

  using ListenCompleteOneCallback = Server::ListenCompleteOneCallback;
  using ListenCompleteManyCallback = Server::ListenCompleteManyCallback;

  /// @throws UaException `BadConfigurationError` when @p components has no crypto provider.
  static shared_ptr<ServerImpl> create(boost::asio::any_io_executor executor,
    ::ua::server::CombinedConfig config, ::ua::server::ServerComponents components);

  // --- Public API (methods that Server delegates to) ---

  /// The key the per-IP connection throttle counts under: the IPv4 address, the embedded IPv4 of a
  /// v4-mapped IPv6 address, or the IPv6 address masked to @p ipv6PrefixLength bits (128 keeps the
  /// whole address, scope id included; 64 makes every address of one /64 one remote). Pure.
  static std::string connection_throttle_key(
    const boost::asio::ip::address& address, uint32_t ipv6PrefixLength);

  AddressSpace& address_space();
  const ::ua::server::CombinedConfig& config() const;
  shared_ptr<const Crypto> crypto() const;
  void start_async(Server::CompleteCallback callback) noexcept;
  void shutdown_async(ShutdownOptions params, Server::CompleteCallback callback);

  void listen_async(TransportProfileId transportProfileId, string_view hostname, uint16_t port,
    ListenOptions options, ListenCompleteManyCallback callback);
  void listen_async(
    ua::transport::BindAddress bindAddress, ListenOptions options, ListenCompleteOneCallback callback);

  void add_endpoint(ListenerHandle listener, ServerEndpointConfig endpoint);
  void remove_endpoint(ListenerHandle listener, ServerEndpointConfig endpoint);
  std::vector<ServerEndpointConfig> endpoints(ListenerHandle listener) const;

  ua::transport::BindAddress requested_bind_address(ListenerHandle listener) const;
  ua::transport::BindAddress bound_bind_address(ListenerHandle listener) const;
  std::vector<ua::transport::EndpointUrl> advertised_urls(ListenerHandle listener) const;

  shared_ptr<CertificateStore> default_application_group_certificate_store() const;
  /// The store holding trust anchors for X.509 user identity tokens, or null when none is configured.
  shared_ptr<CertificateStore> user_token_certificate_store() const;

  /// Post-bind discovery URLs aggregated across all listeners. Valid only after start.
  std::vector<std::string> discovery_urls() const;

  /// The ApplicationDescription this server advertises. Built post-bind from identity +
  /// discovery_urls().
  ApplicationDescription application_description() const;

  /// The inbound LDS registry, or nullptr when the server-as-LDS feature is gated OFF.
  shared_ptr<RegisteredServerStore> registered_server_store() const;

  // Reverse connect
  void start_reverse_connect_async(
    ServerConfig::ReverseConnectTarget target, std::function<void(ReverseConnectHandleResult)> callback);
  void stop_reverse_connect_async(ReverseConnectHandle handle, std::function<void(VoidResult)> callback);
  void stop_all_reverse_connects_async(std::function<void(VoidResult)> callback);

  void set_node_management_delegate(std::shared_ptr<NodeManagementDelegate> delegate);
  void set_observer(std::shared_ptr<ServerObserver> handler);

  void set_log_level(LogLevel level);

  ServerHealthSnapshot health_snapshot() const;
  std::vector<SessionHealthSnapshot> session_health_snapshots() const;

  EventBus& event_bus();

  std::shared_ptr<EventBus> event_bus_shared() const
  {
    return mEventBus;
  }

  Conditions& conditions();

  shared_ptr<const UaBinaryDataValueCodec> ua_binary_data_value_codec();

  void register_structure_type(const NodeId& encodingId, StructureFactory::CreateMethod factory);

  // Discover the custom DataTypes in the server's own address space and register their
  // structure/union types with mStructureFactory (the decode factory). See Server's public wrappers.
  Result<dynamic_types::LoaderRegistrationStats> try_register_address_space_types_sync(
    dynamic_types::TypeFilter filter);
  dynamic_types::LoaderRegistrationStats register_address_space_types_sync(dynamic_types::TypeFilter filter);
  void register_address_space_types_async(dynamic_types::TypeFilter filter,
    std::function<void(Result<dynamic_types::LoaderRegistrationStats>)> completion);

  // A lifetime-safe resolver over the server's structure factory (weak-captures the server; resolves
  // both binary and xml encoding ids of every registered type). `Server`'s import wrappers default
  // `NodeSetImportOptions::structure_resolver` to this, so an import into the server's address space
  // decodes values against the types the server knows.
  StructureResolver structure_resolver();

  // A `<RequiredModel>` resolver that satisfies the standard OPC UA base model
  // (`http://opcfoundation.org/UA/`) from the server's own compiled-in NS0 nodeset. `Server`'s
  // import wrappers default `NodeSetImportOptions::resolveRequiredModel` to this, so importing a
  // companion spec that declares the UA base model needs no caller-supplied base NodeSet - the
  // dependency is loaded (parsed) alongside, so custom types are classified, based, and discovered.
  // Returns nullptr for any other model URI (the caller supplies deeper dependencies).
  std::function<std::unique_ptr<Stream>(const ModelRef&)> required_model_resolver() const;

private:
  friend class ServerDependencies;
  friend class ServerReverseConnectDeps;

  // --- Internal API (accessed via ServerDependencies or internally) ---

  boost::asio::any_io_executor executor() const;
  ::ua::ApplicationIdentity identity() const;
  const ::ua::ApplicationConfig& configuration() const;
  /// The configuration as a shared handle, so a collaborator can OWN it rather than hold a
  /// reference whose validity depends on this server still existing.
  std::shared_ptr<const ::ua::ApplicationConfig> shared_configuration() const;
  const ::ua::server::ServerConfig& server_configuration() const;
  /// The components the server was created with, as supplied (the session layer reads the
  /// authenticator and Role configuration from here).
  const ::ua::server::ServerComponents& components() const;
  StructureFactory& structure_factory();
  Logger logger() const;

  std::shared_ptr<ServerObserver> observer() const;
  void add_internal_observer(std::shared_ptr<ServerObserver> observer);

  ListenerHandleList listeners() const;
  std::vector<ServerEndpointConfig> endpoints() const;

  void new_tcp_connection(ListenerHandle listener, std::string listenerName, StatusCode status,
    string_view errorDescription, shared_ptr<TcpTransportConnection> connection);
  // The accept path with the peer's endpoint given: new_tcp_connection passes the socket's own. The
  // unit arms pass an IPv6 peer over an IPv4 loopback socket, so the IPv6 keying is exercised on a
  // host without IPv6 loopback.
  void accept_tcp_connection(ListenerHandle listener, std::string listenerName, StatusCode status,
    shared_ptr<TcpTransportConnection> connection, const asio::ip::tcp::endpoint& remote);
  void new_connection_complete(ListenerHandle listener, std::string listenerName, StatusCode status,
    shared_ptr<ConnectionProtocol> connection, ua::connection_protocol::NegotiatedLimits negotiatedLimits,
    std::string remoteAddress = {});

  void add_secure_channel(shared_ptr<SecureChannel> secureChannel);
  void remove_secure_channel(const shared_ptr<SecureChannel>& channel);
  void create_session(
    SecureChannelInfo secureChannelInfo, uint32_t requestId, CreateSessionRequest&& request);
  [[nodiscard]] VoidResult admit_session(shared_ptr<Session> session) noexcept;
  void activate_session_on_channel(
    SecureChannelInfo newChannelInfo, uint32_t requestId, ActivateSessionRequest&& request);
  void remove_session(const shared_ptr<Session>& session);
  uint32_t get_next_secure_channel_id();
  String server_uri() const;
  ua::connection_protocol::Limits connection_protocol_limits() const;
  static void dispatch_apply_changes_channel_close(std::vector<weak_ptr<SecureChannel>> channels,
    const std::vector<shared_ptr<Session>>& sessions, const NodeId& originSessionId,
    MethodResponseCorrelation correlation, std::function<void(VoidResult)> callback);
  static void dispatch_certificate_reevaluation(std::vector<weak_ptr<SecureChannel>> channels,
    const std::vector<shared_ptr<Session>>& sessions, const NodeId& originSessionId,
    MethodResponseCorrelation correlation, std::function<void(VoidResult)> callback);

  shared_ptr<SessionDependencies> session_dependencies();
  shared_ptr<SecureChannelDependencies> secure_channel_dependencies();
  std::shared_ptr<NodeManagementDelegate> node_management_delegate() const;

  // Counter accessors for dependency injection into sessions/channels.
  std::shared_ptr<ServerSummaryCounters> summary_counters() const;
  std::shared_ptr<SecureChannelCounters> secure_channel_counters() const;
  std::shared_ptr<ConnectionCounters> connection_counters() const;
  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() const;
  std::shared_ptr<RequestLatencyTracker> latency_tracker() const;
  SubscriptionIdAllocator& subscription_id_allocator();
  SubscriptionRouter& subscription_router();
  OrphanedSubscriptionStore& orphaned_subscription_store();
  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() const;
  std::shared_ptr<std::atomic<uint32_t>> in_flight_requests() const;

  // S11: Identity token attack protection.
  optional<StatusCode> begin_identity_attempt(const ClientId& client, std::string_view claimedUserId);
  void finish_identity_attempt(
    const ClientId& client, std::string_view claimedUserId, IdentityAttemptOutcome outcome);

  // Test-only helpers - accessible via friend class ServerImplTestAccess.
  // Skips the startup refusal of an own certificate violating a served endpoint's SecurityPolicy, for
  // fixtures that start a server on deliberately non-compliant certificates.
  bool mBypassOwnCertificatePolicyCheckForTests{false};
  void initialise_listeners_from_config_for_tests();
  std::vector<shared_ptr<Session>> sessions_for_tests() const;
  // Whether a Session with this NodeId is still held by the server (the push service's liveness
  // question). A scan of mSessions under the read lock.
  bool session_exists(const NodeId& sessionId) const;
  std::function<void()> mOnNetworkActivationForTests;

  // Test/fuzz hook: called when a new SecureChannel is created, before it processes any messages.
  // Allows tests to install request observers and response interceptors on the server channel.
  using SecureChannelAvailableCallback = std::function<void(std::shared_ptr<SecureChannel>)>;
  SecureChannelAvailableCallback mOnSecureChannelAvailable;
  void set_on_secure_channel_available(SecureChannelAvailableCallback callback);
  std::function<void(Session&)> mOnSessionAdmittedForTests;

  struct ListenerState
  {
    ListenerHandle handle;
    std::string name;

    ua::transport::BindAddress requestedBind;
    ua::transport::BindAddress boundBind;
    std::vector<ua::transport::EndpointUrl> advertisedUrls;

    // Temporary internal representation until more transports are implemented.
    TransportProfileId transportProfileId{TransportProfileId::UaTcpUaScUaBinary};
    TcpEndpoint endpoint;
    std::optional<TcpEndpoint> boundEndpoint;
    ListenOptions listenOptions;

    shared_ptr<TcpTransportAcceptor> tcpTransportAcceptor;
    std::vector<ServerEndpointConfig> endpoints;
  };

  mutable std::shared_mutex mMutex;

  // Heap-allocated dynamic state shared with ExternalValueSource handlers on address space nodes.
  // ServerImpl writes; handlers co-own via shared_ptr so reads are safe even if ServerImpl is destroyed.
  std::shared_ptr<ServerDynamicState> mDynamicState{std::make_shared<ServerDynamicState>()};

  AddressSpace mAddressSpace;
  const boost::asio::any_io_executor mExecutor;
  const ::ua::server::CombinedConfig mConfig;
  shared_ptr<const Crypto> mCrypto;
  shared_ptr<CertificateStore> mDefaultApplicationGroupCertificateStore;
  // Trust anchors for X.509 user identity tokens. Null when neither the components nor the
  // configured trust-list path supplies one, which is the case for a server offering no X.509
  // user-token policy.
  shared_ptr<CertificateStore> mUserTokenCertificateStore;
  // The components as the application supplied them. Declared after the members initialised from
  // them, which copy rather than move.
  const ::ua::server::ServerComponents mComponents;

  // Inbound server-as-LDS registry. Constructed only when ServerConfig::LocalDiscoveryServer
  // is enabled; nullptr otherwise (keeps the FindServers aggregation a null-check).
  shared_ptr<RegisteredServerStore> mRegisteredServerStore;
  optional<ServerModel> mServerModel;

  std::vector<ListenerState> mListeners;

  std::uint64_t mNextListenerHandle{1};

  struct ReverseConnectState
  {
    ReverseConnectHandle handle;
    std::string targetName;
    ListenerHandle syntheticListenerHandle;
    std::shared_ptr<ReverseConnectListenerDependencies> dependencies;
    std::shared_ptr<ReverseConnectListener> manager;
  };

  std::vector<ReverseConnectState> mReverseConnects;  // guarded by mMutex

  /// The configured target name when @p listener is the synthetic handle of a reverse-connect
  /// target, otherwise empty. Lets the connection/channel paths - which are shared with forward
  /// connections - raise the reverse-connect observer hooks for the right target.
  /// Takes mMutex.
  std::optional<std::string> reverse_target_name_for(ListenerHandle listener) const;

  std::uint64_t mNextReverseConnectHandleId{1};

  // Logging: shared level allows runtime changes visible to all loggers immediately.
  std::shared_ptr<std::atomic<LogLevel>> mLogLevel{std::make_shared<std::atomic<LogLevel>>(LogLevel::Info)};
  std::shared_ptr<LogSink> mLogSink;
  // Set once in the constructor from the create()-time logSink and never reassigned (there is no
  // runtime sink setter), so logger() reads it without a lock or a race. The shared mLogLevel lets
  // set_log_level() change verbosity at runtime for every derived logger.
  Logger mLogger;

  // mObserver is declared before connection/channel/session collections so that it is
  // destroyed after them (C++ reverse-declaration-order destruction). This ensures that
  // weak_ptr<ServerObserver> held by SecureChannel/Session destructors can still lock
  // during server teardown.
  shared_ptr<ServerObserver> mObserver;
  std::vector<shared_ptr<ServerObserver>> mInternalObservers;  // guarded by mMutex
  shared_ptr<ServerObserver> mCompositeObserver;  // dispatches to mObserver + all mInternalObservers

  // Diagnostic counters (heap-allocated, shared via shared_ptr for safe handler capture).
  std::shared_ptr<std::atomic<bool>> mDiagnosticsEnabled{std::make_shared<std::atomic<bool>>(true)};
  std::shared_ptr<ServerSummaryCounters> mSummaryCounters{std::make_shared<ServerSummaryCounters>()};
  std::shared_ptr<SecureChannelCounters> mSecureChannelCounters{std::make_shared<SecureChannelCounters>()};
  std::shared_ptr<ConnectionCounters> mConnectionCounters{std::make_shared<ConnectionCounters>()};
  std::shared_ptr<RequestLatencyTracker> mLatencyTracker{std::make_shared<RequestLatencyTracker>()};
  // Active Part-18 role configuration used to materialise Role nodes and map
  // activated identities to granted Role NodeIds.
  std::shared_ptr<RoleConfiguration> mRoleConfiguration;
  SubscriptionIdAllocator mSubscriptionIdAllocator;
  SubscriptionRouter mSubscriptionRouter;
  // Maintains the per-subscription SubscriptionDiagnosticsType child nodes under
  // SubscriptionDiagnosticsArray (OPC 10000-5 6.3.7); driven by mSubscriptionRouter lifecycle.
  std::shared_ptr<SubscriptionDiagnosticsNodeManager> mSubscriptionDiagnosticsNodes;
  // Maintains the per-interval SamplingIntervalDiagnosticsType nodes under SamplingIntervalDiagnosticsArray
  // (OPC 10000-5 6.3.6); reconciled on MonitoredItem changes through mSubscriptionRouter.
  std::shared_ptr<SamplingIntervalDiagnosticsNodeManager> mSamplingIntervalDiagnosticsNodes;
  OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  // Held as shared_ptr so observers (e.g. AuditEventEmitter) can keep a
  // weak_ptr and gracefully no-op if they fire after the bus is destroyed.
  std::shared_ptr<EventBus> mEventBus;
  // Held as shared_ptr because Conditions inherits enable_shared_from_this
  // so its async-flow continuations can capture
  // weak_from_this() instead of raw `this`.
  std::shared_ptr<Conditions> mConditions;

  // Push certificate management (Phase 5 - GDS push model)
  std::optional<PushManagementComponents> mPushManagement;

  std::shared_ptr<NodeManagementDelegate> mNodeManagementDelegate;

  // S12: Server-wide in-flight discovery request counter for load-aware throttling.
  std::shared_ptr<std::atomic<uint32_t>> mInFlightDiscoveryRequests{
    std::make_shared<std::atomic<uint32_t>>(0)};

  // Server-wide in-flight (non-Publish) service-request counter, enforced as an admission cap
  // (`ServerConfig::maxInFlightRequests`) at the SecureChannel. Incremented when a request
  // is forwarded to a session, decremented when its response is sent.
  std::shared_ptr<std::atomic<uint32_t>> mInFlightRequests{std::make_shared<std::atomic<uint32_t>>(0)};

  // S10: Per-IP connection throttling state.
  struct PerIpState
  {
    uint32_t activeCount{0};
    std::vector<std::chrono::steady_clock::time_point> recentAttempts;
  };

  std::unordered_map<std::string, PerIpState> mPerIpState;  // guarded by mMutex
  // Hard cap on distinct attacker-controlled IP keys; at cap a new key evicts the least-recently-seen
  // entry (LRU by last attempt) so a spoofed-source-IP flood cannot grow the map without limit.
  size_t mMaxPerIpThrottleEntries{10000};  // guarded by mMutex
  // Maps the transport connection's identity -> throttle key, written in the same locked step as the
  // reservation (the transport exists before the ConnectionProtocol, so no release can run before the
  // entry does) and erased when the connection leaves the server: a failed handshake, a refusal at
  // any gate, or the removal of the channel it became. The slot bounds concurrent CONNECTIONS from
  // one remote, not concurrent handshakes.
  std::unordered_map<const TransportConnection*, std::string> mConnectionRemoteIp;  // guarded by mMutex

  // S11: Identity token attack protection state.
  struct IdentityThrottleState
  {
    /// Failures per claimed user of this client application. A success clears only its own user's
    /// entry; the sum stays below the threshold, so the map holds at most that many users.
    std::unordered_map<std::string, uint32_t> failuresByUser;
    /// Authentication attempts reserved and not yet finished (SESS-2).
    uint32_t inFlight{0};
    std::chrono::steady_clock::time_point lastFailureTime;
    std::chrono::steady_clock::time_point lockedUntil;

    uint32_t failures() const noexcept
    {
      uint32_t total = 0;
      for (const auto& [user, count] : failuresByUser)
      {
        total += count;
      }
      return total;
    }
  };

  std::unordered_map<ClientId, IdentityThrottleState> mIdentityThrottleState;  // guarded by mMutex
  // Hard cap on distinct Client application keys; at cap a new key evicts the least-recently-failed entry
  // (LRU by last failure). Active lockouts have recent timestamps and so survive eviction until the
  // map is saturated with recent failures (itself a bounded state).
  size_t mMaxIdentityThrottleEntries{10000};  // guarded by mMutex

  std::vector<shared_ptr<ConnectionProtocol>> mInitialisingConnections;
  /// Test hook: runs in `new_tcp_connection` after the ConnectionProtocol is created and before its
  /// entry is published, so a test can drive the handshake to a terminal outcome in that window.
  std::function<void()> mBeforeInitialisingPublicationForTests;
  std::vector<shared_ptr<SecureChannel>> mSecureChannels;
  std::vector<shared_ptr<Session>> mSessions;
  std::unordered_map<NodeId, weak_ptr<Session>> mSessionsByToken;

  // Single structure factory shared by both codecs: it holds each type's binary AND xml encoding
  // ids (distinct NodeIds, so no collision), so a type registered once is resolvable on the binary
  // wire and the XML / NodeSet-import paths alike.
  StructureFactory mStructureFactory;

  uint32_t mNextSecureChannelId{};

  shared_ptr<ServerDependencies> mDependencies;
  shared_ptr<NamespaceMetadataPublication> mNamespaceMetadataPublication;

  ServerImpl(boost::asio::any_io_executor executor, ::ua::server::CombinedConfig config,
    ::ua::server::ServerComponents components);

  std::vector<shared_ptr<ua::xml::nodeset::NodeSet>> get_ns0_nodeset();

  enum class StartupState
  {
    Idle,
    PreparingMetadata,
    StartingNetwork,
    Started,
  };

  class StartupAttempt;

  void on_start_metadata_prepared(const shared_ptr<StartupAttempt>& attempt, VoidResult result) noexcept;
  void finish_start_attempt(
    const shared_ptr<StartupAttempt>& attempt, VoidResult result, StartupState failureState) noexcept;
  [[nodiscard]] ListenerHandle configure_listener(
    ua::transport::BindAddress bindAddress, ListenOptions options);
  /// Materialise listeners, then continue the start - directly when no endpoint needs a
  /// certificate, otherwise after an ASYNCHRONOUS fetch from the application-group store.
  ///
  /// It used to fetch with `try_get_application_certificates_sync()`, which blocks on a future
  /// whose work is posted to the store's executor. Where that executor is the server's own and
  /// has a single worker, the worker running this continuation was the only thread that could
  /// have completed the fetch, so `Server::start_sync()` hung with no timeout and no error.
  void start_network_surfaces(const shared_ptr<StartupAttempt>& attempt);

  /// Continuation of `start_network_surfaces` once the certificate list is in hand. Carries
  /// everything from endpoint validation through acceptor activation to the Running commit, so
  /// the acceptor rollback that runs on failure stays on ONE side of the suspension point.
  void continue_start_network_surfaces(const shared_ptr<StartupAttempt>& attempt,
    const std::vector<ServerEndpointConfig>& endpoints,
    const std::vector<CertificateStore::ApplicationCertificate>& available) noexcept;

  /// The start continuation's last step: binds the listeners and enters Running, or fails the start
  /// with @p populated's failure. Runs on the Server's strand.
  void activate_listeners(const shared_ptr<StartupAttempt>& attempt, VoidResult populated) noexcept;

  void create_standard_nodes(std::span<const NodeId> roleManagementAccessRoles);

  void create_standard_nodes_from_nodeset(shared_ptr<xml::nodeset::ImportEngine> engine,
    const std::vector<shared_ptr<ua::xml::nodeset::NodeSet>>& nodeSets);

  void create_crypto_components();

  StartupState mStartupState{StartupState::Idle};  // guarded by mMutex
  shared_ptr<StartupAttempt> mStartupAttempt;  // guarded by mMutex

  void initialise_next_secure_channel_id();

  /// Validate, seed and seal the construction-time Role configuration before NS0 import.
  /// @return Registered Roles whose ordinary Role-management policy must be authored by that import.
  std::vector<NodeId> prepare_role_configuration();

  /// Materialise the configured RoleSet and attach its management handlers.
  /// Must be called after `create_standard_nodes()` so that NS0 + any app-installed namespaces are
  /// available for Part-18 routing.
  void wire_role_configuration();

  void validate_configuration(const ::ua::ApplicationConfig& configuration);

  void rebuild_composite_observer();

  /// The certificate types these endpoints require. Pure: no store, no I/O, no blocking.
  [[nodiscard]] static std::set<CertificateType> required_certificate_types(
    const std::vector<ServerEndpointConfig>& endpoints, bool includeNoneEndpointTokenTypes = true);

  /// Compare what the endpoints require against what the store holds; throws `UaException` on a
  /// missing type or an over-long mixed-RSA key. Pure - the CALLER supplies the certificate list,
  /// which is what keeps the blocking fetch out of the validator and off the strand.
  static void validate_endpoint_certificates(const std::vector<ServerEndpointConfig>& endpoints,
    const std::vector<CertificateStore::ApplicationCertificate>& available);

  // S10: Release the per-IP slot the transport connection reserved at accept, if it still holds one.
  // Idempotent. Must be called under WriteLock.
  void decrement_per_ip_count_locked(const TransportConnection* transport);

  /// Removes an initialising (pre-handshake) connection from the list and releases its per-IP count.
  /// Returns the released owner, or null when the connection is not in the list (its handshake
  /// completed, or it was already released). Caller holds `mMutex` for writing.
  shared_ptr<ConnectionProtocol> release_initialising_connection_locked(ConnectionProtocol* connection);

  /// Outcome record shared between `new_tcp_connection` (which publishes the initialising entry)
  /// and the ConnectionProtocol's terminal callbacks, which may run first: the protocol starts its
  /// I/O inside `ConnectionProtocol::create`, so a peer whose bytes are already buffered at accept
  /// can fail (or complete) its handshake before the accept path publishes the entry. Guarded by
  /// `mMutex`.
  struct InitialisingSlot
  {
    enum class Outcome
    {
      Pending,
      Failed,
      Completed
    };
    ConnectionProtocol* connection{nullptr};  ///< set when the entry is published
    Outcome outcome{Outcome::Pending};  ///< set by a terminal callback that ran before publication
    StatusCode status{Status::Good};  ///< the failure status, when `outcome == Failed`
  };

  /// Releases the per-IP concurrent-connection reservation made at accept for `remoteIp`. Caller
  /// holds `mMutex` for writing.
  void release_per_ip_reservation_locked(const std::string& remoteIp);

  /// Terminal-outcome sink for a connection created by `new_tcp_connection`, fired by the
  /// ConnectionProtocol's close observer on its own strand. A failed handshake (refused first frame,
  /// early peer close, handshake timeout) releases the MaxConnections slot and the per-IP count the
  /// accept path reserved; after a successful handshake the entry is already gone and this is a no-op.
  /// A failure that arrives before the entry is published is recorded in `slot`, and the publication
  /// step then releases the reservation instead of publishing.
  void initialising_connection_failed(
    std::shared_ptr<InitialisingSlot> slot, StatusCode status, std::string remoteAddress);

  // Shutdown internals.
  Server::CompleteCallback mShutdownCallback;  // guarded by mMutex
  std::optional<Timer> mShutdownTimer;  // guarded by mMutex
  /// Bounds the wait for namespaces to stop their background work, so a namespace that never
  /// answers cannot turn a hang at join() into a hang at shutdown(). Shutdown-path only.
  std::optional<Timer> mNamespaceShutdownTimer;
  void on_grace_period_expired();
  void on_reverse_connects_stopped();
  /// Tears down server-internal infrastructure and asks every namespace to stop its background
  /// work. @p onNamespacesStopped, when supplied, runs once the namespaces have answered or the
  /// wait has been bounded out; the destructor supplies none, because it cannot wait.
  /// Reports shutdown complete (observer on_shutdown_complete, then @p callback) after the event bus has
  /// closed the application's event listener.
  void report_shutdown_complete(Server::CompleteCallback callback);
  void complete_shutdown(std::function<void(VoidResult)> onNamespacesStopped = {});
  void close_all_acceptors();
};

}  // namespace server

}  // namespace ua

#endif  // !UA_SERVER_IMPL_H
