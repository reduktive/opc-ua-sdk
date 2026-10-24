// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CORE_CLIENT_IMPL_H
#define UA_CORE_CLIENT_IMPL_H

#include "ua_core_client.h"
// The shared impl still serves the tier-1 managed entry points (client design section 7.1): Client
// composes a CoreClient and forwards into this object, so the tier-1 callback/result typedefs are
// needed here.
#include "ua_client.h"
#include "ua_client_config_bundle.h"
#include "ua_client_configuration.h"
#include "ua_observer_sink.h"
#include "ua_pull_certificate_manager.h"
#include "ua_reverse_connect_config.h"
#include "ua_client_secure_channel.h"
#include "ua_client_secure_channel_impl.h"
#include "ua_connection_protocol_limits.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_reverse_connect_listener.h"
#include "ua_structure_factory.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace ua
{
class ConnectionProtocolDependencies;
class CertificateStore;
}  // namespace ua

namespace ua::mdns
{
class MdnsTransport;
}  // namespace ua::mdns

namespace ua::client
{

class SecureChannelImpl;
class SessionImpl;

namespace detail
{
struct OpenChannelOrchestrator;
class DiscoveryChannelFactory;
class ConnectionImpl;
class ConnectionEstablisher;
class PullCertificateManagerClientHost;
}  // namespace detail

class CoreClientImpl : public std::enable_shared_from_this<CoreClientImpl>
{
public:
  CoreClientImpl() = delete;
  CoreClientImpl(const CoreClientImpl&) = delete;
  CoreClientImpl(CoreClientImpl&&) noexcept = delete;
  CoreClientImpl& operator=(const CoreClientImpl&) = delete;
  CoreClientImpl& operator=(CoreClientImpl&&) noexcept = delete;
  ~CoreClientImpl();

  // --- Public API (called from Client forwarding methods) ---

  using SecureChannelResult = CoreClient::SecureChannelResult;
  using OpenChannelCallback = CoreClient::OpenChannelCallback;
  using ConnectResult = Client::ConnectResult;
  using ConnectCallback = Client::ConnectCallback;

  void open_channel_async(CoreClient::OpenChannelConfig config, OpenChannelCallback callback) noexcept;

  // Managed connect (section 7.3 / section 8.2A): build a ConnectPlan from @p config, drive the tier-0
  // connect via the injected ConnectionEstablisher (open channel -> CreateSession -> ActivateSession ->
  // construct ConnectionImpl), RAII-register the Connection (weak) + install its unregister teardown hook,
  // run the NamespaceArray bootstrap, and deliver a Connection handle (or a source-tagged bad Result) EXACTLY
  // ONCE on the executor. Weak-captures `this`; strong-captures the freshly-built ConnectionImpl across
  // start_async.
  void connect_async(ua::client::ConnectionConfig config, Client::ConnectCallback callback) noexcept;

  // EasyConnect-only entry point. `discoveryEndpoints` is the complete unsecured GetEndpoints
  // response that CreateSession must verify against its secured endpoint response.
  void connect_async(ua::client::ConnectionConfig config,
    std::vector<ua::EndpointDescription> discoveryEndpoints, Client::ConnectCallback callback) noexcept;

  void start_reverse_connect(client::ReverseConnectListenerConfig config,
    std::function<void(client::ReverseConnectHandleResult)> callback) noexcept;
  void stop_reverse_connect(
    client::ReverseConnectHandle handle, std::function<void(ua::VoidResult)> callback) noexcept;
  void stop_all_reverse_connects(std::function<void(ua::VoidResult)> callback) noexcept;

  // Foolproof shutdown: stop reverse-connect listeners, close every tracked
  // Session, then close every tracked SecureChannel, then fire the user
  // callback. The facade CoreClient::shutdown_async drives the impl-reset cycle
  // so the strong ref drops as the last action.
  void shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept;

  // RAII registry - called by SecureChannelImpl::create_unstarted / ~SecureChannelImpl
  // via SecureChannelDependencies, and by SessionImpl::create / ~SessionImpl
  // via SessionDependencies. Weak entries; the facade controls impl lifetime
  // so the registry never extends it.
  void register_channel(std::weak_ptr<SecureChannelImpl> channel);
  void unregister_channel(SecureChannelImpl* channel);
  void register_session(std::weak_ptr<SessionImpl> session);
  void unregister_session(SessionImpl* session);

  // Connection registry (section 722/section 727, CL-RECONN-006 / CL-SECADMIN-004). connect_async
  // RAII-registers each tier-1 Connection here on establish-success and installs a teardown hook on the
  // ConnectionImpl that unregisters it on destruction (bootstrap-fail drop, graceful close, or handle drop).
  // Weak entries keyed by raw ptr, guarded by the SAME mRegistryMutex as the channel/session registries
  // (identical lock-then-copy discipline; no nesting). The registry never extends impl lifetime.
  void register_connection(std::weak_ptr<detail::ConnectionImpl> connection);
  void unregister_connection(detail::ConnectionImpl* connection);

  // Fans certificate-update handling out to every live Connection (section 722/section 727,
  // CL-RECONN-006). @p ownCertificateChanged forces every reconnect-capable Connection onto CertRotated;
  // @p revalidateServerCertificate independently requests validation against the updated trust store.
  // Snapshots the registry under mRegistryMutex, RELEASES the lock, and aggregates acknowledgements exactly
  // once.
  void revalidate_connections_async(bool ownCertificateChanged, bool revalidateServerCertificate,
    std::function<void(ua::VoidResult)> callback) noexcept;

  // --- Pull-Model certificate management (section 8.1A / W6) ---

  /// Result of @ref start_pull_cert_management_async: the shared @ref ua::client::PullCertificateManager
  /// handle on success, or an @ref ua::ErrorDetail (e.g. `Bad_AlreadyExists` for a second live start,
  /// CL-MULTI-001).
  using PullCertManagementResult = ua::Result<std::shared_ptr<ua::client::PullCertificateManager>>;

  /// Starts the per-Client Pull-Model certificate + trust-list refresh engine (section 8.1A, W6). Constructs
  /// the concrete @ref detail::PullCertificateManagerClientHost shim (weak this + the Client-scoped
  /// @ref detail::ClientObserverSink) and the own-strand @ref detail::PullCertificateManagerImpl, wires the
  /// two, and hands back the shared @ref ua::client::PullCertificateManager handle. Write-once: a second live
  /// start completes `Bad_AlreadyExists` (CL-MULTI-001) via an atomic latch. The callback is posted to the
  /// executor; never throws.
  void start_pull_cert_management_async(ua::client::PullCertManagementConfig config,
    std::function<void(PullCertManagementResult)> callback) noexcept;

  void set_log_level(ua::LogLevel level);

  // --- Observer registration (section 7.8 / wiring section 1) ---
  // Client-level default observer slots (process-wide). Stored under mMutex; a per-Connection observer
  // overrides the Client-level default for its family (section 7.3/section 7.7). The connect path that
  // CONSUMES these defaults (resolving them into each new ConnectionImpl) is a later slice  -  see the note
  // on client_observer_slots_snapshot().

  void set_connection_observer(std::shared_ptr<ConnectionObserver> observer);
  void set_subscription_observer(std::shared_ptr<SubscriptionObserver> observer);
  void set_security_observer(std::shared_ptr<SecurityObserver> observer);
  void set_type_observer(std::shared_ptr<TypeObserver> observer);
  void set_address_space_observer(std::shared_ptr<AddressSpaceObserver> observer);
  void set_server_state_observer(std::shared_ptr<ServerStateObserver> observer);
  void set_alarm_observer(std::shared_ptr<AlarmObserver> observer);

  /// A copy of the current Client-level observer defaults (thread-safe). `connect_async` threads this into
  /// the ConnectionEstablisher (and on into `ConnectionImpl::create_from_ops(..., clientObserverDefaults)`)
  /// so each Connection resolves its per-Connection @ref ConnectionConfig::observers slots against these
  /// defaults (per-Connection non-null wins; section 7.3/section 7.7).
  [[nodiscard]] detail::ObserverSlots client_observer_slots_snapshot() const;

  /// The Client-scoped observer fan-out sink (section 7.8 / wiring section 1). Constructed EAGERLY in @ref
  /// create with an empty (Client-scoped) weak ConnectionImpl, so every fire delivers a null `const
  /// Connection*`. Fires the Client-level SecurityObserver hooks  -  pull-cert management (@ref
  /// detail::ClientObserverSink)  -  whose `Connection` is nullable. W6's PullCertificateManager host shim
  /// holds this STRONG and forwards its observer hooks through it. Set once at construction and never
  /// reassigned, so the read is lock-free.
  [[nodiscard]] std::shared_ptr<detail::ClientObserverSink> client_observer_sink() const;

  // --- Discovery facade support (client design section 7.6 / section 8.1) ---

  // Produces the production ephemeral-channel factory backing the Discovery facade. Cheap to build
  // (holds a weak_ptr to this CoreClientImpl); a fresh one per call is fine.
  std::shared_ptr<detail::DiscoveryChannelFactory> discovery_channel_factory();

  // The installed mDNS transport, lazily defaulting to ua::mdns::DefaultMdnsTransport. Never null.
  std::shared_ptr<ua::mdns::MdnsTransport> mdns_transport();

  // Installs an alternative mDNS transport (client design section 8.12). A null argument restores the default
  // on the next mdns_transport() call.
  void set_mdns_transport(std::shared_ptr<ua::mdns::MdnsTransport> transport);

  // --- Accessors ---

  boost::asio::any_io_executor executor() const;
  std::shared_ptr<const ua::Crypto> crypto() const;
  std::shared_ptr<ua::CertificateStore> certificate_store() const;
  const CombinedConfig& config() const;
  const ua::ApplicationConfig& configuration() const;
  const ClientConfig& client_configuration() const;
  ua::StructureFactory& structure_factory();
  ua::Logger logger() const;

  // --- Factory ---

  static std::shared_ptr<CoreClientImpl> create(boost::asio::any_io_executor executor, CombinedConfig config,
    std::shared_ptr<const ua::Crypto> crypto, std::shared_ptr<ua::CertificateStore> certStore,
    std::shared_ptr<ua::LogSink> logSink = nullptr, ua::LogLevel logLevel = ua::LogLevel::Info);

  uint32_t service_timeout_ms() const;
  uint32_t default_return_diagnostics() const;
  bool wrap_tier0() const;

private:
  CoreClientImpl(boost::asio::any_io_executor executor, CombinedConfig config,
    std::shared_ptr<const ua::Crypto> crypto, std::shared_ptr<ua::CertificateStore> certStore,
    std::shared_ptr<ua::LogSink> logSink = nullptr, ua::LogLevel logLevel = ua::LogLevel::Info);

  void create_crypto_components();

  // open_channel orchestration lives entirely in ua_client_impl.cpp. Per-call
  // OpenChannelFlow state and the named continuations are encapsulated in
  // ua::client::detail::OpenChannelOrchestrator (a friend) so the .cpp owns
  // all the lifetime and threading details. CoreClientImpl is captured weakly
  // by the flow; each step re-locks before touching members.
  friend struct ::ua::client::detail::OpenChannelOrchestrator;

  const boost::asio::any_io_executor mExecutor;
  const CombinedConfig mConfig;
  std::shared_ptr<const ua::Crypto> mCrypto;
  std::shared_ptr<ua::CertificateStore> mCertStore;

  // Logging: shared level allows runtime changes visible to all loggers immediately.
  std::shared_ptr<std::atomic<ua::LogLevel>> mLogLevel{
    std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Info)};
  std::shared_ptr<ua::LogSink> mLogSink;
  ua::Logger mLogger;
  mutable std::shared_mutex mMutex;

  ua::StructureFactory mStructureFactory;

  std::shared_ptr<SecureChannelDependencies> mSecureChannelDeps;
  std::shared_ptr<ua::ConnectionProtocolDependencies> mConnectionProtocolDeps;

  struct ReverseConnectState
  {
    client::ReverseConnectHandle handle;
    std::shared_ptr<ReverseConnectListener> listener;
  };

  std::vector<ReverseConnectState> mReverseConnects;  // guarded by mMutex
  std::uint64_t mNextReverseConnectHandleId{1};

  // Client-level default observer slots (section 7.8). Guarded by mMutex; copied out under lock into a
  // resolved snapshot at connect (per-Connection non-null wins). Registration holds each observer strong.
  detail::ObserverSlots mClientObserverDefaults;  // guarded by mMutex

  // Client-scoped observer fan-out sink (section 7.8 / wiring section 1). Constructed eagerly in create()
  // with an empty (Client-scoped) weak ConnectionImpl. set_security_observer re-installs the security slot
  // into it so a runtime-registered Client SecurityObserver receives Client-scoped fires (pull-cert lifecycle
  // / cert rotation). Set once at construction (before the impl is handed out) and never reassigned, so reads
  // are lock-free. Its own set_slots is an atomic store  -  safe to call without holding mMutex.
  std::shared_ptr<detail::ClientObserverSink> mClientObserverSink;

  // The tier-0 connect interface driving connect_async (section 8.2A): open channel -> CreateSession ->
  // ActivateSession
  // -> construct ConnectionImpl. Constructed EAGERLY in create() as a detail::RealConnectionEstablisher bound
  // to this Client's open-channel path (weak this); a unit test swaps it for a fake via CoreClientTestAccess.
  // Set once at construction and never reassigned in production, so connect_async reads it without a lock.
  std::shared_ptr<detail::ConnectionEstablisher> mConnectionEstablisher;

  // Pull-Model certificate management (section 8.1A / W6). Write-once, guarded by the CL-MULTI-001 atomic
  // latch: the CAS winner constructs the shim + manager and stores them here; a second live start observes
  // the set latch and fails Bad_AlreadyExists. CoreClientImpl holds both STRONG so the engine outlives the
  // user's handle drop (the manager impl holds the shim STRONG  -  the one intentional cycle-exception  -
  // while the shim holds CoreClientImpl WEAK, so no strong cycle re-forms). Only the CAS winner writes these;
  // readers (test access) synchronise via mPullCertStarted's acquire/release ordering.
  std::atomic<bool> mPullCertStarted{false};
  std::shared_ptr<detail::PullCertificateManagerClientHost> mPullCertHost;
  std::shared_ptr<ua::client::PullCertificateManager> mPullCertManager;

  // mDNS transport for the Discovery facade. Lazily defaulted; replaceable via set_mdns_transport.
  // Guarded by its own mutex so discovery() never contends with the config/registry locks.
  mutable std::mutex mMdnsMutex;
  std::shared_ptr<ua::mdns::MdnsTransport> mMdnsTransport;  // guarded by mMdnsMutex

  // Cascading-shutdown registry. Keyed by raw impl pointer (stable for the
  // impl's lifetime) so unregister-by-this in the destructor is O(1). Values
  // are weak_ptrs so the facade controls impl lifetime; the registry never
  // extends it. Guarded by mRegistryMutex (independent of mMutex so callers
  // can dispatch close work without nested locks).
  mutable std::mutex mRegistryMutex;
  std::unordered_map<SecureChannelImpl*, std::weak_ptr<SecureChannelImpl>> mChannels;
  std::unordered_map<SessionImpl*, std::weak_ptr<SessionImpl>> mSessions;
  // Tier-1 Connection registry (section 8.1A / W5). Weak entries keyed by raw impl pointer (stable for
  // lifetime), guarded by mRegistryMutex  -  mirrors mChannels/mSessions. The connect path
  // register-on-construct / unregister-on-destruct (W5 tests register directly, since no connect path exists
  // yet). Walked by revalidate_connections_async so a trust-list / cert-store change re-validates each open
  // Connection's server cert (W6 PullCert consumer). Never extends Connection lifetime.
  std::unordered_map<detail::ConnectionImpl*, std::weak_ptr<detail::ConnectionImpl>> mConnections;

  // Test/fuzzer hooks (set via CoreClientTestAccess, not public API).
  friend class CoreClientTestAccess;

  struct TestHooks
  {
    std::function<std::shared_ptr<ua::TransportConnection>(std::shared_ptr<ua::TransportConnection>)>
      transportDecorator;
    std::function<std::shared_ptr<ua::SecurityPolicy>(ua::SecurityPolicyId)> securityPolicyFactory;
  };

  TestHooks mTestHooks;
};

}  // namespace ua::client

#endif  // !UA_CORE_CLIENT_IMPL_H
