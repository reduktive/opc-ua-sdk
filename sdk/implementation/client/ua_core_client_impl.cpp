// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// CoreClientImpl - top-level client implementation.
//
// Implements SecureChannelDependencies + ConnectionProtocolDependencies for
// dependency injection into SecureChannelImpl and ConnectionProtocol.
//
// open_channel_async() is the canonical implementation (callback-canonical,
// per-flow struct + named continuations + complete_open/fail_open completion points):
//   parse URL -> DNS resolve -> TCP connect -> HEL/ACK -> OPN -> SecureChannel.

#include "ua_certificate_validation_paths.h"
#include "ua_core_client_impl.h"

#include "ua_client_secure_channel_impl.h"
#include "ua_client_security_policy_gate.h"
#include "ua_client_session_impl.h"
#include "ua_connect_plan.h"  // detail::build_connect_plan + ConnectPlan (connect_async)
#include "ua_connection.h"  // ua::client::Connection (connect_async result)
#include "ua_connection_config.h"  // ua::client::ConnectionConfig (connect_async input)
#include "ua_connection_establisher.h"  // detail::ConnectionEstablisher / RealConnectionEstablisher
#include "ua_security_policy.h"
#include "ua_server_cert_validator.h"  // detail::make_server_cert_revalidation (CL-SECADMIN-004/PULLCRT-006)
#include "ua_connection_handle_factory.h"  // detail::ConnectionHandleFactory::make_connection
#include "ua_connection_impl.h"  // detail::ConnectionImpl  -  revalidate_server_cert_async (W5 registry walk)
#include "ua_real_session_ops.h"  // detail::make_real_reopen (the connect-path reopen adapter)
#include "ua_pull_certificate_manager_client_host.h"  // detail::PullCertificateManagerClientHost (W6 shim)
#include "ua_pull_certificate_manager_impl.h"  // detail::PullCertificateManagerImpl / ...Factory (W6)
#include "ua_default_mdns_transport.h"
#include "ua_discovery_channel.h"
#include "ua_connection_protocol.h"
#include "ua_reverse_hello.h"

#include "ua_certificate_store_files.h"
#include "ua_data_type_registration.h"
#include "ua_crypto.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_callback_safety.h"
#include "ua_log_sink.h"
#include "ua_resolver.h"
#include "ua_tcp_transport_connector.h"
#include "ua_to_result.h"
#include "ua_transport_connection.h"
#include "ua_url_parser.h"

#include "fmt/format.h"
#include "ua_on_strand.h"  // ua::async::guarded (exception-consuming wrapper for posted user callbacks)

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <chrono>
#include <utility>

namespace ua::client
{

namespace
{

/// Dependencies bridge: exposes CoreClientImpl state to SecureChannelImpl and ConnectionProtocol.
class ClientDependencies : public SecureChannelDependencies,
                           public ua::ConnectionProtocolDependencies,
                           public std::enable_shared_from_this<ClientDependencies>
{
public:
  explicit ClientDependencies(std::weak_ptr<CoreClientImpl> client) : mClient(std::move(client))
  {}

  boost::asio::any_io_executor executor() override
  {
    auto c = mClient.lock();
    check(c);
    return c->executor();
  }

  std::shared_ptr<const ua::Crypto> crypto() override
  {
    auto c = mClient.lock();
    check(c);
    return c->crypto();
  }

  std::shared_ptr<ua::CertificateStore> certificate_store() override
  {
    auto c = mClient.lock();
    check(c);
    return c->certificate_store();
  }

  const ua::ApplicationConfig& configuration() override
  {
    auto c = mClient.lock();
    check(c);
    return c->configuration();
  }

  ua::StructureFactory& structure_factory() override
  {
    auto c = mClient.lock();
    check(c);
    return c->structure_factory();
  }

  ua::Logger logger() override
  {
    auto c = mClient.lock();
    if (!c)
    {
      return {};
    }
    return c->logger();
  }

  uint32_t service_timeout_ms() override
  {
    auto c = mClient.lock();
    check(c);
    return c->service_timeout_ms();
  }

  uint32_t default_return_diagnostics() override
  {
    auto c = mClient.lock();
    check(c);
    return c->default_return_diagnostics();
  }

  bool wrap_tier0() override
  {
    auto c = mClient.lock();
    check(c);
    return c->wrap_tier0();
  }

  ua::EncodingLimits encoding_limits() const override
  {
    auto c = mClient.lock();
    check(c);
    return ua::make_encoding_limits(c->configuration());
  }

  ua::connection_protocol::Limits connection_protocol_limits() const override
  {
    auto c = mClient.lock();
    check(c);
    return c->configuration().stack_limits().connectionProtocolLimits;
  }

  void register_channel(std::weak_ptr<SecureChannelImpl> channel) override
  {
    if (auto c = mClient.lock())
      c->register_channel(std::move(channel));
  }

  void unregister_channel(SecureChannelImpl* channel) override
  {
    if (auto c = mClient.lock())
      c->unregister_channel(channel);
  }

  void register_session(std::weak_ptr<SessionImpl> session) override
  {
    if (auto c = mClient.lock())
      c->register_session(std::move(session));
  }

  void unregister_session(SessionImpl* session) override
  {
    if (auto c = mClient.lock())
      c->unregister_session(session);
  }

private:
  const std::weak_ptr<CoreClientImpl> mClient;

  static void check(const std::shared_ptr<CoreClientImpl>& p)
  {
    if (!p)
    {
      throw ua::UaException{ua::Status::BadInternalError,
        ua::make_error_detail("ClientDestroyed", "Client instance has been destroyed", "ClientImpl")};
    }
  }
};

}  // namespace

// --- Lifecycle ---

CoreClientImpl::CoreClientImpl(boost::asio::any_io_executor executor, CombinedConfig config,
  std::shared_ptr<const ua::Crypto> crypto, std::shared_ptr<ua::CertificateStore> certStore,
  std::shared_ptr<ua::LogSink> logSink, ua::LogLevel logLevel)
  : mExecutor(executor), mConfig(std::move(config)), mCrypto(std::move(crypto)),
    mCertStore(std::move(certStore))
{
  // Install the construction-time log sink before any subsystem (session, secure channel, transport)
  // captures a logger via deps->logger(). Set once; there is no runtime sink setter (set_log_level
  // still adjusts verbosity via the shared atomic).
  if (logSink)
  {
    mLogLevel->store(logLevel, std::memory_order_relaxed);
    mLogSink = std::move(logSink);
    mLogger = ua::Logger{mLogSink, mLogLevel, "client"};
  }

  const ua::CodecNamespaceContext nsConfig{};
  ua::register_ua_data_types_with_factory(nsConfig, &mStructureFactory, nullptr);

  create_crypto_components();
}

CoreClientImpl::~CoreClientImpl() = default;

std::shared_ptr<CoreClientImpl> CoreClientImpl::create(boost::asio::any_io_executor executor,
  CombinedConfig config, std::shared_ptr<const ua::Crypto> crypto,
  std::shared_ptr<ua::CertificateStore> certStore, std::shared_ptr<ua::LogSink> logSink,
  ua::LogLevel logLevel)
{
  // There is no default provider: one the SDK invented would hold a private-key credential the
  // application could not supply again, so keys written by pull certificate management would fail
  // or be unreadable after a restart (security review B3-8; decision 1a).
  if (!crypto)
  {
    throw ua::UaException{ua::Status::BadConfigurationError,
      ua::ErrorDetail::build("CryptoProviderRequired",
        "ClientComponents::crypto is null; the client needs the application's crypto provider",
        "Client")};
  }

  class Wrapper : public CoreClientImpl
  {
  public:
    Wrapper(boost::asio::any_io_executor executor, CombinedConfig config,
      std::shared_ptr<const ua::Crypto> crypto, std::shared_ptr<ua::CertificateStore> certStore,
      std::shared_ptr<ua::LogSink> logSink, ua::LogLevel logLevel)
      : CoreClientImpl(
          executor, std::move(config), std::move(crypto), std::move(certStore), std::move(logSink), logLevel)
    {}
  };

  auto impl = std::make_shared<Wrapper>(
    executor, std::move(config), std::move(crypto), std::move(certStore), std::move(logSink), logLevel);

  auto deps = std::make_shared<ClientDependencies>(impl);
  impl->mSecureChannelDeps = deps;
  impl->mConnectionProtocolDeps = deps;

  // Construct the Client-scoped observer sink eagerly, now that the impl shared_ptr exists. It carries an
  // EMPTY (Client-scoped) weak ConnectionImpl, so every fire delivers a null const Connection*. Its initial
  // slots snapshot is the current Client-level defaults (only the security slot is ever consulted); the W6
  // PullCert host shim fires its Client-level SecurityObserver hooks through it. set_security_observer
  // re-installs the security slot so a runtime-registered observer is delivered to (see below).
  impl->mClientObserverSink = detail::ClientObserverSink::create(impl->executor(), {}, impl->logger());
  impl->mClientObserverSink->set_slots(impl->client_observer_slots_snapshot());

  // The managed-connect tier-0 interface (section 8.2A). The open-channel factory binds this Client WEAK (a
  // strong capture would form ConnectionImpl -> FSM -> reopen -> Client and invert the Client-weak->
  // Connection topology); a gone Client yields Bad_ConnectionClosed on the executor. The SAME factory output
  // backs both the initial open and every reconnect reopen, so a reconnect re-opens with the identical
  // secured config.
  std::weak_ptr<CoreClientImpl> weakImpl = impl;
  auto establisherExecutor = impl->executor();
  auto establisherLogger = impl->logger();
  detail::RealConnectionEstablisher::OpenChannelOpsFactory openOpsFactory =
    [weakImpl, establisherExecutor, establisherLogger](
      const CoreClient::OpenChannelConfig& channelConfig) -> detail::ReopenChannelOps
  {
    return detail::make_real_reopen(
      [weakImpl, establisherExecutor, establisherLogger, channelConfig](
        std::function<void(ua::Result<SecureChannel>)> innerCallback)
      {
        if (auto self = weakImpl.lock())
        {
          self->open_channel_async(channelConfig, std::move(innerCallback));
        }
        else
        {
          // Client gone: complete the reopen Bad on the executor (never inline), guarded so a throwing
          // downstream handler cannot cross the Asio boundary into std::terminate (the design specification).
          boost::asio::post(establisherExecutor,
            ua::async::guarded(establisherLogger,
              [innerCallback = std::move(innerCallback)]() mutable {
                innerCallback(ua::Result<SecureChannel>{ua::StatusCode{ua::Status::BadConnectionClosed}});
              }));
        }
      });
  };
  // Server-cert re-validation interface factory (CL-SECADMIN-004 immediate revalidation / CL-PULLCRT-006 /
  // CL-RECONN-006). Per connection, yields an interface that re-validates the endpoint's pinned server
  // certificate against the Client store on demand  -  driven by revalidate_connections_async when the
  // PullCertificateManager applies a trust-list/cert update. Binds the Client WEAK (same topology as the open
  // factory) and reads the store at VALIDATION time so it sees the CURRENT trust material (the trust list
  // changed  -  that is the point).
  detail::RealConnectionEstablisher::ServerCertValidatorFactory serverCertValidatorFactory =
    [weakImpl](const CoreClient::OpenChannelConfig& channelConfig)
    -> std::function<void(std::function<void(ua::VoidResult)>)>
  {
    // Resolve the store at VALIDATION time (weak-bound Client) so it sees the CURRENT trust material; the
    // interface logic + contract live in make_server_cert_revalidation (unit-tested directly).
    // The request the channel validates the server with: the pinned certificate, Table 43 use, the
    // channel's SecurityPolicy (step 4) and the endpoint URL (host-name binding).
    ua::CertificateValidationRequest request;
    request.certificate = channelConfig.serverCertificate;
    request.use = ua::CertificateUse::ServerApplicationInstance;
    if (channelConfig.securityPolicyId != ua::SecurityPolicyId::Invalid)
    {
      request.policyId = channelConfig.securityPolicyId;
    }
    if (!channelConfig.endpointUrl.empty() && !channelConfig.relaxHostNameCheck)
    {
      request.endpointUrl = channelConfig.endpointUrl;
    }
    // The channel records the exact request it validated with (presented issuers included) in
    // validatedServerRequest; revalidation resubmits that, against the store the channel validates with.
    return detail::make_connection_server_cert_revalidation(
      [weakImpl,
        trustStoreOverride = channelConfig.trustStoreOverride]() -> std::shared_ptr<ua::CertificateStore>
      {
        if (trustStoreOverride)
        {
          return trustStoreOverride;
        }
        auto self = weakImpl.lock();
        return self ? self->certificate_store() : nullptr;
      },
      channelConfig.validatedServerRequest,
      std::move(request),
      [&weakImpl]
      {
        auto self = weakImpl.lock();
        return self ? self->logger() : ua::Logger{};
      }());
  };
  detail::RealConnectionEstablisher::ServerCertificateDecoder serverCertificateDecoder =
    [weakImpl](const ua::ByteString& certificateDer) -> ua::Result<std::shared_ptr<const ua::X509Certificate>>
  {
    auto self = weakImpl.lock();
    if (!self)
    {
      return ua::Result<std::shared_ptr<const ua::X509Certificate>>{ua::Status::BadConnectionClosed,
        ua::make_error_detail("ClientDestroyed",
          "the Client was destroyed before the discovered server certificate could be decoded",
          "client.tier1.connect.discovery.certificate_decode")};
    }
    try
    {
      // The one chain parser: a GetEndpoints serverCertificate may carry the issuers after the leaf.
      auto parsed = ua::detail::parse_certificate_field(*self->mCrypto, certificateDer);
      if (!parsed.is_good())
      {
        return ua::Result<std::shared_ptr<const ua::X509Certificate>>{parsed.status_code()};
      }
      return ua::Result<std::shared_ptr<const ua::X509Certificate>>{std::move(parsed).value().front()};
    }
    catch (...)
    {
      return ua::Result<std::shared_ptr<const ua::X509Certificate>>{
        ua::exception_to_status_code(std::current_exception())};
    }
  };
  impl->mConnectionEstablisher = std::make_shared<detail::RealConnectionEstablisher>(establisherExecutor,
    impl->logger(),
    std::move(openOpsFactory),
    std::move(serverCertValidatorFactory),
    std::move(serverCertificateDecoder),
    impl->mConfig.application->allowDeprecatedSecurityPolicies);
  return impl;
}

void CoreClientImpl::create_crypto_components()
{
  if (!mCertStore)
  {
    auto& trustListConfig = mConfig.application->file_trust_list_configuration();
    if (!trustListConfig.defaultApplicationGroupTrustListPath.empty())
    {
      mCertStore = ua::CertificateStoreFiles::create(mExecutor,
        mCrypto,
        {.trustListPath = trustListConfig.defaultApplicationGroupTrustListPath,
          .validationOptions = trustListConfig.defaultApplicationGroupTrustListValidationOptions,
          .refreshPeriod = trustListConfig.trustListRefreshPeriod,
          .storeRejectedCertificates = trustListConfig.storeRejectedCertificates});
    }
  }
}

// --- Accessors ---

boost::asio::any_io_executor CoreClientImpl::executor() const
{
  return mExecutor;
}

std::shared_ptr<const ua::Crypto> CoreClientImpl::crypto() const
{
  return mCrypto;
}

std::shared_ptr<ua::CertificateStore> CoreClientImpl::certificate_store() const
{
  return mCertStore;
}

const CombinedConfig& CoreClientImpl::config() const
{
  return mConfig;
}

const ua::ApplicationConfig& CoreClientImpl::configuration() const
{
  return *mConfig.application;
}

const ClientConfig& CoreClientImpl::client_configuration() const
{
  return mConfig.client;
}

ua::StructureFactory& CoreClientImpl::structure_factory()
{
  return mStructureFactory;
}

ua::Logger CoreClientImpl::logger() const
{
  // Lock-free: mLogger is set once in the constructor (from the create()-time logSink) and never
  // reassigned - there is no runtime sink setter - so no lock is needed. set_log_level() adjusts
  // verbosity via the shared atomic without touching mLogger.
  return mLogger;
}

std::shared_ptr<detail::DiscoveryChannelFactory> CoreClientImpl::discovery_channel_factory()
{
  return detail::make_secure_channel_discovery_factory(weak_from_this(), mLogger);
}

std::shared_ptr<ua::mdns::MdnsTransport> CoreClientImpl::mdns_transport()
{
  std::lock_guard<std::mutex> lock(mMdnsMutex);
  if (!mMdnsTransport)
  {
    mMdnsTransport = std::make_shared<ua::mdns::DefaultMdnsTransport>(mExecutor, mLogger);
  }
  return mMdnsTransport;
}

void CoreClientImpl::set_mdns_transport(std::shared_ptr<ua::mdns::MdnsTransport> transport)
{
  std::lock_guard<std::mutex> lock(mMdnsMutex);
  mMdnsTransport = std::move(transport);
}

uint32_t CoreClientImpl::service_timeout_ms() const
{
  return numeric_cast<uint32_t>(mConfig.client.defaultServiceTimeout.count());
}

uint32_t CoreClientImpl::default_return_diagnostics() const
{
  return mConfig.client.defaultReturnDiagnostics;
}

bool CoreClientImpl::wrap_tier0() const
{
  return mConfig.client.diagnostics.wrapTier0;
}

// --- Logging ---

void CoreClientImpl::set_log_level(ua::LogLevel level)
{
  mLogLevel->store(level, std::memory_order_relaxed);
}

// --- Observer registration (section 7.8 / wiring section 1) ---
// Each setter replaces one Client-level default family slot under mMutex; passing null clears it. The connect
// path that resolves these into each ConnectionImpl is a later slice (see client_observer_slots_snapshot).

void CoreClientImpl::set_connection_observer(std::shared_ptr<ConnectionObserver> observer)
{
  const ua::WriteLock lock(mMutex);
  mClientObserverDefaults.connection = std::move(observer);
}

void CoreClientImpl::set_subscription_observer(std::shared_ptr<SubscriptionObserver> observer)
{
  const ua::WriteLock lock(mMutex);
  mClientObserverDefaults.subscription = std::move(observer);
}

void CoreClientImpl::set_security_observer(std::shared_ptr<SecurityObserver> observer)
{
  detail::ObserverSlots snapshot;
  {
    const ua::WriteLock lock(mMutex);
    mClientObserverDefaults.security = std::move(observer);
    snapshot = mClientObserverDefaults;
  }
  // Re-install the (only-security-consulted) slots into the Client-scoped sink so a SecurityObserver
  // registered at RUNTIME still receives Client-scoped fires (pull-cert lifecycle / cert rotation). set_slots
  // is an atomic store  -  no user callback runs  -  so it is safe off the mMutex (and mClientObserverSink is
  // set once at construction, so the read is lock-free). Once the sink has been closed, set_slots is a no-op.
  if (mClientObserverSink)
  {
    mClientObserverSink->set_slots(std::move(snapshot));
  }
}

void CoreClientImpl::set_type_observer(std::shared_ptr<TypeObserver> observer)
{
  const ua::WriteLock lock(mMutex);
  mClientObserverDefaults.type = std::move(observer);
}

void CoreClientImpl::set_address_space_observer(std::shared_ptr<AddressSpaceObserver> observer)
{
  const ua::WriteLock lock(mMutex);
  mClientObserverDefaults.addressSpace = std::move(observer);
}

void CoreClientImpl::set_server_state_observer(std::shared_ptr<ServerStateObserver> observer)
{
  const ua::WriteLock lock(mMutex);
  mClientObserverDefaults.serverState = std::move(observer);
}

void CoreClientImpl::set_alarm_observer(std::shared_ptr<AlarmObserver> observer)
{
  const ua::WriteLock lock(mMutex);
  mClientObserverDefaults.alarm = std::move(observer);
}

detail::ObserverSlots CoreClientImpl::client_observer_slots_snapshot() const
{
  const ua::ReadLock lock(mMutex);
  return mClientObserverDefaults;
}

std::shared_ptr<detail::ClientObserverSink> CoreClientImpl::client_observer_sink() const
{
  // Set once in create() before the impl is handed out, never reassigned  -  a lock-free read.
  return mClientObserverSink;
}

// --- Reverse Connect ---

void CoreClientImpl::start_reverse_connect(client::ReverseConnectListenerConfig config,
  std::function<void(client::ReverseConnectHandleResult)> callback) noexcept
{
  try
  {
    auto listener = ReverseConnectListener::create(mExecutor,
      mConnectionProtocolDeps,
      std::move(config),
      logger(),
      mConfig.client.writeQueueDepthPerConnection,
      mConfig.client.writeQueueBytesPerConnection);
    listener->start();

    client::ReverseConnectHandle handle;
    {
      const ua::WriteLock lk(mMutex);
      handle = client::ReverseConnectHandle{mNextReverseConnectHandleId++};
      mReverseConnects.push_back(ReverseConnectState{handle, listener});
    }

    callback(client::ReverseConnectHandleResult{handle});
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

void CoreClientImpl::stop_reverse_connect(
  client::ReverseConnectHandle handle, std::function<void(ua::VoidResult)> callback) noexcept
{
  std::shared_ptr<ReverseConnectListener> listener;
  {
    ua::WriteLock lk(mMutex);
    auto it = std::find_if(mReverseConnects.begin(),
      mReverseConnects.end(),
      [&](const ReverseConnectState& s) { return s.handle == handle; });

    if (it == mReverseConnects.end())
    {
      // Release lock before calling callback (callback safety rule).
      lk.unlock();
      callback(ua::VoidResult{ua::Status::BadNotFound,
        ua::ErrorDetail::build(
          "ReverseConnectHandleNotFound", "No reverse connect listener with the given handle", "Client")
          .context(ua::ContextKeys::reverseConnectHandle, std::to_string(handle.value))});
      return;
    }

    listener = std::move(it->listener);
    mReverseConnects.erase(it);
  }

  listener->stop_async([callback = std::move(callback)](ua::VoidResult) { callback(ua::VoidResult{}); });
}

void CoreClientImpl::stop_all_reverse_connects(std::function<void(ua::VoidResult)> callback) noexcept
{
  std::vector<ReverseConnectState> toStop;
  {
    const ua::WriteLock lk(mMutex);
    // Move the listeners out and leave the member as a fresh empty vector in one
    // step, so the moved-from member is never read afterwards.
    toStop = std::exchange(mReverseConnects, {});
  }

  if (toStop.empty())
  {
    callback(ua::VoidResult{});
    return;
  }

  // Keep listeners alive until all stop callbacks have fired.
  auto kept = std::make_shared<std::vector<ReverseConnectState>>(std::move(toStop));
  auto remaining = std::make_shared<std::atomic<size_t>>(kept->size());

  for (auto& state : *kept)
  {
    state.listener->stop_async(
      [remaining, callback, kept](ua::VoidResult)
      {
        if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
        {
          callback(ua::VoidResult{});
        }
      });
  }
}

// --- Cascading-shutdown registry ---

void CoreClientImpl::register_channel(std::weak_ptr<SecureChannelImpl> channel)
{
  auto sh = channel.lock();
  if (!sh)
    return;
  const std::lock_guard lk{mRegistryMutex};
  mChannels.emplace(sh.get(), std::move(channel));
}

void CoreClientImpl::unregister_channel(SecureChannelImpl* channel)
{
  const std::lock_guard lk{mRegistryMutex};
  mChannels.erase(channel);
}

void CoreClientImpl::register_session(std::weak_ptr<SessionImpl> session)
{
  auto sh = session.lock();
  if (!sh)
    return;
  const std::lock_guard lk{mRegistryMutex};
  mSessions.emplace(sh.get(), std::move(session));
}

void CoreClientImpl::unregister_session(SessionImpl* session)
{
  const std::lock_guard lk{mRegistryMutex};
  mSessions.erase(session);
}

void CoreClientImpl::register_connection(std::weak_ptr<detail::ConnectionImpl> connection)
{
  auto sh = connection.lock();
  if (!sh)
    return;
  const std::lock_guard lk{mRegistryMutex};
  // insert_or_assign (not emplace): if a prior Connection died without unregistering and a NEW one is later
  // allocated at the same address (address reuse), emplace would keep the stale expired weak and silently
  // drop the live one. insert_or_assign overwrites, so the live Connection is always the tracked entry.
  mConnections.insert_or_assign(sh.get(), std::move(connection));
}

void CoreClientImpl::unregister_connection(detail::ConnectionImpl* connection)
{
  const std::lock_guard lk{mRegistryMutex};
  mConnections.erase(connection);
}

// --- Cascading shutdown ---
//
// Foolproof shutdown contract: stop reverse-connect listeners, close every
// tracked open Session, then close every tracked SecureChannel, then fire
// the user callback. Per-child failures are tolerated - OPC UA Close{Session,
// SecureChannel} are courtesy messages; the local-resource-release contract
// is still met.

namespace
{

/// Snapshot a weak_ptr registry, locking each entry to a strong ref. The
/// registry is *not* cleared - RAII unregistration in each impl's destructor
/// removes its own entry when the impl finally dies.
template<typename Impl>
std::vector<std::shared_ptr<Impl>> snapshot_strong(
  std::mutex& mu, const std::unordered_map<Impl*, std::weak_ptr<Impl>>& registry)
{
  std::vector<std::shared_ptr<Impl>> alive;
  const std::lock_guard lk{mu};
  alive.reserve(registry.size());
  for (auto& [_, wk] : registry)
  {
    if (auto sh = wk.lock())
      alive.push_back(std::move(sh));
  }
  return alive;
}

/// Close every impl in `kept` and invoke `done` after the last completion.
/// `kept` is captured into the per-child callbacks to keep impls alive until
/// the cascade completes.
template<typename Impl, typename CloseFn>
void close_all(std::vector<std::shared_ptr<Impl>> children, CloseFn closeFn, std::function<void()> done)
{
  if (children.empty())
  {
    done();
    return;
  }
  auto remaining = std::make_shared<std::atomic<size_t>>(children.size());
  auto sharedDone = std::make_shared<std::function<void()>>(std::move(done));
  auto kept = std::make_shared<std::vector<std::shared_ptr<Impl>>>(std::move(children));
  for (auto& child : *kept)
  {
    closeFn(*child,
      [remaining, sharedDone, kept](ua::VoidResult)
      {
        if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
          (*sharedDone)();
      });
  }
}

}  // namespace

void CoreClientImpl::shutdown_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  // noexcept facade: the synchronous body below (shared_from_this, make_shared,
  // and the closure-construction inside stop_all_reverse_connects) can throw
  // (e.g. bad_alloc). The user's `callback` is copied - not moved - into the
  // shared completion state, so the original parameter stays callable for the
  // catch and the error is never silently dropped.
  try
  {
    auto self = shared_from_this();
    auto sharedCb = std::make_shared<std::function<void(ua::VoidResult)>>(callback);

    // Step 1: stop reverse-connect listeners.
    stop_all_reverse_connects(
      [self, sharedCb](ua::VoidResult) mutable
      {
        // Step 2: close every tracked Session. Sessions are closed before
        // channels so any pending session work observes its own close path
        // (instead of being abruptly torn down by the channel's CLO).
        auto sessions = snapshot_strong(self->mRegistryMutex, self->mSessions);
        close_all<SessionImpl>(
          std::move(sessions),
          [](SessionImpl& s, std::function<void(ua::VoidResult)> cb) { s.close(std::move(cb)); },
          [self, sharedCb]() mutable
          {
            // Step 3: close every tracked SecureChannel.
            auto channels = snapshot_strong(self->mRegistryMutex, self->mChannels);
            close_all<SecureChannelImpl>(
              std::move(channels),
              [](SecureChannelImpl& c, std::function<void(ua::VoidResult)> cb) { c.close(std::move(cb)); },
              [self, sharedCb]()
              { ua::detail::invoke_user_callback(self->logger(), *sharedCb, ua::VoidResult{}); });
          });
      });
  }
  catch (...)
  {
    // The cascade was never queued, so its completion callback will never fire.
    // Report synchronously via the surviving original callback copy.
    ua::detail::invoke_user_callback(logger(),
      callback,
      ua::VoidResult{ua::Status::BadOutOfMemory,
        ua::make_error_detail("ShutdownDispatchFailed", "Failed to dispatch client shutdown", "ClientImpl")});
  }
}

// --- Server-cert revalidation walk (section 8.1A / W5) ---

void CoreClientImpl::revalidate_connections_async(bool ownCertificateChanged,
  bool revalidateServerCertificate, std::function<void(ua::VoidResult)> callback) noexcept
{
  // Walk the Connection registry (snapshot-then-release, mirroring the shutdown walk) and dispatch
  // certificate-update handling to each LIVE Connection's own strand. An own-cert change categorically
  // triggers CertRotated; a now-untrusted server cert independently triggers the same cause. Each Connection
  // owns its reconnect and acknowledges Good (the aggregate is advisory). Fire @p callback EXACTLY ONCE on
  // the executor after every Connection has acknowledged. Expired weak entries are silently skipped.
  //
  // noexcept + guarded (like shutdown_async): a bad_alloc from the snapshot vector / barrier make_shared /
  // the per-Connection std::function construction must NOT escape the *_async surface AND must not drop the
  // owed aggregate. `callback` is COPIED (never moved) into the shared/posted state  -  mirroring
  // shutdown_async  -  so it stays intact for the catch even when the throw lands AFTER a partial dispatch (a
  // mid-loop bad_alloc leaves `remaining` unreachable-by-zero, so the copy in `shared` would never fire; only
  // the surviving original delivers the terminal Bad). On the success path the copy fires and the original is
  // simply unused.
  try
  {
    auto connections = snapshot_strong(mRegistryMutex, mConnections);
    if (connections.empty())
    {
      boost::asio::post(
        mExecutor, ua::async::guarded(ua::Logger{}, [callback]() mutable { callback(ua::VoidResult{}); }));
      return;
    }
    auto remaining = std::make_shared<std::atomic<std::size_t>>(connections.size());
    auto shared = std::make_shared<std::function<void(ua::VoidResult)>>(callback);
    for (auto& connection : connections)
    {
      connection->revalidate_server_cert_async(ownCertificateChanged,
        revalidateServerCertificate,
        [remaining, shared, exec = mExecutor](ua::VoidResult) mutable
        {
          // The last per-Connection acknowledgement fires the aggregate Good on the executor. Each
          // per-Connection callback already ran on the executor; re-post to normalise the delivery thread and
          // decouple from the completing Connection's strand/lifetime.
          if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
          {
            boost::asio::post(
              exec, ua::async::guarded(ua::Logger{}, [shared]() mutable { (*shared)(ua::VoidResult{}); }));
          }
        });
    }
  }
  catch (...)
  {
    // The walk was never fully dispatched, so its aggregate will never fire  -  surface synchronously via the
    // surviving (intact) callback so the W6 consumer's post-commit continuation is never lost.
    if (callback)
    {
      ua::detail::invoke_user_callback(logger(),
        callback,
        ua::VoidResult{ua::Status::BadOutOfMemory,
          ua::make_error_detail("RevalidateConnectionsDispatchFailed",
            "failed to dispatch the server-cert revalidation walk",
            "client.tier1.client.revalidate_connections")});
    }
  }
}

// --- Pull-Model certificate management (section 8.1A / W6) ---

void CoreClientImpl::start_pull_cert_management_async(ua::client::PullCertManagementConfig config,
  std::function<void(PullCertManagementResult)> callback) noexcept
{
  // CL-MULTI-001: write-once atomic latch. A second live start observes the already-set latch and completes
  // Bad_AlreadyExists (never a second engine  -  two pull managers would double-drive the GDS + the cert
  // store).
  bool expected = false;
  if (!mPullCertStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(ua::Logger{},
        [callback = std::move(callback)]() mutable
        {
          callback(PullCertManagementResult{ua::StatusCode{ua::Status::BadAlreadyExists},
            ua::make_error_detail("PullCertAlreadyStarted",
              "a Pull-Model certificate manager is already running for this Client",
              "client.tier1.pull_cert.start.already_exists")});
        }));
    return;
  }

  try
  {
    // Construct the concrete host shim (weak this + the Client-scoped observer sink; own-cert snapshot is
    // seeded null  -  the live GDS-connection cert-rotation tracking is the deferred W6b wiring) and the
    // own-strand manager, then wire them. CoreClientImpl holds both STRONG so the engine outlives the user's
    // handle drop; the manager holds the shim STRONG (the intentional cycle-exception) while the shim holds
    // CoreClientImpl WEAK, so no strong cycle re-forms.
    auto host = std::make_shared<detail::PullCertificateManagerClientHost>(
      weak_from_this(), mExecutor, mClientObserverSink, /*ownCert=*/nullptr, logger());
    auto impl = detail::PullCertificateManagerImpl::create(mExecutor, host, logger(), std::move(config));
    auto manager = detail::PullCertificateManagerFactory::wrap(impl);

    // Post the success completion BEFORE publishing the strong refs, and COPY `callback` (never move) so a
    // throwing post (bad_alloc) leaves the outer `callback` live for the catch below  -  otherwise the owed
    // completion is silently dropped (mirrors revalidate_connections_async's copy-not-move discipline).
    boost::asio::post(mExecutor,
      ua::async::guarded(
        ua::Logger{}, [callback, manager]() mutable { callback(PullCertManagementResult{manager}); }));

    // The post is safely queued: publish CoreClientImpl's strong refs (write-once) so the engine outlives the
    // user's handle drop. Reached only after the post cannot throw, so the CL-MULTI-001 latch and these
    // members stay consistent (a mid-construction throw rolls the latch back with nothing published).
    mPullCertHost = host;
    mPullCertManager = manager;
  }
  catch (...)
  {
    // Construction threw (e.g. bad_alloc). Roll the latch back so a retry is possible, and surface the error
    // through the surviving callback (never silently dropped).
    mPullCertStarted.store(false, std::memory_order_release);
    ua::detail::invoke_user_callback(logger(),
      callback,
      PullCertManagementResult{ua::StatusCode{ua::Status::BadOutOfMemory},
        ua::make_error_detail("PullCertStartFailed",
          "failed to construct the Pull-Model certificate manager",
          "client.tier1.pull_cert.start.construction_failed")});
  }
}

// --- Open channel ---

namespace detail
{

// Per-call flow state. Carries cross-step locals + the user's completion
// callback. Held alive across the chain by the shared_ptr captured into each
// child component's callback. CoreClientImpl is captured weakly via mClient, so a
// dropped client does not delay flow teardown.
struct OpenChannelFlow
{
  std::weak_ptr<CoreClientImpl> client;
  CoreClient::OpenChannelConfig config;
  CoreClientImpl::OpenChannelCallback onComplete;
  ua::Logger log;

  std::string hostname;
  uint16_t port{0};

  std::shared_ptr<ua::Resolver> resolver;
  std::shared_ptr<std::shared_ptr<ua::TcpTransportConnector>> connectorHolder;
  std::shared_ptr<std::shared_ptr<ua::ConnectionProtocol>> cpHolder;
  std::shared_ptr<ua::TransportConnection> tcpConnection;

  // SecureChannel slot - holds the impl from create_unstarted() before start() begins the OPN; onOpened
  // fires async.
  std::shared_ptr<std::shared_ptr<SecureChannelImpl>> scSlot;
};

// Friend of CoreClientImpl. Holds the entire open-channel orchestration so that
// continuation logic stays in one place and CoreClientImpl's header does not need
// to expose internal types or transport headers. All members are static.
struct OpenChannelOrchestrator
{
  using SecureChannelResult = CoreClientImpl::SecureChannelResult;

  // 5.4.5 success completion point: move callback out, release flow state, fire.
  // The channel is open: a Good subcode or an Uncertain ServiceResult (@p status) of the OpenSecureChannel
  // response stays with it.
  static void complete_open(
    std::shared_ptr<OpenChannelFlow> flow, SecureChannel channel, ua::StatusCode status)
  {
    auto cb = std::move(flow->onComplete);
    flow.reset();
    if (cb)
    {
      cb(ua::detail::held(std::move(channel), std::move(status)));
    }
  }

  // 5.4.5 failure completion point: move callback out, release flow state, fire.
  static void fail_open(std::shared_ptr<OpenChannelFlow> flow, SecureChannelResult result)
  {
    auto cb = std::move(flow->onComplete);
    flow.reset();
    if (cb)
    {
      cb(std::move(result));
    }
  }

  static SecureChannelResult client_destroyed_result()
  {
    return SecureChannelResult{ua::Status::BadInternalError,
      ua::make_error_detail("ClientDestroyed", "Client instance destroyed mid-open", "Client")};
  }

  static void start_secure_channel_open(std::shared_ptr<OpenChannelFlow> flow,
    std::shared_ptr<ua::ConnectionProtocol> cpConnection,
    const ua::connection_protocol::NegotiatedLimits& negotiatedLimits)
  {
    auto self = flow->client.lock();
    if (!self)
    {
      fail_open(std::move(flow), client_destroyed_result());
      return;
    }

    auto resolvedLifetimeMs = numeric_cast<uint32_t>(
      flow->config.requestedLifetime.value_or(self->mConfig.client.defaultChannelLifetime).count());

    const SecureChannelImpl::Config scConfig{.securityMode = flow->config.securityMode,
      .securityPolicyId = flow->config.securityPolicyId,
      .requestedLifetimeMs = resolvedLifetimeMs,
      .endpointUrl = flow->config.endpointUrl,
      .auditEntryIdProvider = flow->config.auditEntryIdProvider,
      .serverCertificate = flow->config.serverCertificate,
      .trustStoreOverride = flow->config.trustStoreOverride,
      .securityPolicyFactory = self->mTestHooks.securityPolicyFactory,
      .onChannelError = std::move(flow->config.onChannelError),
      .validatedServerRequest = flow->config.validatedServerRequest,
      .defaultSessionTimeout = self->mConfig.client.defaultSessionTimeout,
      .incomingChunkQueueDepth = self->mConfig.client.incomingChunkQueueDepth,
      .maxInboundStringLength = self->mConfig.client.maxInboundStringLength,
      .maxInboundByteStringLength = self->mConfig.client.maxInboundByteStringLength,
      .maxInboundArrayLength = self->mConfig.client.maxInboundArrayLength,
      .relaxHostNameCheck = flow->config.relaxHostNameCheck};

    flow->scSlot = std::make_shared<std::shared_ptr<SecureChannelImpl>>();
    auto slot = flow->scSlot;

    auto handler = [flow](ua::VoidResult openResult) mutable
    {
      if (!flow->onComplete)
      {
        return;  // either path already fired the user callback
      }
      if (openResult.is_bad())
      {
        flow->log.warning({{"endpoint_url", flow->config.endpointUrl}}, "OPN handshake failed");
        // Read flow before the move: a sibling argument that reads `flow` is
        // unsequenced with std::move(flow), so clang may null `flow` first.
        const auto endpointUrl = flow->config.endpointUrl;
        fail_open(std::move(flow),
          SecureChannelResult{openResult.status_code(),
            ua::ErrorDetail::build("OpenSecureChannelFailed", "OPN handshake failed", "Client")
              .context(ua::ContextKeys::endpointUrl, endpointUrl)
              .cause(openResult.shared_detail())});
        return;
      }
      auto channelImpl = *flow->scSlot;
      flow->log.info({{"endpoint_url", flow->config.endpointUrl},
                       {"channel_id", uint64_t(channelImpl->secure_channel_id())}},
        "Channel opened");
      complete_open(std::move(flow), SecureChannel{channelImpl}, openResult.status_code());
    };

    // The handler reads the slot, so the impl is in it before the OPN handshake starts: the handshake's
    // answer fires on the channel strand and can otherwise arrive before the assignment.
    *slot = SecureChannelImpl::create_unstarted(self->mSecureChannelDeps,
      std::move(cpConnection),
      negotiatedLimits,
      scConfig,
      handler,  // onOpened
      handler);  // onError - same handler; first invocation wins via onComplete guard
    try
    {
      (*slot)->start();
    }
    catch (...)
    {
      // As when create() throws: the impl goes, and its destructor answers the handler.
      slot->reset();
      throw;
    }
  }

  static void start_connection_protocol(std::shared_ptr<OpenChannelFlow> flow)
  {
    auto self = flow->client.lock();
    if (!self)
    {
      fail_open(std::move(flow), client_destroyed_result());
      return;
    }

    auto timeout = self->configuration().stack_limits().connectionProtocolTimeout;
    auto messageReadTimeout = self->configuration().stack_limits().connectionProtocolMessageReadTimeout;
    auto endpointUrl = flow->config.endpointUrl;
    auto deps = self->mConnectionProtocolDeps;

    flow->cpHolder = std::make_shared<std::shared_ptr<ua::ConnectionProtocol>>();
    auto cpHolder = flow->cpHolder;

    auto cp = ua::ConnectionProtocol::create(
      ua::ConnectionProtocolRole::Client,
      deps,
      flow->tcpConnection,
      false,
      timeout,
      [flow, cpHolder](ua::StatusCode status,
        std::shared_ptr<ua::ConnectionProtocol>
          cpHandle,
        ua::connection_protocol::NegotiatedLimits negotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage> /*reverseHello*/) mutable
      {
        cpHolder.reset();
        if (status.is_bad())
        {
          flow->log.warning(
            {{"endpoint_url", flow->config.endpointUrl}}, "Connection protocol handshake failed");
          // Read flow before the move (sibling arg unsequenced with std::move(flow)).
          const auto failedEndpointUrl = flow->config.endpointUrl;
          fail_open(std::move(flow),
            SecureChannelResult{status,
              ua::ErrorDetail::build("ConnectionProtocolFailed", "HEL/ACK handshake failed", "Client")
                .context(ua::ContextKeys::endpointUrl, failedEndpointUrl)});
          return;
        }
        start_secure_channel_open(std::move(flow), std::move(cpHandle), negotiatedLimits);
      },
      [flow, cpHolder](ua::StatusCode status, ua::string_view errorDesc, ua::FatalCloseDisposition) mutable
      {
        cpHolder.reset();
        if (!flow->onComplete)
        {
          return;  // already completed via the connection-complete callback
        }
        flow->log.warning(
          {{"endpoint_url", flow->config.endpointUrl}}, "Connection protocol handshake failed");
        fail_open(std::move(flow),
          SecureChannelResult{status,
            ua::ErrorDetail::build("ConnectionProtocolError", "Connection protocol error", "Client")
              .context(ua::ContextKeys::errorMessage, std::string{errorDesc})});
      },
      endpointUrl,
      {},
      messageReadTimeout);

    *flow->cpHolder = std::move(cp);
  }

  static void start_tcp_connect(std::shared_ptr<OpenChannelFlow> flow, ua::EndpointList endpoints)
  {
    auto self = flow->client.lock();
    if (!self)
    {
      fail_open(std::move(flow), client_destroyed_result());
      return;
    }

    flow->connectorHolder = std::make_shared<std::shared_ptr<ua::TcpTransportConnector>>();
    auto connectorHolder = flow->connectorHolder;
    auto log = flow->log;

    *connectorHolder = ua::TcpTransportConnector::create(
      self->mExecutor,
      std::move(endpoints),
      [flow, connectorHolder](ua::StatusCode status,
        ua::string_view errorDesc,
        std::shared_ptr<ua::TcpTransportConnection>
          conn) mutable
      {
        connectorHolder.reset();
        if (status.is_bad())
        {
          flow->log.warning({{"endpoint_url", flow->config.endpointUrl}}, "TCP connect failed");
          // Built before the call: an argument that reads flow is unsequenced with the one that moves it.
          SecureChannelResult failure{status,
            ua::ErrorDetail::build("TcpConnectFailed", "TCP connect failed", "Client")
              // The endpoint is the first thing anyone reading this failure asks for, and a client
              // that tries several of them cannot tell from the message alone which one this was.
              .context(ua::ContextKeys::endpointUrl, flow->config.endpointUrl)
              .context(ua::ContextKeys::errorMessage, std::string{errorDesc})};
          fail_open(std::move(flow), std::move(failure));
          return;
        }
        auto self2 = flow->client.lock();
        if (!self2)
        {
          fail_open(std::move(flow), client_destroyed_result());
          return;
        }
        std::shared_ptr<ua::TransportConnection> tcpConnection = std::move(conn);
        if (self2->mTestHooks.transportDecorator)
        {
          tcpConnection = self2->mTestHooks.transportDecorator(std::move(tcpConnection));
        }
        flow->tcpConnection = std::move(tcpConnection);
        start_connection_protocol(std::move(flow));
      },
      log,
      self->mConfig.client.writeQueueDepthPerConnection,
      self->mConfig.client.writeQueueBytesPerConnection);
  }

  static void on_endpoints_resolved(std::shared_ptr<OpenChannelFlow> flow, ua::EndpointListResult result)
  {
    if (!result.is_good())
    {
      flow->log.warning(
        {{"hostname", flow->hostname}, {"port", uint64_t(flow->port)}}, "DNS resolution failed");
      fail_open(std::move(flow), SecureChannelResult{result.status_code(), result.shared_detail()});
      return;
    }

    const auto& endpoints = result.value();
    if (endpoints.empty())
    {
      // Read flow before the move (sibling args unsequenced with std::move(flow)).
      const auto hostname = flow->hostname;
      const auto port = flow->port;
      fail_open(std::move(flow),
        SecureChannelResult{ua::Status::BadTcpEndpointUrlInvalid,
          ua::ErrorDetail::build("NoEndpoints", "DNS resolution returned no endpoints", "Client")
            .context(ua::ContextKeys::endpointAddress, hostname)
            .context(ua::ContextKeys::endpointPort, std::to_string(port))});
      return;
    }

    start_tcp_connect(std::move(flow), endpoints);
  }

  static void start_normal_path(std::shared_ptr<OpenChannelFlow> flow)
  {
    auto self = flow->client.lock();
    if (!self)
    {
      fail_open(std::move(flow), client_destroyed_result());
      return;
    }

    flow->resolver =
      ua::Resolver::create(self->mExecutor, self->configuration().stack_limits().connectionProtocolTimeout);

    auto hostname = flow->hostname;
    auto port = flow->port;
    flow->resolver->resolve_endpoints_async(hostname,
      port,
      std::nullopt,
      [flow](ua::EndpointListResult result) mutable
      { on_endpoints_resolved(std::move(flow), std::move(result)); });
  }

  static void on_reverse_connection_consumed(
    std::shared_ptr<OpenChannelFlow> flow, client::QueuedConnectionResult result)
  {
    if (!result.is_good())
    {
      flow->log.warning({{"endpoint_url", flow->config.endpointUrl}}, "Reverse connect consume failed");
      fail_open(std::move(flow), SecureChannelResult{result.status_code(), result.shared_detail()});
      return;
    }
    auto queued = std::move(result).value();
    // The connection is already HEL/ACK'd; advance directly to OPN.
    start_secure_channel_open(std::move(flow), std::move(queued.connection), queued.negotiatedLimits);
  }
};

}  // namespace detail

void CoreClientImpl::connect_async(
  ua::client::ConnectionConfig config, Client::ConnectCallback callback) noexcept
{
  connect_async(std::move(config), {}, std::move(callback));
}

void CoreClientImpl::connect_async(ua::client::ConnectionConfig config,
  std::vector<ua::EndpointDescription> discoveryEndpoints, Client::ConnectCallback callback) noexcept
{
  // Fire-once + guarded delivery of the user callback: EVERY outcome (invalid plan, establish failure,
  // bootstrap failure, connect-deadline, internal throw, success) is posted through ua::async::guarded (so a
  // throwing user callback is swallowed+logged, never crossing the Asio boundary into std::terminate  -
  // the design specification) and passes the fire-once gate, so the user callback runs exactly once
  // regardless of how (or how many times) an underlying interface completes.
  //
  // Delivery AND the deadline timer run on a private per-connect strand over the executor (not the bare
  // executor): the timer's cancel() (from a `deliver` completion) and its expiry-completion would otherwise
  // race on a multi-threaded io_context  -  Asio timers are not thread-safe for concurrent access. The strand
  // serialises them (mirrors ReconnectionFSM's strand-owned timers). A strand is still "on the executor", so
  // the callback contract is unchanged.
  auto executor = mExecutor;
  auto logger = mLogger;
  auto strand = boost::asio::make_strand(executor);
  auto delivered = std::make_shared<std::atomic_flag>();
  auto sharedCallback = std::make_shared<Client::ConnectCallback>(std::move(callback));
  // Shared box holding a WEAK ref to the (later-armed) overall-connect deadline timer, so `deliver`  -  which
  // is built before the timer exists  -  can cancel it on the first outcome. The timer keeps ITSELF alive
  // (its wait handler holds it strong), so it still fires even if a misbehaving establisher drops its
  // callback; on a normal completion `deliver` cancels it (no lingering to expiry). No strong cycle: the box
  // holds the timer only weakly.
  auto timerBox = std::make_shared<std::weak_ptr<boost::asio::steady_timer>>();

  auto deliver = [strand, logger, delivered, sharedCallback, timerBox](ConnectResult result)
  {
    boost::asio::post(strand,
      ua::async::guarded(logger,
        [delivered, sharedCallback, timerBox, result = std::move(result)]() mutable
        {
          // On the strand: cancel() here is serialised with the timer's expiry-completion (also on the
          // strand).
          if (auto timer = timerBox->lock())
          {
            timer->cancel();
          }
          if (!delivered->test_and_set() && *sharedCallback)
          {
            (*sharedCallback)(std::move(result));
          }
        }));
  };

  // noexcept boundary: the substantive throwing work (build_connect_plan's string allocations, the
  // EstablishFlow / open-interface construction inside establish_async) runs inside this try, so a throw is
  // routed through the fire-once `deliver` rather than crossing the noexcept boundary into std::terminate.
  // (The small fixed setup allocations ABOVE  -  the atomic_flag / callback / box / strand  -  are OOM-only
  // and, as elsewhere in this file, treated as fatal; they cannot self-report since `deliver` depends on
  // them.)
  try
  {
    auto policyValidation = detail::validate_client_security_policy(
      config.securityPolicyId, mConfig.application->allowDeprecatedSecurityPolicies);
    if (policyValidation.is_bad())
    {
      deliver(ConnectResult{policyValidation.status_code(), policyValidation.shared_detail()});
      return;
    }
    if (mConfig.application->allowDeprecatedSecurityPolicies)
    {
      detail::warn_deprecated_client_security_policy_once(config.securityPolicyId, logger);
    }

    // Translate the user config (pure). A rejected plan (unwired endpoint selection / empty URL)
    // short-circuits with its source-tagged status  -  never reaching the establisher.
    detail::ConnectPlan plan = detail::build_connect_plan(config, std::move(discoveryEndpoints));
    if (!plan.valid)
    {
      deliver(ConnectResult{plan.error});
      return;
    }

    // Arm the overall connect deadline (soft): on expiry deliver Bad_Timeout through the fire-once gate. It
    // covers channel-open + CreateSession + ActivateSession + bootstrap (the per-phase tier-0 configs carry
    // no request deadline). In-flight tier-0 work continues but its later result is discarded by the gate.
    if (plan.connectTimeout && *plan.connectTimeout > std::chrono::milliseconds::zero())
    {
      // The timer is bound to the delivery strand, so its expiry-completion and the cancel() posted by
      // `deliver` (also on the strand) never touch the timer concurrently. It is armed here on the caller
      // thread, sequenced-before any strand work (the first cancel can only follow the establish call below).
      auto deadlineTimer = std::make_shared<boost::asio::steady_timer>(strand);
      deadlineTimer->expires_after(*plan.connectTimeout);
      *timerBox = deadlineTimer;  // let `deliver` cancel it on a normal completion
      // The wait handler holds the timer STRONG (self-sustaining): a standard Asio timer keep-alive that
      // breaks when the wait completes (expiry -> fire, or cancel-on-completion -> abort). So the deadline
      // fires even if the establisher never completes its callback.
      deadlineTimer->async_wait(ua::async::guarded(logger,
        [deliver, deadlineTimer](const boost::system::error_code& error)
        {
          if (error)  // operation_aborted: the connect completed first and `deliver` cancelled the timer.
          {
            return;
          }
          deliver(ConnectResult{ua::StatusCode{ua::Status::BadTimeout,
            ua::make_error_detail("ConnectTimeout",
              "connect exceeded ConnectionConfig::connectTimeout",
              "client.tier1.connect.deadline")}});
        }));
    }

    auto self = shared_from_this();
    auto observerDefaults = client_observer_slots_snapshot();
    auto establishedOnce = std::make_shared<std::atomic_flag>();
    mConnectionEstablisher->establish_async(std::move(plan),
      std::move(observerDefaults),
      [self, deliver, establishedOnce](ua::Result<std::shared_ptr<detail::ConnectionImpl>> established)
      {
        // Guard the register/start orchestration against a spurious second establish completion (a
        // misbehaving interface): only the first proceeds, so no double-register / double-start.
        if (establishedOnce->test_and_set())
        {
          return;
        }
        if (!established.has_value())
        {
          deliver(ConnectResult{established.status_code(), established.shared_detail()});
          return;
        }
        auto connection = std::move(established).value();

        // RAII-register (weak) + install the unregister teardown hook, BEFORE start: the reconnect drivers
        // are all post-Active and a bootstrap failure is terminal (not a reconnect), so nothing can fire
        // ahead of registration. The hook (weak Client + raw ptr, layering-safe) unregisters exactly once on
        // every destruction path  -  bootstrap-fail drop, graceful close, or handle drop.
        self->register_connection(std::weak_ptr<detail::ConnectionImpl>(connection));
        std::weak_ptr<CoreClientImpl> weakSelf = self;
        auto* raw = connection.get();
        connection->set_teardown_hook(
          [weakSelf, raw]
          {
            if (auto client = weakSelf.lock())
            {
              client->unregister_connection(raw);
            }
          });

        // Run the NamespaceArray bootstrap. Hold the ConnectionImpl STRONG through the continuation (the
        // registry is weak and must not be relied on for liveness). On success the impl is handed into the
        // Connection handle; on bootstrap failure it is dropped here, firing the teardown hook (unregister).
        // The deadline timer self-sustains and is cancelled by `deliver` when this completes.
        connection->start_async(
          [deliver, connection](ua::VoidResult bootstrap)
          {
            if (bootstrap.is_bad())
            {
              deliver(ConnectResult{bootstrap.status_code(), bootstrap.shared_detail()});
              return;
            }
            deliver(ConnectResult{detail::ConnectionHandleFactory::make_connection(connection)});
          });
      });
  }
  catch (...)
  {
    deliver(ConnectResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void CoreClientImpl::open_channel_async(
  CoreClient::OpenChannelConfig config, OpenChannelCallback callback) noexcept
{
  // `flow` is declared outside the try so the catch can still report through it:
  // once `callback` has been moved into `flow->onComplete`, the moved-from
  // parameter is empty and must not be invoked. The catch reports through
  // whichever sink still owns the user callback so it fires exactly once.
  //
  // Zero-copy hoist: the normal-path `start_normal_path(std::move(flow))` consumes `flow`, so it runs
  // after the prologue try/catch. The catch therefore only fires for prologue throws, where `flow`
  // (or the original `callback`) still owns the user callback. The reverse-connection path consumes
  // `flow` and returns inside the try; the normal path falls through to the post-try start.
  std::shared_ptr<detail::OpenChannelFlow> flow;
  try
  {
    auto policyValidation = detail::validate_client_security_policy(
      config.securityPolicyId, mConfig.application->allowDeprecatedSecurityPolicies);
    if (policyValidation.is_bad())
    {
      callback(SecureChannelResult{policyValidation.status_code()});
      return;
    }
    if (mConfig.application->allowDeprecatedSecurityPolicies)
    {
      detail::warn_deprecated_client_security_policy_once(config.securityPolicyId, logger());
    }

    // 5.3 synchronous-completion path: URL parse failure fires inline.
    auto parsed = ua::transport::parse_opc_tcp_url(config.endpointUrl, "Client");
    if (!parsed)
    {
      callback(SecureChannelResult{parsed.status_code(), parsed.shared_detail()});
      return;
    }

    auto& [hostname, port, path] = parsed.value();
    auto log = logger().with_category("client");
    log.info({{"endpoint_url", config.endpointUrl}}, "Opening channel");

    flow = std::make_shared<detail::OpenChannelFlow>();
    flow->client = weak_from_this();
    flow->log = log;
    flow->hostname = hostname;
    flow->port = port;
    flow->config = std::move(config);
    flow->onComplete = std::move(callback);

    if (flow->config.connectMode == client::ConnectMode::Reverse)
    {
      // 5.3 synchronous-completion path: no matching listener fires inline.
      std::shared_ptr<ReverseConnectListener> matchingListener;
      {
        const ua::ReadLock lk(mMutex);
        for (const auto& rc : mReverseConnects)
        {
          if (rc.listener->matches_endpoint(flow->config.endpointUrl))
          {
            matchingListener = rc.listener;
            break;
          }
        }
      }

      if (!matchingListener)
      {
        auto endpointUrl = flow->config.endpointUrl;
        detail::OpenChannelOrchestrator::fail_open(std::move(flow),
          SecureChannelResult{ua::Status::BadTcpEndpointUrlInvalid,
            ua::ErrorDetail::build(
              "NoMatchingListener", "No reverse connect listener matches the requested endpoint", "Client")
              .context(ua::ContextKeys::endpointUrl, endpointUrl)});
        return;
      }

      auto timeout = flow->config.timeout.value_or(std::chrono::milliseconds{30000});
      auto timeoutSeconds = std::chrono::duration_cast<std::chrono::seconds>(timeout);
      if (timeoutSeconds.count() == 0)
      {
        timeoutSeconds = std::chrono::seconds{30};
      }

      auto endpointUrl = flow->config.endpointUrl;
      matchingListener->consume_connection(std::move(endpointUrl),
        timeoutSeconds,
        [flow](client::QueuedConnectionResult consumeResult) mutable
        {
          detail::OpenChannelOrchestrator::on_reverse_connection_consumed(
            std::move(flow), std::move(consumeResult));
        });
      return;
    }

    // Normal path: fall through to the post-try start, which consumes `flow`.
  }
  catch (...)
  {
    auto status = ua::exception_to_status_code(std::current_exception());
    // If the throw happened after the callback was moved into the flow, the
    // flow still owns it; otherwise the original parameter is still live.
    if (flow && flow->onComplete)
    {
      auto onComplete = std::move(flow->onComplete);
      onComplete(std::move(status));
    }
    else if (callback)
    {
      callback(std::move(status));
    }
    return;
  }

  // `flow` is started here, outside the prologue catch that references it. A synchronous throw out of
  // the start step must report through the flow's own failure path (which owns the callback), not the
  // moved-from `callback`. Pass `flow` by copy so the local stays valid for this catch.
  try
  {
    detail::OpenChannelOrchestrator::start_normal_path(flow);
  }
  catch (...)
  {
    auto status = ua::exception_to_status_code(std::current_exception());
    detail::OpenChannelOrchestrator::fail_open(std::move(flow), SecureChannelResult{std::move(status)});
  }
}

}  // namespace ua::client
