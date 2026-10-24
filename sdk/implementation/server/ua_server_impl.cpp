// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_callback_safety.h"
#include "ua_certificate_validation_paths.h"
#include "ua_user_token_certificate_validation.h"
#include "ua_server_impl.h"

#include "ua_sync_wait.h"
#include "ua_address_space_change_event_emitter.h"
#include "ua_address_space_change_events.h"
#include "ua_address_space_session_events.h"
#include "ua_file_handle_budget.h"
#include "ua_register_address_space_types.h"
#include "ua_conditions.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_aggregate_registry.h"
#include "ua_server_model.h"
#include "ua_subscription.h"
#include "ua_sampling_interval_diagnostics_node_manager.h"
#include "ua_subscription_diagnostics_node_manager.h"
#include "ua_variable_id.h"
#include "ua_audit_event_emitter.h"
#include "ua_generic_event.h"
#include "ua_timer.h"
#include "ua_callback_safety.h"
#include "ua_log_exception.h"
#include "ua_namespace_metadata_publication.h"
#include "ua_role_configuration.h"
#include "ua_role_method_handlers.h"
#include "ua_role_set_population.h"
#include "ua_well_known_role_permissions.h"
#include "ua_server_event_emit.h"
#include "ua_server_encoding_limits.h"
#include "ua_tcp_transport_acceptor.h"
#include "ua_tcp_transport_connection.h"
#include "ua_registered_server_store.h"
#include "secure_channel/ua_server_secure_channel.h"
#include "ua_data_type_registration.h"
#include "ua_application_configuration.h"
#include "session/ua_server_session.h"
#include "ua_nodeset_import_engine.h"
#include "ua_structure.h"
#include "ua_tcp_endpoint_asio.h"
#include "nodeset_ns0.h"
#include "ua_ns0_access_decoration.h"
#include "ua_random.h"
#include "ua_security_policy.h"
#include "ua_security_policy_compatibility.h"
#include "ua_security_policy_internal.h"
#include "ua_stack_utilities.h"
#include "ua_default_namespace.h"
#include "ua_to_result.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_reverse_hello.h"
#include "ua_connection_protocol_limits.h"
#include "ua_url_parser.h"
#include "ua_on_strand.h"

#include "fmt/format.h"
#include "fmt/ranges.h"

#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <limits>
#include <array>
#include <atomic>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <set>

#include <ua_certificate_store_files.h>
#include <ua_crypto.h>
#include <ua_resolver.h>
#include <ua_utilities.h>

using namespace std::chrono_literals;

namespace ua::server
{

namespace
{

/// The served endpoints' SecurityPolicies, each with a name for messages (policy URI and mode).
std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>> served_endpoint_policies_of(
  const std::vector<ServerEndpointConfig>& endpoints)
{
  std::vector<std::pair<std::string, std::shared_ptr<const SecurityPolicy>>> result;
  for (const auto& endpoint : endpoints)
  {
    try
    {
      std::shared_ptr<const SecurityPolicy> policy = SecurityPolicy::create(endpoint.securityPolicyId);
      if (!policy || !policy->is_authenticated())
      {
        continue;
      }
      // The endpoint as the application named it (ServerConfig::validate requires a name), so a
      // refusal points at its configuration.
      result.emplace_back(endpoint.name, std::move(policy));
    }
    catch (...)
    {
      ::ua::detail::ignore_expected_exception();
    }
  }
  return result;
}

/// Internal F: every served endpoint's SecurityPolicy against the own certificate that endpoint uses.
VoidResult check_own_certificates_for_endpoints(const std::vector<ServerEndpointConfig>& endpoints,
  std::vector<CertificateStore::ApplicationCertificate> available)
{
  for (const auto& [name, policy] : served_endpoint_policies_of(endpoints))
  {
    CertificateStore::ApplicationCertificate own;
    try
    {
      own = stack_utils::get_local_cert_and_keys(available, policy->id());
    }
    catch (...)
    {
      // A missing certificate is reported by the endpoint setup that needs it.
      ::ua::detail::ignore_expected_exception();
      continue;
    }
    if (!own.certificate)
    {
      continue;
    }
    const X509Certificate& signer = own.issuerCertificates.empty() || !own.issuerCertificates.front()
                                      ? *own.certificate
                                      : *own.issuerCertificates.front();
    auto compliance =
      server::detail::check_own_certificate_against_endpoints(*own.certificate, signer, {{name, policy}});
    if (compliance.is_bad())
    {
      return compliance;
    }
  }
  // A None-channel endpoint whose user tokens are secured needs one held certificate valid for every token
  // policy's SecurityPolicy (OPC 10000-4 7.41.4 Table 193; OPC 10000-6 6.8.3). Without one the endpoint
  // cannot be served as configured, so the server refuses to start rather than pick a certificate a policy
  // forbids.
  for (const auto& endpoint : endpoints)
  {
    if (endpoint.securityPolicyId != SecurityPolicyId::None)
      continue;
    const bool tokensSecured = std::ranges::any_of(endpoint.userIdentityTokens,
      [](const UserTokenPolicy& token)
      {
        const auto& uri = token.security_policy_uri();
        if (uri.empty())
          return false;
        const auto id = utils::get_security_policy_id(uri);
        return id != SecurityPolicyId::None && id != SecurityPolicyId::Invalid;
      });
    if (!tokensSecured)
      continue;
    if (!stack_utils::resolve_certificate_type_for_endpoint(
          SecurityPolicyId::None, endpoint.userIdentityTokens, available))
    {
      return VoidResult{StatusCode{Status::BadConfigurationError,
        make_error_detail("NoCertificateForTokenPolicies",
          "No application certificate is valid for every user token policy of endpoint " + endpoint.name +
            " (OPC 10000-6 6.8.3)",
          "ServerImpl")}};
    }
  }
  return VoidResult{};
}

}  // namespace

namespace
{

struct AnyEntryEvictable
{
  bool operator()(const auto&) const noexcept
  {
    return true;
  }
};

// If @p map is at @p cap and @p incomingKey is not already present, evict the least-recently-active
// entry (smallest timestamp from @p timeOf) among those @p evictable allows, so an attacker-controlled
// key space cannot grow the map without limit. Returns false when the map is at cap and no entry may be
// evicted: the caller must then not insert @p incomingKey. Caller holds the map's mutex. O(n) scan, only
// on the rare insert-at-cap path.
template<typename Map, typename TimeOf, typename Evictable = AnyEntryEvictable>
bool evict_lru_if_at_cap(
  Map& map, size_t cap, const typename Map::key_type& incomingKey, TimeOf timeOf, Evictable evictable = {})
{
  if (cap == 0 || map.size() < cap || map.find(incomingKey) != map.end())
  {
    return true;
  }
  auto victim = map.end();
  for (auto it = map.begin(); it != map.end(); ++it)
  {
    if (evictable(it->second) && (victim == map.end() || timeOf(it->second) < timeOf(victim->second)))
    {
      victim = it;
    }
  }
  if (victim == map.end())
  {
    return false;
  }
  map.erase(victim);
  return true;
}

// Drives a sequence of async import-engine operations in order, blocking the calling (startup)
// thread once until all complete or the first one fails. Used for the synchronous server NS0 load
// (D-T): it is refused on a thread of @p executor, where the engine's posted steps drain.
ua::VoidResult drive_import_steps_sync(const boost::asio::any_io_executor& executor,
  std::vector<std::function<void(ua::xml::nodeset::ImportEngine::Completion)>> steps)
{
  using ua::xml::nodeset::ImportEngine;

  struct StepRunner : std::enable_shared_from_this<StepRunner>
  {
    std::vector<std::function<void(ImportEngine::Completion)>> steps;
    std::function<void(ua::VoidResult)> complete;

    void run(std::size_t index)
    {
      if (index >= steps.size())
      {
        complete(ua::VoidResult{});
        return;
      }
      auto self = shared_from_this();
      // A step that THROWS must become a failed startup, not a dead process. Import steps consume the
      // configured LoopLimit / work budgets, and those consume sites throw on exhaustion rather than
      // returning - so an under-configured limit reached this lambda on an executor thread and
      // terminated. Converting the throw into the result keeps the failure on the startup path, where
      // create_standard_nodes_from_nodeset already turns a bad result into a UaException the host can
      // catch.
      try
      {
        steps[index](
          [self, index](ua::VoidResult result)
          {
            if (result.is_bad())
            {
              self->complete(ua::VoidResult{result.status_code()});
              return;
            }
            self->run(index + 1);
          });
      }
      catch (...)
      {
        self->complete(ua::VoidResult{::ua::exception_to_status_code(std::current_exception())});
      }
    }
  };

  // blocking_call accepts only the first completion, so a step that throws after it has already
  // completed cannot answer twice.
  return ua::async::detail::blocking_call<ua::VoidResult>(executor,
    [&steps](std::function<void(ua::VoidResult)> complete)
    {
      auto runner = std::make_shared<StepRunner>();
      runner->steps = std::move(steps);
      runner->complete = std::move(complete);
      runner->run(0);
    });
}

std::string to_bind_address_string(const asio::ip::tcp::endpoint& ep)
{
  const auto host = ep.address().to_string();
  if (ep.address().is_v6())
  {
    return fmt::format("[{}]:{}", host, ep.port());
  }
  return fmt::format("{}:{}", host, ep.port());
}

std::string to_bind_address_string(const TcpEndpoint& ep)
{
  const auto asioEp = ua::detail::to_asio(ep);
  return to_bind_address_string(asioEp);
}

std::string derive_host_for_advertisement(std::string_view boundHost)
{
  // Best-effort: wildcard bind is not a usable client URL host.
  if ((boundHost == "0.0.0.0") || (boundHost == "::") || (boundHost == "[::]") || boundHost.empty())
  {
    auto host = boost::asio::ip::host_name();
    if (host.empty())
    {
      host = "localhost";
    }
    return host;
  }

  // Strip brackets if present; we'll add them back for IPv6 URLs.
  if (boundHost.size() >= 2 && boundHost.front() == '[' && boundHost.back() == ']')
  {
    return std::string{boundHost.substr(1, boundHost.size() - 2)};
  }
  return std::string{boundHost};
}

ua::transport::EndpointUrl derive_opc_tcp_advertised_url(const ua::transport::BindAddress& boundBind)
{
  // Expect <host>:<port> or [<host>]:<port>.
  const auto hostPort = boundBind.address;
  auto host = std::string{};
  auto port = std::string{};

  if (!hostPort.empty() && hostPort.front() == '[')
  {
    const auto close = hostPort.find(']');
    if (close != std::string::npos)
    {
      host = hostPort.substr(1, close - 1);
      if (close + 2 <= hostPort.size() && hostPort[close + 1] == ':')
      {
        port = hostPort.substr(close + 2);
      }
    }
  }
  else
  {
    const auto colon = hostPort.rfind(':');
    if (colon != std::string::npos)
    {
      host = hostPort.substr(0, colon);
      port = hostPort.substr(colon + 1);
    }
  }

  host = derive_host_for_advertisement(host);

  const bool hostNeedsBrackets = (host.find(':') != std::string::npos);
  const auto urlHost = hostNeedsBrackets ? fmt::format("[{}]", host) : host;
  return ua::transport::EndpointUrl{fmt::format("opc.tcp://{}:{}", urlHost, port)};
}

}  // namespace

class ServerImpl::StartupAttempt final
{
public:
  StartupAttempt(Server::CompleteCallback callback, Logger logger)
    : mCallback(std::move(callback)), mLogger(std::move(logger))
  {}

  void complete(VoidResult result) noexcept
  {
    Server::CompleteCallback callback;
    {
      const std::lock_guard lock(mMutex);
      callback = std::move(mCallback);
    }
    ua::detail::invoke_user_callback(mLogger, callback, std::move(result));
  }

private:
  std::mutex mMutex;
  Server::CompleteCallback mCallback;
  Logger mLogger;
};

class ServerDependencies : public DiscoveryDependencies,
                           public SecureChannelDependencies,
                           public SessionDependencies,
                           public ConnectionProtocolDependencies,
                           public std::enable_shared_from_this<ServerDependencies>
{
public:
  explicit ServerDependencies(const shared_ptr<ServerImpl>& server)
    : mServer(server), mIdentity(server->identity()), mApplication(server->shared_configuration()),
      mServerConfiguration(server->server_configuration())
  {}

  // Ensure both overload sets stay visible.
  using DiscoveryDependencies::endpoints;

  boost::asio::any_io_executor executor() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->executor();
  }

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return std::static_pointer_cast<DiscoveryDependencies>(shared_from_this());
  }

  ua::connection_protocol::Limits connection_protocol_limits() const override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->connection_protocol_limits();
  }

  ua::EncodingLimits encoding_limits() const override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return ua::server::make_server_encoding_limits(server->configuration(), server->server_configuration());
  }

  shared_ptr<const Crypto> crypto() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->crypto();
  }

  WeakAddressSpace address_space() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      return WeakAddressSpace{};
    }
    return server->address_space().weak();
  }

  /// Owned, not borrowed. These three used to lock the weak server, then return a reference INTO
  /// it - so the lock that made the reference valid died with the accessor's stack frame and the
  /// caller read through a reference nothing was keeping alive. TSan caught exactly that: a
  /// discovery continuation building endpoint descriptions on a pool thread while ~ServerImpl freed
  /// the identity's strings on the main one.
  ///
  /// A longer lock would not fix it and is not allowed: a continuation must not hold one. So the
  /// object that hands these out owns them instead. All three are fixed at construction - the
  /// identity is static, the application configuration is shared and immutable, the server
  /// configuration is set once - so a copy taken here cannot go stale, and there is nothing left
  /// to lock.
  ::ua::ApplicationIdentity identity() override
  {
    // Still reports a dead server, which is the documented contract and what
    // ServerShutdownTests.DeadServerDependencyAccessorsThrowBadInvalidState pins. Owning the data
    // fixes a different problem - handing out a REFERENCE into a server that may be torn down
    // while the caller reads it - and does not make a dead server a normal one to talk to.
    if (mServer.expired())
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return mIdentity;
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    // Still reports a dead server, which is the documented contract and what
    // ServerShutdownTests.DeadServerDependencyAccessorsThrowBadInvalidState pins. Owning the data
    // fixes a different problem - handing out a REFERENCE into a server that may be torn down
    // while the caller reads it - and does not make a dead server a normal one to talk to.
    if (mServer.expired())
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return *mApplication;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    // Still reports a dead server, which is the documented contract and what
    // ServerShutdownTests.DeadServerDependencyAccessorsThrowBadInvalidState pins. Owning the data
    // fixes a different problem - handing out a REFERENCE into a server that may be torn down
    // while the caller reads it - and does not make a dead server a normal one to talk to.
    if (mServer.expired())
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return mServerConfiguration;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    // Return null (not throw) when the server is gone. This accessor is invoked from in-flight
    // session / secure-channel async completions that can resume on their strand AFTER the server
    // is destroyed (e.g. session-eviction teardown); a throw there escapes the noexcept strand
    // handler and calls std::terminate. Every caller null-checks the result (or holds it in a
    // weak_ptr whose consumer null-checks the lock), matching the sibling accessors
    // (registered_server_store(), observer(), node_management_delegate()).
    auto server = mServer.lock();
    if (!server)
      return nullptr;
    return server->default_application_group_certificate_store();
  }

  shared_ptr<CertificateStore> user_token_certificate_store() override
  {
    // Null-on-destroyed-server, as above: this runs from the activation flow, which can resume
    // after teardown. A null store here is already a legitimate configuration, so every caller
    // handles it.
    auto server = mServer.lock();
    if (!server)
      return nullptr;
    return server->user_token_certificate_store();
  }

  shared_ptr<RegisteredServerStore> registered_server_store() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      return nullptr;
    }
    return server->registered_server_store();
  }

  ::ua::server::ListenerHandleList listeners() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->listeners();
  }

  std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle listener) override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->endpoints(listener);
  }

  std::vector<::ua::transport::EndpointUrl> advertised_urls(::ua::server::ListenerHandle listener) override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->advertised_urls(listener);
  }

  // Aggregated endpoint configurations (used by secure channel/session dependencies).
  std::vector<ServerEndpointConfig> endpoints() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->endpoints();
  }

  const ::ua::server::ServerComponents& components() const override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->components();
  }

  uint32_t get_next_secure_channel_id() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->get_next_secure_channel_id();
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      return nullptr;
    }
    return server->observer();
  }

  Logger logger() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      return {};
    }
    return server->logger();
  }

  void create_session(
    SecureChannelInfo secureChannelInfo, uint32_t requestId, CreateSessionRequest&& request) override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    server->create_session(secureChannelInfo, requestId, std::move(request));
  }

  void activate_session_on_channel(
    SecureChannelInfo newChannelInfo, uint32_t requestId, ActivateSessionRequest&& request) override
  {
    auto server = mServer.lock();
    if (!server)
      return;
    server->activate_session_on_channel(std::move(newChannelInfo), requestId, std::move(request));
  }

  void remove_session(const shared_ptr<Session>& session) override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    server->remove_session(session);
  }

  void remove_secure_channel(const shared_ptr<SecureChannel>& channel) override
  {
    auto server = mServer.lock();
    if (!server)
      return;
    server->remove_secure_channel(channel);
  }

  StructureFactory& structure_factory() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->structure_factory();
  }

  std::shared_ptr<RequestLatencyTracker> latency_tracker() override
  {
    auto server = mServer.lock();
    return server ? server->latency_tracker() : nullptr;
  }

  std::shared_ptr<ServerSummaryCounters> summary_counters() override
  {
    auto server = mServer.lock();
    return server ? server->summary_counters() : nullptr;
  }

  std::shared_ptr<SecureChannelCounters> secure_channel_counters() override
  {
    auto server = mServer.lock();
    if (!server)
      return nullptr;
    auto enabled = server->diagnostics_enabled();
    if (!enabled || !enabled->load(std::memory_order_relaxed))
      return nullptr;
    return server->secure_channel_counters();
  }

  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() override
  {
    auto server = mServer.lock();
    return server ? server->diagnostics_enabled() : nullptr;
  }

  SubscriptionIdAllocator& subscription_id_allocator() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->subscription_id_allocator();
  }

  SubscriptionRouter& subscription_router() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->subscription_router();
  }

  OrphanedSubscriptionStore& orphaned_subscription_store() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->orphaned_subscription_store();
  }

  EventBus& event_bus() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      throw UaException{Status::BadInvalidState,
        make_error_detail("ServerDestroyed", "Server instance has been destroyed", "ServerImpl")};
    }
    return server->event_bus();
  }

  std::shared_ptr<EventBus> event_bus_shared() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      return {};
    }
    return server->event_bus_shared();
  }

  std::shared_ptr<NodeManagementDelegate> node_management_delegate() override
  {
    auto server = mServer.lock();
    if (!server)
    {
      return nullptr;
    }
    return server->node_management_delegate();
  }

  optional<StatusCode> begin_identity_attempt(const ClientId& client, std::string_view claimedUserId) override
  {
    auto server = mServer.lock();
    if (!server)
      return std::nullopt;
    return server->begin_identity_attempt(client, claimedUserId);
  }

  void finish_identity_attempt(
    const ClientId& client, std::string_view claimedUserId, IdentityAttemptOutcome outcome) override
  {
    auto server = mServer.lock();
    if (!server)
      return;
    server->finish_identity_attempt(client, claimedUserId, outcome);
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    auto server = mServer.lock();
    return server ? server->in_flight_discovery_requests() : nullptr;
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_requests() override
  {
    auto server = mServer.lock();
    return server ? server->in_flight_requests() : nullptr;
  }

private:
  const weak_ptr<ServerImpl> mServer;
  // Copied at construction while the server is provably alive, and immutable thereafter - see the
  // accessors above for why they must not be references into the server.
  const ::ua::ApplicationIdentity mIdentity;
  const std::shared_ptr<const ::ua::ApplicationConfig> mApplication;
  const ::ua::server::ServerConfig mServerConfiguration;
};

shared_ptr<SessionDependencies> ServerImpl::session_dependencies()
{
  return mDependencies;
}

shared_ptr<SecureChannelDependencies> ServerImpl::secure_channel_dependencies()
{
  return mDependencies;
}

shared_ptr<ServerImpl> ServerImpl::create(boost::asio::any_io_executor executor,
  ::ua::server::CombinedConfig config, ::ua::server::ServerComponents components)
{
  // Checked here as well as in Server::create, because tests and internal callers build a ServerImpl
  // directly: no server exists without the application's crypto provider (security review B3-8).
  if (!components.crypto)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("CryptoProviderRequired",
        "ServerComponents::crypto is null; the server needs the application's crypto provider",
        "ServerImpl")};
  }

  // Building the Server populates and wires its address space by blocking calls whose answers run on
  // this executor. On an application thread that is a wait; on a thread of the executor it could never
  // end, so it is refused before anything is built.
  if (ua::async::detail::on_executor_context(executor))
  {
    throw UaException{Status::BadWouldBlock, ua::async::detail::would_block_detail()};
  }

  class Wrapper : public ServerImpl
  {
  public:
    Wrapper(boost::asio::any_io_executor executor, ::ua::server::CombinedConfig config,
      ::ua::server::ServerComponents components)
      : ServerImpl(executor, std::move(config), std::move(components))
    {}
  };

  auto server = make_shared<Wrapper>(executor, std::move(config), std::move(components));
  server->mDependencies = make_shared<ServerDependencies>(server);
  server->initialise_next_secure_channel_id();
  const auto roleManagementAccessRoles = server->prepare_role_configuration();
  server->create_standard_nodes(roleManagementAccessRoles);
  server->wire_role_configuration();
  server->mNamespaceMetadataPublication = NamespaceMetadataPublication::create(server->mAddressSpace);
  ::ua::detail::AddressSpaceNamespaceLifecycle::install_participant(
    server->mAddressSpace, server->mNamespaceMetadataPublication);

  // Surface events dropped by the EventBus pending-dispatch backstop to registered observers. The
  // callback fires on the dispatch strand; observer() resolves the current composite lazily, so
  // observers registered after this point are still notified. Wired here (not in the ctor) because
  // it needs the owning shared_ptr for weak capture.
  {
    const std::weak_ptr<ServerImpl> weakServer = server;
    server->mEventBus->set_dispatch_dropped_observer(
      [weakServer](const DroppedEventInfo& info)
      {
        auto self = weakServer.lock();
        if (!self)
          return;
        auto observerHandle = self->observer();
        detail::emit_event(
          self->mLogger, observerHandle, [&] { observerHandle->on_event_dispatch_dropped(info); });
      });
  }

  return server;
}

namespace
{

/// Tells the address space that a Session has ended, so the state that Session owned is released.
///
/// The address space cannot see this for itself: a Session is a server-layer object, and a node
/// holding Session-scoped state -- a FileType's open handles, which OPC 10000-20 section 4.2.2 makes valid
/// only "while the session is open" -- has no way to learn that its owner is gone. Registered
/// unconditionally, because the obligation is the standard's and not a configurable behaviour.
class AddressSpaceSessionReaper final : public ServerObserver
{
public:
  explicit AddressSpaceSessionReaper(WeakAddressSpace addressSpace) : mAddressSpace(std::move(addressSpace))
  {}

  // Fired from the Session's destructor, so this covers every way a Session can end: an orderly
  // CloseSession, a dropped transport, and a timeout alike.
  void on_session_closed(const SessionEventInfo& info, StatusCode /*reason*/) override
  {
    // Weak, because this fires during teardown as readily as during normal operation, and the
    // server that owns both this observer and the address space may already be unwinding.
    if (auto addressSpace = mAddressSpace.lock())
      ::ua::detail::AddressSpaceSessionEvents::notify_closed(*addressSpace, info.sessionId);
  }

private:
  WeakAddressSpace mAddressSpace;
};

}  // namespace

ServerImpl::ServerImpl(boost::asio::any_io_executor executor, ::ua::server::CombinedConfig config,
  ::ua::server::ServerComponents components)
  : mAddressSpace{AddressSpace::create(
      config.application->application_description_part().applicationUri, executor)},
    mExecutor(executor), mConfig(std::move(config)), mCrypto(components.crypto),
    mDefaultApplicationGroupCertificateStore(components.applicationGroupCertificateStore),
    mComponents(std::move(components)),
    // Apply the configured server-internal resource caps (memory fail-safes; not OPC-UA-advertised).
    mMaxPerIpThrottleEntries(mConfig.server.connectionThrottling.maxTrackedEndpoints),
    mMaxIdentityThrottleEntries(mConfig.server.identityThrottling.maxTrackedIdentities)
{
  // Install the construction-time log sink BEFORE any subsystem captures a logger, so the address
  // space (set_logger below), the namespaces / sampling engine (create_standard_nodes), conditions,
  // etc. all get a live logger from birth instead of a silent snapshot. The sink is fixed for the
  // server's lifetime (there is no runtime sink setter); set_log_level() adjusts the level via the
  // shared atomic.
  if (mComponents.logSink)
  {
    mLogLevel->store(mComponents.logLevel, std::memory_order_relaxed);
    mLogSink = mComponents.logSink;
    mLogger = Logger{mLogSink, mLogLevel, "server"};
  }
  mLogger.debug("ServerImpl created");

  mOrphanedSubscriptionStore.set_max_entries(mConfig.server.resourceLimits.orphanedSubscriptionStore);

  mAddressSpace.set_limits(configuration().execution_limits());
  mAddressSpace.set_operation_limits(server_configuration().server_capabilities().operationLimits);
  mAddressSpace.set_logger(mLogger.with_category("address-space"));
  ::ua::detail::AddressSpaceFileHandles::set_limits(mAddressSpace,
    mConfig.server.resourceLimits.openFileHandlesPerSession,
    mConfig.server.resourceLimits.openFileHandles);
  add_internal_observer(std::make_shared<AddressSpaceSessionReaper>(mAddressSpace.weak()));
  mEventBus =
    std::make_shared<EventBus>(mAddressSpace, mConfig.server.resourceLimits.eventDispatchQueueDepth);
  auto addressSpaceChangeEmitter =
    std::make_shared<AddressSpaceChangeEventEmitter>(std::weak_ptr<EventSink>{mEventBus},
      mLogger.with_category("model-changes"),
      server_configuration().server_capabilities().maxArrayLength);
  // The Model and Semantic changes the address space raises become ModelChangeEvents and
  // SemanticChangeEvents. The SemanticsChanged bit of the owner's monitored items is set by the namespace
  // that changed the Property (NR-37).
  ::ua::detail::AddressSpaceChangeEvents::set_handler(mAddressSpace,
    [addressSpaceChangeEmitter](const ::ua::detail::AddressSpaceChange& change)
    { addressSpaceChangeEmitter->emit(change); });
  mConditions = std::make_shared<Conditions>(
    Conditions::ConstructionKey{}, mExecutor, std::weak_ptr<EventSink>{mEventBus}, mAddressSpace);
  mConditions->set_max_branches_per_condition(mConfig.server.resourceLimits.conditionBranchesPerCondition);

  // Create AuditEventEmitter if auditing is enabled. The emitter holds a weak EventBus reference
  // and contains rich emission failures if an observer outlives the bus during teardown.
  if (mConfig.server.auditingEnabled)
  {
    auto serverUri = mConfig.application->application_description_part().applicationUri;
    add_internal_observer(std::make_shared<AuditEventEmitter>(
      std::weak_ptr<EventSink>{mEventBus}, std::move(serverUri), mLogger.with_category("audit")));
  }

  create_crypto_components();

  const CodecNamespaceContext nsConfig = mAddressSpace.codec_namespace_context();
  register_ua_data_types_with_factory(nsConfig, &mStructureFactory, &mStructureFactory);

  // Server-as-LDS: stand up the inbound registry only when the feature is enabled. Left nullptr
  // otherwise, so FindServers aggregation and the inbound dispatch are a simple null-check.
  if (mConfig.server.localDiscoveryServer.enabled)
  {
    mRegisteredServerStore =
      RegisteredServerStore::create(mExecutor, mConfig.server.localDiscoveryServer, mLogger);
  }
}

shared_ptr<RegisteredServerStore> ServerImpl::registered_server_store() const
{
  return mRegisteredServerStore;
}

std::vector<shared_ptr<ua::xml::nodeset::NodeSet>> ServerImpl::get_ns0_nodeset()
{
  using namespace ua::xml::nodeset;

  memory_stream_device::ExternalReadOnly streamDevice{utils::span_of_char_to_span_of_byte(nodesetNs0)};
  const MemoryStream inputStream{streamDevice};

  auto& serverArray = mAddressSpace.server_array();
  auto& namespaceArray = mAddressSpace.namespace_array();

  // Trusted local input: the built-in NS0 nodeset is compiled into the binary, so lift the size caps
  // (the bounded-floor defaults guard hostile remote wire input, not our own standard nodeset).
  return Parser::parse(ua::make_trusted_local_encoding_limits(configuration()),
    inputStream,
    mStructureFactory,
    namespaceArray,
    serverArray,
    Parser::GetDependentModelCallback{});
}

std::function<std::unique_ptr<Stream>(const ModelRef&)> ServerImpl::required_model_resolver() const
{
  return [](const ModelRef& model) -> std::unique_ptr<Stream>
  {
    // The server already carries the standard OPC UA base model (NS0) compiled in. Serve it for a
    // companion spec's `<RequiredModel http://opcfoundation.org/UA/>` so the dependency is parsed
    // alongside the spec - which is what lets the spec's custom DataTypes be classified (is_a_
    // structure walks the parsed hierarchy up to Structure), based, and discovered. Deeper
    // dependencies (a spec that requires another companion spec) must be supplied by the caller.
    if (static_cast<string_view>(model.uri) != "http://opcfoundation.org/UA/")
    {
      return nullptr;
    }
    // The device refers to the compiled-in, immutable NS0 bytes and each MemoryStream holds its own
    // read cursor, so a single shared static device backs every resolved stream safely.
    static memory_stream_device::ExternalReadOnly ns0Device{utils::span_of_char_to_span_of_byte(nodesetNs0)};
    return std::make_unique<MemoryStream<memory_stream_device::ExternalReadOnly>>(ns0Device);
  };
}

::ua::ApplicationIdentity ServerImpl::identity() const
{
  return mConfig.identity;
}

const ::ua::ApplicationConfig& ServerImpl::configuration() const
{
  return *mConfig.application;
}

std::shared_ptr<const ::ua::ApplicationConfig> ServerImpl::shared_configuration() const
{
  return mConfig.application;
}

const ::ua::server::ServerConfig& ServerImpl::server_configuration() const
{
  return mConfig.server;
}

const ::ua::server::CombinedConfig& ServerImpl::config() const
{
  return mConfig;
}

const ::ua::server::ServerComponents& ServerImpl::components() const
{
  return mComponents;
}

namespace
{

/// Dispatches all ServerObserver callbacks to a list of delegates.
class CompositeObserver final : public ServerObserver
{
public:
  explicit CompositeObserver(std::vector<std::shared_ptr<ServerObserver>> observers)
    : mObservers(std::move(observers))
  {}

  void on_secure_channel_opened(const SecureChannelEventInfo& info) override
  {
    for (auto& o : mObservers)
      o->on_secure_channel_opened(info);
  }

  void on_secure_channel_closed(const SecureChannelEventInfo& info, StatusCode reason) override
  {
    for (auto& o : mObservers)
      o->on_secure_channel_closed(info, reason);
  }

  void on_secure_channel_renewed(const SecureChannelEventInfo& info) override
  {
    for (auto& o : mObservers)
      o->on_secure_channel_renewed(info);
  }

  void on_secure_channel_open_failed(const SecureChannelEventInfo& info, StatusCode reason) override
  {
    for (auto& o : mObservers)
      o->on_secure_channel_open_failed(info, reason);
  }

  void on_secure_channel_renew_failed(const SecureChannelEventInfo& info, StatusCode reason) override
  {
    for (auto& o : mObservers)
      o->on_secure_channel_renew_failed(info, reason);
  }

  void on_session_created(const SessionEventInfo& info) override
  {
    for (auto& o : mObservers)
      o->on_session_created(info);
  }

  void on_session_create_failed(const SessionEventInfo& info, StatusCode reason) override
  {
    for (auto& o : mObservers)
      o->on_session_create_failed(info, reason);
  }

  void on_session_activated(const SessionEventInfo& info) override
  {
    for (auto& o : mObservers)
      o->on_session_activated(info);
  }

  void on_session_closed(const SessionEventInfo& info, StatusCode reason) override
  {
    for (auto& o : mObservers)
      o->on_session_closed(info, reason);
  }

  void on_session_timed_out(const SessionEventInfo& info) override
  {
    for (auto& o : mObservers)
      o->on_session_timed_out(info);
  }

  void on_connection_accepted(const std::string& remoteAddress) override
  {
    for (auto& o : mObservers)
      o->on_connection_accepted(remoteAddress);
  }

  void on_connection_closed(
    const std::string& remoteAddress, ConnectionCloseReason reason, StatusCode status) override
  {
    for (auto& o : mObservers)
      o->on_connection_closed(remoteAddress, reason, status);
  }

  void on_certificate_rejected(const CertificateEventInfo& info) override
  {
    for (auto& o : mObservers)
      o->on_certificate_rejected(info);
  }

  void on_certificate_error_suppressed(const CertificateEventInfo& info) override
  {
    for (auto& o : mObservers)
      o->on_certificate_error_suppressed(info);
  }

  void on_authentication_failed(const SessionEventInfo& info, StatusCode reason) override
  {
    for (auto& o : mObservers)
      o->on_authentication_failed(info, reason);
  }

  void on_reverse_connect_opened(const std::string& targetName, const std::string& remoteAddress) override
  {
    for (auto& observer : mObservers)
      observer->on_reverse_connect_opened(targetName, remoteAddress);
  }

  void on_reverse_connect_closed(
    const std::string& targetName, const std::string& remoteAddress, StatusCode reason) override
  {
    for (auto& observer : mObservers)
      observer->on_reverse_connect_closed(targetName, remoteAddress, reason);
  }

  void on_reverse_connect_channel_established(
    const std::string& targetName, uint32_t secureChannelId) override
  {
    for (auto& observer : mObservers)
      observer->on_reverse_connect_channel_established(targetName, secureChannelId);
  }

  void on_internal_error(StatusCode status, const std::string& description) override
  {
    for (auto& o : mObservers)
      o->on_internal_error(status, description);
  }

  void on_event_dispatch_dropped(const DroppedEventInfo& info) override
  {
    for (auto& o : mObservers)
      o->on_event_dispatch_dropped(info);
  }

  void on_shutdown_initiated(uint32_t secondsTillShutdown, const LocalizedText& reason) override
  {
    for (auto& o : mObservers)
      o->on_shutdown_initiated(secondsTillShutdown, reason);
  }

  void on_shutdown_complete() override
  {
    for (auto& o : mObservers)
      o->on_shutdown_complete();
  }

private:
  std::vector<std::shared_ptr<ServerObserver>> mObservers;
};

}  // namespace

void ServerImpl::rebuild_composite_observer()
{
  // Must be called under WriteLock.
  std::vector<std::shared_ptr<ServerObserver>> all;
  all.reserve(mInternalObservers.size() + (mObserver ? 1 : 0));
  for (auto& obs : mInternalObservers)
    all.push_back(obs);
  if (mObserver)
    all.push_back(mObserver);

  if (all.size() > 1)
    mCompositeObserver = std::make_shared<CompositeObserver>(std::move(all));
  else
    mCompositeObserver = nullptr;
}

void ServerImpl::release_per_ip_reservation_locked(const std::string& remoteIp)
{
  auto ipIt = mPerIpState.find(remoteIp);
  if (ipIt != mPerIpState.end() && ipIt->second.activeCount > 0)
  {
    ipIt->second.activeCount--;
    if (ipIt->second.activeCount == 0 && ipIt->second.recentAttempts.empty())
    {
      mPerIpState.erase(ipIt);
    }
  }
}

std::string ServerImpl::connection_throttle_key(
  const boost::asio::ip::address& address, uint32_t ipv6PrefixLength)
{
  if (address.is_v4())
  {
    return address.to_string();
  }
  const auto v6 = address.to_v6();
  if (v6.is_v4_mapped())
  {
    return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, v6).to_string();
  }
  if (ipv6PrefixLength >= 128 || v6.is_link_local())
  {
    // The whole address, scope id included. A link-local address (fe80::/10) is never masked: every
    // link-local peer of every interface would otherwise collapse into the one key "fe80::/N".
    return v6.to_string();
  }
  auto bytes = v6.to_bytes();
  const size_t wholeBytes = ipv6PrefixLength / 8;
  const unsigned remainingBits = ipv6PrefixLength % 8;
  for (size_t i = wholeBytes + (remainingBits ? 1 : 0); i < bytes.size(); ++i)
  {
    bytes[i] = 0;
  }
  if (remainingBits)
  {
    bytes[wholeBytes] &= static_cast<unsigned char>(0xFFu << (8 - remainingBits));
  }
  return fmt::format("{}/{}", boost::asio::ip::address_v6{bytes}.to_string(), ipv6PrefixLength);
}

void ServerImpl::decrement_per_ip_count_locked(const TransportConnection* transport)
{
  auto it = mConnectionRemoteIp.find(transport);
  if (it != mConnectionRemoteIp.end())
  {
    release_per_ip_reservation_locked(it->second);
    mConnectionRemoteIp.erase(it);
  }
}

shared_ptr<ConnectionProtocol> ServerImpl::release_initialising_connection_locked(
  ConnectionProtocol* connection)
{
  const auto it = std::ranges::find_if(
    mInitialisingConnections, [connection](const auto& candidate) { return candidate.get() == connection; });
  if (it == mInitialisingConnections.end())
  {
    return nullptr;
  }
  auto released = std::move(*it);
  mInitialisingConnections.erase(it);
  decrement_per_ip_count_locked(connection->transport_identity());
  return released;
}

void ServerImpl::initialising_connection_failed(
  std::shared_ptr<InitialisingSlot> slot, StatusCode status, std::string remoteAddress)
{
  shared_ptr<ConnectionProtocol> released;
  {
    const WriteLock lk(mMutex);
    if (slot->connection == nullptr)
    {
      // Not published yet: the publication step releases the reservation and emits the event. A
      // handshake that already completed owns its own release and event (new_connection_complete and
      // the Completed arm of publication), so a close that follows it must not recast it as a failure.
      if (slot->outcome == InitialisingSlot::Outcome::Pending)
      {
        slot->outcome = InitialisingSlot::Outcome::Failed;
        slot->status = status;
      }
      return;
    }
    released = release_initialising_connection_locked(slot->connection);
  }
  if (!released)
  {
    return;  // the handshake completed (entry released on success) or was already released
  }

  // This runs inside the ConnectionProtocol's own strand handler. The posted handler becomes the only
  // list-derived owner, so the object is never destroyed from within its own member call.
  ua::async::post_borrowing(
    this, mExecutor, mLogger, [released = std::move(released)](ServerImpl&) mutable { released.reset(); })();

  auto eh = observer();
  detail::emit_event(mLogger,
    eh,
    [&] { eh->on_connection_closed(remoteAddress, ConnectionCloseReason::ProtocolError, status); });
}

void ServerImpl::set_observer(std::shared_ptr<ServerObserver> handler)
{
  const WriteLock lk(mMutex);
  mObserver = std::move(handler);
  rebuild_composite_observer();
}

std::shared_ptr<ServerObserver> ServerImpl::observer() const
{
  const ReadLock lk(mMutex);
  if (mCompositeObserver)
    return mCompositeObserver;
  if (!mInternalObservers.empty())
    return mInternalObservers.front();
  return mObserver;
}

void ServerImpl::add_internal_observer(std::shared_ptr<ServerObserver> observer)
{
  const WriteLock lk(mMutex);
  mInternalObservers.push_back(std::move(observer));
  rebuild_composite_observer();
}

void ServerImpl::set_node_management_delegate(std::shared_ptr<NodeManagementDelegate> delegate)
{
  const WriteLock lk(mMutex);
  mNodeManagementDelegate = std::move(delegate);
}

std::shared_ptr<NodeManagementDelegate> ServerImpl::node_management_delegate() const
{
  const ReadLock lk(mMutex);
  return mNodeManagementDelegate;
}

optional<StatusCode> ServerImpl::begin_identity_attempt(
  const ClientId& client, std::string_view claimedUserId)
{
  const auto& cfg = mConfig.server.identityThrottling;
  if (!cfg.enabled)
    return std::nullopt;
  const WriteLock lk(mMutex);
  const auto now = std::chrono::steady_clock::now();
  auto it = mIdentityThrottleState.find(client);
  if (it != mIdentityThrottleState.end())
  {
    auto& state = it->second;
    // A lockout period that has run its course also ends the count that started it: the client
    // application begins again with a fresh budget (otherwise the budget check below would refuse it
    // for as long as the entry lived).
    if (state.lockedUntil != std::chrono::steady_clock::time_point{} && now >= state.lockedUntil)
    {
      state.failuresByUser.clear();
      state.lockedUntil = {};
    }
    // Failures below the threshold age out after one lockout duration of quiet, so a stale count
    // neither caps a client application's concurrency nor turns a later single failure into a lockout.
    if (!state.failuresByUser.empty() && now - state.lastFailureTime >= cfg.lockoutDuration)
    {
      state.failuresByUser.clear();
    }
    if (now < state.lockedUntil)
    {
      const auto clientText = describe(client);
      mLogger.warning({{"client", std::string_view{clientText}}, {"user_id", claimedUserId}},
        "Identity locked out ({} failed attempts)",
        state.failures());
      // A locked-out client application is answered Bad_IdentityTokenInvalid (the OPC 10000-4 7.41.2.1
      // identity-token error code, shared with the ordinary token-validation failure path), while a
      // wrong password is answered Bad_UserAccessDenied by the authenticator: the two ARE distinguishable
      // by status code. What the lockout does not leak is timing: the session routes this refusal
      // through the same constant-time hold as a validation failure (on_authenticator_completed), so
      // the client hears it no sooner than a wrong guess. Changing the lockout code to match the
      // authenticator's is an owner option; it would change the SDK's own lockout tests and the
      // conformance expectation P4_SS_0029.
      return StatusCode{Status::BadIdentityTokenInvalid};
    }
    // SESS-2: the budget counts attempts in flight as well as recorded failures, so N parallel guesses
    // cannot exceed the threshold. Spending the budget refuses without starting a lockout period; only a
    // recorded failure can start one.
    if (state.failures() + state.inFlight >= cfg.maxFailedAttemptsBeforeLockout)
    {
      const auto clientText = describe(client);
      mLogger.warning({{"client", std::string_view{clientText}}, {"user_id", claimedUserId}},
        "Identity attempt refused: budget spent ({} failed, {} in flight)",
        state.failures(),
        state.inFlight);
      return StatusCode{Status::BadIdentityTokenInvalid};
    }
    ++state.inFlight;
    return std::nullopt;
  }
  // First sight of this client application: bound the attacker-keyed map before reserving. An entry
  // with an attempt in flight reads as most recently active, so it is never the eviction victim.
  evict_lru_if_at_cap(mIdentityThrottleState,
    mMaxIdentityThrottleEntries,
    client,
    [now](const IdentityThrottleState& s) { return s.inFlight > 0 ? now : s.lastFailureTime; });
  ++mIdentityThrottleState[client].inFlight;
  return std::nullopt;
}

void ServerImpl::finish_identity_attempt(
  const ClientId& client, std::string_view claimedUserId, IdentityAttemptOutcome outcome)
{
  using Outcome = IdentityAttemptOutcome;
  const auto& cfg = mConfig.server.identityThrottling;
  if (!cfg.enabled)
    return;
  const WriteLock lk(mMutex);
  const auto now = std::chrono::steady_clock::now();
  if (outcome == Outcome::Failure)
  {
    // Opportunistic cleanup, on the failure path only (as before): remove idle entries whose lockout
    // has expired and whose last failure is stale. A success or an abandoned attempt pays one lookup.
    const auto staleThreshold = now - (cfg.lockoutDuration * 2);
    std::erase_if(mIdentityThrottleState,
      [&](const auto& entry)
      {
        return entry.second.inFlight == 0 && entry.second.lockedUntil < now &&
               entry.second.lastFailureTime < staleThreshold;
      });
  }
  auto it = mIdentityThrottleState.find(client);
  if (it == mIdentityThrottleState.end())
  {
    if (outcome != Outcome::Failure)
      return;  // nothing reserved and nothing to count
    // A failure recorded without a live reservation (the entry was cleaned up meanwhile) still counts.
    evict_lru_if_at_cap(mIdentityThrottleState,
      mMaxIdentityThrottleEntries,
      client,
      [now](const IdentityThrottleState& s) { return s.inFlight > 0 ? now : s.lastFailureTime; });
    it = mIdentityThrottleState.try_emplace(client).first;
  }
  auto& state = it->second;
  if (state.inFlight > 0)
    --state.inFlight;
  switch (outcome)
  {
  case Outcome::Abandoned:
    return;
  case Outcome::Success:
    // Only this user's failures are cleared: another user's guesses from the same client application
    // keep counting, and an active lockout period is never lifted by a success (Part 4 7.41.2.1).
    state.failuresByUser.erase(std::string{claimedUserId});
    return;
  case Outcome::Failure:
    break;
  }
  ++state.failuresByUser[std::string{claimedUserId}];
  state.lastFailureTime = now;
  if (state.failures() >= cfg.maxFailedAttemptsBeforeLockout)
  {
    state.lockedUntil = now + cfg.lockoutDuration;
    const auto clientText = describe(client);
    mLogger.warning({{"client", std::string_view{clientText}}, {"user_id", claimedUserId}},
      "Identity locked out for {}ms after {} failed attempts",
      cfg.lockoutDuration.count(),
      state.failures());
  }
}

void ServerImpl::set_log_level(LogLevel level)
{
  mLogLevel->store(level, std::memory_order_relaxed);
}

void ServerImpl::set_on_secure_channel_available(SecureChannelAvailableCallback callback)
{
  mOnSecureChannelAvailable = std::move(callback);
}

Logger ServerImpl::logger() const
{
  // Lock-free and race-free: mLogger is set once in the constructor (from the create()-time logSink)
  // and never reassigned - there is no runtime sink setter - so this needs no lock. That also matters
  // for correctness: logger() is reached on executor threads from paths that already hold mMutex
  // (create_session -> SecureChannel::send_response_message -> handler->logger()), and mMutex is a
  // non-recursive shared_mutex, so taking it here would deadlock.
  return mLogger;
}

void ServerImpl::initialise_listeners_from_config_for_tests()
{
  // Test helper: materialize configured listeners into runtime state without binding sockets.
  const auto listenerCfgs = mConfig.server.listeners();

  {
    const WriteLock lk(mMutex);
    mListeners.clear();
    mNextListenerHandle = 1;
  }

  for (const auto& listenerCfg : listenerCfgs)
  {
    auto options = listenerCfg.listenOptions;
    options.failIfAlreadyListening = false;
    const auto handle = configure_listener(listenerCfg.bind, options);

    const WriteLock lk(mMutex);
    auto it =
      std::ranges::find_if(mListeners, [&handle](const ListenerState& ls) { return ls.handle == handle; });
    if (it != mListeners.end())
    {
      it->name = listenerCfg.name;
      it->endpoints = listenerCfg.endpoints;
      if (listenerCfg.externalUrl)
      {
        it->advertisedUrls = {*listenerCfg.externalUrl};
      }
    }
  }
}

void ServerImpl::shutdown_async(ShutdownOptions params, Server::CompleteCallback callback)
{
  // ServerStatus.SecondsTillShutdown is a UInt32: a negative grace is an immediate shutdown, and a longer
  // one than it can carry is the longest it can.
  const auto requestedGrace =
    params.grace.value_or(std::chrono::seconds{mConfig.server.defaultShutdownGracePeriodSeconds}).count();
  const auto gracePeriod = static_cast<uint32_t>(std::clamp<std::chrono::seconds::rep>(
    requestedGrace, 0, std::chrono::seconds::rep{std::numeric_limits<uint32_t>::max()}));

  shared_ptr<StartupAttempt> cancelledStart;
  bool accepted = false;
  {
    // Startup and shutdown linearize through this same lock. In particular, shutdown cannot detach the
    // startup attempt between listener activation and the NoConfiguration -> Running transition.
    WriteLock lock(mMutex);
    if (mDynamicState->serverState.exchange(ServerState::Shutdown) != ServerState::Shutdown)
    {
      accepted = true;
      mShutdownCallback = std::move(callback);
      cancelledStart = std::exchange(mStartupAttempt, {});
      if (cancelledStart)
      {
        mStartupState = StartupState::Idle;
      }
    }
  }
  if (!accepted)
  {
    ua::detail::invoke_user_callback(mLogger,
      callback,
      VoidResult{Status::BadInvalidState,
        make_error_detail("ServerShutdownAlreadyStarted",
          "A shutdown operation has already claimed this server",
          "ServerImpl::shutdown_async")});
    return;
  }
  if (cancelledStart)
  {
    cancelledStart->complete(VoidResult{Status::BadShutdown,
      make_error_detail("ServerShutdownDuringStart",
        "Server shutdown cancelled the in-flight startup operation",
        "ServerImpl::shutdown_async")});
  }

  // Store shutdown reason under the dynamic state's own mutex (handlers read it there).
  {
    const std::unique_lock lk(mDynamicState->mutex);
    mDynamicState->shutdownReason = params.reason;
  }

  // Update atomics - ExternalValueSource handlers on address space nodes read these. server_state was
  // already set to Shutdown by the exchange in the single-shutdown guard above.
  mDynamicState->secondsTillShutdown.store(gracePeriod);
  mDynamicState->serviceLevel.store(0);

  mLogger.info({{"seconds_till_shutdown", std::to_string(gracePeriod)}}, "Server shutdown initiated");

  // Emit SystemStatusChangeEventType event (type NodeId = ns=0;i=11446).
  {
    GenericEvent event{NodeId{0, 11446U}};
    event.sourceNode = NodeId{ObjectId::Server};
    event.sourceName = String{"Server"};
    event.message = params.reason.text().empty() ? LocalizedText{"", "Server shutting down"} : params.reason;
    event.severity = 500;
    // SystemState property (NodeId ns=0;i=11696) - value is the ServerState enum as int32_t.
    event.set_field({QualifiedName{0, "SystemState"}}, Variant{int32_t{4}});  // Shutdown = 4
    mEventBus->emit(event);
  }

  // Notify observer.
  {
    auto eh = observer();
    detail::emit_event(mLogger, eh, [&] { eh->on_shutdown_initiated(gracePeriod, params.reason); });
  }

  // Stop accepting new connections.
  close_all_acceptors();

  // Check if there are connected clients.
  bool hasClients = false;
  {
    const ReadLock lk(mMutex);
    hasClients = !mSessions.empty() || !mSecureChannels.empty() || !mInitialisingConnections.empty();
  }

  if (gracePeriod > 0 && hasClients)
  {
    // Start countdown timer - decrement every second.
    auto me = weak_from_this();

    auto timer = Timer::schedule_every(mExecutor,
      std::chrono::seconds{1},
      [me](boost::system::error_code ec)
      {
        if (ec)
          return;
        auto self = me.lock();
        if (!self)
          return;

        auto remaining = self->mDynamicState->secondsTillShutdown.load();
        if (remaining <= 1)
        {
          self->mDynamicState->secondsTillShutdown.store(0);
          self->on_grace_period_expired();
        }
        else
        {
          self->mDynamicState->secondsTillShutdown.store(remaining - 1);
          self->mLogger.debug({}, "Shutdown countdown: {}s remaining", remaining - 1);
        }
      });

    // Store timer so it stays alive.
    const WriteLock lk(mMutex);
    mShutdownTimer = std::move(timer);
  }
  else
  {
    on_grace_period_expired();
  }
}

void ServerImpl::close_all_acceptors()
{
  const ReadLock lk(mMutex);
  for (auto& listener : mListeners)
  {
    if (listener.tcpTransportAcceptor)
    {
      listener.tcpTransportAcceptor->close_async();
      mLogger.debug({{"listener_name", std::string_view{listener.name}}}, "Listener closed for shutdown");
    }
  }
}

void ServerImpl::on_grace_period_expired()
{
  mLogger.info({}, "Executing final shutdown - closing sessions and channels");

  // Cancel countdown timer.
  {
    const WriteLock lk(mMutex);
    if (mShutdownTimer)
    {
      mShutdownTimer->cancel();
      mShutdownTimer.reset();
    }
  }

  // Stop reverse connect managers before closing channels. Wait for all managers to
  // stop before proceeding - this prevents a manager from delivering a new connection
  // while sessions and channels are being torn down.
  std::vector<ReverseConnectState> toStop;
  {
    const WriteLock lk(mMutex);
    toStop = std::exchange(mReverseConnects, {});

    for (const auto& rc : toStop)
    {
      std::erase_if(
        mListeners, [&](const ListenerState& ls) { return ls.handle == rc.syntheticListenerHandle; });
    }
  }

  if (!toStop.empty())
  {
    auto me = weak_from_this();
    auto remaining = std::make_shared<std::atomic<size_t>>(toStop.size());
    // Keep managers alive until all stop callbacks have fired.
    auto kept = std::make_shared<std::vector<ReverseConnectState>>(std::move(toStop));

    for (auto& rc : *kept)
    {
      rc.manager->stop_async(
        [me, remaining, kept](VoidResult)
        {
          if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
          {
            auto self = me.lock();
            if (!self)
              return;
            self->on_reverse_connects_stopped();
          }
        });
    }
    return;  // on_reverse_connects_stopped will pick up from here
  }

  on_reverse_connects_stopped();
}

void ServerImpl::on_reverse_connects_stopped()
{
  bool noActiveConnections = false;
  {
    const ReadLock lk(mMutex);
    noActiveConnections = mSessions.empty() && mSecureChannels.empty() && mInitialisingConnections.empty();
  }

  // Always run complete_shutdown so server-internal infrastructure (certificate
  // store refresh timer, reverse-connect managers, etc.) is torn down even when
  // there are no client connections to close. Skipping it leaves armed timers
  // that pin the io_context and prevent the thread pool from draining.
  complete_shutdown();

  if (noActiveConnections)
  {
    mLogger.info({}, "Shutdown complete (no active connections)");
    Server::CompleteCallback cb;
    {
      const WriteLock lk(mMutex);
      cb = std::move(mShutdownCallback);
    }
    report_shutdown_complete(std::move(cb));
    return;
  }

  // The existing remove_session/remove_secure_channel callbacks will fire as sessions/channels
  // are torn down. We use a delayed post to fire the completion callback - by the time the
  // executor runs this, the async teardown has had a chance to drain.
  auto me = weak_from_this();

  // Use a short delay to let strand-posted teardown complete.
  auto completionTimer = Timer::schedule_after(mExecutor,
    std::chrono::milliseconds{100},
    [me](boost::system::error_code)
    {
      auto self = me.lock();
      if (!self)
        return;

      self->mLogger.info({}, "Shutdown complete");
      Server::CompleteCallback cb;
      {
        const WriteLock lk(self->mMutex);
        cb = std::move(self->mShutdownCallback);
      }
      self->report_shutdown_complete(std::move(cb));
    });

  // Store timer to keep it alive.
  const WriteLock lk(mMutex);
  mShutdownTimer = std::move(completionTimer);
}

void ServerImpl::report_shutdown_complete(Server::CompleteCallback callback)
{
  // The application's event listener is cleared on the event bus strand first, so no event - not even
  // one already in flight - reaches it once shutdown has been reported complete; the application may
  // then destroy whatever the listener uses.
  auto finish = [logger = mLogger, eh = observer(), callback = std::move(callback)]() mutable
  {
    detail::emit_event(logger, eh, [&] { eh->on_shutdown_complete(); });
    if (callback)
    {
      callback(VoidResult{});
    }
  };
  if (mEventBus)
  {
    mEventBus->close_listener_async(std::move(finish));
    return;
  }
  finish();
}

void ServerImpl::complete_shutdown(std::function<void(VoidResult)> onNamespacesStopped)
{
  // Shut down the certificate stores (cancels their periodic refresh timers). A host-supplied
  // user-token store is shut down too: the server armed nothing on it, but leaving a store the
  // server published as DefaultUserTokenGroup live past shutdown keeps its refresh timer on an
  // executor that is going away.
  if (mDefaultApplicationGroupCertificateStore)
  {
    mDefaultApplicationGroupCertificateStore->shutdown();
  }
  if (mUserTokenCertificateStore)
  {
    mUserTokenCertificateStore->shutdown();
  }

  // Snapshot under the lock so that a pool thread completing an in-flight handshake
  // (e.g. via add_secure_channel) cannot reallocate any of these vectors while we
  // iterate them. We then iterate and call close()/terminate_for_shutdown() outside
  // the lock, because those calls post to other strands and we must not hold mMutex
  // across user-visible callbacks (and to avoid lock-ordering issues with the strand
  // work that may itself acquire mMutex via add_/remove_secure_channel).
  std::vector<shared_ptr<Session>> sessions;
  std::vector<shared_ptr<SecureChannel>> secureChannels;
  std::vector<shared_ptr<ConnectionProtocol>> initialisingConnections;
  {
    const WriteLock lk(mMutex);
    sessions.swap(mSessions);
    secureChannels.swap(mSecureChannels);
    initialisingConnections.swap(mInitialisingConnections);
    mSessionsByToken.clear();
    // Every connection the slot map describes is being torn down with the lists above; release the
    // per-IP slots with them (the attempt history stays for the rate limit).
    for (const auto& [connectionIdentity, key] : mConnectionRemoteIp)
    {
      release_per_ip_reservation_locked(key);
    }
    mConnectionRemoteIp.clear();
  }

  // Terminate sessions - posts to each session's strand, sets close reason to BadShutdown,
  // runs the close state machine which drains publish queues (sending ServiceFault for each
  // queued Publish request) and cancels session timeout timers.
  for (auto& session : sessions)
  {
    session->terminate_for_shutdown();
  }

  // Close any subscriptions still parked in the orphan store (orphaned by a CloseSession with
  // deleteSubscriptions=false and not yet transferred), cancelling their lifetime timers.
  mOrphanedSubscriptionStore.clear();

  // Close secure channels - this closes transport connections and cancels async operations.
  for (auto& sc : secureChannels)
  {
    sc->close();
  }

  // Close initialising connections. close_async posts to each CP's strand and
  // delegates to the transport, which cancels in-flight reads/writes via
  // socket.close(); those handlers capture weak_ptr<CP> internally (7.2) and
  // no-op cleanly if the CP is already gone. After this loop returns, the
  // local vector drops its refs; ~CP runs on the shutdown thread while the
  // CP's strand executor is still alive, so ~strand_impl deregisters cleanly.
  //
  // Do NOT extend each CP's lifetime by capturing it strongly into the
  // close_async callback - that would push ~CP into the queue of the socket's
  // executor (often a different execution_context from the CP's strand) and
  // produce a use-after-free on the CP's strand_executor_service during
  // teardown (7.5: long-lived components must not capture shared_ptr to
  // themselves into any callback).
  for (auto& cp : initialisingConnections)
  {
    cp->close_async();
  }

  // Finally the namespaces. A namespace that samples values, or refreshes a cache, keeps a timer
  // armed on THIS executor; joining an executor with work still on it never returns, and the
  // symptom is a process that will not exit with nothing in the log to say why. The certificate
  // stores above are stopped for exactly this reason - sampling was simply missing from the list.
  //
  // Asked LAST so nothing is still delivering samples into a subscription that is being closed,
  // and BOUNDED, because a namespace that never answers must not turn a hang at join() into a
  // hang at shutdown(). The default namespace answers inline; a custom one may take its own
  // strand's time.
  auto answered = std::make_shared<std::atomic<bool>>(false);
  // The logger is COPIED into this completion rather than reached through `this`, and that is not
  // tidiness. This completion is handed to every namespace and to the bounding timer below, so it
  // is answered by whoever gets there first - and one of those is `~NamespaceRegistrationCoordinator`,
  // which fires an outstanding request's callback when the last POSTED handler holding the
  // coordinator drops it. That handler runs on a strand turn after `~ServerImpl` has already
  // returned, so `this` is freed memory by the time the completion reads `mLogger`. A `Logger` is a
  // value holding shared ownership of its sink and its level, so a copy keeps both alive and still
  // logs correctly with the server gone.
  //
  // Found as a segmentation fault, not deduced: under a poisoning allocator the read faulted on the
  // poison pattern inside `Logger::is_enabled`, reached from this lambda through the coordinator's
  // destructor. @see ServerShutdownCompletionLifetimeTest
  auto deliver = [logger = mLogger, answered, onNamespacesStopped](VoidResult result)
  {
    if (answered->exchange(true))
    {
      return;  // whichever of the fan-out and the bound got here first has already answered
    }
    if (result.is_bad())
    {
      logger.error({{"status", ua::to_string(result.status_code())}},
        "A namespace did not stop its background work; the executor may not drain");
    }
    if (onNamespacesStopped)
    {
      onNamespacesStopped(result);
    }
  };

  if (onNamespacesStopped)
  {
    // Generous: a namespace stopping honestly is quick, and this only has to catch one that
    // never answers at all.
    constexpr auto namespaceShutdownBound = std::chrono::seconds{5};
    mNamespaceShutdownTimer = Timer::schedule_after(mExecutor,
      namespaceShutdownBound,
      [deliver](boost::system::error_code errorCode)
      {
        if (!errorCode)
        {
          deliver(VoidResult{StatusCode{Status::BadTimeout}});
        }
      });
  }
  // Conditions close before the namespaces stop, and the namespaces WAIT on that completion
  // rather than merely following it in program order. A condition instance arms timers on THIS
  // executor - shelving, re-alarm, branch upkeep - and the registry serialises its own state on a
  // strand of its own; left running they are work the executor never finishes, and the Runtime's
  // drain budget expires with BadTimeout naming nothing. That much is the same defect the
  // certificate stores and the namespaces were each fixed for.
  //
  // The waiting is the part that is easy to get wrong. Closing an instance removes its own subtree
  // from the address space (ConditionInstance::close_async -> remove_async), so a namespace that
  // has already stopped would be asked to mutate nodes it has released. Both sides are
  // asynchronous and the removal takes a further hop of its own, so initiating the close first and
  // stopping the namespaces immediately afterwards ordered nothing at all.
  //
  // Asked after sessions and channels are gone, so closing a condition cannot emit an event into a
  // subscription that is being torn down.
  //
  // The continuation holds a WEAK self-reference (7.2): a server destroyed while the close is in
  // flight must leave it doing nothing rather than touching a dead `this`, and ~ServerImpl already
  // delivers a terminal status to a caller still waiting. close_async delivers its completion
  // exactly once - its gone path fires too - so the namespaces cannot be stranded by a close that
  // silently disappears, and a close whose post never runs at all is bounded by the namespace timer
  // above, which answers the caller with BadTimeout.
  if (mConditions)
  {
    mConditions->close_async(
      [weakSelf = weak_from_this(), deliver](VoidResult)
      {
        if (auto self = weakSelf.lock())
        {
          self->mAddressSpace.shutdown_async(deliver);
        }
      });
  }
  else
  {
    mAddressSpace.shutdown_async(deliver);
  }
}

ServerImpl::~ServerImpl()
{
  mLogger.info("Server stopping");

  // Terminal delivery of any in-flight shutdown_async callback. If the user
  // dropped the Server handle mid-grace-period, the grace timer is still armed
  // and mShutdownCallback is still set; fire it once with BadServerHalted so
  // the single-shot contract holds even when the facade is destroyed before
  // grace expiry. Done first so the callback runs while the rest of teardown
  // (acceptors, sessions, channels) is still wired up - the user receives a
  // terminal status before observing any other teardown effects.
  Server::CompleteCallback shutdownCb;
  shared_ptr<StartupAttempt> startupAttempt;
  {
    const WriteLock lk(mMutex);
    if (mShutdownTimer)
    {
      mShutdownTimer->cancel();
      mShutdownTimer.reset();
    }
    shutdownCb = std::move(mShutdownCallback);
    startupAttempt = std::exchange(mStartupAttempt, {});
    if (startupAttempt)
    {
      mStartupState = StartupState::Idle;
    }
  }
  if (startupAttempt)
  {
    startupAttempt->complete(VoidResult{Status::BadShutdown,
      make_error_detail("ServerDestroyedDuringStart",
        "Server lifetime ended before startup completed",
        "ServerImpl::~ServerImpl")});
  }
  if (shutdownCb)
  {
    ua::detail::invoke_user_callback(mLogger, shutdownCb, VoidResult{Status::BadServerHalted});
  }

  // Stop reverse connect managers (fire-and-forget - the destructor must not block
  // on the thread pool because it may itself be running on a pool thread, which would
  // deadlock a single-threaded executor). The subsequent teardown below will terminate
  // any in-flight work on the managers' connections.
  for (auto& rc : mReverseConnects)
  {
    rc.manager->stop_async([](VoidResult) {});
  }
  mReverseConnects.clear();

  // Close TCP acceptors first to stop accepting new connections.
  close_all_acceptors();

  // Terminate sessions, close channels/connections, shut down certificate store,
  // and drop all strong references so the io_context can drain.
  complete_shutdown();

  mLogger.debug("ServerImpl destroyed");
}

AddressSpace& ServerImpl::address_space()
{
  return mAddressSpace;
}

boost::asio::any_io_executor ServerImpl::executor() const
{
  return mExecutor;
}

String ServerImpl::server_uri() const
{
  return mConfig.application->application_description_part().applicationUri;
}

ua::connection_protocol::Limits ServerImpl::connection_protocol_limits() const
{
  return mConfig.application->stack_limits().connectionProtocolLimits;
}

void ServerImpl::start_async(Server::CompleteCallback callback) noexcept
{
  // A caller that passes no callback still has the server started; a failure is logged instead.
  callback = ua::detail::completion_or_log(std::move(callback), mLogger, "Server::start_async");

  shared_ptr<StartupAttempt> attempt;
  try
  {
    attempt = make_shared<StartupAttempt>(std::move(callback), mLogger);
    std::optional<VoidResult> rejection;
    {
      const WriteLock lock(mMutex);
      if (mDynamicState->serverState.load() == ServerState::Shutdown)
      {
        rejection.emplace(Status::BadShutdown,
          make_error_detail("ServerShutdownDuringStart",
            "Server startup cannot begin after shutdown has started",
            "ServerImpl::start_async"));
      }
      else if (mStartupState != StartupState::Idle ||
               mDynamicState->serverState.load() != ServerState::NoConfiguration)
      {
        rejection.emplace(Status::BadInvalidState,
          make_error_detail("ServerStartNotIdle",
            "Server startup is already in progress or has completed",
            "ServerImpl::start_async"));
      }
      else
      {
        mStartupState = StartupState::PreparingMetadata;
        mStartupAttempt = attempt;
      }
    }
    if (rejection)
    {
      attempt->complete(std::move(*rejection));
      return;
    }

    auto continuation = ua::async::post_borrowing(this,
      mExecutor,
      mLogger,
      [attempt](ServerImpl& server, VoidResult result) mutable
      { server.on_start_metadata_prepared(attempt, std::move(result)); });
    ::ua::detail::AddressSpaceNamespaceLifecycle::prepare_installed_namespaces_async(
      mAddressSpace, std::move(continuation));
  }
  catch (...)
  {
    auto failure = VoidResult{::ua::exception_to_status_code(std::current_exception())};
    if (attempt)
    {
      finish_start_attempt(attempt, std::move(failure), StartupState::Idle);
      return;
    }
    ua::detail::invoke_user_callback(mLogger, callback, std::move(failure));
  }
}

void ServerImpl::on_start_metadata_prepared(
  const shared_ptr<StartupAttempt>& attempt, VoidResult result) noexcept
{
  if (result.is_bad())
  {
    finish_start_attempt(attempt, std::move(result), StartupState::Idle);
    return;
  }

  try
  {
    {
      const WriteLock lock(mMutex);
      if (mStartupAttempt != attempt)
      {
        return;
      }
      if (mStartupState != StartupState::PreparingMetadata)
      {
        result = VoidResult{Status::BadInvalidState,
          make_error_detail("ServerStartStateChanged",
            "Server startup state changed before namespace metadata preparation completed",
            "ServerImpl::start_async")};
      }
      else if (mDynamicState->serverState.load() == ServerState::Shutdown)
      {
        result = VoidResult{Status::BadShutdown,
          make_error_detail("ServerShutdownDuringStart",
            "Server shutdown started while namespace metadata was being prepared",
            "ServerImpl::start_async")};
      }
      else
      {
        mStartupState = StartupState::StartingNetwork;
      }
    }
    if (result.is_bad())
    {
      finish_start_attempt(attempt, std::move(result), StartupState::Idle);
      return;
    }

    start_network_surfaces(attempt);
  }
  catch (...)
  {
    finish_start_attempt(
      attempt, VoidResult{::ua::exception_to_status_code(std::current_exception())}, StartupState::Idle);
  }
}

void ServerImpl::finish_start_attempt(
  const shared_ptr<StartupAttempt>& attempt, VoidResult result, StartupState state) noexcept
{
  bool ownsAttempt = false;
  try
  {
    const WriteLock lock(mMutex);
    if (mStartupAttempt == attempt)
    {
      mStartupAttempt.reset();
      mStartupState = state;
      ownsAttempt = true;
    }
  }
  catch (...)
  {
    ua::async::detail::report_guarded_exception(mLogger, "ServerImpl::finish_start_attempt");
  }
  if (ownsAttempt)
  {
    attempt->complete(std::move(result));
  }
}

void ServerImpl::start_network_surfaces(const shared_ptr<StartupAttempt>& attempt)
{
  if (mOnNetworkActivationForTests)
  {
    mOnNetworkActivationForTests();
  }

  // Startup consistency check: warn (non-fatal) for any advertised ServerProfile whose required
  // feature is disabled in this configuration. Run at start() - the natural server-startup
  // checkpoint - rather than during model creation. The logger is whatever sink was passed to
  // create() (there is no runtime sink setter). The operator owns the profile list, so a partial
  // claim is a conformance warning, not a fatal error - surface it instead of silently advertising a
  // capability the server will not honour.
  for (const auto& inconsistency : find_advertised_profile_inconsistencies(mConfig.server))
  {
    mLogger.with_category("server").warning({{"profile", inconsistency.profileUri},
                                              {"feature", inconsistency.feature},
                                              {"disabled_setting", inconsistency.disabledSetting}},
      "Advertised ServerProfile claims a feature that is disabled in this configuration");
  }

  // Materialize configured listeners (configuration-time only; no binding here).
  // DEF-3: the two admission limits are consecutive gates (reject, then evict); configured equal or
  // inverted, the evicting gate Part 4 5.5.2.1 requires is never reached. A warning, not a refusal:
  // tests and some deployments choose the connection limit as the refusal point on purpose.
  if (mConfig.server.maxConnections && mConfig.server.maxSecureChannels &&
      *mConfig.server.maxConnections <= *mConfig.server.maxSecureChannels)
  {
    mLogger.with_category("server").warning(
      {{"max_connections", uint64_t{*mConfig.server.maxConnections}},
        {"max_secure_channels", uint64_t{*mConfig.server.maxSecureChannels}}},
      "MaxConnections is not above MaxSecureChannels: the secure-channel eviction gate is unreachable");
  }

  for (const auto& listenerCfg : mConfig.server.listeners())
  {
    auto options = listenerCfg.listenOptions;
    options.failIfAlreadyListening = false;
    const auto handle = configure_listener(listenerCfg.bind, options);
    for (const auto& endpoint : listenerCfg.endpoints)
    {
      if (auto policy = SecurityPolicy::create(endpoint.securityPolicyId); policy->is_deprecated())
      {
        mLogger.warning(
          {{"security_policy", std::string_view{policy->uri()}}, {"listener", listenerCfg.name}},
          "Deprecated security policy declared in configuration - AllowDeprecatedSecurityPolicies is "
          "enabled");
      }
    }

    const WriteLock lk(mMutex);
    auto it =
      std::ranges::find_if(mListeners, [&handle](const ListenerState& ls) { return ls.handle == handle; });
    if (it != mListeners.end())
    {
      it->name = listenerCfg.name;
      it->endpoints = listenerCfg.endpoints;
      if (listenerCfg.externalUrl)
      {
        it->advertisedUrls = {*listenerCfg.externalUrl};
      }
    }
  }

  // The certificate list the endpoint validation needs. Gathering the endpoints is synchronous;
  // FETCHING is not, and that is the whole point of the split. The old code called
  // try_get_application_certificates_sync() right here, on the strand, and blocked the one worker
  // that could have completed the fetch, so the start never finished.
  std::vector<ServerEndpointConfig> allEndpoints;
  {
    ReadLock lk(mMutex);
    for (const auto& listener : mListeners)
    {
      allEndpoints.insert(allEndpoints.end(), listener.endpoints.begin(), listener.endpoints.end());
    }
  }

  // Fast path kept deliberately: an endpoint set that needs no certificate must not gain a post.
  // Starting a server with no security is the common embedded case and stays entirely synchronous.
  if (!mDefaultApplicationGroupCertificateStore || required_certificate_types(allEndpoints).empty())
  {
    continue_start_network_surfaces(attempt, allEndpoints, {});
    return;
  }

  auto continuation = ua::async::post_borrowing(this,
    mExecutor,
    mLogger,
    [attempt, allEndpoints](
      ServerImpl& server, CertificateStore::ApplicationCertificateListResult certificates) mutable
    {
      if (!certificates.is_good())
      {
        // The server starts only on certificates the store answered Good: an Uncertain answer is refused
        // with Bad_InternalError, its refusal (CertificateStoreAnswerUncertain) the detail's cause.
        const StatusCode failure = ua::security_internal::not_good_store_answer(
          certificates.status_code(), Status::BadInternalError, "ServerImpl::start_async");
        const std::shared_ptr<const ErrorDetail> refusal =
          certificates.is_bad() ? nullptr : failure.shared_detail();
        server.finish_start_attempt(attempt,
          VoidResult{failure,
            make_error_detail("CertificateStoreError",
              "Failed to retrieve application certificates from the store",
              "ServerImpl::start_async",
              refusal)},
          StartupState::Idle);
        return;
      }
      // Internal F: a server whose own certificate violates a served endpoint's SecurityPolicy does not
      // start (Bad_ConfigurationError naming the endpoint and the rule).
      if (!server.mBypassOwnCertificatePolicyCheckForTests)
      {
        const auto compliance = check_own_certificates_for_endpoints(allEndpoints, certificates.value());
        if (compliance.is_bad())
        {
          server.finish_start_attempt(attempt, compliance, StartupState::Idle);
          return;
        }
      }
      server.continue_start_network_surfaces(attempt, allEndpoints, certificates.value());
    });
  mDefaultApplicationGroupCertificateStore->get_application_certificates_async(std::move(continuation));
}

void ServerImpl::continue_start_network_surfaces(const shared_ptr<StartupAttempt>& attempt,
  const std::vector<ServerEndpointConfig>& endpoints,
  const std::vector<CertificateStore::ApplicationCertificate>& available) noexcept
{
  try
  {
    // Re-checked after the suspension point: the fetch is the one place this path can be
    // overtaken, and binding acceptors for an attempt that has already been abandoned would leak
    // listening sockets that no rollback owns. INSIDE the try: this function is noexcept, and a
    // throwing lock acquisition outside it would call std::terminate rather than fail the start.
    {
      const ReadLock lock(mMutex);
      if (mStartupAttempt != attempt)
      {
        return;
      }
    }

    // Preserves the pre-split validator's early return on a null store. Reachable only by an
    // internal caller: create() substitutes a default CertificateStoreFiles when none is supplied,
    // so through the public factory this member is never null and the branch never taken. Kept
    // because the guard is what makes the pure validator's contract match the old one - without
    // it, a null store would report every required type as missing and throw.
    if (mDefaultApplicationGroupCertificateStore)
    {
      validate_endpoint_certificates(endpoints, available);
    }

    // Populate HistoryServerCapabilities from registered namespace delegates. Awaited, never waited
    // on: the population's lookups and writes may be answered by a post to the executor this strand
    // runs on. Listener activation resumes on it once the population is done.
    ServerModel::populate_history_capabilities_async(mAddressSpace,
      mConfig.server.historyConfiguration,
      mConfig.server.server_capabilities(),
      ua::async::post_borrowing(this,
        mExecutor,
        mLogger,
        [attempt](ServerImpl& server, VoidResult populated) mutable
        { server.activate_listeners(attempt, std::move(populated)); }));
  }
  catch (...)
  {
    finish_start_attempt(
      attempt, VoidResult{::ua::exception_to_status_code(std::current_exception())}, StartupState::Idle);
  }
}

void ServerImpl::activate_listeners(const shared_ptr<StartupAttempt>& attempt, VoidResult populated) noexcept
{
  bool startupCommitted = false;
  try
  {
    if (populated.is_bad())
    {
      finish_start_attempt(attempt, std::move(populated), StartupState::Idle);
      return;
    }
    // Re-checked after this second suspension point, for the reason given before the first.
    {
      const ReadLock lock(mMutex);
      if (mStartupAttempt != attempt)
      {
        return;
      }
    }

    auto me = this->weak_from_this();

    struct ListenerActivationSnapshot
    {
      ListenerHandle handle;
      ua::transport::BindAddress boundBind;
      std::optional<TcpEndpoint> boundEndpoint;
      std::vector<ua::transport::EndpointUrl> advertisedUrls;
    };

    std::vector<ListenerActivationSnapshot> snapshots;
    std::vector<shared_ptr<TcpTransportAcceptor>> rollbackAcceptors;
    std::vector<std::pair<std::string, std::string>> startedListeners;
    {
      WriteLock lock(mMutex);
      snapshots.reserve(mListeners.size());
      rollbackAcceptors.reserve(mListeners.size());
      startedListeners.reserve(mListeners.size());

      try
      {
        for (auto& listener : mListeners)
        {
          if (listener.tcpTransportAcceptor)
          {
            continue;
          }

          snapshots.push_back(ListenerActivationSnapshot{
            listener.handle, listener.boundBind, listener.boundEndpoint, listener.advertisedUrls});

          const auto ipEndpoint = ua::detail::to_asio(listener.endpoint);
          const auto listenerHandle = listener.handle;
          const auto listenerName = listener.name;
          listener.tcpTransportAcceptor = TcpTransportAcceptor::create(
            mExecutor,
            ipEndpoint,
            [me, listenerHandle, listenerName](
              StatusCode status, string_view errorDescription, shared_ptr<TcpTransportConnection> connection)
            {
              auto server = me.lock();
              if (server)
              {
                try
                {
                  server->new_tcp_connection(
                    listenerHandle, listenerName, status, errorDescription, connection);
                }
                catch (...)
                {
                  auto error = ::ua::exception_to_status_code(std::current_exception());
                  const auto statusCode = error;
                  log_exception(server->mLogger, LogLevel::Error, "new_tcp_connection", error);
                  const auto statusHex = fmt::format("0x{:08x}", statusCode.as_uint32());
                  const auto description =
                    error.shared_detail()
                      ? fmt::format("ServerImpl::new_tcp_connection: {}", to_string(*error.shared_detail()))
                      : fmt::format("ServerImpl::new_tcp_connection: {}", statusHex);
                  auto observerHandle = server->observer();
                  detail::emit_event(server->mLogger,
                    observerHandle,
                    [&] { observerHandle->on_internal_error(statusCode, description); });
                }
              }
            },
            mLogger.with_category("transport"),
            mConfig.server.resourceLimits.writeQueueDepthPerConnection,
            mConfig.server.resourceLimits.writeQueueBytesPerConnection);

          listener.boundEndpoint = ua::detail::from_asio(listener.tcpTransportAcceptor->get_local_endpoint());

          if (listener.boundEndpoint)
          {
            listener.boundBind.transportProfileId = listener.transportProfileId;
            listener.boundBind.address = to_bind_address_string(*listener.boundEndpoint);
          }

          if (listener.advertisedUrls.empty())
          {
            // Best-effort default advertisement.
            listener.advertisedUrls.push_back(derive_opc_tcp_advertised_url(listener.boundBind));
          }

          startedListeners.emplace_back(listener.name, listener.boundBind.address);
        }
      }
      catch (...)
      {
        const auto failure = std::current_exception();
        for (auto& snapshot : snapshots)
        {
          auto listener = std::ranges::find_if(
            mListeners, [&snapshot](const ListenerState& item) { return item.handle == snapshot.handle; });
          if (listener == mListeners.end())
          {
            continue;
          }
          if (listener->tcpTransportAcceptor)
          {
            rollbackAcceptors.push_back(std::move(listener->tcpTransportAcceptor));
          }
          listener->boundBind = std::move(snapshot.boundBind);
          listener->boundEndpoint = snapshot.boundEndpoint;
          listener->advertisedUrls = std::move(snapshot.advertisedUrls);
        }
        lock.unlock();
        for (auto& acceptor : rollbackAcceptors)
        {
          acceptor->close_async();
        }
        std::rethrow_exception(failure);
      }
    }

    for (const auto& [listenerName, bindAddress] : startedListeners)
    {
      mLogger.info(
        {{"listener_name", std::string_view{listenerName}}, {"bind_address", std::string_view{bindAddress}}},
        "Listener started");
    }

    bool committed = false;
    ServerState observedState{ServerState::NoConfiguration};
    {
      const WriteLock lock(mMutex);
      if (mStartupAttempt != attempt)
      {
        return;
      }
      observedState = ServerState::NoConfiguration;
      committed = mDynamicState->serverState.compare_exchange_strong(observedState, ServerState::Running);
      if (committed)
      {
        mDynamicState->startTime = DateTime::now();
        mDynamicState->serviceLevel.store(255);
        mStartupState = StartupState::Started;
        mStartupAttempt.reset();
      }
    }

    if (!committed)
    {
      close_all_acceptors();
      auto failure = observedState == ServerState::Shutdown
                       ? VoidResult{Status::BadShutdown,
                           make_error_detail("ServerShutdownDuringStart",
                             "Server shutdown won the lifecycle transition before startup completed",
                             "ServerImpl::start_async")}
                       : VoidResult{Status::BadInvalidState,
                           make_error_detail("ServerStateChangedDuringStart",
                             "Server state changed before startup could enter Running",
                             "ServerImpl::start_async")};
      finish_start_attempt(attempt, std::move(failure), StartupState::Idle);
      return;
    }
    startupCommitted = true;

    for (const auto& reverseTarget : mConfig.server.reverseConnectTargets)
    {
      try
      {
        start_reverse_connect_async(reverseTarget,
          [logger = mLogger](ReverseConnectHandleResult reverseResult)
          {
            if (reverseResult.is_bad())
            {
              logger.error({{"status", to_string(reverseResult.status_code())}},
                "Configured reverse connect target failed to start");
            }
          });
      }
      catch (...)
      {
        log_exception(mLogger, "Configured reverse connect target failed to start", std::current_exception());
      }
    }

    mLogger.info("Server started");
    attempt->complete(VoidResult{});
  }
  catch (...)
  {
    if (startupCommitted)
    {
      log_exception(mLogger, "Server post-start activation", std::current_exception());
      attempt->complete(VoidResult{});
      return;
    }
    finish_start_attempt(
      attempt, VoidResult{::ua::exception_to_status_code(std::current_exception())}, StartupState::Idle);
  }
}

void ServerImpl::listen_async(TransportProfileId transportProfileId, string_view hostname, uint16_t port,
  ListenOptions options, ListenCompleteManyCallback callback)
{
  auto resolver = Resolver::create(mExecutor, options.timeout);

  auto me = weak_from_this();

  resolver->resolve_endpoints_async(hostname,
    port,
    {},
    [me, resolver, transportProfileId, options, cb = std::move(callback)](EndpointListResult result) mutable
    {
      UA_UNUSED(resolver);

      if (!result)
      {
        cb(result.status_code());
        return;
      }

      auto server = me.lock();
      if (!server)
      {
        cb(StatusCode{Status::BadInvalidState});
        return;
      }

      auto endpoints = std::move(result).value();
      ListenerHandleList handles;

      try
      {
        handles.reserve(endpoints.size());
        for (const auto& endpoint : endpoints)
        {
          ua::transport::BindAddress bind;
          bind.transportProfileId = transportProfileId;
          bind.address = to_bind_address_string(endpoint);
          handles.push_back(server->configure_listener(std::move(bind), options));
        }
      }
      catch (...)
      {
        cb(::ua::exception_to_status_code(std::current_exception()));
        return;
      }

      cb(std::move(handles));
    });
}

ListenerHandle ServerImpl::configure_listener(ua::transport::BindAddress bindAddress, ListenOptions options)
{
  if (bindAddress.transportProfileId != TransportProfileId::UaTcpUaScUaBinary)
  {
    throw UaException{Status::BadNotSupported,
      ErrorDetail::build(
        "UnsupportedTransportProfile", "Only UaTcpUaScUaBinary transport profile is supported", "ServerImpl")
        .context(
          ua::ContextKeys::typeName, std::to_string(utils::to_underlying(bindAddress.transportProfileId)))};
  }

  const auto endpoint = TcpEndpoint::from_string(bindAddress.address);

  const WriteLock lk(mMutex);

  if (auto it = std::ranges::find_if(mListeners,
        [&bindAddress](const ListenerState& listener) { return listener.requestedBind == bindAddress; });
      it != mListeners.end())
  {
    if (options.failIfAlreadyListening)
    {
      throw UaException{Status::BadAlreadyExists,
        ErrorDetail::build("ListenerAlreadyExists", "Listener for bind address already exists", "ServerImpl")
          .context(ua::ContextKeys::endpointAddress, bindAddress.address)};
    }

    return it->handle;
  }

  ListenerState listener;
  listener.handle = ListenerHandle{mNextListenerHandle++};
  listener.requestedBind = std::move(bindAddress);
  listener.transportProfileId = listener.requestedBind.transportProfileId;
  listener.endpoint = endpoint;
  listener.boundEndpoint = std::nullopt;
  listener.boundBind = listener.requestedBind;
  listener.listenOptions = options;
  listener.tcpTransportAcceptor = nullptr;
  listener.endpoints = {};
  listener.advertisedUrls = {};
  const auto handle = listener.handle;
  mListeners.push_back(std::move(listener));

  return handle;
}

void ServerImpl::listen_async(
  ua::transport::BindAddress bindAddress, ListenOptions options, ListenCompleteOneCallback callback)
{
  try
  {
    auto handle = configure_listener(std::move(bindAddress), options);
    callback(handle);
  }
  catch (...)
  {
    callback(::ua::exception_to_status_code(std::current_exception()));
  }
}

void ServerImpl::new_tcp_connection(ListenerHandle listener, std::string listenerName, StatusCode status,
  string_view errorDescription, shared_ptr<TcpTransportConnection> connection)
{
  UA_UNUSED(errorDescription);
  const auto remote =
    (status.is_good() && connection) ? connection->get_remote_endpoint() : asio::ip::tcp::endpoint{};
  accept_tcp_connection(listener, std::move(listenerName), status, std::move(connection), remote);
}

void ServerImpl::accept_tcp_connection(ListenerHandle listener, std::string listenerName, StatusCode status,
  shared_ptr<TcpTransportConnection> connection, const asio::ip::tcp::endpoint& remote)
{
  if (status.is_good() && connection)
  {
    // Reject new connections during shutdown.
    if (mDynamicState->serverState.load() == ServerState::Shutdown)
    {
      auto remoteAddr = to_bind_address_string(remote);
      connection->close_async();
      auto eh = observer();
      detail::emit_event(mLogger,
        eh,
        [&] {
          eh->on_connection_closed(remoteAddr, ConnectionCloseReason::ServerShutdown, Status::BadShutdown);
        });
      return;
    }

    auto remoteAddr = to_bind_address_string(remote);
    auto remoteIp =
      connection_throttle_key(remote.address(), mConfig.server.connectionThrottling.ipv6PrefixLength);

    mLogger.debug({{"listener_name", std::string_view{listenerName}}}, "TCP connection accepted");

    // Emit connection accepted BEFORE taking any mutex.
    auto eh = observer();
    detail::emit_event(mLogger, eh, [&] { eh->on_connection_accepted(remoteAddr); });

    // MaxConnections is applied at accept as well, before the ConnectionProtocol (its strand, timers
    // and read buffer) exists: a flood of sockets that never send HEL costs two container sizes each
    // here instead of a handshake's resources until its timeout. The post-ACK gate in
    // new_connection_complete stays, because the count moves during the handshake.
    if (const auto maxConnections = mConfig.server.maxConnections; maxConnections.has_value())
    {
      size_t currentConnections = 0;
      {
        const ReadLock lk(mMutex);
        currentConnections = mInitialisingConnections.size() + mSecureChannels.size();
      }
      if (currentConnections >= *maxConnections)
      {
        if (mDiagnosticsEnabled->load(std::memory_order_relaxed))
        {
          mConnectionCounters->rejectedCount.fetch_add(1, std::memory_order_relaxed);
        }
        mLogger.warning({{"listener_name", std::string_view{listenerName}},
                          {"remote_address", std::string_view{remoteAddr}}},
          "MaxConnections limit reached ({}/{}) at accept, closing the connection",
          currentConnections,
          *maxConnections);
        // Nothing has been negotiated yet, so there is no ERR to answer with (the shape the per-IP
        // throttle refusal below has as well); the socket is closed at once.
        connection->close_async();
        detail::emit_event(mLogger,
          eh,
          [&]
          {
            eh->on_connection_closed(
              remoteAddr, ConnectionCloseReason::MaxConnections, Status::BadMaxConnectionsReached);
          });
        return;
      }
    }

    // S10: Per-IP connection throttling.
    const auto& throttleCfg = mConfig.server.connectionThrottling;
    if (throttleCfg.enabled)
    {
      enum class Refusal
      {
        None,
        TrackedEndpoints,
        ConnectionsPerEndpoint,
        AttemptRate
      };
      auto refusal = Refusal::None;
      {
        const WriteLock lk(mMutex);
        // Bound the attacker-keyed map: at cap, evict the IP with the oldest last attempt among those
        // holding no live connection. An entry with a live connection holds that connection's slot, so
        // replacing it would let the address reconnect past its limit and its release miscount; when
        // every entry is live, the untracked address is refused instead.
        const auto lastAttempt = [](const PerIpState& s)
        {
          return s.recentAttempts.empty() ? std::chrono::steady_clock::time_point::min()
                                          : s.recentAttempts.back();
        };
        const auto holdsNoConnection = [](const PerIpState& s)
        {
          return s.activeCount == 0;
        };
        const bool tracked = evict_lru_if_at_cap(
          mPerIpState, mMaxPerIpThrottleEntries, remoteIp, lastAttempt, holdsNoConnection);
        if (!tracked)
        {
          refusal = Refusal::TrackedEndpoints;
        }
        else
        {
          auto& ipState = mPerIpState[remoteIp];
          auto now = std::chrono::steady_clock::now();

          // Prune attempts older than 60 seconds.
          std::erase_if(
            ipState.recentAttempts, [&](const auto& t) { return (now - t) > std::chrono::seconds{60}; });

          // Only the newest maxConnectionAttemptsPerMinute attempts can decide the verdict below, so older
          // ones are dropped: a peer connecting at a high rate would otherwise grow the list, and this scan
          // under the write lock, with every attempt in the window.
          ipState.recentAttempts.push_back(now);
          if (ipState.recentAttempts.size() > throttleCfg.maxConnectionAttemptsPerMinute)
            ipState.recentAttempts.erase(ipState.recentAttempts.begin(),
              ipState.recentAttempts.end() -
                static_cast<std::ptrdiff_t>(throttleCfg.maxConnectionAttemptsPerMinute));

          if (ipState.activeCount >= throttleCfg.maxConnectionsPerEndpoint)
          {
            refusal = Refusal::ConnectionsPerEndpoint;
          }
          else if (ipState.recentAttempts.size() >= throttleCfg.maxConnectionAttemptsPerMinute)
          {
            refusal = Refusal::AttemptRate;
          }
          else
          {
            ipState.activeCount++;
            // The slot's owner is recorded in the same locked step, keyed by the transport (which exists
            // now, before the protocol), so every release path finds it whatever it interleaves with.
            mConnectionRemoteIp[connection.get()] = remoteIp;
          }
        }
      }

      // Logged after the lock is released: the configured LogSink is application code, and may call
      // back into the server.
      switch (refusal)
      {
      case Refusal::None:
        break;
      case Refusal::TrackedEndpoints:
        mLogger.warning({{"remote_ip", std::string_view{remoteIp}}},
          "Per-IP connection throttle is tracking its maximum of {} addresses, each with a live connection",
          mMaxPerIpThrottleEntries);
        break;
      case Refusal::ConnectionsPerEndpoint:
        mLogger.warning({{"remote_ip", std::string_view{remoteIp}}},
          "Per-IP connection limit reached ({})",
          throttleCfg.maxConnectionsPerEndpoint);
        break;
      case Refusal::AttemptRate:
        mLogger.warning({{"remote_ip", std::string_view{remoteIp}}},
          "Per-IP connection rate limit exceeded ({}/min)",
          throttleCfg.maxConnectionAttemptsPerMinute);
        break;
      }
      if (refusal != Refusal::None)
      {
        if (mDiagnosticsEnabled->load(std::memory_order_relaxed))
        {
          mConnectionCounters->rejectedCount.fetch_add(1, std::memory_order_relaxed);
        }
        // Close the raw TCP connection immediately - no HEL/ACK or backoff delay at this layer.
        connection->close_async();
        return;
      }
    }

    auto me = this->weak_from_this();

    const weak_ptr<ConnectionProtocolDependencies> deps{
      std::static_pointer_cast<ConnectionProtocolDependencies>(mDependencies)};

    // The completion callback below fires only on success (ConnectionProtocol's single-fire contract);
    // the close observer is the failure-side delivery that releases what this accept reserved. Both
    // may run before the entry is published (create() starts the protocol's I/O), so they record the
    // outcome in the slot and the publication step below honours it.
    auto slot = std::make_shared<InitialisingSlot>();
    auto closeObserver = [me, slot, observedRemoteAddr = remoteAddr](StatusCode closeStatus, string_view)
    {
      if (auto server = me.lock())
      {
        server->initialising_connection_failed(slot, closeStatus, observedRemoteAddr);
      }
    };

    // The slot reserved above is keyed by the transport, which this function owns until the
    // protocol is published. A throw before then (the protocol's creation, the test hook) would
    // leave the slot with a transport that is about to be freed, so it is released on that path.
    struct SlotGuard
    {
      SlotGuard(ServerImpl& owner, const TransportConnection* acceptedTransport,
        std::shared_ptr<InitialisingSlot> initialSlot) noexcept
        : server(owner), transport(acceptedTransport), slot(std::move(initialSlot))
      {}

      SlotGuard(const SlotGuard&) = delete;
      SlotGuard& operator=(const SlotGuard&) = delete;
      SlotGuard(SlotGuard&&) = delete;
      SlotGuard& operator=(SlotGuard&&) = delete;

      ServerImpl& server;
      const TransportConnection* transport;
      std::shared_ptr<InitialisingSlot> slot;
      bool armed{true};

      ~SlotGuard()
      {
        if (armed)
        {
          const WriteLock lk(server.mMutex);
          // A handshake that completed inside the call has handed the slot to new_connection_complete
          // (held by the channel, or already released by a refusal): it is not this guard's to release.
          if (slot->outcome != InitialisingSlot::Outcome::Completed)
          {
            server.decrement_per_ip_count_locked(transport);
          }
        }
      }
    } slotGuard{*this, connection.get(), slot};

    auto cp = ConnectionProtocol::create(
      ConnectionProtocolRole::Server,
      deps,
      connection,
      false,
      mConfig.application->stack_limits().connectionProtocolTimeout,
      [me, slot, listener, listenerName = std::move(listenerName), remoteAddr = remoteAddr](
        StatusCode cpStatus,
        shared_ptr<ConnectionProtocol>
          completedCp,
        ua::connection_protocol::NegotiatedLimits negotiatedLimits,
        std::optional<ua::detail::ReverseHelloMessage> /*reverseHello*/)
      {
        auto server = me.lock();
        if (server)
        {
          {
            // A completion that lands before publication must not be followed by a stale entry.
            const WriteLock lk(server->mMutex);
            if (slot->connection == nullptr)
            {
              slot->outcome = InitialisingSlot::Outcome::Completed;
            }
          }
          server->new_connection_complete(
            listener, listenerName, cpStatus, completedCp, negotiatedLimits, remoteAddr);
        }
      },
      [me](StatusCode errorStatus, string_view description, FatalCloseDisposition)
      {
        // CP errors are client protocol violations (bad HEL, wrong message type, etc.),
        // not internal SDK errors. The connection is already being closed.
        auto server = me.lock();
        if (!server)
          return;
        server->mLogger.warning({{"status", fmt::format("0x{:08x}", errorStatus.as_uint32())}},
          "ConnectionProtocol error: {}",
          description);
      },
      {},
      [me, listener](string_view endpointUrl)
      {
        auto server = me.lock();
        if (!server)
        {
          return false;
        }

        auto incoming = transport::parse_opc_tcp_url(std::string{endpointUrl}, "ConnectionProtocol");
        if (!incoming)
        {
          return false;
        }

        const ReadLock lk(server->mMutex);
        const auto it = std::ranges::find_if(
          server->mListeners, [&](const ListenerState& ls) { return ls.handle == listener; });
        if (it == server->mListeners.end())
        {
          return false;
        }

        // Part 6, 7.1.2.3: accept if the URL identifies the same resource (port + path).
        // The hostname is not checked - if the TCP connection arrived on this listener,
        // the host already resolved correctly.
        for (const auto& adv : it->advertisedUrls)
        {
          auto advertised = transport::parse_opc_tcp_url(adv.str(), "ConnectionProtocol");
          if (advertised && transport::matches_port_and_path(incoming.value(), advertised.value()))
          {
            return true;
          }
        }
        return false;
      },
      mConfig.application->stack_limits().connectionProtocolMessageReadTimeout,
      /*serverUri=*/{},
      /*reverseHelloValidator=*/{},
      std::move(closeObserver));

    if (mBeforeInitialisingPublicationForTests)
    {
      mBeforeInitialisingPublicationForTests();
    }

    std::optional<StatusCode> failedBeforePublication;
    {
      const WriteLock lk(mMutex);
      switch (slot->outcome)
      {
      case InitialisingSlot::Outcome::Pending:
        slot->connection = cp.get();
        mInitialisingConnections.push_back(cp);
        break;
      case InitialisingSlot::Outcome::Failed:
        // The handshake already failed on the protocol's strand: nothing to publish; the close
        // observer found no initialising entry to release, so the slot is released here.
        failedBeforePublication = slot->status;
        decrement_per_ip_count_locked(connection.get());
        break;
      case InitialisingSlot::Outcome::Completed:
        // The handshake completed inside this call. The slot is keyed by the transport since the
        // reservation, so new_connection_complete has already either released it (a refusal) or left
        // it with the channel that holds the connection (released when that channel is removed).
        break;
      }
      // Published: from here the initialising entry, the channel or the refusal path owns the slot.
      slotGuard.armed = false;
    }
    // `remoteAddr` is still this function's own: the completion lambda above holds a copy.
    if (failedBeforePublication)
    {
      auto closeSink = observer();
      detail::emit_event(mLogger,
        closeSink,
        [&]
        {
          closeSink->on_connection_closed(
            remoteAddr, ConnectionCloseReason::ProtocolError, *failedBeforePublication);
        });
    }
  }
}

std::optional<std::string> ServerImpl::reverse_target_name_for(ListenerHandle listener) const
{
  const ReadLock lk(mMutex);
  for (const auto& rc : mReverseConnects)
  {
    if (rc.syntheticListenerHandle == listener)
      return rc.targetName;
  }
  return std::nullopt;
}

void ServerImpl::new_connection_complete(ListenerHandle listener, std::string listenerName, StatusCode status,
  shared_ptr<ConnectionProtocol> connection, ua::connection_protocol::NegotiatedLimits negotiatedLimits,
  std::string remoteAddress)
{
  if (status.is_good())
  {
    {
      const WriteLock lk(mMutex);
      const auto it = std::ranges::find(mInitialisingConnections, connection);
      if (it != mInitialisingConnections.end())
      {
        mInitialisingConnections.erase(it);
      }
    }

    // Reject connections that completed handshake during shutdown.
    if (mDynamicState->serverState.load() == ServerState::Shutdown)
    {
      {
        const WriteLock lk(mMutex);
        decrement_per_ip_count_locked(connection->transport_identity());
      }
      connection->send_error(Status::BadShutdown, "Server shutting down");
      connection->close_async();
      auto eh = observer();
      detail::emit_event(mLogger,
        eh,
        [&] {
          eh->on_connection_closed(remoteAddress, ConnectionCloseReason::ServerShutdown, Status::BadShutdown);
        });
      return;
    }

    const auto maxConnections = mConfig.server.maxConnections;
    if (maxConnections.has_value())
    {
      size_t currentConnections = 0;
      {
        const ReadLock lk(mMutex);
        // Initialising connections have already been removed above, so count only established channels +
        // remaining initialising handshakes.
        currentConnections = mInitialisingConnections.size() + mSecureChannels.size();
      }

      if (currentConnections >= *maxConnections)
      {
        // MaxConnections is the hard TCP-level admission ceiling (a DoS backstop): when it is reached
        // the connection is rejected outright. The Errata-1.02.2 "reclaim unused SecureChannels"
        // behaviour belongs to the SecureChannel layer below (MaxSecureChannels eviction); deployments
        // that need clobbering set MaxConnections above MaxSecureChannels so that layer governs.
        if (mDiagnosticsEnabled->load(std::memory_order_relaxed))
        {
          mConnectionCounters->rejectedCount.fetch_add(1, std::memory_order_relaxed);
        }

        {
          const WriteLock lk(mMutex);
          decrement_per_ip_count_locked(connection->transport_identity());
        }

        mLogger.warning({{"remote_address", std::string_view{remoteAddress}}},
          "MaxConnections limit reached ({}/{}), rejecting connection",
          currentConnections,
          *maxConnections);
        connection->send_error(Status::BadMaxConnectionsReached, "Max connections reached");
        connection->close_async();

        auto eh = observer();
        detail::emit_event(mLogger,
          eh,
          [&]
          {
            eh->on_connection_closed(
              remoteAddress, ConnectionCloseReason::MaxConnections, Status::BadMaxConnectionsReached);
          });
        return;
      }
    }

    if (mDiagnosticsEnabled->load(std::memory_order_relaxed))
    {
      mConnectionCounters->currentCount.fetch_add(1, std::memory_order_relaxed);
      mConnectionCounters->cumulatedCount.fetch_add(1, std::memory_order_relaxed);
    }

    mLogger.info({{"listener_name", std::string_view{listenerName}},
                   {"remote_address", std::string_view{remoteAddress}}},
      "Connection established");

    // Enforce MaxSecureChannels limit before creating a new channel.
    const auto maxSecureChannels = mConfig.server.maxSecureChannels;
    if (maxSecureChannels.has_value())
    {
      size_t channelCount = 0;
      {
        const ReadLock lk(mMutex);
        channelCount = mSecureChannels.size();
      }
      if (channelCount >= *maxSecureChannels)
      {
        // Per OPC UA Part 4 5.5.2.1: evict the oldest sessionless channel to make room.
        shared_ptr<SecureChannel> evictTarget;
        auto oldestLastUsed = std::chrono::steady_clock::time_point::max();
        {
          const ReadLock lk(mMutex);
          for (const auto& ch : mSecureChannels)
          {
            if (ch && ch->session_count() == 0)
            {
              const auto lastUsed = ch->last_used_time();
              if (!evictTarget || lastUsed < oldestLastUsed)
              {
                evictTarget = ch;
                oldestLastUsed = lastUsed;
              }
            }
          }
        }

        if (evictTarget)
        {
          mLogger.warning({{"remote_address", std::string_view{remoteAddress}}},
            "MaxSecureChannels limit reached ({}/{}), evicting oldest sessionless channel",
            channelCount,
            *maxSecureChannels);
          evictTarget->close();
          remove_secure_channel(evictTarget);
        }
        else
        {
          // All channels have sessions; cannot evict - reject the connection.
          if (mDiagnosticsEnabled->load(std::memory_order_relaxed))
          {
            mConnectionCounters->rejectedCount.fetch_add(1, std::memory_order_relaxed);
          }

          {
            const WriteLock lk(mMutex);
            decrement_per_ip_count_locked(connection->transport_identity());
          }

          mLogger.warning({{"remote_address", std::string_view{remoteAddress}}},
            "MaxSecureChannels limit reached ({}/{}), all channels have sessions - rejecting connection",
            channelCount,
            *maxSecureChannels);
          // OPC 10000-6 v1.05 7.1.2.3: if the Server lacks resources to establish a new
          // SecureChannel it SHALL immediately return a Bad_TcpNotEnoughResources Error Message
          // and gracefully close the socket. This is a transport (UA-TCP) layer reject, so the
          // transport-level status applies - not the session-level Bad_TooManySessions.
          connection->send_error(Status::BadTcpNotEnoughResources, "Max secure channels reached");
          connection->close_async();

          auto eh = observer();
          detail::emit_event(mLogger,
            eh,
            [&]
            {
              eh->on_connection_closed(
                remoteAddress, ConnectionCloseReason::MaxConnections, Status::BadTcpNotEnoughResources);
            });
          return;
        }
      }
    }

    // The per-IP slot reserved at accept is NOT released here: it is held by the channel and released
    // when the channel is removed, so the limit bounds concurrent connections from one remote. Should
    // the channel fail to come into being, the connection leaves the server without a channel and the
    // slot is released on that path.
    try
    {
      // Forward and reverse connections share this path; the synthetic listener handle is what
      // distinguishes them. The channel carries the target name so it can raise the reverse-connect
      // hooks at the points it already emits opened/closed.
      auto reverseTargetName = reverse_target_name_for(listener);

      auto secureChannel = SecureChannel::create(mDependencies,
        connection,
        negotiatedLimits,
        listener,
        std::move(listenerName),
        std::move(remoteAddress),
        std::move(reverseTargetName));

      // Test hook: notify callback before the channel processes any messages.
      if (mOnSecureChannelAvailable)
      {
        mOnSecureChannelAvailable(secureChannel);
      }

      add_secure_channel(secureChannel);
    }
    catch (...)
    {
      {
        const WriteLock lk(mMutex);
        decrement_per_ip_count_locked(connection->transport_identity());
      }
      throw;
    }
  }
  else
  {
    // Handshake failure: clean up the initialising connection (same release as the close observer).
    {
      const WriteLock lk(mMutex);
      (void)release_initialising_connection_locked(connection.get());
    }

    auto eh = observer();
    detail::emit_event(mLogger,
      eh,
      [&] { eh->on_connection_closed(remoteAddress, ConnectionCloseReason::ProtocolError, status); });
  }
}

// --- Reverse connect ---

class ServerReverseConnectDeps : public ReverseConnectListenerDependencies,
                                 public std::enable_shared_from_this<ServerReverseConnectDeps>
{
public:
  /// All getter data is captured at construction time. These values are effectively immutable
  /// after server start, and the reverse connect manager is only created after start. This
  /// avoids the need to lock a weak_ptr<ServerImpl> on every getter call - eliminating a
  /// window where the server could be destroyed between the deps weak_ptr check and the
  /// actual ServerImpl access.
  ServerReverseConnectDeps(
    std::shared_ptr<ServerImpl> server, ListenerHandle syntheticHandle, std::string targetName)
    : mServer(server), mSyntheticHandle(syntheticHandle), mTargetName(std::move(targetName)),
      mExecutor(server->executor()), mLogger(server->logger()), mServerUri(std::string{server->server_uri()}),
      mConnectionProtocolDeps(
        std::static_pointer_cast<ConnectionProtocolDependencies>(server->mDependencies)),
      mConnectionProtocolLimits(server->connection_protocol_limits()),
      mConnectionProtocolTimeout(server->configuration().stack_limits().connectionProtocolTimeout),
      mConnectionProtocolMessageReadTimeout(
        server->configuration().stack_limits().connectionProtocolMessageReadTimeout),
      mWriteQueueDepthCap(server->config().server.resourceLimits.writeQueueDepthPerConnection),
      mWriteQueueBytesCap(server->config().server.resourceLimits.writeQueueBytesPerConnection)
  {}

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  ua::Logger logger() override
  {
    return mLogger;
  }

  std::string server_uri() override
  {
    return mServerUri;
  }

  std::weak_ptr<ConnectionProtocolDependencies> connection_protocol_dependencies() override
  {
    return mConnectionProtocolDeps;
  }

  ua::connection_protocol::Limits connection_protocol_limits() override
  {
    return mConnectionProtocolLimits;
  }

  std::chrono::seconds connection_protocol_timeout() override
  {
    return mConnectionProtocolTimeout;
  }

  std::chrono::milliseconds connection_protocol_message_read_timeout() override
  {
    return mConnectionProtocolMessageReadTimeout;
  }

  size_t write_queue_depth_cap() override
  {
    return mWriteQueueDepthCap;
  }

  size_t write_queue_bytes_cap() override
  {
    return mWriteQueueBytesCap;
  }

  void on_reverse_connection_ready(std::shared_ptr<ConnectionProtocol> connection,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits) override
  {
    auto server = mServer.lock();
    if (!server)
      return;
    server->new_connection_complete(
      mSyntheticHandle, mTargetName, Status::Good, std::move(connection), negotiatedLimits);
  }

  void on_reverse_connect_opened(const std::string& remoteAddress) override
  {
    auto server = mServer.lock();
    if (!server)
      return;
    auto eh = server->observer();
    detail::emit_event(mLogger, eh, [&] { eh->on_reverse_connect_opened(mTargetName, remoteAddress); });
  }

  void on_reverse_connect_closed(const std::string& remoteAddress, ua::StatusCode reason) override
  {
    auto server = mServer.lock();
    if (!server)
      return;
    auto eh = server->observer();
    detail::emit_event(
      mLogger, eh, [&] { eh->on_reverse_connect_closed(mTargetName, remoteAddress, reason); });
  }

  void on_reverse_connect_error(ua::VoidResult error) override
  {
    auto server = mServer.lock();
    if (!server)
      return;
    auto status = error.status_code();
    const auto& detail = error.shared_detail();
    mLogger.warning(
      {{"target", std::string_view{mTargetName}}, {"status", fmt::format("0x{:08x}", status.as_uint32())}},
      "Reverse connect error: {}",
      detail ? detail->summary : ua::to_string(status));

    // No TCP socket exists on this path, so there is no remote address to report. A failed dial is
    // nevertheless a terminal transition for this attempt and must be visible to the application;
    // otherwise a target retrying forever is indistinguishable from an idle connected target.
    auto eh = server->observer();
    detail::emit_event(
      mLogger, eh, [&] { eh->on_reverse_connect_closed(mTargetName, std::string{}, status); });
  }

private:
  std::weak_ptr<ServerImpl> mServer;
  ListenerHandle mSyntheticHandle;
  std::string mTargetName;

  // Cached at construction - all immutable after server start.
  boost::asio::any_io_executor mExecutor;
  ua::Logger mLogger;
  std::string mServerUri;
  std::weak_ptr<ConnectionProtocolDependencies> mConnectionProtocolDeps;
  ua::connection_protocol::Limits mConnectionProtocolLimits;
  std::chrono::seconds mConnectionProtocolTimeout;
  std::chrono::milliseconds mConnectionProtocolMessageReadTimeout;
  size_t mWriteQueueDepthCap;
  size_t mWriteQueueBytesCap;
};

void ServerImpl::start_reverse_connect_async(
  ServerConfig::ReverseConnectTarget target, std::function<void(ReverseConnectHandleResult)> callback)
{
  // DEF-2: a runtime reverse-connect target declares endpoints like a listener does; they pass the
  // same gates add_endpoint applies before the synthetic listener that would serve them exists.
  for (const auto& endpoint : target.endpoints)
  {
    auto gate = validate_endpoint_security_gates(*mConfig.application, endpoint);
    if (gate.is_bad())
    {
      callback(ReverseConnectHandleResult{gate.status_code(),
        ErrorDetail::build("ReverseConnectEndpointRejected",
          "A reverse-connect target endpoint fails the endpoint security gates",
          "ServerImpl")
          .context(ua::ContextKeys::listenerName, target.name + " (reverse connect)")
          .context(ua::ContextKeys::endpointName, endpoint.name)
          .cause(gate.status_code())});
      return;
    }
  }

  // Create a synthetic listener for endpoint lookup.
  ListenerHandle syntheticHandle;
  {
    const WriteLock lk(mMutex);
    syntheticHandle = ListenerHandle{mNextListenerHandle++};

    ListenerState syntheticListener;
    syntheticListener.handle = syntheticHandle;
    syntheticListener.name = target.name + "_reverse";
    syntheticListener.endpoints = target.endpoints;
    syntheticListener.advertisedUrls = {ua::transport::EndpointUrl{target.serverEndpointUrl}};
    syntheticListener.tcpTransportAcceptor = nullptr;  // outbound, not inbound

    mListeners.push_back(std::move(syntheticListener));
  }

  // Create dependencies adapter. Pass shared_from_this() so the constructor can capture
  // immutable server state. The deps only holds a weak_ptr for the callback methods.
  auto deps = std::make_shared<ServerReverseConnectDeps>(shared_from_this(), syntheticHandle, target.name);

  // Create the manager (but don't start yet - store it first so stop_reverse_connect works).
  auto manager = ReverseConnectListener::create(deps, target);
  if (!manager)
  {
    // create() fails closed when the dependencies have expired. `deps` was constructed two lines
    // above and is still held here, so this is unreachable today; it is handled rather than
    // asserted because an assert would compile out of every shipped build.
    {
      // Drop the synthetic listener registered above, or it outlives the reverse connect it exists
      // to serve.
      const WriteLock lk(mMutex);
      std::erase_if(mListeners, [&](const ListenerState& ls) { return ls.handle == syntheticHandle; });
    }
    callback(ReverseConnectHandleResult{StatusCode{Status::BadInternalError,
      make_error_detail("ReverseConnectDependenciesExpired",
        "Reverse connect dependencies expired before the listener could be created",
        "ServerImpl::start_reverse_connect_async")}});
    return;
  }

  // Assign handle and store state under the lock (mNextReverseConnectHandleId is guarded by mMutex).
  ReverseConnectHandle handle;
  {
    const WriteLock lk(mMutex);
    handle = ReverseConnectHandle{mNextReverseConnectHandleId++};
    mReverseConnects.push_back(ReverseConnectState{
      .handle = handle,
      .targetName = target.name,
      .syntheticListenerHandle = syntheticHandle,
      .dependencies = std::move(deps),
      .manager = manager,
    });
  }

  // Start after storing so the handle is findable if the executor runs inline.
  manager->start();

  mLogger.info({{"target", std::string_view{target.name}},
                 {"client_endpoint", std::string_view{target.clientEndpointUrl}}},
    "Reverse connect started");

  callback(handle);
}

void ServerImpl::stop_reverse_connect_async(
  ReverseConnectHandle handle, std::function<void(VoidResult)> callback)
{
  std::shared_ptr<ReverseConnectListener> manager;
  ListenerHandle syntheticHandle{};
  std::string targetName;

  {
    WriteLock lk(mMutex);
    auto it = std::ranges::find_if(
      mReverseConnects, [&](const ReverseConnectState& s) { return s.handle == handle; });
    if (it == mReverseConnects.end())
    {
      lk.unlock();
      callback(VoidResult{Status::BadNotFound,
        ErrorDetail::build(
          "ReverseConnectHandleNotFound", "No reverse connect target with the given handle", "ServerImpl")
          .context(ua::ContextKeys::reverseConnectHandle, std::to_string(handle.value))});
      return;
    }

    manager = it->manager;
    syntheticHandle = it->syntheticListenerHandle;
    targetName = it->targetName;
    mReverseConnects.erase(it);

    // Remove the synthetic listener.
    std::erase_if(mListeners, [&](const ListenerState& ls) { return ls.handle == syntheticHandle; });
  }

  mLogger.info({{"target", std::string_view{targetName}}}, "Stopping reverse connect");

  manager->stop_async([callback = std::move(callback)](VoidResult) { callback(VoidResult{}); });
}

void ServerImpl::stop_all_reverse_connects_async(std::function<void(VoidResult)> callback)
{
  std::vector<ReverseConnectState> toStop;

  {
    const WriteLock lk(mMutex);
    toStop = std::exchange(mReverseConnects, {});

    // Remove all synthetic listeners.
    for (const auto& rc : toStop)
    {
      std::erase_if(
        mListeners, [&](const ListenerState& ls) { return ls.handle == rc.syntheticListenerHandle; });
    }
  }

  if (toStop.empty())
  {
    callback(VoidResult{});
    return;
  }

  mLogger.info({}, "Stopping all reverse connects ({})", toStop.size());

  // Keep managers alive until all stop callbacks have fired.
  auto kept = std::make_shared<std::vector<ReverseConnectState>>(std::move(toStop));

  auto remaining = std::make_shared<std::atomic<std::size_t>>(kept->size());
  auto finalCallback = std::make_shared<Server::CompleteCallback>(std::move(callback));
  auto strand = boost::asio::make_strand(mExecutor);
  auto onOneDone = [remaining, finalCallback, strand, logger = mLogger](VoidResult)
  {
    if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
    {
      boost::asio::post(strand,
        ua::async::guarded(logger,
          [finalCallback]()
          {
            if (*finalCallback)
              (*finalCallback)(VoidResult{});
          }));
    }
  };

  for (auto& rc : *kept)
  {
    rc.manager->stop_async([kept, onOneDone](VoidResult r) mutable { onOneDone(std::move(r)); });
  }
}

void ServerImpl::add_endpoint(ListenerHandle listener, ServerEndpointConfig endpoint)
{
  WriteLock lk(mMutex);

  auto listenerIt =
    std::ranges::find_if(mListeners, [&listener](const ListenerState& ls) { return ls.handle == listener; });
  if (listenerIt == mListeners.end())
  {
    throw UaException{Status::BadNotFound,
      ErrorDetail::build("ListenerNotFound", "Listener not found for add_endpoint", "ServerImpl")
        .context(ua::ContextKeys::listenerHandle, std::to_string(listener.value))};
  }

  if (std::ranges::find(listenerIt->endpoints, endpoint) != listenerIt->endpoints.end())
  {
    throw UaException{Status::BadAlreadyExists,
      make_error_detail(
        "EndpointAlreadyExists", "Endpoint configuration already exists on this listener", "ServerImpl")};
  }

  // DEF-2: the one gate every endpoint passes, whatever path declared it (configuration-declared
  // listener and reverse-connect endpoints are checked by Server::create with the same function).
  auto gate = validate_endpoint_security_gates(*mConfig.application, endpoint);
  if (!gate.is_good())
  {
    gate.value();  // throws UaException with the gate's ErrorDetail
  }
  if (auto securityPolicy = SecurityPolicy::create(endpoint.securityPolicyId);
      securityPolicy->is_deprecated())
  {
    mLogger.warning({{"security_policy", std::string_view{securityPolicy->uri()}}},
      "Deprecated security policy registered - AllowDeprecatedSecurityPolicies is enabled");
  }

  auto tokenValidation = validate_endpoint_user_token_policies(endpoint);
  if (!tokenValidation.is_good())
  {
    tokenValidation.value();  // throws UaException with ErrorDetail
  }

  // If the server is already running, validate certificate availability for the new endpoint.
  if (mDynamicState->serverState.load() == ServerState::Running)
  {
    lk.unlock();
    // The fetch is explicit HERE rather than buried in the validator, so the one blocking call on
    // this path is visible at the call site that owns it. add_endpoint is a synchronous public API,
    // so blocking the CALLER's thread is by design. get_application_certificates_async always posts
    // and never completes inline, so a caller on a thread of the Server's executor is refused with
    // Bad_WouldBlock below instead of deadlocking.
    std::vector<CertificateStore::ApplicationCertificate> available;
    if (mDefaultApplicationGroupCertificateStore && !required_certificate_types({endpoint}).empty())
    {
      // Refused rather than entered on a thread of the Server's executor: the fetch is answered by a
      // post to it, so a thread of it cannot wait for the answer.
      if (ua::async::detail::on_executor_context(mExecutor))
      {
        throw UaException{Status::BadWouldBlock, ua::async::detail::would_block_detail()};
      }
      auto certsResult = mDefaultApplicationGroupCertificateStore->try_get_application_certificates_sync();
      if (!certsResult.is_good())
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build("CertificateStoreError",
            "Failed to retrieve application certificates from the store",
            "ServerImpl")
            .cause(certsResult.status_code())};
      }
      available = std::move(certsResult).value();
    }
    validate_endpoint_certificates({endpoint}, available);
    lk.lock();
    // Re-find the listener since we released the lock.
    listenerIt = std::ranges::find_if(
      mListeners, [&listener](const ListenerState& ls) { return ls.handle == listener; });
    if (listenerIt == mListeners.end())
    {
      throw UaException{Status::BadNotFound,
        ErrorDetail::build("ListenerNotFound", "Listener removed during endpoint validation", "ServerImpl")
          .context(ua::ContextKeys::listenerHandle, std::to_string(listener.value))};
    }
  }

  listenerIt->endpoints.push_back(endpoint);
}

void ServerImpl::remove_endpoint(ListenerHandle listener, ServerEndpointConfig endpoint)
{
  const WriteLock lk(mMutex);

  auto listenerIt =
    std::ranges::find_if(mListeners, [&listener](const ListenerState& ls) { return ls.handle == listener; });
  if (listenerIt == mListeners.end())
  {
    throw UaException{Status::BadNotFound,
      ErrorDetail::build("ListenerNotFound", "No listener found with the given handle", "ServerImpl")
        .context(ua::ContextKeys::listenerHandle, std::to_string(listener.value))};
  }

  if (auto it = std::ranges::find(listenerIt->endpoints, endpoint); it != listenerIt->endpoints.end())
  {
    listenerIt->endpoints.erase(it);
  }
}

std::vector<ServerEndpointConfig> ServerImpl::endpoints(ListenerHandle listener) const
{
  const ReadLock lk(mMutex);

  auto listenerIt =
    std::ranges::find_if(mListeners, [&listener](const ListenerState& ls) { return ls.handle == listener; });
  if (listenerIt == mListeners.end())
  {
    throw UaException{Status::BadNotFound,
      ErrorDetail::build("ListenerNotFound", "No listener found with the given handle", "ServerImpl")
        .context(ua::ContextKeys::listenerHandle, std::to_string(listener.value))};
  }
  return listenerIt->endpoints;
}

ua::transport::BindAddress ServerImpl::requested_bind_address(ListenerHandle listener) const
{
  const ReadLock lk(mMutex);

  auto listenerIt =
    std::ranges::find_if(mListeners, [&listener](const ListenerState& ls) { return ls.handle == listener; });
  if (listenerIt == mListeners.end())
  {
    throw UaException{Status::BadNotFound,
      ErrorDetail::build("ListenerNotFound", "No listener found with the given handle", "ServerImpl")
        .context(ua::ContextKeys::listenerHandle, std::to_string(listener.value))};
  }

  return listenerIt->requestedBind;
}

ua::transport::BindAddress ServerImpl::bound_bind_address(ListenerHandle listener) const
{
  const ReadLock lk(mMutex);

  auto listenerIt =
    std::ranges::find_if(mListeners, [&listener](const ListenerState& ls) { return ls.handle == listener; });
  if (listenerIt == mListeners.end())
  {
    throw UaException{Status::BadNotFound,
      ErrorDetail::build("ListenerNotFound", "No listener found with the given handle", "ServerImpl")
        .context(ua::ContextKeys::listenerHandle, std::to_string(listener.value))};
  }

  if (!listenerIt->boundEndpoint.has_value())
  {
    throw UaException{Status::BadInvalidState,
      ErrorDetail::build(
        "ListenerNotStarted", "Listener has not been started; no bound endpoint available", "ServerImpl")
        .context(ua::ContextKeys::listenerHandle, std::to_string(listener.value))};
  }

  return listenerIt->boundBind;
}

std::vector<ua::transport::EndpointUrl> ServerImpl::advertised_urls(ListenerHandle listener) const
{
  const ReadLock lk(mMutex);

  auto listenerIt =
    std::ranges::find_if(mListeners, [&listener](const ListenerState& ls) { return ls.handle == listener; });
  if (listenerIt == mListeners.end())
  {
    throw UaException{Status::BadNotFound,
      ErrorDetail::build("ListenerNotFound", "No listener found with the given handle", "ServerImpl")
        .context(ua::ContextKeys::listenerHandle, std::to_string(listener.value))};
  }

  return listenerIt->advertisedUrls;
}

ListenerHandleList ServerImpl::listeners() const
{
  const ReadLock lk(mMutex);
  ListenerHandleList handles;
  handles.reserve(mListeners.size());
  for (const auto& l : mListeners)
  {
    handles.push_back(l.handle);
  }
  return handles;
}

StructureFactory& ServerImpl::structure_factory()
{
  return mStructureFactory;
}

shared_ptr<const UaBinaryDataValueCodec> ServerImpl::ua_binary_data_value_codec()
{
  // Capture weak_ptr; lock on each call so we don't prevent shutdown.
  auto weak = weak_from_this();
  StructureResolver resolver = [weak](const NodeId& encodingId) -> std::unique_ptr<Structure>
  {
    auto self = weak.lock();
    if (!self)
    {
      return nullptr;
    }
    return self->mStructureFactory.create_instance(encodingId);
  };

  auto nsConfig = mAddressSpace.codec_namespace_context();
  auto limits = make_encoding_limits(configuration());

  return UaBinaryDataValueCodec::create(std::move(resolver), std::move(nsConfig), limits);
}

void ServerImpl::register_structure_type(const NodeId& encodingId, StructureFactory::CreateMethod factory)
{
  mStructureFactory.register_type(encodingId, std::move(factory));
}

Result<dynamic_types::LoaderRegistrationStats> ServerImpl::try_register_address_space_types_sync(
  dynamic_types::TypeFilter filter)
{
  return dynamic_types::try_register_address_space_types_sync(
    mAddressSpace, mStructureFactory, std::move(filter));
}

dynamic_types::LoaderRegistrationStats ServerImpl::register_address_space_types_sync(
  dynamic_types::TypeFilter filter)
{
  return dynamic_types::register_address_space_types_sync(
    mAddressSpace, mStructureFactory, std::move(filter));
}

void ServerImpl::register_address_space_types_async(dynamic_types::TypeFilter filter,
  std::function<void(Result<dynamic_types::LoaderRegistrationStats>)> completion)
{
  dynamic_types::register_address_space_types_async(
    mAddressSpace, mStructureFactory, std::move(filter), std::move(completion));
}

StructureResolver ServerImpl::structure_resolver()
{
  // Weak-capture the server so the resolver cannot outlive (and dangle against) the factory.
  auto weak = weak_from_this();
  return [weak](const NodeId& encodingId) -> std::unique_ptr<Structure>
  {
    auto self = weak.lock();
    if (!self)
    {
      return nullptr;
    }
    return self->mStructureFactory.create_instance(encodingId);
  };
}

shared_ptr<const Crypto> ServerImpl::crypto() const
{
  return mCrypto;
}

shared_ptr<CertificateStore> ServerImpl::default_application_group_certificate_store() const
{
  return mDefaultApplicationGroupCertificateStore;
}

shared_ptr<CertificateStore> ServerImpl::user_token_certificate_store() const
{
  return mUserTokenCertificateStore;
}

std::vector<std::string> ServerImpl::discovery_urls() const
{
  // Aggregate the advertised URLs across every bound listener. Valid only post-bind;
  // pre-bind there are no listeners materialised, so the result is empty rather than an error.
  const ReadLock lk(mMutex);
  std::vector<std::string> urls;
  for (const auto& listenerState : mListeners)
  {
    for (const auto& advertisedUrl : listenerState.advertisedUrls)
    {
      urls.push_back(advertisedUrl.str());
    }
  }
  return urls;
}

ApplicationDescription ServerImpl::application_description() const
{
  const std::vector<std::string> urls = discovery_urls();
  std::vector<std::string_view> urlViews;
  urlViews.reserve(urls.size());
  for (const auto& url : urls)
  {
    urlViews.emplace_back(url);
  }
  return mConfig.application->construct_application_description(mConfig.identity, urlViews);
}

void ServerImpl::add_secure_channel(shared_ptr<SecureChannel> secureChannel)
{
  const WriteLock lk(mMutex);
  mSecureChannels.push_back(secureChannel);

  if (mDiagnosticsEnabled->load(std::memory_order_relaxed))
  {
    mSecureChannelCounters->currentCount.fetch_add(1, std::memory_order_relaxed);
    mSecureChannelCounters->cumulatedCount.fetch_add(1, std::memory_order_relaxed);
  }
}

void ServerImpl::remove_secure_channel(const shared_ptr<SecureChannel>& channel)
{
  const WriteLock lk(mMutex);
  const auto [first, last] = std::ranges::remove(mSecureChannels, channel);
  const auto removedCount = numeric_cast<uint32_t>(std::distance(first, last));
  mSecureChannels.erase(first, last);

  if (removedCount > 0 && channel)
  {
    // The channel leaving the server ends the connection's hold on its per-IP slot.
    decrement_per_ip_count_locked(channel->transport_identity());
  }

  if (removedCount > 0 && mDiagnosticsEnabled->load(std::memory_order_relaxed))
  {
    mSecureChannelCounters->currentCount.fetch_sub(removedCount, std::memory_order_relaxed);
    mConnectionCounters->currentCount.fetch_sub(removedCount, std::memory_order_relaxed);
  }
}

void ServerImpl::create_session(
  SecureChannelInfo secureChannelInfo, uint32_t requestId, CreateSessionRequest&& request)
{
  const auto notifyCreateFailure = [&](StatusCode reason)
  {
    SessionEventInfo info;
    info.sessionName = request.session_name();
    info.secureChannelId = secureChannelInfo.channel_id();
    info.remoteAddress = secureChannelInfo.remote_address();
    info.auditEntryId = request.request_header().audit_entry_id();
    info.endpointUrl = request.endpoint_url();
    if (auto certificate = secureChannelInfo.client_certificate())
    {
      info.clientCertificate = certificate->der_encoding();
      info.clientCertificateThumbprint = ua::to_string(certificate->thumbprint());
    }
    auto eventObserver = observer();
    detail::emit_event(
      mLogger, eventObserver, [&] { eventObserver->on_session_create_failed(info, reason); });
  };

  // Reject session creation during shutdown.
  if (mDynamicState->serverState.load() == ServerState::Shutdown)
  {
    StatusCode failure{Status::BadServerHalted};
    notifyCreateFailure(failure);
    auto sc = secureChannelInfo.secure_channel().lock();
    if (sc)
    {
      sc->send_response_message(
        std::make_pair(requestId, stack_utils::create_service_fault(nullptr, failure)));
    }
    return;
  }

  // Session::create must happen outside the lock - the Session constructor calls
  // deps->logger() which takes ReadLock on mMutex, and holding WriteLock + ReadLock
  // on the same std::shared_mutex from the same thread is undefined behavior.
  Session::create(mDependencies,
    secureChannelInfo,
    requestId,
    std::move(request),
    [weakSelf = weak_from_this()](shared_ptr<Session> session) -> VoidResult
    {
      auto self = weakSelf.lock();
      if (!self)
      {
        return VoidResult{Status::BadShutdown,
          make_error_detail(
            "ServerUnavailableForSessionAdmission", "Server unavailable during Session admission", "Server")};
      }
      return self->admit_session(std::move(session));
    });
}

VoidResult ServerImpl::admit_session(shared_ptr<Session> session) noexcept
{
  shared_ptr<Session> evictedSession;
  try
  {
    if (mOnSessionAdmittedForTests)
      mOnSessionAdmittedForTests(*session);

    {
      const WriteLock lk(mMutex);

      if (mDynamicState->serverState.load() == ServerState::Shutdown)
        return VoidResult{Status::BadServerHalted};

      if (const auto maxSessions = mConfig.server.server_capabilities().maxSessions;
          maxSessions && mSessions.size() >= numeric_cast<size_t>(*maxSessions))
      {
        // P4-SS-0005: the oldest non-activated Session is the only Session eligible for eviction.
        const auto oldestInactive =
          std::ranges::find_if(mSessions, [](const auto& candidate) { return !candidate->is_activated(); });
        if (oldestInactive == mSessions.end())
        {
          mLogger.warning(
            {}, "MaxSessions limit reached ({}) with no evictable sessions, rejecting", *maxSessions);
          return VoidResult{Status::BadTooManySessions,
            ErrorDetail::build(
              "TooManySessions", "Server session limit reached with no evictable session", "Server")
              .context(ua::ContextKeys::limit, std::to_string(*maxSessions))
              .context(ua::ContextKeys::countTotal, std::to_string(mSessions.size()))};
        }
        evictedSession = *oldestInactive;
        mLogger.warning(
          {}, "MaxSessions limit reached ({}), evicting oldest unactivated session", *maxSessions);
      }

      const auto [tokenEntry, tokenInserted] =
        mSessionsByToken.emplace(session->authentication_token(), session);
      if (!tokenInserted)
      {
        return VoidResult{Status::BadInternalError,
          make_error_detail("DuplicateSessionAuthenticationToken",
            "Session authentication token is already registered",
            "Server")};
      }

      try
      {
        mSessions.push_back(session);
      }
      catch (...)
      {
        mSessionsByToken.erase(tokenEntry);
        throw;
      }

      if (evictedSession && !evictedSession->suppress_create_completion_for_eviction())
      {
        mSessions.pop_back();
        mSessionsByToken.erase(tokenEntry);
        const auto maxSessions = *mConfig.server.server_capabilities().maxSessions;
        return VoidResult{Status::BadTooManySessions,
          ErrorDetail::build("SessionCreateCompletionInProgress",
            "Oldest unactivated Session is crossing its CreateSession response queue boundary",
            "Server")
            .context(ua::ContextKeys::limit, std::to_string(maxSessions))
            .context(ua::ContextKeys::countTotal, std::to_string(mSessions.size()))};
      }

      if (evictedSession)
      {
        mSessionsByToken.erase(evictedSession->authentication_token());
        const auto [first, last] = std::ranges::remove(mSessions, evictedSession);
        mSessions.erase(first, last);
        evictedSession->set_close_reason(Status::BadTooManySessions);
      }

      if (mDiagnosticsEnabled->load(std::memory_order_relaxed))
      {
        if (evictedSession)
        {
          mSummaryCounters->currentSessionCount.fetch_sub(1, std::memory_order_relaxed);
          if (!evictedSession->creation_committed())
            mSummaryCounters->cumulatedSessionCount.fetch_sub(1, std::memory_order_relaxed);
        }
        mSummaryCounters->currentSessionCount.fetch_add(1, std::memory_order_relaxed);
        mSummaryCounters->cumulatedSessionCount.fetch_add(1, std::memory_order_relaxed);
      }
    }

    if (evictedSession)
      evictedSession->terminate_for_eviction();

    return VoidResult{};
  }
  catch (...)
  {
    return VoidResult{Status::BadInternalError,
      ErrorDetail::build("SessionAdmissionFailed", "Session admission failed", "Server")
        .cause(::ua::exception_to_status_code(std::current_exception()))};
  }
}

void ServerImpl::activate_session_on_channel(
  SecureChannelInfo newChannelInfo, uint32_t requestId, ActivateSessionRequest&& request)
{
  auto token = request.request_header().authentication_token();
  shared_ptr<Session> session;

  {
    const ReadLock lk(mMutex);
    auto it = mSessionsByToken.find(token);
    if (it != mSessionsByToken.end())
    {
      session = it->second.lock();
    }
  }

  if (session)
  {
    session->activate(requestId, std::move(request), std::move(newChannelInfo));
  }
  else
  {
    // ActivateSession referencing an unknown / never-created session is a session-establishment
    // request rejected for a non-security reason (OPC 10000-5 12.9 ServerDiagnosticsSummary): it
    // increments rejectedSessionCount but NOT its securityRejectedSessionCount subset.
    if (mDiagnosticsEnabled->load(std::memory_order_relaxed))
    {
      mSummaryCounters->rejectedSessionCount.fetch_add(1, std::memory_order_relaxed);
    }

    // Session not found - send ServiceFault back through the originating channel. Echo the request
    // header so the fault carries the client's RequestHandle and a current Timestamp (Part 4 7.28).
    auto sc = newChannelInfo.secure_channel().lock();
    if (sc)
    {
      sc->send_response_message(std::make_pair(requestId,
        stack_utils::create_service_fault(&request.request_header(), Status::BadSessionIdInvalid)));
    }
  }
}

void ServerImpl::remove_session(const shared_ptr<Session>& session)
{
  const WriteLock lk(mMutex);
  mSessionsByToken.erase(session->authentication_token());
  const auto [first, last] = std::ranges::remove(mSessions, session);
  const auto removedCount = numeric_cast<uint32_t>(std::distance(first, last));
  mSessions.erase(first, last);

  if (removedCount > 0 && mDiagnosticsEnabled->load(std::memory_order_relaxed))
  {
    mSummaryCounters->currentSessionCount.fetch_sub(removedCount, std::memory_order_relaxed);
    if (!session->creation_committed())
      mSummaryCounters->cumulatedSessionCount.fetch_sub(removedCount, std::memory_order_relaxed);
  }
}

bool ServerImpl::session_exists(const NodeId& sessionId) const
{
  const ReadLock lk(mMutex);
  return std::ranges::any_of(
    mSessions, [&](const shared_ptr<Session>& session) { return session->session_id() == sessionId; });
}

std::vector<shared_ptr<Session>> ServerImpl::sessions_for_tests() const
{
  const ReadLock lk(mMutex);
  return mSessions;
}

std::shared_ptr<ServerSummaryCounters> ServerImpl::summary_counters() const
{
  return mSummaryCounters;
}

std::shared_ptr<SecureChannelCounters> ServerImpl::secure_channel_counters() const
{
  return mSecureChannelCounters;
}

std::shared_ptr<ConnectionCounters> ServerImpl::connection_counters() const
{
  return mConnectionCounters;
}

std::shared_ptr<std::atomic<bool>> ServerImpl::diagnostics_enabled() const
{
  return mDiagnosticsEnabled;
}

std::shared_ptr<RequestLatencyTracker> ServerImpl::latency_tracker() const
{
  return mLatencyTracker;
}

SubscriptionIdAllocator& ServerImpl::subscription_id_allocator()
{
  return mSubscriptionIdAllocator;
}

SubscriptionRouter& ServerImpl::subscription_router()
{
  return mSubscriptionRouter;
}

OrphanedSubscriptionStore& ServerImpl::orphaned_subscription_store()
{
  return mOrphanedSubscriptionStore;
}

EventBus& ServerImpl::event_bus()
{
  return *mEventBus;
}

Conditions& ServerImpl::conditions()
{
  return *mConditions;
}

std::shared_ptr<std::atomic<uint32_t>> ServerImpl::in_flight_discovery_requests() const
{
  return mInFlightDiscoveryRequests;
}

std::shared_ptr<std::atomic<uint32_t>> ServerImpl::in_flight_requests() const
{
  return mInFlightRequests;
}

namespace
{

// One named entry per service (API-D3.1). The switch has no default, so a service added to ServiceKind
// without an entry here fails the build (-Wswitch), and the size check catches an entry without a service.
static_assert(sizeof(ServerHealthSnapshot::ServiceLatency) ==
                serviceKindCount * sizeof(ServerHealthSnapshot::LatencyEntry),
  "ServerHealthSnapshot::ServiceLatency must have exactly one entry per service");

ServerHealthSnapshot::LatencyEntry* latency_entry(
  ServerHealthSnapshot::ServiceLatency& latency, ServiceKind kind)
{
  switch (kind)
  {
  case ServiceKind::DiscoveryFindServers:
    return &latency.findServers;
  case ServiceKind::DiscoveryFindServersOnNetwork:
    return &latency.findServersOnNetwork;
  case ServiceKind::DiscoveryGetEndpoints:
    return &latency.getEndpoints;
  case ServiceKind::Read:
    return &latency.read;
  case ServiceKind::Write:
    return &latency.write;
  case ServiceKind::Browse:
    return &latency.browse;
  case ServiceKind::BrowseNext:
    return &latency.browseNext;
  case ServiceKind::Call:
    return &latency.call;
  case ServiceKind::TranslateBrowsePathsToNodeIds:
    return &latency.translateBrowsePaths;
  case ServiceKind::RegisterNodes:
    return &latency.registerNodes;
  case ServiceKind::UnregisterNodes:
    return &latency.unregisterNodes;
  case ServiceKind::CreateSubscription:
    return &latency.createSubscription;
  case ServiceKind::ModifySubscription:
    return &latency.modifySubscription;
  case ServiceKind::DeleteSubscriptions:
    return &latency.deleteSubscriptions;
  case ServiceKind::SetPublishingMode:
    return &latency.setPublishingMode;
  case ServiceKind::Publish:
    return &latency.publish;
  case ServiceKind::Republish:
    return &latency.republish;
  case ServiceKind::CreateMonitoredItems:
    return &latency.createMonitoredItems;
  case ServiceKind::DeleteMonitoredItems:
    return &latency.deleteMonitoredItems;
  case ServiceKind::ModifyMonitoredItems:
    return &latency.modifyMonitoredItems;
  case ServiceKind::SetMonitoringMode:
    return &latency.setMonitoringMode;
  case ServiceKind::SetTriggering:
    return &latency.setTriggering;
  case ServiceKind::TransferSubscriptions:
    return &latency.transferSubscriptions;
  case ServiceKind::AddNodes:
    return &latency.addNodes;
  case ServiceKind::AddReferences:
    return &latency.addReferences;
  case ServiceKind::DeleteNodes:
    return &latency.deleteNodes;
  case ServiceKind::DeleteReferences:
    return &latency.deleteReferences;
  case ServiceKind::HistoryRead:
    return &latency.historyRead;
  case ServiceKind::HistoryUpdate:
    return &latency.historyUpdate;
  case ServiceKind::Unknown:
    return nullptr;
  }
  return nullptr;
}

}  // namespace

ServerHealthSnapshot ServerImpl::health_snapshot() const
{
  ServerHealthSnapshot snap;

  // Server summary (spec-aligned)
  snap.currentSessionCount = mSummaryCounters->currentSessionCount.load(std::memory_order_relaxed);
  snap.cumulatedSessionCount = mSummaryCounters->cumulatedSessionCount.load(std::memory_order_relaxed);
  snap.securityRejectedSessionCount =
    mSummaryCounters->securityRejectedSessionCount.load(std::memory_order_relaxed);
  snap.rejectedSessionCount = mSummaryCounters->rejectedSessionCount.load(std::memory_order_relaxed);
  snap.sessionTimeoutCount = mSummaryCounters->sessionTimeoutCount.load(std::memory_order_relaxed);
  snap.sessionAbortCount = mSummaryCounters->sessionAbortCount.load(std::memory_order_relaxed);
  snap.currentSubscriptionCount = mSummaryCounters->currentSubscriptionCount.load(std::memory_order_relaxed);
  snap.cumulatedSubscriptionCount =
    mSummaryCounters->cumulatedSubscriptionCount.load(std::memory_order_relaxed);
  snap.serverViewCount = mSummaryCounters->serverViewCount.load(std::memory_order_relaxed);
  snap.publishingIntervalCount = mSummaryCounters->publishingIntervalCount.load(std::memory_order_relaxed);
  snap.securityRejectedRequestsCount =
    mSummaryCounters->securityRejectedRequestsCount.load(std::memory_order_relaxed);
  snap.rejectedRequestsCount = mSummaryCounters->rejectedRequestsCount.load(std::memory_order_relaxed);

  // Secure channel
  snap.currentSecureChannelCount = mSecureChannelCounters->currentCount.load(std::memory_order_relaxed);
  snap.cumulatedSecureChannelCount = mSecureChannelCounters->cumulatedCount.load(std::memory_order_relaxed);
  snap.rejectedSecureChannelCount = mSecureChannelCounters->rejectedCount.load(std::memory_order_relaxed);

  // Connection
  snap.currentConnectionCount = mConnectionCounters->currentCount.load(std::memory_order_relaxed);
  snap.cumulatedConnectionCount = mConnectionCounters->cumulatedCount.load(std::memory_order_relaxed);
  snap.rejectedConnectionCount = mConnectionCounters->rejectedCount.load(std::memory_order_relaxed);

  // Per-service latency, by name (API-D3.1).
  for (std::size_t index = 0; index < serviceKindCount; ++index)
  {
    const auto kind = static_cast<ServiceKind>(index);
    ServerHealthSnapshot::LatencyEntry* named = latency_entry(snap.latency, kind);
    if (named == nullptr)
    {
      continue;
    }
    const auto& e = mLatencyTracker->entry(kind);
    named->averageUs = e.averageUs.load(std::memory_order_relaxed);
    named->maxUs = e.maxUs.load(std::memory_order_relaxed);
    named->sampleCount = e.sampleCount.load(std::memory_order_relaxed);
  }

  return snap;
}

std::vector<SessionHealthSnapshot> ServerImpl::session_health_snapshots() const
{
  std::vector<shared_ptr<Session>> sessionsCopy;
  {
    const ReadLock lk(mMutex);
    sessionsCopy = mSessions;
  }

  std::vector<SessionHealthSnapshot> snapshots;
  snapshots.reserve(sessionsCopy.size());
  for (const auto& session : sessionsCopy)
  {
    snapshots.push_back(session->health_snapshot());
  }
  return snapshots;
}

uint32_t ServerImpl::get_next_secure_channel_id()
{
  const WriteLock lk(mMutex);
  return mNextSecureChannelId++;
}

std::vector<ServerEndpointConfig> ServerImpl::endpoints() const
{
  const ReadLock lk(mMutex);

  std::vector<ServerEndpointConfig> result;
  for (const auto& listener : mListeners)
  {
    for (const auto& ep : listener.endpoints)
    {
      if (std::ranges::find(result, ep) == result.end())
      {
        result.push_back(ep);
      }
    }
  }
  return result;
}

void ServerImpl::dispatch_apply_changes_channel_close(std::vector<weak_ptr<SecureChannel>> channels,
  const std::vector<shared_ptr<Session>>& sessions, const NodeId& originSessionId,
  MethodResponseCorrelation correlation, std::function<void(VoidResult)> callback)
{
  const auto origin = std::ranges::find(sessions, originSessionId, &Session::session_id);
  if (origin == sessions.end())
  {
    callback(VoidResult{Status::BadInternalError,
      make_error_detail("ApplyChangesOriginSessionMissing",
        "Cannot correlate ApplyChanges to its origin Session and SecureChannel",
        "ServerImpl")});
    return;
  }

  (*origin)->close_secure_channel_after_response_async(correlation,
    [channels = std::move(channels), callback = std::move(callback)](
      Result<weak_ptr<SecureChannel>> originChannel) mutable
    {
      VoidResult result;
      try
      {
        if (!originChannel.is_good())
        {
          result = VoidResult{originChannel.status_code()};
        }
        else if (auto exactOriginChannel = originChannel.value().lock())
        {
          for (const auto& channelHandle : channels)
          {
            auto channel = channelHandle.lock();
            if (channel && channel != exactOriginChannel)
              channel->close();
          }
        }
        else
        {
          result = VoidResult{Status::BadConnectionClosed,
            make_error_detail("ApplyChangesOriginChannelExpired",
              "ApplyChanges origin SecureChannel expired before close registration completed",
              "ServerImpl")};
        }
      }
      catch (...)
      {
        result = VoidResult{Status::BadInternalError,
          ErrorDetail::build("ApplyChangesChannelDispatchFailed",
            "Failed while closing non-origin SecureChannels",
            "ServerImpl")
            .cause(::ua::exception_to_status_code(std::current_exception()))};
      }
      callback(std::move(result));
    });
}

void ServerImpl::dispatch_certificate_reevaluation(std::vector<weak_ptr<SecureChannel>> channels,
  const std::vector<shared_ptr<Session>>& sessions, const NodeId& originSessionId,
  MethodResponseCorrelation correlation, std::function<void(VoidResult)> callback)
{
  // OPC 10000-12 7.8.2.3 / 7.10.6: each open Session and SecureChannel re-checks what it holds against
  // the lists now in force and closes itself if that is no longer valid. The caller's Session and its
  // SecureChannel do so once the response is written; every other one now.
  VoidResult dispatchResult;
  try
  {
    const auto origin = std::ranges::find(sessions, originSessionId, &Session::session_id);
    for (const auto& session : sessions)
    {
      if (origin == sessions.end() || session != *origin)
        session->reevaluate_certificates_async();
    }
    if (origin != sessions.end())
    {
      (*origin)->reevaluate_certificates_after_response_async(correlation,
        [channels = std::move(channels), originSession = *origin, callback](
          Result<weak_ptr<SecureChannel>> originChannel) mutable
        {
          // A stale correlation defers nothing: the origin Session and every channel are re-evaluated now.
          if (!originChannel.is_good())
            originSession->reevaluate_certificates_async();
          const auto exactOriginChannel =
            originChannel.is_good() ? originChannel.value().lock() : shared_ptr<SecureChannel>{};
          for (const auto& channelHandle : channels)
          {
            auto channel = channelHandle.lock();
            if (channel && channel != exactOriginChannel)
              channel->reevaluate_certificate_async();
          }
          callback(!originChannel.is_good() ? VoidResult{originChannel.status_code()} : VoidResult{});
        });
      return;
    }
    for (const auto& channelHandle : channels)
    {
      if (auto channel = channelHandle.lock())
        channel->reevaluate_certificate_async();
    }
  }
  catch (...)
  {
    dispatchResult = VoidResult{Status::BadInternalError,
      ErrorDetail::build("CertificateReevaluationDispatchFailed",
        "Failed while dispatching certificate re-evaluation",
        "ServerImpl")
        .cause(::ua::exception_to_status_code(std::current_exception()))};
  }
  callback(std::move(dispatchResult));
}

void ServerImpl::create_standard_nodes(std::span<const NodeId> roleManagementAccessRoles)
{
  using namespace ua::xml::nodeset;

  // Namespace allocator (D-R callable form): NS0 declares no extra namespaces, but the engine takes
  // an allocator for generality.
  NamespaceAllocator namespaceAllocator = [executor = mExecutor](string_view uri) -> shared_ptr<Namespace>
  {
    return ua::default_ns::Namespace::create(uri, executor);
  };

  auto nodeSets = get_ns0_nodeset();
  // Trusted local input: NS0 is our own standard nodeset; lift the size caps (see get_ns0_nodeset).
  auto engine = ImportEngine::create(ua::make_trusted_local_encoding_limits(configuration()),
    mAddressSpace,
    nodeSets,
    std::move(namespaceAllocator));

  // NS0's own decoration is not enforceable as it stands - see `compute_ns0_access_decoration`. The
  // engine applies the difference as it creates each Node, so no Node is ever reachable undecorated.
  if (!nodeSets.empty() && nodeSets.front())
  {
    engine->set_access_decoration(
      compute_ns0_access_decoration(*nodeSets.front(), roleManagementAccessRoles));
  }

  create_standard_nodes_from_nodeset(engine, nodeSets);

  DiagnosticState diagnostics{
    mSummaryCounters, mSecureChannelCounters, mConnectionCounters, mDiagnosticsEnabled, {}, {}, {}};

  // Provide live-session snapshots to the SessionDiagnosticsArray / SessionSecurityDiagnosticsArray
  // read handlers. The handler may run off the server strand, so snapshot the session list under the
  // lock, release it, then capture each session's counters/security-state shared_ptrs (which keep
  // the diagnostic state alive while records are built without holding any lock).
  diagnostics.sessionDiagnosticsProvider = [weak = weak_from_this()]() -> std::vector<SessionDiagnosticsEntry>
  {
    // Weak-capture: this provider is installed as an
    // address-space read handler co-owned by the AddressSpace value handle, so it can be invoked off the
    // server strand on a pool thread and may outlive (or race the teardown of) ServerImpl - which does NOT
    // drain the externally-owned executor. A raw `this` here would dereference a destroyed ServerImpl
    // (mMutex / mSessions). Lock the weak_ptr and bail if the server is gone.
    auto self = weak.lock();
    if (!self)
    {
      return {};
    }
    std::vector<shared_ptr<Session>> sessions;
    {
      const ReadLock lk(self->mMutex);
      sessions = self->mSessions;
    }
    std::vector<SessionDiagnosticsEntry> entries;
    entries.reserve(sessions.size());
    for (const auto& session : sessions)
    {
      entries.push_back(SessionDiagnosticsEntry{
        session->counters(), session->security_state(), session->descriptive_state()});
    }
    return entries;
  };

  // Provide live-subscription snapshots (server-wide, across all sessions) to the
  // SubscriptionDiagnosticsArray / SamplingIntervalDiagnosticsArray read handlers. The router
  // returns locked (subscription, owning-session) pairs; each subscription's cross-strand
  // get_info() snapshot is copied into a shared_ptr so records build lock-free.
  diagnostics.subscriptionDiagnosticsProvider =
    [weak = weak_from_this()]() -> std::vector<SubscriptionDiagnosticsEntry>
  {
    // Weak-capture: same lifetime contract as session_diagnostics_provider above - the handler is
    // co-owned by the AddressSpace and can race/outlive ServerImpl teardown; a raw `this` would touch a
    // destroyed mSubscriptionRouter.
    auto self = weak.lock();
    if (!self)
    {
      return {};
    }
    std::vector<SubscriptionDiagnosticsEntry> entries;
    auto live = self->mSubscriptionRouter.live_subscriptions();
    entries.reserve(live.size());
    for (auto& [subscription, session] : live)
    {
      if (!subscription)
        continue;
      SubscriptionDiagnosticsEntry entry;
      entry.info = std::make_shared<const SubscriptionInfo>(subscription->get_info());
      entry.sessionId = session ? session->session_id() : NodeId{};
      entries.push_back(std::move(entry));
    }
    return entries;
  };
  const auto subscriptionDiagnosticsProvider = diagnostics.subscriptionDiagnosticsProvider;
  const auto diagnosticsEnabledFlag = diagnostics.enabled;

  // When the EnabledFlag is toggled, bring every Session's diagnostics in line, then run @p settled.
  diagnostics.onEnabledFlagChanged = [weak = weak_from_this()](bool enabled, std::function<void()> settled)
  {
    // Weak-capture: this handler is co-owned by the AddressSpace (EnabledFlag write notifier) and can
    // outlive/race ServerImpl teardown; a raw `this` would touch a destroyed mMutex / mSessions.
    auto self = weak.lock();
    if (!self)
    {
      settled();
      return;
    }
    // Every Session, and the interval reconcile, holds a copy of one token; @p settled runs when the
    // last of them lets go.
    auto token = Session::release_token(self->mLogger, std::move(settled));
    std::vector<shared_ptr<Session>> sessions;
    {
      const std::shared_lock lock(self->mMutex);
      sessions = self->mSessions;
    }
    for (auto& session : sessions)
    {
      session->set_diagnostics_enabled(enabled, token);
    }
    // The per-interval nodes are dynamic diagnostic Nodes: they go when diagnostics are disabled and
    // return, for the intervals then in use, when they are enabled (Part 5 6.3.3).
    if (auto intervals = self->mSamplingIntervalDiagnosticsNodes)
      intervals->reconcile_async([token] {});
  };

  mDynamicState->buildInfo = mConfig.identity.buildInfo;

  auto me = weak_from_this();
  ShutdownRequestHandler shutdownHandler = [me](ShutdownOptions params, Server::CompleteCallback callback)
  {
    auto self = me.lock();
    if (!self)
    {
      if (callback)
      {
        callback(StatusCode{Status::BadInvalidState});
      }
      return;
    }
    self->shutdown_async(std::move(params), std::move(callback));
  };

  mServerModel = ServerModel::create(mAddressSpace,
    mConfig,
    diagnostics,
    mDynamicState,
    std::move(shutdownHandler),
    mLogger,
    mSubscriptionRouter.weak());

  // Maintain a per-subscription SubscriptionDiagnosticsType node under SubscriptionDiagnosticsArray
  // (OPC 10000-5 6.3.7), so clients can browse/read per-subscription diagnostics by SubscriptionId.
  mSubscriptionDiagnosticsNodes = SubscriptionDiagnosticsNodeManager::create(
    mAddressSpace, NodeId{VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray});
  const std::weak_ptr<SubscriptionDiagnosticsNodeManager> weakDiagNodes = mSubscriptionDiagnosticsNodes;
  // And one SamplingIntervalDiagnosticsType node per sampling interval in use under
  // SamplingIntervalDiagnosticsArray (OPC 10000-5 6.3.6), reconciled whenever MonitoredItems change.
  mSamplingIntervalDiagnosticsNodes = SamplingIntervalDiagnosticsNodeManager::create(mAddressSpace,
    NodeId{VariableId::Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray},
    subscriptionDiagnosticsProvider,
    mSubscriptionRouter,
    diagnosticsEnabledFlag);
  const std::weak_ptr<SamplingIntervalDiagnosticsNodeManager> weakIntervalNodes =
    mSamplingIntervalDiagnosticsNodes;
  mSubscriptionRouter.set_lifecycle_observers(
    [weakDiagNodes](IntegerId id, std::weak_ptr<Subscription> subscription, std::weak_ptr<Session> owner)
    {
      if (auto manager = weakDiagNodes.lock())
        manager->on_subscription_added(id, std::move(subscription), std::move(owner));
    },
    [weakDiagNodes, weakIntervalNodes](IntegerId id)
    {
      if (auto manager = weakDiagNodes.lock())
        manager->on_subscription_removed(id);
      // A Subscription that goes takes its MonitoredItems, and possibly the last use of an interval.
      if (auto intervals = weakIntervalNodes.lock())
        intervals->reconcile_async([] {});
    });
  mSubscriptionRouter.set_monitoring_reflection_callback(
    [weakIntervalNodes](std::function<void()> completion)
    {
      if (auto manager = weakIntervalNodes.lock())
        manager->reconcile_async(std::move(completion));
      else
        completion();
    });
  // Let CreateSubscription defer its response until the per-subscription diagnostic node is visible.
  mSubscriptionRouter.set_node_readiness_callback(
    [weakDiagNodes](IntegerId id, std::function<void()> completion)
    {
      if (auto manager = weakDiagNodes.lock())
        manager->when_ready_async(id, std::move(completion));
      else
        completion();
    });

  const auto removeUnimplementedModel = [this](ObjectId objectId, std::string_view objectName)
  {
    const NodeId nodeId{objectId};
    if (mAddressSpace.try_find_node_sync(nodeId).is_bad())
      return;
    auto removed =
      mAddressSpace.try_delete_node_sync(nodeId, /*deleteForwardHierarchicallyReferencedNodes=*/true);
    if (removed.is_bad())
    {
      mLogger.warning("Server model: failed to remove unimplemented {} ({})",
        objectName,
        removed.status_code().as_uint32());
    }
  };

  // Push management off: the whole Part 12 ServerConfiguration model goes, so nothing can change the
  // server's certificates or trust lists through the server (its store has another writer, e.g. pull).
  const bool pushManagementEnabled = mConfig.server.pushCertificateManagementEnabled;
  if (!pushManagementEnabled)
  {
    removeUnimplementedModel(ObjectId::ServerConfiguration, "ServerConfiguration");
  }
  else
  {
    // Part 12 7.10 publishes only certificate groups this deployment implements.
    // This SDK has no HTTPS transport/trust-list backend, and the user-token group
    // exists only when a user-token certificate store was configured.
    removeUnimplementedModel(ObjectId::ServerConfiguration_CertificateGroups_DefaultHttpsGroup,
      "certificate group DefaultHttpsGroup");
    if (!mUserTokenCertificateStore)
    {
      removeUnimplementedModel(ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup,
        "certificate group DefaultUserTokenGroup");
    }
  }

  // Wire push certificate management (GDS push model - Part 12).
  if (pushManagementEnabled && mDefaultApplicationGroupCertificateStore && mCrypto)
  {
    auto weakSelf = weak_from_this();
    auto closeAllChannels = [weakSelf](const NodeId& originSessionId,
                              MethodResponseCorrelation correlation,
                              std::function<void(VoidResult)>
                                callback)
    {
      auto self = weakSelf.lock();
      if (!self)
      {
        callback(VoidResult{Status::BadShutdown});
        return;
      }

      std::vector<weak_ptr<SecureChannel>> channels;
      std::vector<shared_ptr<Session>> sessions;
      {
        const ReadLock lk(self->mMutex);
        channels.reserve(self->mSecureChannels.size());
        for (const auto& channel : self->mSecureChannels)
          channels.emplace_back(channel);
        sessions = self->mSessions;
      }
      dispatch_apply_changes_channel_close(
        std::move(channels), sessions, originSessionId, correlation, std::move(callback));
    };

    // ResetToServerDefaults (Part 12 7.10.10) shutdown trigger: transition to
    // SHUTDOWN with a credential-warning ShutdownReason and the configured grace
    // period (SecondsTillShutdown), so clients can receive the Method response.
    auto requestShutdown = [weakSelf]()
    {
      auto self = weakSelf.lock();
      if (!self)
        return;
      ShutdownOptions shutdownParams;
      shutdownParams.reason = LocalizedText{
        "", "Server reset to defaults - client credentials may no longer be valid after restart"};
      shutdownParams.grace = std::chrono::seconds{self->mConfig.server.defaultShutdownGracePeriodSeconds};
      self->shutdown_async(std::move(shutdownParams), {});
    };

    // Part 12 7.8.2.3 / 7.10.6 certificate re-evaluation after a TrustList change: every open SecureChannel
    // and Session re-checks its certificates and only those no longer valid close.
    auto reevaluateCertificates = [weakSelf](const NodeId& originSessionId,
                                    MethodResponseCorrelation correlation,
                                    std::function<void(VoidResult)>
                                      callback)
    {
      auto self = weakSelf.lock();
      if (!self)
      {
        callback(VoidResult{Status::BadShutdown});
        return;
      }
      std::vector<weak_ptr<SecureChannel>> channels;
      std::vector<shared_ptr<Session>> sessions;
      {
        const ReadLock lk(self->mMutex);
        channels.reserve(self->mSecureChannels.size());
        for (const auto& channel : self->mSecureChannels)
          channels.emplace_back(channel);
        sessions = self->mSessions;
      }
      dispatch_certificate_reevaluation(
        std::move(channels), sessions, originSessionId, correlation, std::move(callback));
    };

    PushManagementWiringParams pushParams{
      .addressSpace = mAddressSpace,
      .certificateStore = mDefaultApplicationGroupCertificateStore,
      .userTokenCertificateStore = mUserTokenCertificateStore,
      .crypto = mCrypto,
      .executor = mExecutor,
      .logger = mLogger,
      .applicationUri = std::string(mConfig.application->application_description_part().applicationUri),
      .hostnames = {"localhost"},
      .closeAllChannels = std::move(closeAllChannels),
      .reevaluateCertificates = std::move(reevaluateCertificates),
      .requestShutdown = std::move(requestShutdown),
      .eventSink =
        mConfig.server.auditingEnabled ? std::weak_ptr<EventSink>{mEventBus} : std::weak_ptr<EventSink>{},
      .serverId = std::string(server_uri()),
      // Asked once per push or trust-list modification (an administrative operation), never per
      // service request.
      .sessionExists =
        [weakSelf = weak_from_this()](const NodeId& sessionId)
      {
        auto self = weakSelf.lock();
        return self && self->session_exists(sessionId);
      },
      // Evaluated at each UpdateCertificate (not once here): endpoints are usually added after the push
      // management is wired.
      .servedEndpointPolicies =
        [weakSelf = weak_from_this()]
      {
        std::vector<ServerEndpointConfig> endpoints;
        if (auto self = weakSelf.lock())
        {
          ReadLock lk(self->mMutex);
          for (const auto& listener : self->mListeners)
          {
            endpoints.insert(endpoints.end(), listener.endpoints.begin(), listener.endpoints.end());
          }
        }
        return served_endpoint_policies_of(endpoints);
      },
    };

    mPushManagement = wire_push_management(std::move(pushParams));
    add_internal_observer(mPushManagement->observer);
  }

  // Wire ConditionRefresh/Refresh2 method handlers on NS0 ConditionType.
  // The validator checks that a subscription belongs to the calling session (COND-135).
  mConditions->register_refresh_methods(
    std::weak_ptr<EventBus>{mEventBus},
    [weak = weak_from_this()](uint32_t subscriptionId, const NodeId& callerSessionId)
    {
      // Weak-capture (matching the sibling resolver below and the diagnostics providers): this
      // validator is invoked from a ConditionRefresh method call and touches mSubscriptionRouter; its
      // safety must not rest on the incidental member-destruction order (mConditions before
      // mSubscriptionRouter). Fail closed (deny the refresh) if ServerImpl is gone.
      auto self = weak.lock();
      if (!self)
        return false;
      auto owner = self->mSubscriptionRouter.find_owner(subscriptionId);
      if (!owner)
        return false;
      return owner->session_id() == callerSessionId;
    },
    // ConditionRefresh2 (Part 9 5.5.8) scopes the refresh to a single
    // MonitoredItem. Resolve its monitored NodeId via the EventBus registry,
    // which holds the live event MonitoredItems. Weak-only capture: the bus
    // owns the strand the lookup posts to, so a destroyed bus simply reports
    // "not found" (nullopt) -> Bad_MonitoredItemIdInvalid.
    [weakBus = std::weak_ptr<EventBus>{mEventBus}](
      uint32_t subscriptionId, uint32_t monitoredItemId, std::function<void(std::optional<NodeId>)> callback)
    {
      auto bus = weakBus.lock();
      if (!bus)
      {
        callback(std::nullopt);
        return;
      }
      bus->resolve_event_item_node_async(subscriptionId, monitoredItemId, std::move(callback));
    });

  // Wire the standard Condition methods (Enable/Disable/AddComment/Acknowledge/Confirm) on
  // the NS0 type method nodes. Clients invoke these using the type method-node id with the
  // condition instance as the object; without these handlers such calls hit a handlerless
  // method node and fail with Bad_NotSupported.
  mConditions->register_condition_methods();
}

void ServerImpl::create_standard_nodes_from_nodeset(shared_ptr<xml::nodeset::ImportEngine> engine,
  const std::vector<shared_ptr<ua::xml::nodeset::NodeSet>>& nodeSets)
{
  using namespace ua::xml::nodeset;
  using Step = std::function<void(ImportEngine::Completion)>;

  // The type-definition import deliberately excludes the PubSub model (import_type_definitions_only
  // below passes "PubSub"). Steps that copy references without that filter - the folder imports and
  // the Server-subtree walk, which re-reach already-imported type nodes (e.g. BaseObjectType via
  // HasTypeDefinition) and idempotently re-merge their references - must not re-introduce forward
  // references into the excluded PubSub subtree, or those targets become dangling (NodeClass=0,
  // "Address Model is broken"). Drop any reference whose target node is PubSub-categorised.
  const std::vector<shared_ptr<NodeSet>> nodeSetsCopy{nodeSets};
  auto excludesPubSubTarget = [nodeSetsCopy](
                                const xml::nodeset::Node&, const xml::nodeset::Node::Reference& reference)
  {
    const NodeSets view{const_cast<shared_ptr<NodeSet>*>(nodeSetsCopy.data()), nodeSetsCopy.size()};
    const auto* target = utilities::find_node(view, reference.targetId);
    if (!target)
    {
      return true;  // target absent here / imported elsewhere - keep the reference
    }
    const auto category = target->category();
    return !(category && string_view{*category}.find("PubSub") != string_view::npos);
  };

  auto importRefPredicate = [excludesPubSubTarget](
                              const xml::nodeset::Node& node, const xml::nodeset::Node::Reference& reference)
  {
    return reference.targetId != NodeId{ObjectId::Aliases} && excludesPubSubTarget(node, reference);
  };

  // GeneralModelChangeEventType (i=2133) IS imported: the SDK raises it (OPC 10000-3 9.32.2, "both or
  // neither"). A namespace that changes a Node carrying a NodeVersion advances it and reports the Node,
  // through its members' versioned-Node output or its context's model_changed; the address space raises one
  // event per operation (NR-36, NR-46, NR-55).

  // The same NS0-load sequence the retired synchronous importer performed, expressed as async
  // import-engine operations. Folders are plain Object nodes (not type definitions), so they are
  // imported individually; then all type definitions; then the Server object subtree.
  std::vector<Step> steps;
  steps.push_back([engine](ImportEngine::Completion cb)
    { engine->import_node_async(NodeId{ObjectId::RootFolder}, {}, std::move(cb)); });
  steps.push_back([engine, importRefPredicate](ImportEngine::Completion cb)
    { engine->import_node_async(NodeId{ObjectId::ObjectsFolder}, importRefPredicate, std::move(cb)); });
  for (auto folder : {ObjectId::Locations,
         ObjectId::ViewsFolder,
         ObjectId::TypesFolder,
         ObjectId::ObjectTypesFolder,
         ObjectId::VariableTypesFolder,
         ObjectId::DataTypesFolder,
         ObjectId::ReferenceTypesFolder,
         ObjectId::EventTypesFolder})
  {
    steps.push_back([engine, folder, excludesPubSubTarget](ImportEngine::Completion cb)
      { engine->import_node_async(NodeId{folder}, excludesPubSubTarget, std::move(cb)); });
  }
  // Well-known singletons that imported nodes reference structurally but that no reachability walk
  // visits: the standard ModellingRule objects (kept as HasModellingRule targets) and the InterfaceTypes
  // folder (Organizes target of the Types tree). Import each by id so the kept references resolve
  // instead of dangling (NodeClass=0). Per-node failure is tolerated (a trimmed NodeSet simply omits
  // the node). They go in before the type definitions, like the folders, so the type import keeps its
  // references to them - BaseInterfaceType's inverse Organizes to InterfaceTypes among them.
  for (auto singleton : {ObjectId::ModellingRule_Mandatory,
         ObjectId::ModellingRule_Optional,
         ObjectId::ModellingRule_ExposesItsArray,
         ObjectId::ModellingRule_OptionalPlaceholder,
         ObjectId::ModellingRule_MandatoryPlaceholder,
         ObjectId::InterfaceTypes})
  {
    steps.push_back(
      [engine, singleton, excludesPubSubTarget](ImportEngine::Completion cb)
      {
        engine->import_node_async(NodeId{singleton},
          excludesPubSubTarget,
          [cb = std::move(cb)](VoidResult) mutable { cb(VoidResult{}); });
      });
  }

  steps.push_back([engine](ImportEngine::Completion cb)
    { engine->import_type_definitions_only_async("PubSub", {}, {}, std::move(cb)); });

  // The Server object and all its forward-referenced children (was imported in ServerModel::create).
  steps.push_back(
    [engine, excludesPubSubTarget](ImportEngine::Completion cb)
    {
      engine->import_node_and_forward_refs_async(
        NodeId{ObjectId::Server}, {}, excludesPubSubTarget, std::move(cb));
    });

  // DefaultHAConfiguration is declared with an inverse Organizes reference to Server, so the
  // forward-only Server reachability walk above cannot discover it. Import the standard singleton
  // and its mandatory AggregateConfiguration children explicitly. Importing its inverse reference
  // also materializes the Server -> DefaultHAConfiguration browse edge.
  steps.push_back(
    [engine, excludesPubSubTarget](ImportEngine::Completion cb)
    {
      engine->import_node_and_forward_refs_async(
        NodeId{ObjectId::DefaultHAConfiguration}, {}, excludesPubSubTarget, std::move(cb));
    });

  // The aggregate-function objects (NS0 i=2341.. etc.) are orphan nodes in the NodeSet - no folder
  // references them - so the reachability-based import above skips them. Import each aggregate the
  // built-in calculator supports by id, so it exists as a browsable AggregateFunctionType object with
  // its NS0 BrowseName. HistoryServerCapabilities advertising (write_history_capabilities) then
  // Organizes the supported set into the AggregateFunctions folder when a raw-history delegate is
  // present. Per-aggregate import failures are tolerated (a trimmed NodeSet simply advertises less).
  for (const auto& aggregateId : aggregates::AggregatorRegistry::instance().supported())
  {
    steps.push_back(
      [engine, aggregateId](ImportEngine::Completion cb)
      {
        engine->import_node_async(
          aggregateId, {}, [cb = std::move(cb)](VoidResult) mutable { cb(VoidResult{}); });
      });
  }

  // Drive the chain to completion, blocking ONCE on the startup thread (D-T). The engine's posted
  // steps drain on the executor's threads, so this is refused on one of them.
  auto result = drive_import_steps_sync(executor(), std::move(steps));
  if (result.is_bad())
  {
    throw UaException(result.status_code());
  }
}

void ServerImpl::create_crypto_components()
{
  const auto& trustLists = mConfig.application->file_trust_list_configuration();

  if (!mDefaultApplicationGroupCertificateStore)
  {
    mDefaultApplicationGroupCertificateStore = CertificateStoreFiles::create(mExecutor,
      mCrypto,
      {.trustListPath = trustLists.defaultApplicationGroupTrustListPath,
        .validationOptions = trustLists.defaultApplicationGroupTrustListValidationOptions,
        .refreshPeriod = trustLists.trustListRefreshPeriod,
        .storeRejectedCertificates = trustLists.storeRejectedCertificates,
        .maxRejectedCertificates = trustLists.maxRejectedCertificates,
        .logger = mLogger});
  }

  // The user-token store is built here rather than on first X.509 activation so that an unreadable
  // trust list fails at start-up, where an operator sees it, instead of surfacing as a rejected
  // login. A host-supplied store wins outright: two CertificateStore instances over one directory
  // would each cache, refresh, and write rejected certificates independently.
  mUserTokenCertificateStore = mComponents.userTokenCertificateStore;
  if (!mUserTokenCertificateStore && trustLists.defaultUserTokenGroupTrustListPath)
  {
    mUserTokenCertificateStore = CertificateStoreFiles::create(mExecutor,
      mCrypto,
      {.trustListPath = *trustLists.defaultUserTokenGroupTrustListPath,
        .validationOptions = trustLists.defaultUserTokenGroupTrustListValidationOptions,
        .refreshPeriod = trustLists.trustListRefreshPeriod,
        .storeRejectedCertificates = trustLists.storeRejectedCertificates,
        .maxRejectedCertificates = trustLists.maxRejectedCertificates,
        // This list holds User Certificates, so OPC 10000-6 section 6.2.3 Table 44 governs it and not
        // section 6.2.2 Table 43. Leaving it on the ApplicationInstance default would require every user
        // certificate to carry nonRepudiation and dataEncipherment, which Table 44 never asks for
        // and which ordinary CA-issued client certificates do not have.
        .use = CertificateUse::User,
        .logger = mLogger});
  }
}

void ServerImpl::initialise_next_secure_channel_id()
{
  Random<uint32_t> random;
  mNextSecureChannelId = random();
}

namespace
{

bool role_selected(const std::optional<std::vector<WellKnownRole>>& selection, WellKnownRole role) noexcept
{
  if (!selection)
  {
    return true;
  }
  return std::find(selection->begin(), selection->end(), role) != selection->end();
}

void seed_well_known_roles(
  RoleConfiguration& config, const std::optional<std::vector<WellKnownRole>>& selection)
{
  for (const auto role : well_known_roles())
  {
    if (!role_selected(selection, role))
    {
      continue;
    }
    const NodeId roleId = well_known_role_node_id(role);
    if (config.role_bit(roleId).has_value())
    {
      continue;  // caller pre-populated this slot - leave it alone.
    }
    RoleConfiguration::RoleDefinition def;
    def.roleId = roleId;
    def.roleBit = *well_known_role_bit(role);
    if (role == WellKnownRole::Anonymous)
    {
      // Part 18 4.3 L408-414: Anonymous Role ships with both the
      // `Anonymous` AND the `AuthenticatedUser` default mapping rules.
      // CTT v1.05.06 `Security Role Well Known Group 2/002.js`
      // cert-enforces both - without the second rule, any authenticated
      // caller would lose access to anything granted only to Anonymous.
      IdentityMappingRuleType anonRule;
      anonRule.criteria_type() = IdentityCriteriaType::Anonymous;
      def.identities.push_back(std::move(anonRule));
      IdentityMappingRuleType authRule;
      authRule.criteria_type() = IdentityCriteriaType::AuthenticatedUser;
      def.identities.push_back(std::move(authRule));
    }
    else if (role == WellKnownRole::AuthenticatedUser)
    {
      IdentityMappingRuleType rule;
      rule.criteria_type() = IdentityCriteriaType::AuthenticatedUser;
      def.identities.push_back(std::move(rule));
    }
    else if (role == WellKnownRole::TrustedApplication)
    {
      // Part 18 4.4.3 (1.05.04+): the TrustedApplication Role is granted to
      // any Session whose ApplicationInstanceCertificate is trusted. Seed it
      // with the matching `TrustedApplication` identity criteria so a
      // trusted-application Session is granted the Role automatically - the
      // same self-seeding pattern as Anonymous / AuthenticatedUser.
      IdentityMappingRuleType rule;
      rule.criteria_type() = IdentityCriteriaType::TrustedApplication;
      def.identities.push_back(std::move(rule));
    }
    // Other well-known roles ship with empty rule lists (no caller matches
    // them) - runtime configuration adds rules via Method handlers in Cut 5.
    if (!config.add_role(std::move(def)))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("WellKnownRoleSeedCollision",
          "A well-known Role could not be registered because its bit slot collides",
          "ServerImpl")
          .context(ContextKeys::nodeId, roleId.as_definition())
          .context(ContextKeys::actual, std::string{well_known_role_name(role)})};
    }
  }
}

void configure_security_admin_claim_mapping(
  RoleConfiguration& config, const std::optional<std::vector<WellKnownRole>>& selection)
{
  constexpr WellKnownRole mappedRole = WellKnownRole::SecurityAdmin;
  if (!role_selected(selection, mappedRole))
  {
    return;
  }

  const NodeId roleId = well_known_role_node_id(mappedRole);
  auto definition = config.get_role(roleId);
  if (!definition)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("ClaimMappedRoleNotRegistered",
        "Claim-to-Role mapping was enabled but SecurityAdmin was not registered",
        "ServerImpl")
        .context(ContextKeys::nodeId, roleId.as_definition())};
  }

  IdentityMappingRuleType claimRule;
  claimRule.criteria_type() = IdentityCriteriaType::Role;
  claimRule.criteria() = String{well_known_role_name(mappedRole)};
  const bool ruleAlreadyPresent = std::any_of(definition->identities.begin(),
    definition->identities.end(),
    [&](const IdentityMappingRuleType& existing)
    {
      return existing.criteria_type() == claimRule.criteria_type() &&
             existing.criteria() == claimRule.criteria();
    });
  if (!ruleAlreadyPresent)
  {
    definition->identities.push_back(std::move(claimRule));
  }
  definition->customConfiguration = true;
  if (!config.add_role(std::move(*definition)))
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build(
        "ClaimMappedRoleUpdateFailed", "SecurityAdmin claim mapping could not be installed", "ServerImpl")
        .context(ContextKeys::nodeId, roleId.as_definition())};
  }
}

}  // namespace

std::vector<NodeId> ServerImpl::prepare_role_configuration()
{
  if (!mComponents.roleConfiguration)
  {
    return {};
  }

  mRoleConfiguration = mComponents.roleConfiguration;
  seed_well_known_roles(*mRoleConfiguration, mConfig.server.wellKnownRoles);
  if (mConfig.server.enableClaimToRoleMapping)
  {
    configure_security_admin_claim_mapping(*mRoleConfiguration, mConfig.server.wellKnownRoles);
  }
  return mRoleConfiguration->consume_role_management_access_roles();
}

void ServerImpl::wire_role_configuration()
{
  if (mRoleConfiguration)
  {
    // NS0 import has already authored the Part-18 access policy. Materialise RoleConfiguration state
    // into the per-role Variables and add any configured custom Role Objects.
    populate_role_set(mAddressSpace, *mRoleConfiguration, mConfig.server.wellKnownRoles);

    // Install the materialised well-known-Role policy as the enforcement default for NS0 and NS1,
    // and mirror that exact array to the shipped NS0 metadata Object. Publication and enforcement
    // must never derive independently.
    install_server_namespace_defaults(mAddressSpace, *mRoleConfiguration, mConfig.server.wellKnownRoles);

    // Spec-prescribed Q-RBAC method-management gating: when role
    // management is enabled, attach Call handlers for the 6 per-role
    // Methods + the RoleSet AddRole/RemoveRole, plus write notifiers
    // on the *Exclude flags. When disabled, the underlying methods stay
    // un-handled and resolve to `Bad_NotExecutable` via the default
    // dispatcher.
    if (mConfig.server.roleManagementEnabled)
    {
      attach_role_management_handlers(mAddressSpace,
        mRoleConfiguration,
        std::weak_ptr<EventBus>{mEventBus},
        mConfig.application->application_description_part().applicationUri,
        mConfig.server.wellKnownRoles);
    }
  }
}

void ServerImpl::validate_configuration(const ::ua::ApplicationConfig& configuration)
{
  const size_t minBufferSize{ua::connection_protocol::nonEccMinBufferSize};

  auto& limits = configuration.stack_limits().connectionProtocolLimits;

  if (limits.maxBufferSize < minBufferSize)
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build(
        "BufferSizeTooSmall", "Send/receive buffer size is below the minimum allowed", "ServerImpl")
        .context(ua::ContextKeys::sizeMin, std::to_string(minBufferSize))
        .context(ua::ContextKeys::sizeActual, std::to_string(limits.maxBufferSize))};
  }
}

// std::string ServerImpl::create_url(const EndpointConfig& endpointConfig)
// {
//   return std::string{"opc.tcp://"} + hostname_as_string(endpointConfig) + std::string{":"} +
//          std::to_string(endpointConfig.mPort) + endpointConfig.mUrlPostfix;
// }

std::set<CertificateType> ServerImpl::required_certificate_types(
  const std::vector<ServerEndpointConfig>& endpoints, bool includeNoneEndpointTokenTypes)
{
  std::set<CertificateType> requiredTypes;
  for (const auto& ep : endpoints)
  {
    const bool noneEndpoint =
      ep.securityPolicyId == SecurityPolicyId::None || ep.securityPolicyId == SecurityPolicyId::Invalid;
    if (!noneEndpoint)
    {
      auto policy = SecurityPolicy::create(ep.securityPolicyId);
      auto certType = policy->certificate_type();
      if (certType != CertificateType::Invalid)
        requiredTypes.insert(certType);
    }
    if (noneEndpoint && !includeNoneEndpointTokenTypes)
      continue;
    for (const auto& tokenPolicy : ep.userIdentityTokens)
    {
      const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
      if (tokenPolicyUri.empty())
        continue;
      auto tokenPolicyId = utils::get_security_policy_id(tokenPolicyUri);
      if (tokenPolicyId == SecurityPolicyId::None || tokenPolicyId == SecurityPolicyId::Invalid)
        continue;
      auto policy = SecurityPolicy::create(tokenPolicyId);
      auto certType = policy->certificate_type();
      if (certType != CertificateType::Invalid)
        requiredTypes.insert(certType);
    }
  }
  return requiredTypes;
}

void ServerImpl::validate_endpoint_certificates(const std::vector<ServerEndpointConfig>& endpoints,
  const std::vector<CertificateStore::ApplicationCertificate>& available)
{
  // A None endpoint needs no certificate of each token policy's own type: it needs one held certificate valid
  // for every token policy (OPC 10000-4 Table 193, OPC 10000-6 6.8.3; decision BR-15), which
  // check_own_certificates_for_endpoints verifies.
  const auto requiredTypes = required_certificate_types(endpoints, /*includeNoneEndpointTokenTypes=*/false);
  if (requiredTypes.empty())
    return;

  std::set<CertificateType> availableTypes;
  for (const auto& cert : available)
    availableTypes.insert(cert.certificateType);

  std::vector<std::string> missing;
  for (auto requiredType : requiredTypes)
  {
    if (!availableTypes.contains(requiredType))
      missing.push_back(fmt::format("CertificateType({})", utils::to_underlying(requiredType)));
  }

  if (!missing.empty())
  {
    throw UaException{Status::BadConfigurationError,
      ErrorDetail::build("MissingCertificates",
        "Server endpoints require certificate types not present in the store",
        "ServerImpl")
        .context(ua::ContextKeys::typeName, fmt::format("{}", fmt::join(missing, ", ")))};
  }

  // Mixed RSA key length check: if an endpoint has both RsaMinApplication and RsaSha256Application
  // user token policies, the RsaSha256Application cert key must be <= 2048 bits (RsaMin max).
  for (const auto& ep : endpoints)
  {
    bool hasRsaMin = false;
    bool hasRsaSha256 = false;
    for (const auto& tokenPolicy : ep.userIdentityTokens)
    {
      const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
      if (tokenPolicyUri.empty())
        continue;
      auto tokenPolicyId = utils::get_security_policy_id(tokenPolicyUri);
      auto policy = SecurityPolicy::create(tokenPolicyId);
      auto certType = policy->certificate_type();
      if (certType == CertificateType::RsaMinApplication)
        hasRsaMin = true;
      else if (certType == CertificateType::RsaSha256Application)
        hasRsaSha256 = true;
    }
    if (hasRsaMin && hasRsaSha256)
    {
      // Find the RsaSha256Application cert and check its key length.
      for (const auto& cert : available)
      {
        if (cert.certificateType == CertificateType::RsaSha256Application && cert.certificate)
        {
          auto keyBits = cert.certificate->public_key_bit_length();
          if (keyBits > 2048)
          {
            throw UaException{Status::BadConfigurationError,
              ErrorDetail::build("MixedRsaKeyTooLarge",
                "RsaSha256Application certificate key length exceeds the RsaMin maximum when both "
                "RsaMin and RsaSha256 user token policies are present",
                "ServerImpl")
                .context(ua::ContextKeys::actual, std::to_string(keyBits))
                .context(ua::ContextKeys::max, std::to_string(2048))};
          }
          break;
        }
      }
    }
  }
}

}  // namespace ua::server
