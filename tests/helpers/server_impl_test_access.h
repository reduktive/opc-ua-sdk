// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_SERVER_IMPL_TEST_ACCESS_H
#define UA_TESTS_HELPERS_SERVER_IMPL_TEST_ACCESS_H

#include <mutex>
#include <shared_mutex>
#include "ua_role_configuration.h"
#include "ua_server_impl.h"
#include "ua_identity_attempt_outcome.h"

namespace ua::test_helpers
{

/// Friend-based accessor for ServerImpl internals needed by tests.
/// Keeps test-only helpers out of the public ServerImpl API.
class ServerImplTestAccess
{
public:
  explicit ServerImplTestAccess(ua::server::ServerImpl& server) : mServer(server)
  {}

  void initialise_listeners_from_config()
  {
    mServer.initialise_listeners_from_config_for_tests();
  }

  /// Fixture-only (MisbehavingServer::CertificateScenario): start without checking the own certificate
  /// against the endpoint policies (approved decision F), so a misbehaving server can present a non-compliant
  /// one.
  void bypass_own_certificate_policy_check()
  {
    mServer.mBypassOwnCertificatePolicyCheckForTests = true;
  }

  void set_on_network_activation(std::function<void()> hook)
  {
    mServer.mOnNetworkActivationForTests = std::move(hook);
  }

  /// Runs after a ConnectionProtocol is created for an accepted connection and before its
  /// initialising entry is published (see ServerImpl::InitialisingSlot).
  void set_before_initialising_publication(std::function<void()> hook)
  {
    mServer.mBeforeInitialisingPublicationForTests = std::move(hook);
  }

  void add_internal_observer(std::shared_ptr<ua::server::ServerObserver> observer)
  {
    mServer.add_internal_observer(std::move(observer));
  }

  std::shared_ptr<ua::server::ServerObserver> observer() const
  {
    return mServer.observer();
  }

  std::vector<shared_ptr<ua::server::Session>> sessions() const
  {
    return mServer.sessions_for_tests();
  }

  bool session_exists(const ua::NodeId& sessionId) const
  {
    return mServer.session_exists(sessionId);
  }

  void remove_session(const shared_ptr<ua::server::Session>& session)
  {
    mServer.remove_session(session);
  }

  // The push service the server wired (null when no certificate store or crypto backend is present).
  shared_ptr<ua::CertificatePushService> certificate_push_service() const
  {
    return mServer.mPushManagement ? mServer.mPushManagement->certificatePushService : nullptr;
  }

  size_t session_token_count() const
  {
    const std::shared_lock lock(mServer.mMutex);
    return mServer.mSessionsByToken.size();
  }

  shared_ptr<ua::server::SecureChannelDependencies> secure_channel_dependencies()
  {
    return mServer.secure_channel_dependencies();
  }

  shared_ptr<ua::server::SessionDependencies> session_dependencies()
  {
    return mServer.session_dependencies();
  }

  const ua::server::ServerConfig& server_configuration() const
  {
    return mServer.server_configuration();
  }

  void add_secure_channel(shared_ptr<ua::server::SecureChannel> sc)
  {
    mServer.add_secure_channel(std::move(sc));
  }

  void remove_secure_channel(const shared_ptr<ua::server::SecureChannel>& sc)
  {
    mServer.remove_secure_channel(sc);
  }

  size_t secure_channel_count() const
  {
    const std::shared_lock lock(mServer.mMutex);
    return mServer.mSecureChannels.size();
  }

  /// Nonblocking observation for a separate test thread checking a synchronous callback's lock context.
  bool server_mutex_available() const
  {
    const std::unique_lock lock(mServer.mMutex, std::try_to_lock);
    return lock.owns_lock();
  }

  bool holds_secure_channel(const shared_ptr<ua::server::SecureChannel>& sc) const
  {
    const std::shared_lock lock(mServer.mMutex);
    return std::ranges::find(mServer.mSecureChannels, sc) != mServer.mSecureChannels.end();
  }

  void create_session(
    ua::server::SecureChannelInfo info, uint32_t requestId, ua::CreateSessionRequest&& request)
  {
    mServer.create_session(std::move(info), requestId, std::move(request));
  }

  void set_on_session_admitted(std::function<void(ua::server::Session&)> hook)
  {
    mServer.mOnSessionAdmittedForTests = std::move(hook);
  }

  void activate_session_on_channel(
    ua::server::SecureChannelInfo info, uint32_t requestId, ua::ActivateSessionRequest&& request)
  {
    mServer.activate_session_on_channel(std::move(info), requestId, std::move(request));
  }

  void new_tcp_connection(ua::server::ListenerHandle listener, std::string listenerName, StatusCode status,
    string_view errorDescription, shared_ptr<TcpTransportConnection> connection)
  {
    mServer.new_tcp_connection(
      listener, std::move(listenerName), status, errorDescription, std::move(connection));
  }

  // The accept path with a given peer endpoint (see ServerImpl::accept_tcp_connection).
  void accept_tcp_connection(ua::server::ListenerHandle listener, std::string listenerName,
    shared_ptr<TcpTransportConnection> connection, const boost::asio::ip::tcp::endpoint& remote)
  {
    mServer.accept_tcp_connection(
      listener, std::move(listenerName), StatusCode{Status::Good}, std::move(connection), remote);
  }

  void new_connection_complete(ua::server::ListenerHandle listener, std::string listenerName,
    StatusCode status, shared_ptr<ua::ConnectionProtocol> connection,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits, std::string remoteAddress = {})
  {
    mServer.new_connection_complete(listener,
      std::move(listenerName),
      status,
      std::move(connection),
      negotiatedLimits,
      std::move(remoteAddress));
  }

  // Counter accessors.
  std::shared_ptr<ua::server::ServerSummaryCounters> summary_counters() const
  {
    return mServer.summary_counters();
  }

  std::shared_ptr<ua::server::SecureChannelCounters> secure_channel_counters() const
  {
    return mServer.secure_channel_counters();
  }

  std::shared_ptr<ua::server::ConnectionCounters> connection_counters() const
  {
    return mServer.connection_counters();
  }

  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() const
  {
    return mServer.diagnostics_enabled();
  }

  std::shared_ptr<ua::server::RequestLatencyTracker> latency_tracker() const
  {
    return mServer.latency_tracker();
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() const
  {
    return mServer.in_flight_discovery_requests();
  }

  std::shared_ptr<ua::server::ServerDynamicState> dynamic_state() const
  {
    return mServer.mDynamicState;
  }

  // S11 / SESS-2: Identity token attack protection. The production protocol is begin (reserve) then
  // finish (release with the outcome); the three shorthands below keep the older tests' vocabulary
  // and are defined in terms of it.
  optional<StatusCode> begin_identity_attempt(
    const ua::server::ClientId& client, std::string_view claimedUserId)
  {
    return mServer.begin_identity_attempt(client, claimedUserId);
  }

  void finish_identity_attempt(const ua::server::ClientId& client, std::string_view claimedUserId,
    ua::server::IdentityAttemptOutcome outcome)
  {
    mServer.finish_identity_attempt(client, claimedUserId, outcome);
  }

  /// Is the client application refused right now? An admitted probe is released at once (Abandoned).
  optional<StatusCode> check_identity_lockout(
    const ua::server::ClientId& client, std::string_view claimedUserId)
  {
    auto refusal = mServer.begin_identity_attempt(client, claimedUserId);
    if (!refusal)
    {
      mServer.finish_identity_attempt(client, claimedUserId, ua::server::IdentityAttemptOutcome::Abandoned);
    }
    return refusal;
  }

  /// One recorded failure / success for (client, user), as an attempt that began and ended.
  void record_auth_failure(const ua::server::ClientId& client, std::string_view claimedUserId)
  {
    if (mServer.begin_identity_attempt(client, claimedUserId))
      return;  // refused before validation: no guess was made, nothing to record
    mServer.finish_identity_attempt(client, claimedUserId, ua::server::IdentityAttemptOutcome::Failure);
  }

  void record_auth_success(const ua::server::ClientId& client, std::string_view claimedUserId)
  {
    if (mServer.begin_identity_attempt(client, claimedUserId))
      return;
    mServer.finish_identity_attempt(client, claimedUserId, ua::server::IdentityAttemptOutcome::Success);
  }

  /// Attempts reserved and not yet finished, summed over every tracked client application.
  uint32_t total_identity_attempts_in_flight()
  {
    const std::shared_lock<std::shared_mutex> lk(mServer.mMutex);
    uint32_t total = 0;
    for (const auto& [client, state] : mServer.mIdentityThrottleState)
      total += state.inFlight;
    return total;
  }

  /// Recorded failures, summed over every tracked client application and user.
  uint32_t total_identity_failures()
  {
    const std::shared_lock<std::shared_mutex> lk(mServer.mMutex);
    uint32_t total = 0;
    for (const auto& [client, state] : mServer.mIdentityThrottleState)
      total += state.failures();
    return total;
  }

  /// Attempts reserved and not yet finished for one client application.
  uint32_t identity_attempts_in_flight(const ua::server::ClientId& client)
  {
    const std::shared_lock<std::shared_mutex> lk(mServer.mMutex);
    const auto it = mServer.mIdentityThrottleState.find(client);
    return it == mServer.mIdentityThrottleState.end() ? 0u : it->second.inFlight;
  }

  // P1.D #7: attacker-keyed throttle-map size caps.
  void set_max_identity_throttle_entries(size_t n)
  {
    mServer.mMaxIdentityThrottleEntries = n;
  }

  size_t identity_throttle_size() const
  {
    return mServer.mIdentityThrottleState.size();
  }

  void set_max_per_ip_throttle_entries(size_t n)
  {
    mServer.mMaxPerIpThrottleEntries = n;
  }

  size_t per_ip_throttle_size() const
  {
    const std::shared_lock lock(mServer.mMutex);
    return mServer.mPerIpState.size();
  }

  /// Connections accepted on TCP whose HEL/ACK handshake has not completed yet.
  size_t initialising_connection_count() const
  {
    const std::shared_lock lock(mServer.mMutex);
    return mServer.mInitialisingConnections.size();
  }

  /// The per-IP concurrent-connection count the throttle holds for `remoteIp` (0 when untracked).
  uint32_t per_ip_active_count(const std::string& remoteIp) const
  {
    const std::shared_lock lock(mServer.mMutex);
    const auto it = mServer.mPerIpState.find(remoteIp);
    return it == mServer.mPerIpState.end() ? 0u : it->second.activeCount;
  }

  /// The connection-attempt times the throttle holds for `remoteIp` (0 when untracked).
  size_t per_ip_recent_attempt_count(const std::string& remoteIp) const
  {
    const std::shared_lock lock(mServer.mMutex);
    const auto it = mServer.mPerIpState.find(remoteIp);
    return it == mServer.mPerIpState.end() ? 0u : it->second.recentAttempts.size();
  }

  void set_on_secure_channel_available(ua::server::ServerImpl::SecureChannelAvailableCallback callback)
  {
    mServer.set_on_secure_channel_available(std::move(callback));
  }

  static void dispatch_apply_changes_channel_close(std::vector<weak_ptr<ua::server::SecureChannel>> channels,
    const std::vector<shared_ptr<ua::server::Session>>& sessions, const ua::NodeId& originSessionId,
    ua::server::MethodResponseCorrelation correlation, std::function<void(ua::VoidResult)> callback)
  {
    ua::server::ServerImpl::dispatch_apply_changes_channel_close(
      std::move(channels), sessions, originSessionId, correlation, std::move(callback));
  }

  static void validate_endpoint_certificates(const std::vector<ua::server::ServerEndpointConfig>& endpoints,
    const std::vector<ua::CertificateStore::ApplicationCertificate>& available)
  {
    ua::server::ServerImpl::validate_endpoint_certificates(endpoints, available);
  }

  static void dispatch_certificate_reevaluation(std::vector<weak_ptr<ua::server::SecureChannel>> channels,
    const std::vector<shared_ptr<ua::server::Session>>& sessions, const ua::NodeId& originSessionId,
    ua::server::MethodResponseCorrelation correlation, std::function<void(ua::VoidResult)> callback)
  {
    ua::server::ServerImpl::dispatch_certificate_reevaluation(
      std::move(channels), sessions, originSessionId, correlation, std::move(callback));
  }

  std::shared_ptr<ua::server::RoleConfiguration> role_configuration() const
  {
    return mServer.mRoleConfiguration;
  }

  ua::AddressSpace& address_space()
  {
    return mServer.mAddressSpace;
  }

private:
  ua::server::ServerImpl& mServer;
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_SERVER_IMPL_TEST_ACCESS_H
