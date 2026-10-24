// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "misbehaving_server.h"

// Server-side test interfaces (test-only; never exposed publicly). These live in tests/helpers and the
// server implementation tree, both of which are on the integration_tests include path. This file is
// cross-listed into integration_tests only (NOT into the opcua-fuzzer executable), so those
// test-only dependencies are always satisfied where it is compiled.
#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_server_impl.h"

#include "ua_built_in_authenticators.h"
#include "ua_role_configuration.h"
#include "ua_certificate_store_files.h"
#include "ua_crypto.h"
#include "ua_exceptions.h"
#include "ua_message_security_mode.h"
#include "ua_secure_channel_context.h"
#include "ua_security_policy.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_server_authentication.h"
#include "ua_transport_address.h"

// Response body types the mutators reach into.
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_response.h"
#include "ua_open_secure_channel_response.h"
#include "ua_publish_response.h"
#include "ua_read_response.h"
#include "ua_republish_response.h"

#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include <cstddef>
#include <filesystem>
#include <thread>
#include <utility>
#include <vector>

namespace ua::test_helpers
{

// ---------------------------------------------------------------------------------------------
// Shared, mutex-guarded scenario state.
//
// Risk mitigation #3 (cross-thread state): scenario configuration (the mutator slots) is written by
// the test thread; the counters and observed data are written on a channel strand and read back by
// the test thread. Every one of those fields is guarded by `mutex`. The fixture and every installed
// interceptor co-own this object through a `shared_ptr` (mitigation #2), so a strand turn that runs
// during teardown still touches a live, synchronized object rather than a destroyed fixture.
// ---------------------------------------------------------------------------------------------
namespace detail
{
struct MisbehavingServerState
{
  mutable std::mutex mutex;

  // Configuration (written by the test thread, read on the strand).
  //
  // Raw mutators COMPOSE: every setter that installs a `ua::Response&` mutator (set_response_mutator,
  // set_service_result, inject_sequence_gap, bad_subscription_id_on_republish,
  // drop_available_sequence_numbers) APPENDS to this ordered list rather than overwriting a single
  // slot, so combining scenarios keeps every effect. run_interceptor invokes them in registration
  // order. The nonce transform is a distinct, single slot (it targets a different response field).
  std::vector<std::function<void(ua::Response&)>> rawMutators;
  std::function<ua::ByteString(const OpnNonceContext&)> nonceTransform;
  bool unbindIssueResponse{false};

  // Request-side observers (the counterpart to rawMutators): invoked on the channel strand for every
  // decoded service request. Read-only; each observer captures its own synchronization.
  std::vector<std::function<void(const ua::Structure&)>> requestObservers;

  // Observation (written on the strand, read by the test thread).
  uint64_t fireCount{0};
  std::optional<ua::ByteString> observedIssueNonce;
  std::optional<std::string> lastMutatorError;
};
}  // namespace detail

namespace
{

// Per-channel, strand-local observation. Created once per accepted channel and captured by that
// channel's interceptor, so its fields are only ever touched on that one channel's strand and need no
// additional locking. Cross-channel/test-thread reads go through ScenarioState instead.
struct ChannelObservation
{
  uint32_t opnResponseCount{0};
  ua::ByteString issueNonce;
  /// The channel's context, which the channel creates once and keeps for its life.
  std::weak_ptr<ua::SecureChannelContext> context;
};

// Record a mutator-boundary failure. Never called while a user mutator is running.
void record_mutator_error(const std::shared_ptr<detail::MisbehavingServerState>& state, std::string what)
{
  std::lock_guard lock(state->mutex);
  state->lastMutatorError = std::move(what);
}

// The interceptor body. Runs on the channel strand, BEFORE signing/encryption.
//
// Risk mitigation #1 (throw-in-asio-handler = process abort): every invocation of a user-supplied
// mutator is wrapped in try/catch here, at the fixture boundary. A throwing mutator is recorded and
// swallowed  -  it is never allowed to unwind out of the asio handler.
void run_interceptor(const std::shared_ptr<detail::MisbehavingServerState>& state,
  const std::shared_ptr<ChannelObservation>& channelObs, ua::Response& response)
{
  // Snapshot the configured mutators under the lock, then release it before invoking them
  // (callback-safety: never run a user callback while holding a mutex).
  std::vector<std::function<void(ua::Response&)>> rawMutators;
  std::function<ua::ByteString(const OpnNonceContext&)> nonceTransform;
  bool unbindIssueResponse = false;
  {
    std::lock_guard lock(state->mutex);
    ++state->fireCount;
    rawMutators = state->rawMutators;
    nonceTransform = state->nonceTransform;
    unbindIssueResponse = state->unbindIssueResponse;
  }

  // OpenSecureChannelResponse: per-channel occurrence tracking + optional nonce rewrite.
  if (auto* opn = dynamic_cast<ua::OpenSecureChannelResponse*>(response.second.get()))
  {
    ++channelObs->opnResponseCount;

    if (nonceTransform)
    {
      OpnNonceContext context{opn->server_nonce(), channelObs->opnResponseCount, channelObs->issueNonce};
      try
      {
        opn->server_nonce() = nonceTransform(context);
      }
      catch (const std::exception& ex)
      {
        record_mutator_error(state, std::string{"mutate_server_nonce transform threw: "} + ex.what());
      }
      catch (...)
      {
        record_mutator_error(state, "mutate_server_nonce transform threw a non-std exception");
      }
    }

    // The encoder binds a response to the request's Signature only while the channel has no ChannelThumbprint
    // (no first response sent yet); one in place before the Issue response is encoded makes the encoder sign
    // that response alone. The interceptor runs before the encode, on the channel strand that owns the
    // context.
    if (unbindIssueResponse && channelObs->opnResponseCount == 1)
    {
      if (const auto context = channelObs->context.lock())
        context->channelThumbprint = ua::ByteString(1, uint8_t{0});
    }

    // Record the nonce the client actually receives on the Issue response, so a later renewal can
    // replay it (CL-SC-016). Captured AFTER the transform, so it matches what the client stores.
    if (channelObs->opnResponseCount == 1)
    {
      channelObs->issueNonce = opn->server_nonce();
      std::lock_guard lock(state->mutex);
      state->observedIssueNonce = channelObs->issueNonce;
    }
  }

  // Raw explicit override / typed header mutators, invoked in registration order so composed scenarios
  // (e.g. set_service_result + a set_response_mutator) each take effect. Each is isolated: one
  // mutator throwing is recorded and swallowed, and the remaining mutators still run.
  for (const auto& rawMutator : rawMutators)
  {
    if (!rawMutator)
      continue;
    try
    {
      rawMutator(response);
    }
    catch (const std::exception& ex)
    {
      record_mutator_error(state, std::string{"response mutator threw: "} + ex.what());
    }
    catch (...)
    {
      record_mutator_error(state, "response mutator threw a non-std exception");
    }
  }
}

// The request-observer body. Runs on the channel strand at the top of request handling. Every observer is
// wrapped in try/catch at the fixture boundary (a throwing observer would abort the asio handler); a throw is
// recorded and swallowed, and the remaining observers still run.
void run_request_observers(
  const std::shared_ptr<detail::MisbehavingServerState>& state, const ua::Structure& request)
{
  std::vector<std::function<void(const ua::Structure&)>> observers;
  {
    std::lock_guard lock(state->mutex);
    observers = state->requestObservers;
  }
  for (const auto& observer : observers)
  {
    if (!observer)
      continue;
    try
    {
      observer(request);
    }
    catch (const std::exception& ex)
    {
      record_mutator_error(state, std::string{"request observer threw: "} + ex.what());
    }
    catch (...)
    {
      record_mutator_error(state, "request observer threw a non-std exception");
    }
  }
}

// Stamp ResponseHeader.serviceResult on the service-response types Phase 1 recognises. The type
// system has no common response-header base, so this is a curated (extensible) ladder. The
// secure-channel handshake responses are intentionally absent  -  stamping them would break the open  -
// as are all types not listed, which pass through unchanged.
void apply_service_result(ua::Structure& body, ua::StatusCode status)
{
  if (auto* r = dynamic_cast<ua::GetEndpointsResponse*>(&body))
  {
    r->response_header().service_result() = status;
  }
  else if (auto* r = dynamic_cast<ua::FindServersResponse*>(&body))
  {
    r->response_header().service_result() = status;
  }
  else if (auto* r = dynamic_cast<ua::ReadResponse*>(&body))
  {
    r->response_header().service_result() = status;
  }
}

// Resolve the server thread-pool size. `std::nullopt` reproduces boost::asio::thread_pool's own
// default (hardware_concurrency * 2, floored at 2), so the default path is behaviourally identical to
// the previously default-constructed pool. A test may force a specific count (e.g. 1).
std::size_t resolve_server_thread_count(std::optional<std::size_t> requested)
{
  if (requested.has_value())
    return *requested;
  const std::size_t doubled = static_cast<std::size_t>(std::thread::hardware_concurrency()) * 2;
  return doubled == 0 ? 2 : doubled;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Owned server + PKI. Mirrors the ComplianceSecured integration fixture's build, kept self-contained
// so the fixture truly owns its server (design section 4/section 5).
// ---------------------------------------------------------------------------------------------
struct MisbehavingServer::Impl
{
  Config config;

  // Sized by resolve_server_thread_count: hardware-sized by default, or a fixed count for tests. The
  // interceptor install is non-blocking, so even a single worker is safe.
  boost::asio::thread_pool serverThreadPool;

  // The PKI stores get their OWN executor rather than sharing the server's.
  //
  // ServerImpl::start_network_surfaces validates the endpoint certificates while running on a server
  // worker, and it does so through CertificateStore::try_get_application_certificates_sync, which posts
  // to the store's executor and blocks on the future. Point the store at the server's pool and, on a
  // single-threaded server, the only worker blocks waiting for work that only it could run: start never
  // returns. Separating the executors keeps this fixture's thread count a property of the SERVER under
  // test rather than a constraint the PKI imposes on it.
  boost::asio::thread_pool pkiThreadPool{2};

  std::shared_ptr<const ua::Crypto> crypto;
  std::shared_ptr<const ua::X509Certificate> serverCert;
  std::shared_ptr<ua::CertificateStore> serverCertStore;
  std::shared_ptr<ua::CertificateStore> clientCertStore;
  std::filesystem::path tempDir;

  std::optional<ua::server::Server> server;
  ua::server::ListenerHandle listenerHandle{0};
  std::string endpointUrl;

  explicit Impl(Config config, std::size_t serverThreadCount)
    : config(config), serverThreadPool(serverThreadCount)
  {}

  ~Impl()
  {
    // Risk mitigation #2 (lifetime): close and drain the server BEFORE the shared ScenarioState is
    // released (the fixture releases mState only after this Impl is destroyed). Draining joins the
    // pool, so no interceptor turn can still be running when mState goes away.
    if (server)
    {
      (void)server->try_shutdown_sync({.grace = std::chrono::seconds{0}});
      server.reset();
    }
    ua::test_utils::drain_with_timeout(serverThreadPool);
    ua::test_utils::drain_with_timeout(pkiThreadPool);

    std::error_code ec;
    std::filesystem::remove_all(tempDir, ec);
  }
};

MisbehavingServer::MisbehavingServer() : MisbehavingServer(Config{})
{}

MisbehavingServer::MisbehavingServer(Config config, std::optional<std::size_t> serverThreadCount)
  : mState(std::make_shared<detail::MisbehavingServerState>()),
    mImpl(std::make_unique<Impl>(config, resolve_server_thread_count(serverThreadCount)))
{
  using namespace ua;
  using namespace ua::server;

  mImpl->crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

  // Server + client application instance certificates.
  const UtcTime expiry{2050, 1, 1, 0, 0, 0};

  Crypto::Name serverSubject;
  serverSubject.commonName = "MisbehavingServer";
  Crypto::SubjectAlternateName serverAltName;
  serverAltName.uris.push_back("urn:test:misbehaving:server");
  serverAltName.hostnames.push_back("localhost");
  serverAltName.hostnames.push_back("127.0.0.1");
  auto serverCertResult = mImpl->crypto->try_create_self_signed_application_instance_certificate_sync(
    serverSubject, expiry, serverAltName, CertificateType::RsaSha256Application, 2048);
  if (serverCertResult.is_bad())
    throw ua::UaException(serverCertResult.status_code());
  auto [serverKeys, serverCert] = std::move(serverCertResult).value();
  mImpl->serverCert = serverCert;

  Crypto::Name clientSubject;
  clientSubject.commonName = "MisbehavingServer Client";
  Crypto::SubjectAlternateName clientAltName;
  clientAltName.uris.push_back("urn:test:misbehaving:client");
  clientAltName.hostnames.push_back("localhost");
  auto clientCertResult = mImpl->crypto->try_create_self_signed_application_instance_certificate_sync(
    clientSubject, expiry, clientAltName, CertificateType::RsaSha256Application, 2048);
  if (clientCertResult.is_bad())
    throw ua::UaException(clientCertResult.status_code());
  auto [clientKeys, clientCert] = std::move(clientCertResult).value();

  mImpl->tempDir = std::filesystem::temp_directory_path() /
                   ("ua_misbehaving_server_" + Guid::create_and_generate().as_string());
  std::filesystem::create_directories(mImpl->tempDir);

  TrustListValidationOptions validationOptions;

  // Server store: holds the server app cert, trusts the client cert.
  auto serverStorePath = mImpl->tempDir / "server_store";
  std::filesystem::create_directories(serverStorePath);
  mImpl->serverCertStore = CertificateStoreFiles::create(mImpl->pkiThreadPool.executor(),
    mImpl->crypto,
    {.trustListPath = serverStorePath, .validationOptions = validationOptions});
  const auto& scenario = mImpl->config.certificateScenario;
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = mImpl->serverCert;
    appCert.keys = std::move(serverKeys);
    if (scenario.has_value() && scenario->certificate)
    {
      // Fixture-only: the scenario's certificate, possibly non-compliant, with its chain (decision 24).
      mImpl->serverCert = scenario->certificate;
      appCert.certificateType = scenario->certificateType;
      appCert.certificate = scenario->certificate;
      appCert.keys = scenario->keys;
      appCert.issuerCertificates = scenario->issuerCertificates;
    }
    mImpl->serverCertStore->add_to_application_certificates_sync(appCert);
  }
  mImpl->serverCertStore->add_to_trusted_certificates_sync(clientCert);
  if (scenario.has_value())
  {
    for (const auto& trusted : scenario->trustedCertificates)
      mImpl->serverCertStore->add_to_trusted_certificates_sync(trusted);
  }

  // Client store: holds the client app cert, trusts the server cert. Exposed for a matching client.
  auto clientStorePath = mImpl->tempDir / "client_store";
  std::filesystem::create_directories(clientStorePath);
  mImpl->clientCertStore = CertificateStoreFiles::create(mImpl->pkiThreadPool.executor(),
    mImpl->crypto,
    {.trustListPath = clientStorePath, .validationOptions = validationOptions});
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = clientCert;
    appCert.keys = std::move(clientKeys);
    mImpl->clientCertStore->add_to_application_certificates_sync(appCert);
  }
  mImpl->clientCertStore->add_to_trusted_certificates_sync(mImpl->serverCert);

  // Server application configuration. A small minimum secure-channel lifetime lets renewal-driven
  // scenarios (CL-SC-016) fire within a bounded test.
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  if (scenario.has_value() && !scenario->applicationUri.empty())
    appCfg.application_description_part().applicationUri = scenario->applicationUri;
  appCfg.stack_limits().secureChannelMinimumLifetime = mImpl->config.secureChannelMinimumLifetime;

  ServerComponents components;
  components.crypto = mImpl->crypto;
  components.applicationGroupCertificateStore = mImpl->serverCertStore;
  components.authenticator = std::make_shared<AnonymousAuthenticator>();
  components.logLevel = LogLevel::Warning;
  components.roleConfiguration = ua::server::RoleConfiguration::from_well_known_grants(
    {{ua::server::WellKnownRole::SecurityAdmin, ua::IdentityCriteriaType::Anonymous}});

  CreateConfig serverCreateCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  mImpl->server.emplace(
    Server::create(mImpl->serverThreadPool.executor(), std::move(serverCreateCfg), std::move(components)));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  mImpl->listenerHandle = mImpl->server->listen_sync(std::move(bind), {});

  ServerEndpointConfig noneEp;
  noneEp.name = "None";
  noneEp.messageSecurityMode = MessageSecurityMode::None;
  noneEp.securityPolicyId = SecurityPolicyId::None;
  noneEp.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  mImpl->server->add_endpoint(mImpl->listenerHandle, std::move(noneEp));

  ServerEndpointConfig signEncryptEp;
  signEncryptEp.name = "Basic256Sha256_SignAndEncrypt";
  signEncryptEp.messageSecurityMode =
    scenario.has_value() ? scenario->securedMode : MessageSecurityMode::SignAndEncrypt;
  signEncryptEp.securityPolicyId =
    scenario.has_value() ? scenario->securedPolicy : SecurityPolicyId::Basic256Sha256;
  signEncryptEp.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  mImpl->server->add_endpoint(mImpl->listenerHandle, std::move(signEncryptEp));

  // Install the per-channel response-interceptor scoping hook (the Phase-1 default scope) BEFORE
  // start(), so it is present for the very first channel.
  //
  // The set_on_secure_channel_available callback runs on a server worker thread (NOT the new channel's
  // strand). The install is therefore NON-BLOCKING: it posts the "set_response_interceptor" work to
  // the channel's strand (SecureChannelTestAccess::post_on_strand) and returns immediately, so it can
  // never wedge a worker on a same-strand post  -  the fixture is safe on an executor of any size,
  // including a single worker. Correctness rests on channel-strand FIFO ordering: this callback fires
  // synchronously, right after SecureChannel::create returns, and the channel's first message-pump
  // turn is only enqueued to the strand once the client sends its first message (post-ACK, a network
  // round trip later), so the interceptor-install post always precedes it  -  the interceptor is in
  // place before the first response is produced. The shared_ptr overload keeps the channel alive until
  // the install runs; the interceptor captures the shared ScenarioState by value (never a raw `this`).
  auto& serverImpl = ServerTestAccess::impl(*mImpl->server);
  ServerImplTestAccess(serverImpl)
    .set_on_secure_channel_available(
      [state = mState](std::shared_ptr<ua::server::SecureChannel> secureChannel)
      {
        auto channelObs = std::make_shared<ChannelObservation>();
        ua::server::SecureChannelTestAccess::post_on_strand(std::move(secureChannel),
          [state, channelObs](auto& guard)
          {
            channelObs->context = guard.context();
            guard.set_response_interceptor(
              [state, channelObs](ua::Response& response) { run_interceptor(state, channelObs, response); });
            // Request-side observation (the BrowseNext continuation-point / releaseContinuationPoints flag,
            // and the ABSENCE of a BrowseNext) is installed on the same strand-ordered hook.
            guard.set_request_observer([state](uint32_t /*requestId*/, const ua::Structure& request)
              { run_request_observers(state, request); });
          });
      });

  // Fixture-only: a scenario certificate may violate the endpoint policy on purpose (approved decision F
  // would refuse to start).
  if (scenario.has_value())
    ServerImplTestAccess(serverImpl).bypass_own_certificate_policy_check();

  mImpl->server->start_sync();

  auto urls = mImpl->server->advertised_urls(mImpl->listenerHandle);
  if (urls.empty())
    throw ua::UaException(ua::StatusCode{ua::Status::BadInternalError});
  mImpl->endpointUrl = urls.front().str();
}

MisbehavingServer::~MisbehavingServer()
{
  // Ordered teardown (risk mitigation #2): destroy the Impl first  -  its destructor closes and drains
  // the server, so no interceptor turn is in flight  -  then release the shared ScenarioState.
  mImpl.reset();
  mState.reset();
}

MisbehavingServer& MisbehavingServer::per_channel()
{
  // Per-channel is the default scope, installed at construction. Nothing to do here; provided for a
  // fluent, self-documenting call site.
  return *this;
}

void MisbehavingServer::set_response_mutator(std::function<void(ua::Response&)> mutator)
{
  std::lock_guard lock(mState->mutex);
  mState->rawMutators.push_back(std::move(mutator));
}

void MisbehavingServer::mutate_server_nonce(std::function<ua::ByteString(const OpnNonceContext&)> transform)
{
  std::lock_guard lock(mState->mutex);
  mState->nonceTransform = std::move(transform);
}

void MisbehavingServer::sign_issue_response_without_request_signature()
{
  std::lock_guard lock(mState->mutex);
  mState->unbindIssueResponse = true;
}

void MisbehavingServer::set_request_observer(std::function<void(const ua::Structure&)> observer)
{
  std::lock_guard lock(mState->mutex);
  mState->requestObservers.push_back(std::move(observer));
}

void MisbehavingServer::set_service_result(ua::StatusCode status)
{
  std::lock_guard lock(mState->mutex);
  mState->rawMutators.push_back(
    [status](ua::Response& response)
    {
      if (response.second)
        apply_service_result(*response.second, status);
    });
}

void MisbehavingServer::inject_sequence_gap(ua::IntegerId subscriptionId, uint32_t skip)
{
  std::lock_guard lock(mState->mutex);
  mState->rawMutators.push_back(
    [subscriptionId, skip](ua::Response& response)
    {
      if (auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get()))
      {
        if (publish->subscription_id() == subscriptionId)
          publish->notification_message().sequence_number() += skip;
      }
    });
}

void MisbehavingServer::bad_subscription_id_on_republish()
{
  std::lock_guard lock(mState->mutex);
  mState->rawMutators.push_back(
    [](ua::Response& response)
    {
      if (auto* republish = dynamic_cast<ua::RepublishResponse*>(response.second.get()))
        republish->response_header().service_result() = ua::StatusCode{ua::Status::BadSubscriptionIdInvalid};
    });
}

void MisbehavingServer::drop_available_sequence_numbers()
{
  std::lock_guard lock(mState->mutex);
  mState->rawMutators.push_back(
    [](ua::Response& response)
    {
      if (auto* publish = dynamic_cast<ua::PublishResponse*>(response.second.get()))
        publish->available_sequence_numbers().clear();
    });
}

uint64_t MisbehavingServer::interceptor_fire_count() const
{
  std::lock_guard lock(mState->mutex);
  return mState->fireCount;
}

std::optional<ua::ByteString> MisbehavingServer::observed_issue_server_nonce() const
{
  std::lock_guard lock(mState->mutex);
  return mState->observedIssueNonce;
}

std::optional<std::string> MisbehavingServer::last_mutator_error() const
{
  std::lock_guard lock(mState->mutex);
  return mState->lastMutatorError;
}

std::string MisbehavingServer::endpoint_url_none() const
{
  // OPC UA advertises one URL per listener; endpoints are distinguished by security parameters on the
  // client's OpenChannelConfig, not by URL.
  return mImpl->endpointUrl;
}

std::string MisbehavingServer::endpoint_url_sign_encrypt() const
{
  return mImpl->endpointUrl;
}

std::shared_ptr<const ua::Crypto> MisbehavingServer::crypto() const
{
  return mImpl->crypto;
}

std::shared_ptr<ua::CertificateStore> MisbehavingServer::client_certificate_store() const
{
  return mImpl->clientCertStore;
}

std::shared_ptr<const ua::X509Certificate> MisbehavingServer::server_certificate() const
{
  return mImpl->serverCert;
}

ua::server::Server& MisbehavingServer::server()
{
  return *mImpl->server;
}

}  // namespace ua::test_helpers
