// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.9 (Server Session).
//
// Local fakes - concrete subclasses of the production interfaces the Session
// constructor consumes. Mirrors the pattern proven in
// tests/unit/server/session/session_shell_wiring_tests.cpp; trimmed to only what
// the pin corpus needs.
//
// These are intentionally local to phase_4_9 and not promoted to tests/helpers/.
//
// All fakes implement every virtual on the production interface; methods the
// pins do not exercise return null/empty/throwing defaults so a future addition
// causes a deterministic failure rather than silent skip.

#ifndef PHASE_4_9_FAKE_SESSION_DEPENDENCIES_H
#define PHASE_4_9_FAKE_SESSION_DEPENDENCIES_H

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel.h"
#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"

#include "fake_async_crypto.h"
#include "fake_certificate_store.h"
#include "fake_discovery_dependencies.h"
#include "fake_namespace.h"

#include "ua_application_configuration.h"
#include "ua_event_bus.h"
#include "ua_security_policy.h"
#include "ua_server_configuration.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_orphaned_subscription_store.h"
#include <boost/asio/thread_pool.hpp>

#include "security/ua_server_authentication.h"
#include "ua_server_components.h"

namespace ua::test::pins_4_9
{

// ---------------------------------------------------------------------------
// FakeAuthenticator - inline-completing.
// Fires success for any non-Unsupported token, failure for Unsupported.
// ---------------------------------------------------------------------------
class AllowAnonymousAuthenticator final : public ::ua::server::UserAuthenticator
{
public:
  void authenticate_async(
    ::ua::server::AuthnRequest req, ::ua::server::AuthnComplete completion) noexcept override
  {
    (void)req;
    completion(::ua::server::make_authn_success(
      ::ua::server::UserIdentity{.userId = "anonymous", .displayName = "Anon", .claims = {}}));
  }
};

// Fails every authentication request with a configurable status + ErrorDetail.
// The detail pointer is preserved so pins can assert pointer-identity.
class DenyingAuthenticator final : public ::ua::server::UserAuthenticator
{
public:
  DenyingAuthenticator(::ua::StatusCode status, std::shared_ptr<const ::ua::ErrorDetail> detail)
    : status(status), detail(std::move(detail))
  {}

  void authenticate_async(
    ::ua::server::AuthnRequest req, ::ua::server::AuthnComplete completion) noexcept override
  {
    (void)req;
    // make_authn_failure embeds the audit string as a string detail; we route
    // through the AuthnResult constructor that accepts a shared_ptr detail so
    // pins can assert pointer-identity via the lossless propagation rule.
    ::ua::server::AuthnResult fail{status, detail};
    completion(std::move(fail));
  }

  ::ua::StatusCode status;
  std::shared_ptr<const ::ua::ErrorDetail> detail;
};

// ---------------------------------------------------------------------------
// FakeSessionDependencies - concrete SessionDependencies.
// ---------------------------------------------------------------------------
class FakeSessionDependencies final : public ::ua::server::SessionDependencies
{
public:
  FakeSessionDependencies(::boost::asio::any_io_executor ex, ::ua::server::ServerComponents hooks)
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mFakeNamespace(::ua::test_helpers::FakeNamespace::create("urn:test:fake-ns")),
      mAddressSpace(::ua::test_helpers::make_address_space_with_fake_namespace(ex, mFakeNamespace)),
      mEventBus(mAddressSpace), mFakeCrypto(::ua::test_helpers::FakeAsyncCrypto::create()),
      mFakeCertStore(::ua::test_helpers::FakeCertificateStore::create()),
      mFakeDiscoveryDeps(std::make_shared<::ua::test_helpers::FakeDiscoveryDependencies>(ex))
  {
    mFakeDiscoveryDeps->set_default_application_group_certificate_store(mFakeCertStore);
  }

  ::ua::weak_ptr<::ua::server::DiscoveryDependencies> discovery_dependencies() override
  {
    return mFakeDiscoveryDeps;
  }

  ::boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  ::ua::shared_ptr<const ::ua::Crypto> crypto() override
  {
    return mFakeCrypto;
  }

  ::ua::WeakAddressSpace address_space() override
  {
    return mAddressSpace.weak();
  }

  /// Test access - concrete fakes for explicit driving from pin tests.
  std::shared_ptr<::ua::test_helpers::FakeNamespace> fake_namespace()
  {
    return mFakeNamespace;
  }

  std::shared_ptr<::ua::test_helpers::FakeAsyncCrypto> fake_crypto()
  {
    return mFakeCrypto;
  }

  std::shared_ptr<::ua::test_helpers::FakeDiscoveryDependencies> fake_discovery_dependencies()
  {
    return mFakeDiscoveryDeps;
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return *mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  ::ua::shared_ptr<::ua::CertificateStore> default_application_group_certificate_store() override
  {
    return mFakeCertStore;
  }

  ::ua::StructureFactory& structure_factory() override
  {
    throw ::ua::UaException{::ua::Status::BadInternalError,
      ::ua::make_error_detail("TestError", "structure_factory not used", "Test")};
  }

  std::vector<::ua::server::ServerEndpointConfig> endpoints() override
  {
    return {};
  }

  void remove_session(const ::ua::shared_ptr<::ua::server::Session>&) override
  {
    removeSessionCalls.fetch_add(1);
  }

  const ::ua::server::ServerComponents& components() const override
  {
    return mHooks;
  }

  std::shared_ptr<::ua::server::ServerObserver> observer() override
  {
    return nullptr;
  }

  ::ua::Logger logger() override
  {
    return {};
  }

  std::shared_ptr<::ua::server::RequestLatencyTracker> latency_tracker() override
  {
    return nullptr;
  }

  std::shared_ptr<::ua::server::ServerSummaryCounters> summary_counters() override
  {
    return nullptr;
  }

  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() override
  {
    return nullptr;
  }

  ::ua::server::SubscriptionIdAllocator& subscription_id_allocator() override
  {
    return mSubAlloc;
  }

  ::ua::server::SubscriptionRouter& subscription_router() override
  {
    return mSubReg;
  }

  ::ua::server::OrphanedSubscriptionStore& orphaned_subscription_store() override
  {
    return mOrphanedSubscriptionStore;
  }

  ::ua::server::EventBus& event_bus() override
  {
    return mEventBus;
  }

  std::shared_ptr<::ua::server::EventBus> event_bus_shared() override
  {
    return {};
  }

  std::shared_ptr<::ua::server::NodeManagementDelegate> node_management_delegate() override
  {
    return nullptr;
  }

  std::optional<::ua::StatusCode> begin_identity_attempt(
    const ::ua::server::ClientId&, std::string_view) override
  {
    authBeginCalls.fetch_add(1);
    return std::nullopt;
  }

  void finish_identity_attempt(
    const ::ua::server::ClientId&, std::string_view, IdentityAttemptOutcome outcome) override
  {
    switch (outcome)
    {
    case IdentityAttemptOutcome::Failure:
      authFailureCalls.fetch_add(1);
      break;
    case IdentityAttemptOutcome::Success:
      authSuccessCalls.fetch_add(1);
      break;
    case IdentityAttemptOutcome::Abandoned:
      authAbandonedCalls.fetch_add(1);
      break;
    }
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

  // Pin observation hooks - atomic counters readable from the test thread.
  std::atomic<uint32_t> removeSessionCalls{0};
  std::atomic<uint32_t> authFailureCalls{0};
  std::atomic<uint32_t> authBeginCalls{0};
  std::atomic<uint32_t> authAbandonedCalls{0};
  std::atomic<uint32_t> authSuccessCalls{0};

private:
  ::ua::server::SubscriptionIdAllocator mSubAlloc;
  ::ua::server::SubscriptionRouter mSubReg;
  ::ua::server::OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  ::boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ::ua::ApplicationConfig> mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  ::ua::server::ServerComponents mHooks;
  // Order matters: mFakeNamespace must outlive mAddressSpace.
  std::shared_ptr<::ua::test_helpers::FakeNamespace> mFakeNamespace;
  ::ua::AddressSpace mAddressSpace;
  ::ua::server::EventBus mEventBus;
  std::shared_ptr<::ua::test_helpers::FakeAsyncCrypto> mFakeCrypto;
  std::shared_ptr<::ua::test_helpers::FakeCertificateStore> mFakeCertStore;
  std::shared_ptr<::ua::test_helpers::FakeDiscoveryDependencies> mFakeDiscoveryDeps;
};

// ---------------------------------------------------------------------------
// FakeSecureChannelDependencies - minimum surface to construct a SecureChannel
// ---------------------------------------------------------------------------
class FakeSecureChannelDependencies final : public ::ua::server::SecureChannelDependencies
{
public:
  explicit FakeSecureChannelDependencies(::boost::asio::any_io_executor ex)
    : mExecutor(ex), mFakeNamespace(::ua::test_helpers::FakeNamespace::create("urn:test:fake-ns-sc")),
      mAddressSpace(::ua::test_helpers::make_address_space_with_fake_namespace(ex, mFakeNamespace)),
      mFakeCrypto(::ua::test_helpers::FakeAsyncCrypto::create()),
      mFakeCertStore(::ua::test_helpers::FakeCertificateStore::create()),
      mFakeDiscoveryDeps(std::make_shared<::ua::test_helpers::FakeDiscoveryDependencies>(ex))
  {
    mFakeDiscoveryDeps->set_default_application_group_certificate_store(mFakeCertStore);
  }

  void create_session(::ua::server::SecureChannelInfo, uint32_t, ::ua::CreateSessionRequest&&) override
  {}

  ::ua::weak_ptr<::ua::server::DiscoveryDependencies> discovery_dependencies() override
  {
    return mFakeDiscoveryDeps;
  }

  ::ua::StructureFactory& structure_factory() override
  {
    throw ::ua::UaException{::ua::Status::BadInternalError,
      ::ua::make_error_detail("TestError", "structure_factory not used", "Test")};
  }

  std::vector<::ua::server::ServerEndpointConfig> endpoints(::ua::server::ListenerHandle) override
  {
    return {};
  }

  ::ua::shared_ptr<const ::ua::Crypto> crypto() override
  {
    return mFakeCrypto;
  }

  ::ua::WeakAddressSpace address_space() override
  {
    return mAddressSpace.weak();
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  ::ua::shared_ptr<::ua::CertificateStore> default_application_group_certificate_store() override
  {
    return mFakeCertStore;
  }

  ::boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  uint32_t get_next_secure_channel_id() override
  {
    return mNextId++;
  }

  std::shared_ptr<::ua::server::ServerObserver> observer() override
  {
    return nullptr;
  }

  ::ua::Logger logger() override
  {
    return {};
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

  void remove_secure_channel(const ::ua::shared_ptr<::ua::server::SecureChannel>&) override
  {}

private:
  ::boost::asio::any_io_executor mExecutor;
  ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
  ::ua::server::ServerConfig mServerCfg;
  uint32_t mNextId{1};
  std::shared_ptr<::ua::test_helpers::FakeNamespace> mFakeNamespace;
  ::ua::AddressSpace mAddressSpace;
  std::shared_ptr<::ua::test_helpers::FakeAsyncCrypto> mFakeCrypto;
  std::shared_ptr<::ua::test_helpers::FakeCertificateStore> mFakeCertStore;
  std::shared_ptr<::ua::test_helpers::FakeDiscoveryDependencies> mFakeDiscoveryDeps;
};

// ---------------------------------------------------------------------------
// SessionPinHarness - composition fixture re-used by every pin test.
//
// Owns a boost::asio::thread_pool, a SecureChannel (with a captured response sink), and the
// Session under test. Pins inject decoded requests via SessionTestAccess and
// observe responses via the captured sink.
//
// The harness is intentionally NOT a base class - pin tests are flow-specific
// and a shared base would tempt premature abstraction. Each pin file
// instantiates this harness directly.
// ---------------------------------------------------------------------------
struct SessionPinHarness
{
  ::boost::asio::thread_pool pool;
  std::shared_ptr<FakeSecureChannelDependencies> scDeps;
  std::shared_ptr<FakeSessionDependencies> sessDeps;
  std::shared_ptr<::ua::server::SecureChannel> sc;
  std::shared_ptr<::ua::server::Session> session;

  std::mutex mutex;
  std::condition_variable cv;
  std::vector<::ua::Response> responses;

  // Wait for the response queue to reach `count` entries (timeout is a safety
  // upper bound; on success the wait is deterministic via condition variable).
  void wait_for_responses(size_t count, std::chrono::milliseconds timeout = std::chrono::milliseconds(2000))
  {
    std::unique_lock<std::mutex> lk(mutex);
    ASSERT_TRUE(cv.wait_for(lk, timeout, [&]() { return responses.size() >= count; }))
      << "expected at least " << count << " response(s), got " << responses.size();
  }

  ::ua::Response take_response()
  {
    std::unique_lock<std::mutex> lk(mutex);
    EXPECT_FALSE(responses.empty());
    if (responses.empty())
      return {};
    auto r = std::move(responses.front());
    responses.erase(responses.begin());
    return r;
  }

  void shutdown()
  {
    if (session)
      session->terminate_for_shutdown();
    if (sc)
      sc->close();
    pool.join();
  }
};

inline std::shared_ptr<const ::ua::X509Certificate> pin_client_certificate(
  const std::shared_ptr<::ua::test_helpers::FakeAsyncCrypto>&)
{
  static const auto certificate = [&]
  {
    const auto crypto = ::ua::create_default_crypto([] { return ::ua::SecureString{"password"}; });
    ::ua::Crypto::Name subject;
    subject.commonName = "Pin Client";
    ::ua::Crypto::SubjectAlternateName alternateName;
    alternateName.uris.push_back("urn:test:pin-client");
    auto result = crypto->try_create_self_signed_application_instance_certificate_sync(subject,
      ::ua::UtcTime{2050, 1, 1, 0, 0, 0},
      alternateName,
      ::ua::CertificateType::RsaSha256Application,
      2048);
    return std::move(result).value().second;
  }();
  return certificate;
}

// Build a harness with a CreateSession already complete on the strand.
//
// `policyId` selects the channel policy (None for happy paths; pass
// Basic256Sha256 to exercise authenticated-channel preconditions).
// `clientNonce` controls CreateSession's client_nonce field - pass an empty
// ByteString for the unauthenticated-default and a 32+ byte one for
// authenticated-channel happy paths.
inline std::unique_ptr<SessionPinHarness> make_harness(::ua::SecurityPolicyId policyId,
  ::ua::ByteString clientNonce,
  std::shared_ptr<::ua::server::UserAuthenticator> authenticator =
    std::make_shared<AllowAnonymousAuthenticator>(),
  std::vector<::ua::UserTokenPolicy> extraUserTokenPolicies = {})
{
  auto h = std::make_unique<SessionPinHarness>();
  auto ex = h->pool.get_executor();

  h->scDeps = std::make_shared<FakeSecureChannelDependencies>(ex);
  h->sc = ::ua::server::SecureChannel::create(
    h->scDeps, nullptr, ::ua::connection_protocol::NegotiatedLimits{}, ::ua::server::ListenerHandle{1}, "L");
  ::ua::server::SecureChannelTestAccess::on_strand(*h->sc,
    [&](auto& g)
    {
      std::vector<::ua::UserTokenPolicy> tokens;
      tokens.push_back(
        ::ua::server::create_user_token_policy(::ua::UserTokenType::Anonymous, ::ua::SecurityPolicyId::None));
      for (auto& extra : extraUserTokenPolicies)
        tokens.push_back(std::move(extra));
      g.set_minimal_context_authenticated(
        ex, "L/Ep", policyId, ::ua::MessageSecurityMode::None, std::move(tokens));
    });

  ::ua::server::SecureChannelTestAccess::on_strand(*h->sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&mx = h->mutex, &cv = h->cv, &q = h->responses](const ::ua::Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          q.push_back(r);
          cv.notify_all();
        });
    });

  ::ua::server::ServerComponents hooks;
  hooks.authenticator = std::move(authenticator);
  h->sessDeps = std::make_shared<FakeSessionDependencies>(ex, std::move(hooks));

  // Configure FakeDiscoveryDependencies so the Discovery endpoint-URL validation
  // accepts the request URL used below. Pin tests don't care about the URL
  // content - they care about session lifecycle. Wire a single listener with a
  // matching advertised URL.
  static constexpr const char* harnessEndpointUrl = "opc.tcp://localhost:4840";
  ::ua::server::ListenerHandle listenerHandle{1};
  h->sessDeps->fake_discovery_dependencies()->add_listener(listenerHandle,
    /*endpoints=*/{},
    /*advertisedUrls=*/{::ua::transport::EndpointUrl{harnessEndpointUrl}});

  const auto clientCertificate = policyId != ::ua::SecurityPolicyId::None
                                   ? pin_client_certificate(h->sessDeps->fake_crypto())
                                   : std::shared_ptr<const ::ua::X509Certificate>{};

  ::ua::server::SecureChannelInfo sci(h->sc->weak_from_this(),
    ::ua::SecurityPolicy::create(policyId),
    ::ua::MessageSecurityMode::None,
    "L/Ep",
    ::ua::server::SecureChannelTestAccess::on_strand(
      *h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }),
    clientCertificate);

  ::ua::CreateSessionRequest csr;
  csr.endpoint_url() = harnessEndpointUrl;
  csr.client_nonce() = std::move(clientNonce);
  if (clientCertificate)
  {
    csr.client_description().application_uri() = "urn:test:pin-client";
    csr.client_certificate() = clientCertificate->der_encoding();
  }
  h->session = ::ua::server::Session::create(h->sessDeps, sci, /*requestId=*/1, std::move(csr));

  // Drain the strand so create_internal completes (or fails) before the test
  // proceeds.
  ::ua::server::SessionTestAccess::strand_barrier(*h->session);
  return h;
}

}  // namespace ua::test::pins_4_9

#endif  // PHASE_4_9_FAKE_SESSION_DEPENDENCIES_H
