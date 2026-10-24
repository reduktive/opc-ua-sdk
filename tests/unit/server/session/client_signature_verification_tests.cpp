// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include "ua_server_secure_channel_test_access.h"
#include "ua_server_impl.h"
#include "ua_server_session.h"
#include "ua_server_session_test_access.h"
#include "server_impl_test_access.h"
#include "fake_async_crypto.h"
#include "fake_certificate_store.h"
#include "fake_discovery_dependencies.h"

#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_security_policy.h"
#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_anonymous_identity_token.h"
#include "ua_x509_identity_token.h"
#include "ua_additional_parameters_type.h"
#include "ua_ephemeral_key_type.h"
#include "ua_key_value_pair.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_service_fault.h"
#include "ua_stack_utilities.h"

#include "ua_crypto.h"
#include "ua_certificate_store_files.h"

#include "ua_server_components.h"

#include <condition_variable>
#include <functional>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <mutex>
#include <string_view>

#include "channel_bound_signature_test_data.h"
#include "test_components.h"
#include "test_pki_helpers.h"
using namespace ua;
using namespace ua::server;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace std::chrono_literals;

namespace
{

class AllowAllAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    (void)req;
    completion(
      make_authn_success(UserIdentity{.userId = "anonymous", .displayName = "Anonymous", .claims = {}}));
  }
};

class CreateFailureObserver final : public ServerObserver
{
public:
  void on_session_create_failed(const SessionEventInfo& info, StatusCode reason) override
  {
    std::lock_guard lock(mMutex);
    mEvents.emplace_back(info, std::move(reason));
  }

  std::vector<std::pair<SessionEventInfo, StatusCode>> events() const
  {
    std::lock_guard lock(mMutex);
    return mEvents;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::pair<SessionEventInfo, StatusCode>> mEvents;
};

/// The ErrorDetail named @p code in the cause chain that starts at @p detail, or null.
const ErrorDetail* find_in_cause_chain(const shared_ptr<const ErrorDetail>& detail, std::string_view code)
{
  for (const ErrorDetail* link = detail.get(); link != nullptr; link = link->cause.get())
  {
    if (link->code == code)
      return link;
  }
  return nullptr;
}

// Records the status an ActivateSession's authentication failed with, ErrorDetail included: the fault of a
// Bad_IdentityTokenInvalid refusal carries none.
class AuthenticationFailureObserver final : public ServerObserver
{
public:
  void on_authentication_failed(const SessionEventInfo&, StatusCode reason) override
  {
    std::lock_guard lock(mMutex);
    mReasons.push_back(std::move(reason));
  }

  std::vector<StatusCode> reasons() const
  {
    std::lock_guard lock(mMutex);
    return mReasons;
  }

private:
  mutable std::mutex mMutex;
  std::vector<StatusCode> mReasons;
};

void inject_create_response_build_failure()
{
  throw UaException{Status::BadInternalError,
    ErrorDetail::build(
      "InjectedCreateResponseBuildFailure", "Injected CreateSession response-build failure", "Test")
      .cause(StatusCode{Status::BadUnexpectedError,
        make_error_detail("InjectedCreateResponseBuildCause", "Injected nested cause", "Test")})};
}

// SessionDependencies with real crypto and certificate store for signature verification tests.
class CryptoSessionDeps final : public SessionDependencies
{
public:
  CryptoSessionDeps(boost::asio::any_io_executor ex, ServerComponents hooks, shared_ptr<const Crypto> crypto,
    shared_ptr<CertificateStore> certStore)
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mCrypto(std::move(crypto)), mCertStore(std::move(certStore)),
      mDiscoveryDeps(std::make_shared<ua::test_helpers::FakeDiscoveryDependencies>(mExecutor))
  {
    ServerEndpointConfig noneEndpoint;
    noneEndpoint.name = "None";
    noneEndpoint.messageSecurityMode = MessageSecurityMode::None;
    noneEndpoint.securityPolicyId = SecurityPolicyId::None;
    noneEndpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    ServerEndpointConfig authenticatedEndpoint;
    authenticatedEndpoint.name = "Basic256Sha256_SignAndEncrypt";
    authenticatedEndpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    authenticatedEndpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    authenticatedEndpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    mDiscoveryDeps->set_default_application_group_certificate_store(mCertStore)
      .add_listener(ListenerHandle{1},
        {std::move(noneEndpoint), std::move(authenticatedEndpoint)},
        {transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"}});
  }

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return mDiscoveryDeps;
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  shared_ptr<const Crypto> crypto() override
  {
    return mCrypto;
  }

  WeakAddressSpace address_space() override
  {
    return {};
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return *mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return mCertStore;
  }

  // The trust anchors for X509 user identity tokens; null (none configured) unless a test sets one.
  shared_ptr<CertificateStore> user_token_certificate_store() override
  {
    return mUserTokenCertificateStore;
  }

  void set_user_token_certificate_store(shared_ptr<CertificateStore> store)
  {
    mUserTokenCertificateStore = std::move(store);
  }

  StructureFactory& structure_factory() override
  {
    throw UaException{
      Status::BadInternalError, make_error_detail("TestError", "Not used in this test", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints() override
  {
    return {};
  }

  void remove_session(const shared_ptr<Session>&) override
  {}

  const ::ua::server::ServerComponents& components() const override
  {
    return mHooks;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    std::lock_guard<std::mutex> lk(mObserverMutex);
    return mObserver;
  }

  // A test may replace the observer while a Session it created earlier still reads it on a pool thread.
  void set_observer(std::shared_ptr<ServerObserver> observer)
  {
    std::lock_guard<std::mutex> lk(mObserverMutex);
    mObserver = std::move(observer);
  }

  Logger logger() override
  {
    return {};
  }

  std::shared_ptr<RequestLatencyTracker> latency_tracker() override
  {
    return nullptr;
  }

  std::shared_ptr<ServerSummaryCounters> summary_counters() override
  {
    return mSummaryCounters;
  }

  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() override
  {
    return mDiagnosticsEnabled;
  }

  SubscriptionIdAllocator& subscription_id_allocator() override
  {
    return mSubscriptionIdAllocator;
  }

  SubscriptionRouter& subscription_router() override
  {
    return mSubscriptionRouter;
  }

  OrphanedSubscriptionStore& orphaned_subscription_store() override
  {
    return mOrphanedSubscriptionStore;
  }

  EventBus& event_bus() override
  {
    return mEventBus;
  }

  std::shared_ptr<::ua::server::EventBus> event_bus_shared() override
  {
    return {};
  }

  std::shared_ptr<NodeManagementDelegate> node_management_delegate() override
  {
    return nullptr;
  }

  optional<StatusCode> begin_identity_attempt(const ::ua::server::ClientId&, std::string_view) override
  {
    return std::nullopt;
  }

  void finish_identity_attempt(
    const ::ua::server::ClientId&, std::string_view, IdentityAttemptOutcome) override
  {}

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

private:
  boost::asio::any_io_executor mExecutor;
  SubscriptionIdAllocator mSubscriptionIdAllocator;
  SubscriptionRouter mSubscriptionRouter;
  OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  EventBus mEventBus{AddressSpace::create("", mExecutor)};
  std::shared_ptr<const ::ua::ApplicationConfig> mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  ::ua::server::ServerComponents mHooks;
  shared_ptr<const Crypto> mCrypto;
  shared_ptr<CertificateStore> mCertStore;
  shared_ptr<CertificateStore> mUserTokenCertificateStore;
  shared_ptr<ua::test_helpers::FakeDiscoveryDependencies> mDiscoveryDeps;
  // Set before a Session is created; the Session reads it on its strand.
  std::mutex mObserverMutex;
  std::shared_ptr<ServerObserver> mObserver;
  // Real diagnostic counters so tests can observe session-rejection accounting; diagnostics enabled.
  std::shared_ptr<ServerSummaryCounters> mSummaryCounters = std::make_shared<ServerSummaryCounters>();
  std::shared_ptr<std::atomic<bool>> mDiagnosticsEnabled = std::make_shared<std::atomic<bool>>(true);
};

// Minimal SecureChannelDependencies that returns real crypto.
class MinimalScDeps : public SecureChannelDependencies
{
public:
  MinimalScDeps(boost::asio::any_io_executor ex, shared_ptr<const Crypto> crypto)
    : mExecutor(ex), mCrypto(std::move(crypto))
  {}

  void create_session(SecureChannelInfo, uint32_t, CreateSessionRequest&&) override
  {}

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
  }

  StructureFactory& structure_factory() override
  {
    throw UaException{Status::BadInternalError, make_error_detail("TestError", "Not used", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints(::ua::server::ListenerHandle) override
  {
    return {};
  }

  shared_ptr<const Crypto> crypto() override
  {
    return mCrypto;
  }

  WeakAddressSpace address_space() override
  {
    return {};
  }

  const ::ua::ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  const ::ua::server::ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return nullptr;
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  uint32_t get_next_secure_channel_id() override
  {
    return 1;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return nullptr;
  }

  Logger logger() override
  {
    return {};
  }

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

  void remove_secure_channel(const shared_ptr<SecureChannel>&) override
  {}

private:
  boost::asio::any_io_executor mExecutor;
  shared_ptr<const Crypto> mCrypto;
  ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
  ::ua::server::ServerConfig mServerCfg;
};

// Test fixture that shares expensive RSA key generation across all tests via SetUpTestSuite.
class ClientSignatureVerificationTests : public ::testing::Test
{
protected:
  // --- Static crypto material shared across all tests (generated once) ---
  static shared_ptr<const Crypto> sCrypto;
  static shared_ptr<const AsymmetricKeyPair> sServerKeys;
  static shared_ptr<const X509Certificate> sServerCert;
  static shared_ptr<const AsymmetricKeyPair> sClientKeys;
  static shared_ptr<const X509Certificate> sClientCert;
  // An ECC_nistP256 server certificate, for the ECC channels of the ECDHPolicyUri rows.
  static shared_ptr<const AsymmetricKeyPair> sServerEccKeys;
  static shared_ptr<const X509Certificate> sServerEccCert;
  static shared_ptr<const AsymmetricKeyPair> sClientEccKeys;
  static shared_ptr<const X509Certificate> sClientEccCert;

  static void SetUpTestSuite()
  {
    sCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    UtcTime expiry{2050, 1, 1, 0, 0, 0};

    // Server certificate.
    Crypto::Name serverSubject;
    serverSubject.commonName = "Test Server";
    Crypto::SubjectAlternateName serverAltName;
    serverAltName.uris.push_back("urn:test:server");
    auto serverCertResult = sCrypto->try_create_self_signed_application_instance_certificate_sync(
      serverSubject, expiry, serverAltName, CertificateType::RsaSha256Application, 2048);
    auto [serverKeys, serverCert] = std::move(serverCertResult).value();
    sServerKeys = std::move(serverKeys);
    sServerCert = std::move(serverCert);

    // Client certificate.
    Crypto::Name clientSubject;
    clientSubject.commonName = "Test Client";
    Crypto::SubjectAlternateName clientAltName;
    clientAltName.uris.push_back("urn:test:client");
    auto clientCertResult = sCrypto->try_create_self_signed_application_instance_certificate_sync(
      clientSubject, expiry, clientAltName, CertificateType::RsaSha256Application, 2048);
    auto [clientKeys, clientCert] = std::move(clientCertResult).value();
    sClientKeys = std::move(clientKeys);
    sClientCert = std::move(clientCert);

    auto serverEccCertResult = sCrypto->try_create_self_signed_application_instance_certificate_sync(
      serverSubject, expiry, serverAltName, CertificateType::EccNistP256Application, 2048);
    auto [serverEccKeys, serverEccCert] = std::move(serverEccCertResult).value();
    sServerEccKeys = std::move(serverEccKeys);
    sServerEccCert = std::move(serverEccCert);

    auto clientEccCertResult = sCrypto->try_create_self_signed_application_instance_certificate_sync(
      clientSubject, expiry, clientAltName, CertificateType::EccNistP256Application, 2048);
    auto [clientEccKeys, clientEccCert] = std::move(clientEccCertResult).value();
    sClientEccKeys = std::move(clientEccKeys);
    sClientEccCert = std::move(clientEccCert);
  }

  static void TearDownTestSuite()
  {
    sClientEccCert.reset();
    sClientEccKeys.reset();
    sServerEccCert.reset();
    sServerEccKeys.reset();
    sClientCert.reset();
    sClientKeys.reset();
    sServerCert.reset();
    sServerKeys.reset();
    sCrypto.reset();
  }

  // --- Per-test infrastructure ---
  boost::asio::thread_pool mThreadPool;
  shared_ptr<SecureChannelDependencies> mScDeps;
  shared_ptr<CryptoSessionDeps> mSessDeps;
  shared_ptr<ServerImpl> mServer;
  shared_ptr<SecureChannel> mSc;
  shared_ptr<Session> mSession;
  shared_ptr<CertificateStore> mCertStore;
  shared_ptr<CreateFailureObserver> mFailureObserver;
  std::filesystem::path mTempDir;

  std::mutex mMutex;
  std::condition_variable mCv;
  optional<Response> mLastResponse;
  size_t mResponseCount{};

  /// Set before make_harness: the Session's crypto (sCrypto when null), and a certificate store the Session
  /// and its discovery use as it is, unseeded (a seeded CertificateStoreFiles when null).
  shared_ptr<const Crypto> mSessionCrypto;
  shared_ptr<CertificateStore> mStoreOverride;

  /// Set before make_harness on an ECC_nistP256 policy: the Session is on an enhanced SignAndEncrypt channel
  /// that carries a ChannelThumbprint and its two certificates, as the production channel hands them over,
  /// with an ECC client application certificate.
  bool mEnhancedChannel{false};
  ByteString mChannelThumbprint;
  /// The ClientNonce of the CreateSession request make_harness sent.
  ByteString mClientNonce;
  /// Sessions replaced by recreate_enhanced_session, kept alive until TearDown (their inactivity timers hold
  /// pool work until they die).
  std::vector<shared_ptr<Session>> mRetiredSessions;

  void SetUp() override
  {}

  void TearDown() override
  {
    // Drop impl shared_ptrs before ::ua::test_utils::drain_with_timeout(pool) so the strand-bound state
    // (timers, queued response sinks) can be torn down; otherwise ::ua::test_utils::drain_with_timeout(pool)
    // blocks on work that won't drain until impls die, which won't happen
    // until after TearDown returns.
    mRetiredSessions.clear();
    mSession.reset();
    mServer.reset();
    mSc.reset();
    mScDeps.reset();
    mSessDeps.reset();
    mCertStore.reset();
    mFailureObserver.reset();

    ::ua::test_utils::drain_with_timeout(mThreadPool);

    std::error_code ec;
    if (!mTempDir.empty())
      std::filesystem::remove_all(mTempDir, ec);
  }

  void make_transactional_server_harness(ByteString requestCertificate, bool injectResponseFailure = false,
    std::string_view applicationUri = "urn:test:client")
  {
    auto executor = mThreadPool.get_executor();

    mTempDir = std::filesystem::temp_directory_path() /
               ("ua_clientsig_server_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    TrustListValidationOptions validationOptions;
    mCertStore = CertificateStoreFiles::create(
      executor, sCrypto, {.trustListPath = mTempDir, .validationOptions = validationOptions});

    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = sServerCert;
    appCert.keys = sServerKeys;
    mCertStore->add_to_application_certificates_sync(appCert);
    mCertStore->add_to_trusted_certificates_sync(sClientCert);

    CombinedConfig config;
    config.identity = ApplicationIdentity::load_default();
    config.application = std::make_shared<const ApplicationConfig>(ApplicationConfig::load_default());

    ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ServerEndpointConfig endpoint;
    endpoint.name = "Basic256Sha256_SignAndEncrypt";
    endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(endpoint));
    config.server.listeners().push_back(std::move(listener));
    config.server.validate();

    ServerComponents components{.crypto = sCrypto, .applicationGroupCertificateStore = mCertStore};
    components.authenticator = std::make_shared<AllowAllAuthenticator>();
    mServer = ServerImpl::create(executor, std::move(config), std::move(components));
    ua::test_helpers::ServerImplTestAccess{*mServer}.initialise_listeners_from_config();
    mFailureObserver = std::make_shared<CreateFailureObserver>();
    mServer->set_observer(mFailureObserver);

    if (injectResponseFailure)
    {
      ua::test_helpers::ServerImplTestAccess{*mServer}.set_on_session_admitted(
        [this](Session& session)
        {
          mSession = session.shared_from_this();
          SessionTestAccess::set_create_response_failure_injector_on_strand(
            session, &inject_create_response_build_failure);
        });
    }

    mScDeps = ua::test_helpers::ServerImplTestAccess{*mServer}.secure_channel_dependencies();
    mSc = SecureChannel::create(
      mScDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
    ua::test_helpers::ServerImplTestAccess{*mServer}.add_secure_channel(mSc);

    SCTA::on_strand(*mSc,
      [&](auto& channel)
      {
        channel.set_response_sink(
          [&mx = mMutex, &cv = mCv, &last = mLastResponse, &count = mResponseCount](const Response& response)
          {
            std::lock_guard lock(mx);
            last = response;
            ++count;
            cv.notify_one();
          });
      });

    SecureChannelInfo channelInfo(mSc->weak_from_this(),
      SecurityPolicy::create(SecurityPolicyId::Basic256Sha256),
      MessageSecurityMode::SignAndEncrypt,
      "L/Ep",
      {},
      sClientCert);

    CreateSessionRequest request;
    request.client_nonce() = sCrypto->get_entropy_sync(32);
    request.client_certificate() = std::move(requestCertificate);
    request.client_description().application_uri() = String{applicationUri};
    ua::test_helpers::ServerImplTestAccess{*mServer}.create_session(
      std::move(channelInfo), 1, std::move(request));
  }

  void expect_transactional_server_refusal(StatusCode expectedStatus, std::string_view expectedDetailCode)
  {
    wait_for_response();
    if (mSession)
      SessionTestAccess::strand_barrier(*mSession);
    SCTA::on_strand(*mSc, [](auto&) {});

    auto* fault = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
    ASSERT_NE(fault, nullptr);
    const auto status = fault->response_header().service_result();
    EXPECT_EQ(status, expectedStatus);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, expectedDetailCode);
    EXPECT_EQ(response_count(), 1u);

    ua::test_helpers::ServerImplTestAccess access{*mServer};
    EXPECT_TRUE(access.sessions().empty());
    EXPECT_EQ(access.session_token_count(), 0u);
    EXPECT_EQ(access.summary_counters()->currentSessionCount.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(access.summary_counters()->cumulatedSessionCount.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(mSc->session_count(), 0u);

    const auto failureEvents = mFailureObserver->events();
    ASSERT_EQ(failureEvents.size(), 1u);
    EXPECT_EQ(failureEvents.front().second, expectedStatus);
    EXPECT_EQ(failureEvents.front().second.shared_detail(), status.shared_detail());
  }

  // Creates per-test infrastructure using the shared crypto material.
  // `userTokens` are the endpoint's UserTokenPolicies (Anonymous when empty); `customiseRequest` edits
  // the CreateSessionRequest before it is sent.
  void make_harness(SecurityPolicyId policyId, optional<ByteString> requestCertificate = std::nullopt,
    bool preserveCreateResponse = false, std::string_view applicationUri = "urn:test:client",
    std::vector<UserTokenPolicy> userTokens = {},
    const std::function<void(CreateSessionRequest&)>& customiseRequest = {})
  {
    auto executor = mThreadPool.get_executor();

    if (mStoreOverride)
    {
      mCertStore = mStoreOverride;
    }
    else
    {
      // Certificate store seeded with the server certificate (per-test because it needs its own temp dir).
      mTempDir = std::filesystem::temp_directory_path() /
                 ("ua_clientsig_test_" + Guid::create_and_generate().as_string());
      std::filesystem::create_directories(mTempDir);

      TrustListValidationOptions validationOptions;
      mCertStore = CertificateStoreFiles::create(
        executor, sCrypto, {.trustListPath = mTempDir, .validationOptions = validationOptions});

      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = sServerCert;
      appCert.keys = sServerKeys;
      mCertStore->add_to_application_certificates_sync(appCert);
      // A Basic128Rsa15 channel selects the RsaMinApplication certificate (the same 2048-bit key suits it).
      if (SecurityPolicy::create(policyId)->certificate_type() == CertificateType::RsaMinApplication)
      {
        appCert.certificateType = CertificateType::RsaMinApplication;
        mCertStore->add_to_application_certificates_sync(appCert);
      }
      // An ECC_nistP256 channel selects the ECC server certificate.
      if (SecurityPolicy::create(policyId)->certificate_type() == CertificateType::EccNistP256Application)
      {
        CertificateStore::ApplicationCertificate eccCert;
        eccCert.certificateType = CertificateType::EccNistP256Application;
        eccCert.certificate = sServerEccCert;
        eccCert.keys = sServerEccKeys;
        mCertStore->add_to_application_certificates_sync(eccCert);
      }
      mCertStore->add_to_trusted_certificates_sync(sClientCert);
      if (mEnhancedChannel)
        mCertStore->add_to_trusted_certificates_sync(sClientEccCert);
    }

    // SecureChannel with authenticated policy.
    mScDeps = std::make_shared<MinimalScDeps>(executor, sCrypto);
    mSc = SecureChannel::create(
      mScDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");

    if (policyId == SecurityPolicyId::None)
    {
      SecureChannelTestAccess::on_strand(
        *mSc, [&](auto& g) { g.set_minimal_context_none(executor, "L/Ep", userTokens); });
    }
    else
    {
      SecureChannelTestAccess::on_strand(*mSc,
        [&](auto& g)
        {
          g.set_minimal_context_authenticated(
            executor, "L/Ep", policyId, MessageSecurityMode::SignAndEncrypt, userTokens);
        });
    }

    SCTA::on_strand(*mSc,
      [&](auto& g)
      {
        g.set_response_sink(
          [&mx = mMutex, &cv = mCv, &last = mLastResponse, &count = mResponseCount](const Response& r)
          {
            std::lock_guard<std::mutex> lk(mx);
            last = r;
            ++count;
            cv.notify_one();
          });
      });

    // SessionDependencies with real crypto.
    ServerComponents hooks;
    hooks.authenticator = std::make_shared<AllowAllAuthenticator>();

    mSessDeps = std::make_shared<CryptoSessionDeps>(
      executor, hooks, mSessionCrypto ? mSessionCrypto : sCrypto, mCertStore);

    const auto endpointTokens =
      SCTA::on_strand(*mSc, [](auto& g) -> const auto& { return g.user_identity_tokens(); });
    if (mEnhancedChannel)
      mChannelThumbprint = sCrypto->get_entropy_sync(64);
    SecureChannelInfo sci = mEnhancedChannel ? SecureChannelInfo(mSc->weak_from_this(),
                                                 SecurityPolicy::create(policyId),
                                                 MessageSecurityMode::SignAndEncrypt,
                                                 "L/Ep",
                                                 endpointTokens,
                                                 sClientEccCert,
                                                 0,
                                                 {},
                                                 {},
                                                 {},
                                                 {},
                                                 mChannelThumbprint,
                                                 sServerEccCert)
                                             : SecureChannelInfo(mSc->weak_from_this(),
                                                 SecurityPolicy::create(policyId),
                                                 MessageSecurityMode::None,
                                                 "L/Ep",
                                                 endpointTokens,
                                                 policyId != SecurityPolicyId::None ? sClientCert : nullptr);

    // Create the session - on authenticated channels, create_internal populates
    // mServerNonce, mServerCertificates, and mClientCertificate automatically.
    CreateSessionRequest csr;
    csr.client_nonce() = sCrypto->get_entropy_sync(32);
    mClientNonce = csr.client_nonce();
    csr.endpoint_url() = "opc.tcp://127.0.0.1:4840";
    csr.client_description().application_uri() = String{applicationUri};
    csr.client_certificate() = requestCertificate.has_value()       ? std::move(*requestCertificate)
                               : mEnhancedChannel                   ? sClientEccCert->der_encoding()
                               : policyId != SecurityPolicyId::None ? sClientCert->der_encoding()
                                                                    : ByteString{};
    if (customiseRequest)
      customiseRequest(csr);
    mSession = Session::create(mSessDeps, sci, 1, std::move(csr));

    // Wait for create_internal to complete on the session strand.
    SessionTestAccess::strand_barrier(*mSession);
    wait_for_response();
    if (!preserveCreateResponse)
      clear_response();
  }

  void wait_for_response()
  {
    std::unique_lock<std::mutex> lk(mMutex);
    ASSERT_TRUE(mCv.wait_for(lk, 2s, [&]() { return mLastResponse.has_value(); }));
  }

  void clear_response()
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mLastResponse.reset();
  }

  size_t response_count()
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mResponseCount;
  }

  void settle_create_response_path()
  {
    SessionTestAccess::strand_barrier(*mSession);
    SCTA::on_strand(*mSc, [](auto&) {});
  }

  /// The serviceResult of the CreateSession answer held in mLastResponse when it is a ServiceFault.
  optional<StatusCode> create_fault_status()
  {
    std::lock_guard<std::mutex> lk(mMutex);
    if (!mLastResponse.has_value())
      return std::nullopt;
    auto* fault = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
    if (fault == nullptr)
      return std::nullopt;
    return fault->response_header().service_result();
  }

  // Creates a Session on a @p policyId channel and activates it with a valid client signature; returns the
  // serverNonce sizes of the CreateSession and ActivateSession responses (a failed expectation, and a size
  // of 0, if either is not a Good response of its type).
  struct NonceSizes
  {
    std::size_t create{0};
    std::size_t activate{0};
  };

  NonceSizes create_and_activate_session_nonce_sizes(SecurityPolicyId policyId)
  {
    NonceSizes sizes;
    make_harness(policyId, std::nullopt, /*preserveCreateResponse*/ true);
    settle_create_response_path();
    {
      std::lock_guard<std::mutex> lk(mMutex);
      EXPECT_TRUE(mLastResponse.has_value());
      if (!mLastResponse.has_value())
        return sizes;
      auto* created = dynamic_cast<CreateSessionResponse*>(mLastResponse->second.get());
      EXPECT_NE(created, nullptr) << "Expected CreateSessionResponse, got ServiceFault or other";
      if (created == nullptr)
        return sizes;
      EXPECT_TRUE(created->response_header().service_result().is_good());
      sizes.create = created->server_nonce().size();
    }
    clear_response();

    ActivateSessionRequest asr;
    asr.request_header().request_handle() = 42;
    asr.client_signature() = sign_with_client_key(build_data_to_sign(), policyId);
    mSession->activate(2, std::move(asr), {});
    wait_for_response();

    std::lock_guard<std::mutex> lk(mMutex);
    EXPECT_TRUE(mLastResponse.has_value());
    if (!mLastResponse.has_value())
      return sizes;
    auto* activated = dynamic_cast<ActivateSessionResponse*>(mLastResponse->second.get());
    EXPECT_NE(activated, nullptr) << "Expected ActivateSessionResponse, got ServiceFault or other";
    if (activated == nullptr)
      return sizes;
    EXPECT_TRUE(activated->response_header().service_result().is_good());
    sizes.activate = activated->server_nonce().size();
    return sizes;
  }

  // What a CreateSession over an ECC_nistP256 channel carrying `ECDHPolicyUri = ecdhPolicyUri` in its
  // RequestHeader AdditionalHeader returns, on an endpoint whose UserTokenPolicies are `userTokens`. The
  // server provisions an EphemeralKey only on an ECC channel (OPC 10000-6 6.8.3: "When a Client calls
  // CreateSession via a SecureChannel based on an ECC SecurityPolicy").
  struct EcdhOutcome
  {
    bool created{false};  ///< a Good CreateSessionResponse (not a ServiceFault)
    bool keyIssued{false};  ///< the response's ECDHKey is an EphemeralKeyType
    optional<StatusCode> keyStatus;  ///< the response's ECDHKey is a StatusCode
    SecurityPolicyId sessionEccPolicy{SecurityPolicyId::Invalid};
  };

  EcdhOutcome create_session_with_ecdh_policy_uri(
    std::string ecdhPolicyUri, std::vector<UserTokenPolicy> userTokens)
  {
    make_harness(SecurityPolicyId::EccNistP256AesGcm,
      std::nullopt,
      /*preserveCreateResponse*/ true,
      "urn:test:client",
      std::move(userTokens),
      [&ecdhPolicyUri](CreateSessionRequest& request)
      {
        auto parameters = std::make_unique<AdditionalParametersType>();
        KeyValuePair policyUri;
        policyUri.key() = QualifiedName{0, "ECDHPolicyUri"};
        policyUri.value() = Variant{String{ecdhPolicyUri}};
        parameters->parameters().payload().push_back(std::move(policyUri));
        request.request_header().additional_header() = std::move(parameters);
      });
    wait_for_response();
    settle_create_response_path();

    EcdhOutcome outcome;
    outcome.sessionEccPolicy =
      SessionTestAccess::on_strand(*mSession, [](auto& g) { return g.ecc_user_token_policy_id(); });
    std::lock_guard<std::mutex> lk(mMutex);
    auto* response = dynamic_cast<CreateSessionResponse*>(mLastResponse->second.get());
    if (response == nullptr || !response->response_header().service_result().is_good())
      return outcome;
    outcome.created = true;
    const auto* parameters =
      dynamic_cast<const AdditionalParametersType*>(response->response_header().additional_header().get());
    if (parameters == nullptr)
      return outcome;
    for (const auto& kv : parameters->parameters().payload())
    {
      if (std::string_view{kv.key().name()} != "ECDHKey")
        continue;
      if (kv.value().try_as<EphemeralKeyType>() != nullptr)
        outcome.keyIssued = true;
      else if (const auto* status = kv.value().try_as<StatusCode>())
        outcome.keyStatus = *status;
    }
    return outcome;
  }

  /// The Session's latest ServerNonce.
  ByteString current_server_nonce()
  {
    return SessionTestAccess::on_strand(*mSession, [](auto& g) -> ByteString { return g.server_nonce(); });
  }

  /// The Table 101 inputs of the enhanced channel (mEnhancedChannel) for @p serverNonce.
  ChannelBoundSignatureInputs enhanced_inputs(const ByteString& serverNonce) const
  {
    return ChannelBoundSignatureInputs{.channelThumbprint = mChannelThumbprint,
      .clientNonce = mClientNonce,
      .serverNonce = serverNonce,
      .serverCertificate = sServerEccCert->der_encoding(),
      .serverChannelCertificate = sServerEccCert->der_encoding(),
      .clientCertificate = sClientEccCert->der_encoding(),
      .clientChannelCertificate = sClientEccCert->der_encoding()};
  }

  /// @p data signed with the ECC client application key, with the algorithm URI @p algorithm.
  static SignatureData sign_with_ecc_client_key(span<const byte> data, std::string_view algorithm = {})
  {
    const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
    SignatureData signature;
    signature.signature() =
      sCrypto->asymmetric_sign_sync(policy->asymmetric_signature_algorithm(), sClientEccKeys, data);
    signature.algorithm() = String{algorithm};
    return signature;
  }

  /// Replaces mSession with a new Session on the enhanced channel of make_harness, whose endpoint offers
  /// @p userTokens: a fresh ClientNonce and ServerNonce, and no activation behind it.
  void recreate_enhanced_session(std::vector<UserTokenPolicy> userTokens)
  {
    clear_response();
    mRetiredSessions.push_back(mSession);
    SecureChannelInfo sci(mSc->weak_from_this(),
      SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm),
      MessageSecurityMode::SignAndEncrypt,
      "L/Ep",
      std::move(userTokens),
      sClientEccCert,
      0,
      {},
      {},
      {},
      {},
      mChannelThumbprint,
      sServerEccCert);
    CreateSessionRequest csr;
    csr.client_nonce() = sCrypto->get_entropy_sync(32);
    mClientNonce = csr.client_nonce();
    csr.endpoint_url() = "opc.tcp://127.0.0.1:4840";
    csr.client_certificate() = sClientEccCert->der_encoding();
    csr.client_description().application_uri() = "urn:test:client";
    mSession = Session::create(mSessDeps, sci, 1, std::move(csr));
    SessionTestAccess::strand_barrier(*mSession);
    wait_for_response();
    clear_response();
  }

  /// The status of the response to an ActivateSession sent as @p request on the Session's channel.
  StatusCode activate_and_wait(ActivateSessionRequest request, uint32_t requestId = 2)
  {
    clear_response();
    mSession->activate(requestId, std::move(request), {});
    wait_for_response();
    std::lock_guard<std::mutex> lk(mMutex);
    if (!mLastResponse.has_value())
      return StatusCode{Status::BadInternalError};
    if (auto* fault = dynamic_cast<ServiceFault*>(mLastResponse->second.get()))
      return fault->response_header().service_result();
    if (auto* ok = dynamic_cast<ActivateSessionResponse*>(mLastResponse->second.get()))
      return ok->response_header().service_result();
    return StatusCode{Status::BadInternalError};
  }

  // Build the data that the client must sign: serverCert(DER) || serverNonce.
  ByteString build_data_to_sign()
  {
    ByteString data = sServerCert->der_encoding();
    std::ranges::copy(
      SessionTestAccess::on_strand(*mSession, [](auto& g) -> auto& { return g.server_nonce(); }),
      std::back_inserter(data));
    return data;
  }

  // Sign data with client private key using the policy's asymmetric signature algorithm.
  static SignatureData sign_with_client_key(
    span<const byte> data, SecurityPolicyId policyId = SecurityPolicyId::Basic256Sha256)
  {
    auto policy = SecurityPolicy::create(policyId);
    auto signature =
      sCrypto->asymmetric_sign_sync(policy->asymmetric_signature_algorithm(), sClientKeys, data);

    SignatureData sigData;
    sigData.signature() = std::move(signature);
    sigData.algorithm() = policy->asymmetric_signature_algorithm_uri();
    return sigData;
  }
};

// Static member definitions.
shared_ptr<const Crypto> ClientSignatureVerificationTests::sCrypto;
shared_ptr<const AsymmetricKeyPair> ClientSignatureVerificationTests::sServerKeys;
shared_ptr<const X509Certificate> ClientSignatureVerificationTests::sServerCert;
shared_ptr<const AsymmetricKeyPair> ClientSignatureVerificationTests::sClientKeys;
shared_ptr<const X509Certificate> ClientSignatureVerificationTests::sClientCert;
shared_ptr<const AsymmetricKeyPair> ClientSignatureVerificationTests::sServerEccKeys;
shared_ptr<const X509Certificate> ClientSignatureVerificationTests::sServerEccCert;
shared_ptr<const AsymmetricKeyPair> ClientSignatureVerificationTests::sClientEccKeys;
shared_ptr<const X509Certificate> ClientSignatureVerificationTests::sClientEccCert;

}  // namespace

// Part 4 section 5.6.2.2 requires the certificate in CreateSession to be the certificate captured from the
// authenticated SecureChannel. The comparison is by canonical leaf DER, while SecurityPolicy None
// ignores this request field.

// @relation(AC-SVR-SESS-011-CERT-CONTINUITY, AC-SVR-SECADMIN-008-CREATESESSION-URI-BINDING, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionAcceptsTheSecureChannelsCertificate)
{
  make_harness(SecurityPolicyId::Basic256Sha256, std::nullopt, true);

  wait_for_response();
  settle_create_response_path();

  auto* response = dynamic_cast<CreateSessionResponse*>(mLastResponse->second.get());
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
  EXPECT_NE(mSession->session_id(), NodeId{});
  EXPECT_EQ(response_count(), 1u);
}

// OPC 10000-6 6.8.3: the Client names in CreateSession the SecurityPolicyUri it plans to encrypt its
// UserIdentityToken with, and a UserIdentityToken is encrypted "using a SecurityPolicy specified by a
// UserTokenPolicy supported by the current Endpoint"; "If the SecurityPolicyUri is not valid the Server
// returns a StatusCode in the ResponseHeader instead of an EphemeralKey" (Table 63). Every row runs over
// an ECC_nistP256 channel. Here the endpoint's only token policy names ECC_nistP384, so ECC_nistP256 is
// not a policy it offers: the ECDHKey slot carries Bad_SecurityPolicyRejected and the Session holds no ECC
// token policy (security review SESS-7(f)).
// @verifies AC-SVR-ECC-008-SESS7F-ECDH-POLICY-URI-MUST-BE-OFFERED
TEST_F(ClientSignatureVerificationTests, CreateSessionRefusesAnEcdhPolicyUriNoTokenPolicyOffers)
{
  const auto outcome = create_session_with_ecdh_policy_uri(
    std::string{SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm)->uri()},
    {create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::EccNistP384AesGcm)});
  ASSERT_TRUE(outcome.created) << "an invalid ECDHPolicyUri must not fail the CreateSession";
  EXPECT_FALSE(outcome.keyIssued) << "an EphemeralKey was issued for a policy the endpoint does not offer";
  ASSERT_TRUE(outcome.keyStatus.has_value()) << "the ECDHKey slot must carry a StatusCode";
  EXPECT_EQ(*outcome.keyStatus, Status::BadSecurityPolicyRejected);
  EXPECT_EQ(outcome.sessionEccPolicy, SecurityPolicyId::Invalid);
}

// An Anonymous token carries no secret, so an Anonymous policy naming the ECC policy offers no key
// exchange: with it as the endpoint's only policy naming ECC_nistP256, the request is refused the same way.
// @verifies AC-SVR-ECC-008-SESS7F-ECDH-POLICY-URI-MUST-BE-OFFERED
TEST_F(ClientSignatureVerificationTests, CreateSessionRefusesAnEcdhPolicyUriOnlyAnAnonymousPolicyNames)
{
  const auto outcome = create_session_with_ecdh_policy_uri(
    std::string{SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm)->uri()},
    {create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::EccNistP256AesGcm)});
  ASSERT_TRUE(outcome.created) << "an invalid ECDHPolicyUri must not fail the CreateSession";
  EXPECT_FALSE(outcome.keyIssued) << "an Anonymous policy was taken as offering a key exchange";
  ASSERT_TRUE(outcome.keyStatus.has_value()) << "the ECDHKey slot must carry a StatusCode";
  EXPECT_EQ(*outcome.keyStatus, Status::BadSecurityPolicyRejected);
  EXPECT_EQ(outcome.sessionEccPolicy, SecurityPolicyId::Invalid);
}

// The same for a URI that is not ECC at all: an EphemeralKey exists only for an ECC policy, so the answer
// is the same StatusCode, and the CreateSession itself still succeeds.
// @verifies AC-SVR-ECC-008-SESS7F-ECDH-POLICY-URI-MUST-BE-OFFERED
TEST_F(ClientSignatureVerificationTests, CreateSessionRefusesAnEcdhPolicyUriThatIsNotEcc)
{
  const auto outcome = create_session_with_ecdh_policy_uri(
    std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()},
    {create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::EccNistP256AesGcm)});
  ASSERT_TRUE(outcome.created) << "an invalid ECDHPolicyUri must not fail the CreateSession";
  EXPECT_FALSE(outcome.keyIssued);
  ASSERT_TRUE(outcome.keyStatus.has_value()) << "the ECDHKey slot must carry a StatusCode";
  EXPECT_EQ(*outcome.keyStatus, Status::BadSecurityPolicyRejected);
  EXPECT_EQ(outcome.sessionEccPolicy, SecurityPolicyId::Invalid);
}

// control: an ECC policy a UserName policy of the endpoint names is honoured with an EphemeralKey.
// @verifies AC-SVR-ECC-008-SESS7F-ECDH-POLICY-URI-MUST-BE-OFFERED
TEST_F(ClientSignatureVerificationTests, CreateSessionIssuesAnEphemeralKeyForAnOfferedEcdhPolicyUri)
{
  const auto outcome = create_session_with_ecdh_policy_uri(
    std::string{SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm)->uri()},
    {create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::EccNistP256AesGcm)});
  ASSERT_TRUE(outcome.created);
  EXPECT_TRUE(outcome.keyIssued) << "control: an offered ECC policy must be answered with an EphemeralKey";
  EXPECT_FALSE(outcome.keyStatus.has_value());
  EXPECT_EQ(outcome.sessionEccPolicy, SecurityPolicyId::EccNistP256AesGcm);
}

// control: a UserName policy with an empty securityPolicyUri inherits the channel's ECC_nistP256 (OPC
// 10000-4 7.41.4), so it offers ECC_nistP256 and the key is issued.
// @verifies AC-SVR-ECC-008-SESS7F-ECDH-POLICY-URI-MUST-BE-OFFERED
TEST_F(
  ClientSignatureVerificationTests, CreateSessionIssuesAnEphemeralKeyForTheChannelPolicyATokenPolicyInherits)
{
  auto inheriting = create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::EccNistP256AesGcm);
  inheriting.security_policy_uri() = String{};
  const auto outcome = create_session_with_ecdh_policy_uri(
    std::string{SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm)->uri()}, {inheriting});
  ASSERT_TRUE(outcome.created);
  EXPECT_TRUE(outcome.keyIssued)
    << "control: a token policy inheriting the ECC channel policy must be answered with an EphemeralKey";
  EXPECT_FALSE(outcome.keyStatus.has_value());
  EXPECT_EQ(outcome.sessionEccPolicy, SecurityPolicyId::EccNistP256AesGcm);
}

// @relation(AC-SVR-SESS-011-CERT-CONTINUITY, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionComparesTheCanonicalLeafOfAFullCertificateChain)
{
  ByteString presentedChain = sClientCert->der_encoding();
  const auto additionalCertificate = sServerCert->der_encoding();
  std::ranges::copy(additionalCertificate, std::back_inserter(presentedChain));

  make_harness(SecurityPolicyId::Basic256Sha256, std::move(presentedChain), true);

  wait_for_response();
  settle_create_response_path();

  auto* response = dynamic_cast<CreateSessionResponse*>(mLastResponse->second.get());
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
  EXPECT_NE(mSession->session_id(), NodeId{});
  EXPECT_EQ(response_count(), 1u);
}

// @relation(AC-SVR-SESS-011-CERT-CONTINUITY, AC-SVR-SC-004-CERT-CONTINUITY-CHAIN, scope=function)
TEST_F(
  ClientSignatureVerificationTests, CreateSessionRejectsDifferentValidCertificateBeforeMaterializingSession)
{
  ASSERT_NE(sServerCert->der_encoding(), sClientCert->der_encoding());
  make_transactional_server_harness(sServerCert->der_encoding());

  expect_transactional_server_refusal(
    Status::BadSecurityChecksFailed, "CreateSessionClientCertificateMismatch");
}

// @relation(AC-SVR-SECADMIN-008-CREATESESSION-URI-BINDING, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionRejectsApplicationUriAbsentFromChannelCertificate)
{
  make_transactional_server_harness(sClientCert->der_encoding(), false, "urn:test:client:forged-application");

  expect_transactional_server_refusal(
    Status::BadCertificateUriInvalid, "CreateSessionClientApplicationUriMismatch");
  auto* fault = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(fault, nullptr);
  const auto detail = fault->response_header().service_result().shared_detail();
  ASSERT_NE(detail, nullptr);
  ASSERT_FALSE(detail->context.empty());
  EXPECT_EQ(detail->context.front().key, ContextKeys::applicationUri.value());
  EXPECT_EQ(detail->context.front().value, "urn:test:client:forged-application");
}

// @relation(AC-SVR-SESS-011-CERT-CONTINUITY, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionRejectsAnAbsentCertificateOnAuthenticatedChannel)
{
  make_transactional_server_harness(ByteString{});

  expect_transactional_server_refusal(Status::BadCertificateInvalid, "CreateSessionClientCertificateMissing");
}

// The certificate field is read by the chain parser (Part 6 6.2.6: a field holds the leaf and its issuers),
// so the refusal's cause is the field parser's CertificateFieldInvalid, which keeps the DER parser's own
// refusal as ITS cause: the whole chain of reasons still reaches the fault. (read_certificates_from_der
// reports bytes that form no complete certificate as CertificateTrailingBytes; approved item 7.)
// @relation(AC-SVR-SESS-011-CERT-CONTINUITY, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionRejectsMalformedCertificateWithItsRichCause)
{
  make_transactional_server_harness(ByteString(32, uint8_t{0xA5}));

  expect_transactional_server_refusal(Status::BadCertificateInvalid, "CreateSessionClientCertificateInvalid");
  auto* fault = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(fault, nullptr);
  const auto status = fault->response_header().service_result();
  const auto detail = status.shared_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadCertificateInvalid}.value());
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->code, "CertificateFieldInvalid");
  ASSERT_NE(detail->cause->cause, nullptr) << "the DER parser's refusal is kept as the field's cause";
  EXPECT_EQ(detail->cause->cause->code, "CertificateTrailingBytes");
}

// @relation(AC-COMP-SVR-SESSION-ADMISSION-01-ROLLBACK, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionResponseBuildFailureRollsBackAdmissionExactlyOnce)
{
  make_transactional_server_harness(sClientCert->der_encoding(), true);

  expect_transactional_server_refusal(Status::BadInternalError, "InjectedCreateResponseBuildFailure");
  auto* fault = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(fault, nullptr);
  const auto failure = fault->response_header().service_result();
  ASSERT_NE(failure.shared_detail(), nullptr);
  ASSERT_NE(failure.shared_detail()->cause, nullptr);
  EXPECT_EQ(failure.shared_detail()->cause->code, "InjectedCreateResponseBuildCause");

  ua::test_helpers::ServerImplTestAccess access{*mServer};
  access.set_on_session_admitted({});
  clear_response();

  SecureChannelInfo channelInfo(mSc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::Basic256Sha256),
    MessageSecurityMode::SignAndEncrypt,
    "L/Ep",
    {},
    sClientCert);
  CreateSessionRequest request;
  request.client_nonce() = sCrypto->get_entropy_sync(32);
  request.client_certificate() = sClientCert->der_encoding();
  request.client_description().application_uri() = "urn:test:client";
  request.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  access.create_session(std::move(channelInfo), 2, std::move(request));

  wait_for_response();
  SCTA::on_strand(*mSc, [](auto&) {});
  auto* response = dynamic_cast<CreateSessionResponse*>(mLastResponse->second.get());
  auto* recoveryFault = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(response, nullptr)
    << "recovery returned "
    << (recoveryFault ? to_string(recoveryFault->response_header().service_result().as_status())
                      : std::string{"an unexpected response type"})
    << (recoveryFault && recoveryFault->response_header().service_result().shared_detail()
           ? ":" + recoveryFault->response_header().service_result().shared_detail()->code
           : std::string{});
  EXPECT_TRUE(response->response_header().service_result().is_good());
  EXPECT_EQ(response_count(), 2u);
  EXPECT_EQ(access.sessions().size(), 1u);
  EXPECT_EQ(access.session_token_count(), 1u);
  EXPECT_EQ(access.summary_counters()->currentSessionCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(access.summary_counters()->cumulatedSessionCount.load(std::memory_order_relaxed), 1u);
  EXPECT_EQ(mSc->session_count(), 1u);
  EXPECT_EQ(mFailureObserver->events().size(), 1u);
}

// @relation(AC-SVR-SESS-010-NONE-IGNORES-CERT, AC-SVR-SECADMIN-008-CREATESESSION-URI-BINDING, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionAtNoneIgnoresMalformedCertificateData)
{
  make_harness(
    SecurityPolicyId::None, ByteString(32, uint8_t{0xA5}), true, "urn:test:client:unverified-none-claim");

  wait_for_response();
  settle_create_response_path();

  auto* response = dynamic_cast<CreateSessionResponse*>(mLastResponse->second.get());
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
  EXPECT_NE(mSession->session_id(), NodeId{});
  EXPECT_TRUE(mSession->client_application_uri().empty())
    << "a None channel must not publish its unverified CreateSession claim as authorization identity";
  EXPECT_EQ(response_count(), 1u);
}

// The CreateSession server nonce is taken only from a Good entropy answer. An Uncertain one is refused: the
// client is answered with a ServiceFault of Bad_InternalError (EntropyFailed, caused by the
// CryptoAnswerUncertain refusal carrying the provider's code), not with a fault carrying the Uncertain code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionRefusesAnUncertainServerNonceAnswer)
{
  auto crypto = ua::test_helpers::FakeAsyncCrypto::create();
  crypto->set_entropy_answer(StatusCode{Status::UncertainLastUsableValue});
  mSessionCrypto = crypto;
  make_harness(SecurityPolicyId::Basic256Sha256, std::nullopt, /*preserveCreateResponse*/ true);
  settle_create_response_path();

  const auto status = create_fault_status();
  ASSERT_TRUE(status.has_value()) << "the CreateSession must be answered with a ServiceFault";
  EXPECT_EQ(status->as_status(), Status::BadInternalError) << to_string(*status);
  EXPECT_NE(find_in_cause_chain(status->shared_detail(), "EntropyFailed"), nullptr) << to_string(*status);
  const auto* refusal = find_in_cause_chain(status->shared_detail(), "CryptoAnswerUncertain");
  ASSERT_NE(refusal, nullptr) << "the fault does not carry the refusal of the Uncertain answer";
  EXPECT_EQ(refusal->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
}

// The server signature of a CreateSession response is built only from a Good signing answer. An Uncertain one
// fails the CreateSession with the step's own code, Bad_ApplicationSignatureInvalid (SigningFailed), whose
// cause is the CryptoAnswerUncertain refusal carrying the provider's code; the code is not lost when the
// provider's answer carries no ErrorDetail.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionRefusesAnUncertainServerSignatureAnswer)
{
  auto crypto = ua::test_helpers::FakeAsyncCrypto::create();
  crypto->set_asymmetric_sign_failure(StatusCode{Status::UncertainLastUsableValue});
  mSessionCrypto = crypto;
  make_harness(SecurityPolicyId::Basic256Sha256, std::nullopt, /*preserveCreateResponse*/ true);
  settle_create_response_path();

  const auto status = create_fault_status();
  ASSERT_TRUE(status.has_value()) << "the CreateSession must be answered with a ServiceFault";
  EXPECT_EQ(status->as_status(), Status::BadApplicationSignatureInvalid) << to_string(*status);
  EXPECT_NE(find_in_cause_chain(status->shared_detail(), "SigningFailed"), nullptr) << to_string(*status);
  const auto* refusal = find_in_cause_chain(status->shared_detail(), "CryptoAnswerUncertain");
  ASSERT_NE(refusal, nullptr) << "the fault does not carry the refusal of the Uncertain answer";
  EXPECT_EQ(refusal->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
}

// The server certificates a CreateSession signs with are taken only from a Good certificate-store answer. An
// Uncertain one is refused with the step's own code, Bad_UnexpectedError (CertificateRetrievalFailed), whose
// cause is the CertificateStoreAnswerUncertain refusal carrying the store's code; the code is not lost when
// the store's answer carries no ErrorDetail.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionRefusesAnUncertainServerCertificateAnswer)
{
  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->getApplicationCertificatesResult =
    CertificateStore::ApplicationCertificateListResult{StatusCode{Status::UncertainLastUsableValue}};
  mStoreOverride = store;
  make_harness(SecurityPolicyId::Basic256Sha256, std::nullopt, /*preserveCreateResponse*/ true);
  settle_create_response_path();

  const auto status = create_fault_status();
  ASSERT_TRUE(status.has_value()) << "the CreateSession must be answered with a ServiceFault";
  EXPECT_EQ(status->as_status(), Status::BadUnexpectedError) << to_string(*status);
  ASSERT_NE(status->shared_detail(), nullptr);
  EXPECT_EQ(status->shared_detail()->code, "CertificateRetrievalFailed");
  const auto* refusal = find_in_cause_chain(status->shared_detail(), "CertificateStoreAnswerUncertain");
  ASSERT_NE(refusal, nullptr) << "the fault does not carry the store's Uncertain code: "
                              << to_string(*status);
  EXPECT_EQ(refusal->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
}

// The endpoints a CreateSession response advertises are built only from a Good certificate-store answer. An
// Uncertain one is refused by the discovery step, so the client is answered with a ServiceFault of
// Bad_InternalError (GetEndpointsFailed, caused by the CertificateStoreAnswerUncertain refusal), not with a
// fault carrying the Uncertain code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionRefusesAnUncertainCertificateStoreAnswerForItsEndpoints)
{
  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->getApplicationCertificatesResult =
    CertificateStore::ApplicationCertificateListResult{StatusCode{Status::UncertainLastUsableValue}};
  mStoreOverride = store;
  make_harness(SecurityPolicyId::None, std::nullopt, /*preserveCreateResponse*/ true);
  settle_create_response_path();

  const auto status = create_fault_status();
  ASSERT_TRUE(status.has_value()) << "the CreateSession must be answered with a ServiceFault";
  EXPECT_EQ(status->as_status(), Status::BadInternalError) << to_string(*status);
  EXPECT_NE(find_in_cause_chain(status->shared_detail(), "GetEndpointsFailed"), nullptr)
    << to_string(*status);
  const auto* refusal = find_in_cause_chain(status->shared_detail(), "CertificateStoreAnswerUncertain");
  ASSERT_NE(refusal, nullptr) << "the fault does not carry the refusal of the Uncertain answer";
  EXPECT_EQ(refusal->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
}

// The public runtime arms above assert the certificate-continuity outcomes. This supplementary
// source-level unit guards the construction order: the continuity decision precedes the first
// materialization of Session identity, so a refused request cannot leave a partial Session behind.
// @relation(AC-SVR-SESS-011-CERT-CONTINUITY, scope=function)
TEST(ClientSignatureVerificationStructureTest, CertificateContinuityPrecedesSessionIdentityMaterialization)
{
  // UASDK_TEST_SOURCE_DIR (absolute; see tests/CMakeLists.txt), not __FILE__, anchors the walk.
  auto root = std::filesystem::path{UASDK_TEST_SOURCE_DIR};
  // parent_path() of the filesystem root is the root itself, so an empty-path test never fires. If the
  // marker cannot be found the walk spins on "/" at full CPU and hangs the whole test binary rather than
  // failing it. Stop when the walk stops moving and let the assertion below report the absence.
  while (!std::filesystem::exists(root / "internal" / "requirements" / "grammar.sgra"))
  {
    auto parent = root.parent_path();
    if (parent == root)
    {
      root.clear();
      break;
    }
    root = std::move(parent);
  }
  // This test reads the SDK's own sources to check a structural property, and finds them by walking
  // up to a marker that exists only in the full development checkout. Without that checkout it fails
  // and names what is missing; a tree that cannot carry the sources leaves this test out of its run
  // through tests/development_only_tests.txt, not by a skip.
  ASSERT_FALSE(root.empty()) << "missing the full development checkout: no repository-root marker "
                                "above UASDK_TEST_SOURCE_DIR (" UASDK_TEST_SOURCE_DIR
                                "), so the audited SDK sources are absent";
  const auto session = root / "sdk" / "implementation" / "server" / "session" / "ua_server_session.cpp";
  ASSERT_TRUE(std::filesystem::exists(session));

  std::ifstream stream{session};
  ASSERT_TRUE(stream.is_open());
  const std::string source{std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};

  const auto createInternal = source.find("void Session::create_internal");
  ASSERT_NE(createInternal, std::string::npos);
  const auto verification = source.find("verify_create_session_certificate_continuity(", createInternal);
  ASSERT_NE(verification, std::string::npos);
  const auto firstIdentityMutation = source.find("mSessionName =", createInternal);
  ASSERT_NE(firstIdentityMutation, std::string::npos);
  EXPECT_LT(verification, firstIdentityMutation);

  const auto callEnd = source.find(");", verification);
  ASSERT_NE(callEnd, std::string::npos);
  const auto verificationCall = source.substr(verification, callEnd - verification);
  EXPECT_NE(verificationCall.find("secureChannelInfo"), std::string::npos);
  EXPECT_NE(verificationCall.find("createSessionRequest.client_certificate()"), std::string::npos);
}

// --- P4-SS-ClientSig: Client application instance signature verification ---

// Unauthenticated channel: activation succeeds without providing a client signature.
// @relation(SVR-SESS-011, scope=function)
TEST_F(ClientSignatureVerificationTests, UnauthenticatedChannelSucceedsWithoutClientSignature)
{
  make_harness(SecurityPolicyId::None);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  // No client_signature set - should succeed on None.
  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* resp = dynamic_cast<ActivateSessionResponse*>(mLastResponse->second.get());
  ASSERT_NE(resp, nullptr) << "Expected ActivateSessionResponse, not ServiceFault";
  EXPECT_TRUE(resp->response_header().service_result().is_good());
}

// Valid client signature on authenticated channel - activation succeeds.
// @relation(SVR-SESS-011, scope=function)
TEST_F(ClientSignatureVerificationTests, ValidClientSignatureSucceeds)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  auto dataToSign = build_data_to_sign();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  asr.client_signature() = sign_with_client_key(dataToSign);

  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* resp = dynamic_cast<ActivateSessionResponse*>(mLastResponse->second.get());
  ASSERT_NE(resp, nullptr) << "Expected ActivateSessionResponse, not ServiceFault";
  EXPECT_TRUE(resp->response_header().service_result().is_good());
}

// Part 4 5.6.2 / 5.6.3: the serverNonce of CreateSession and of every ActivateSession response is at least
// 32 bytes, whatever the channel's SecureChannelNonceLength. Basic128Rsa15's channel nonce is 16 (owner
// decision 11), so on that channel the two differ; each other RSA policy's channel nonce is 32.
// Falsifiable: a call site (CreateSession or ActivateSession) that sized its nonce from the channel
// policy's nonce_length() hands out 16 bytes on the Basic128Rsa15 channel.
// @verifies AC-SVR-SESS-015-SESSION-NONCE-FLOOR-ON-A-SHORT-CHANNEL-NONCE
// @relation(AC-SVR-SESS-015-SESSION-NONCE-FLOOR-ON-A-SHORT-CHANNEL-NONCE, scope=function)
TEST_F(ClientSignatureVerificationTests, ABasic128Rsa15ChannelSessionGetsThirtyTwoByteServerNonces)
{
  const auto sizes = create_and_activate_session_nonce_sizes(SecurityPolicyId::Basic128Rsa15);
  EXPECT_EQ(SecurityPolicy::create(SecurityPolicyId::Basic128Rsa15)->nonce_length(), 16u)
    << "the precondition: this channel's own nonce is shorter than the Session floor";
  EXPECT_EQ(sizes.create, 32u) << "CreateSessionResponse.serverNonce on a Basic128Rsa15 channel";
  EXPECT_EQ(sizes.activate, 32u) << "ActivateSessionResponse.serverNonce on a Basic128Rsa15 channel";
}

// Control: the same Session on a Basic256Sha256 channel, whose channel nonce is itself 32 bytes.
// @verifies AC-SVR-SESS-015-SESSION-NONCE-FLOOR-ON-A-SHORT-CHANNEL-NONCE
// @relation(AC-SVR-SESS-015-SESSION-NONCE-FLOOR-ON-A-SHORT-CHANNEL-NONCE, scope=function)
TEST_F(ClientSignatureVerificationTests, ABasic256Sha256ChannelSessionGetsThirtyTwoByteServerNonces)
{
  const auto sizes = create_and_activate_session_nonce_sizes(SecurityPolicyId::Basic256Sha256);
  EXPECT_EQ(sizes.create, 32u);
  EXPECT_EQ(sizes.activate, 32u);
}

// Empty ClientSignature on an authenticated channel -> the specific Bad_ApplicationSignatureInvalid
// (OPC 10000-4 Table 18); session services are past SecureChannel establishment, so no masking.
// @relation(SVR-SESS-011, scope=function)
TEST_F(ClientSignatureVerificationTests, EmptySignatureOnAuthenticatedChannelRejected)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  // client_signature left empty intentionally.

  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "Expected ServiceFault for missing signature";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadApplicationSignatureInvalid);
}

// A rejected ActivateSession authentication (here: missing client application signature on a secured
// channel) is a session-establishment request rejected for a SECURITY reason, so it increments BOTH
// rejectedSessionCount and its securityRejectedSessionCount subset (OPC 10000-5 12.9). Reproduces the
// security-rejection half of the RejectedSessionCount accounting the CTT checks.
// Covers SVR-DIAG-RejectedSessionCount (CTT Base Info Diagnostics/023 step 1)
TEST_F(ClientSignatureVerificationTests, SecurityRejectedActivationIncrementsBothRejectionCounters)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  auto counters = mSessDeps->summary_counters();
  ASSERT_NE(counters, nullptr);
  const auto rejectedBefore = counters->rejectedSessionCount.load();
  const auto securityRejectedBefore = counters->securityRejectedSessionCount.load();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  // client_signature left empty -> BadApplicationSignatureInvalid, a security rejection.
  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "Expected ServiceFault for the rejected activation";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadApplicationSignatureInvalid);

  EXPECT_EQ(counters->rejectedSessionCount.load(), rejectedBefore + 1)
    << "a security-rejected ActivateSession must increment rejectedSessionCount";
  EXPECT_EQ(counters->securityRejectedSessionCount.load(), securityRejectedBefore + 1)
    << "a security-rejected ActivateSession must increment securityRejectedSessionCount";
}

// A session-service ServiceFault must echo the request's RequestHandle in its ResponseHeader
// (Part 4 section 7.28). Covers F30b (CTT Session Base ActivateSession Err cases):
// create_and_send_service_fault previously built faults with a null RequestHeader, so every session fault
// carried RequestHandle=0.
TEST_F(ClientSignatureVerificationTests, ServiceFaultEchoesRequestHandle)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 4242;
  // Empty client_signature on an authenticated channel -> rejected -> ServiceFault.

  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "Expected ServiceFault for missing signature";
  EXPECT_EQ(sf->response_header().request_handle(), 4242u)
    << "ActivateSession fault must echo the request's RequestHandle, not 0";
}

// Wrong algorithm string -> BadApplicationSignatureInvalid.
// @relation(SVR-SESS-011, SVR-SESS-022, SVR-SESS-043, scope=function)
TEST_F(ClientSignatureVerificationTests, WrongAlgorithmRejected)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  auto dataToSign = build_data_to_sign();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  asr.client_signature() = sign_with_client_key(dataToSign);
  asr.client_signature().algorithm() = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "Expected ServiceFault for algorithm mismatch";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadApplicationSignatureInvalid);
}

// Tampered signature (flipped bit) -> BadApplicationSignatureInvalid.
// @relation(SVR-SESS-011, scope=function)
TEST_F(ClientSignatureVerificationTests, TamperedSignatureRejected)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  auto dataToSign = build_data_to_sign();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  asr.client_signature() = sign_with_client_key(dataToSign);

  // Flip a bit in the signature.
  auto& sig = asr.client_signature().signature();
  ASSERT_FALSE(sig.empty());
  sig[0] ^= uint8_t{0x01};

  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "Expected ServiceFault for tampered signature";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadApplicationSignatureInvalid);
}

// Signature over wrong data (different nonce) -> BadApplicationSignatureInvalid.
// @relation(SVR-IDENT-017, SVR-JWT-015, SVR-SESS-011, SVR-SESS-025, SVR-SESS-043, scope=function)
TEST_F(ClientSignatureVerificationTests, SignatureOverWrongDataRejected)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  // Build data with a different nonce.
  ByteString wrongData = sServerCert->der_encoding();
  ByteString fakeNonce(32, uint8_t{0xFF});
  std::ranges::copy(fakeNonce, std::back_inserter(wrongData));

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  asr.client_signature() = sign_with_client_key(wrongData);

  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "Expected ServiceFault for wrong-nonce signature";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadApplicationSignatureInvalid);
}

// Signature signed with wrong key (server key instead of client key) -> rejected.
// @relation(SVR-SESS-011, scope=function)
TEST_F(ClientSignatureVerificationTests, SignatureWithWrongKeyRejected)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  auto dataToSign = build_data_to_sign();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  // Sign with server key instead of client key.
  auto wrongSig =
    sCrypto->asymmetric_sign_sync(policy->asymmetric_signature_algorithm(), sServerKeys, dataToSign);

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  asr.client_signature().signature() = std::move(wrongSig);
  asr.client_signature().algorithm() = policy->asymmetric_signature_algorithm_uri();

  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "Expected ServiceFault for wrong-key signature";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadApplicationSignatureInvalid);
}

// No client certificate on authenticated channel -> BadApplicationSignatureInvalid.
// LIMITATION: This test manipulates the component under test (client_certificate) via
// TestAccess to simulate a missing client certificate. In practice, the client certificate
// is set during CreateSession from the SecureChannelInfo. To test this edge case without
// TestAccess manipulation would require creating a session on an authenticated channel
// without a client certificate, which the real CreateSession flow does not permit.
// @relation(SVR-SESS-011, scope=function)
TEST_F(ClientSignatureVerificationTests, NoClientCertificateRejected)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  // Clear the client certificate that was set during session creation.
  SessionTestAccess::on_strand(*mSession, [](auto& g) { g.client_certificate() = nullptr; });

  auto dataToSign = build_data_to_sign();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  asr.client_signature() = sign_with_client_key(dataToSign);

  mSession->activate(2, std::move(asr), {});

  wait_for_response();

  auto* sf = dynamic_cast<ServiceFault*>(mLastResponse->second.get());
  ASSERT_NE(sf, nullptr) << "Expected ServiceFault for missing client certificate";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadApplicationSignatureInvalid);
}

// Part 4 7.41: the X509 userTokenSignature is computed over the server certificate (DER) followed by
// the last ServerNonce - the certificate is what binds the proof of possession to THIS server, and
// the order is normative. An implementation that verifies over the nonce alone (or that concatenates
// the two the other way round) still rejects tampered signatures and wrong keys, so every other
// signature test in this file passes; it nonetheless accepts a signature a man-in-the-middle can
// replay to the real server, because nothing in the signed bytes names the server. The positive leg
// is asserted too: without it a server that simply refuses every X509 token would satisfy the
// refusals vacuously.
// @verifies AC-SVR-IDENT-017-X509-SIGNATURE-DATA
TEST_F(ClientSignatureVerificationTests, X509UserTokenSignatureCoversServerCertificateThenNonce)
{
  make_harness(SecurityPolicyId::Basic256Sha256);

  // ActivateSession matches the presented token against the endpoint's advertised user token
  // policies, and make_harness' channel advertises Anonymous only. Rebuild the session over a
  // SecureChannelInfo that advertises an X509 (Certificate) policy so the presented token reaches
  // the signature check rather than being turned away as an unadvertised token type.
  const std::vector<UserTokenPolicy> tokenPolicies{
    ::ua::server::create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::Basic256Sha256)};

  // The session validates the X509 user certificate against the server's user-token store before the
  // signature is checked (Part 4 section 5.6.3; owner review 2026-10-02, item 8), so the token carries a
  // User Certificate (Part 6 Table 44: cA FALSE, digitalSignature) that the user-token store trusts. The
  // application certificate is self-signed with cA TRUE, which Table 44 refuses as a User Certificate.
  TestPki pki{sCrypto};
  const auto userKeys = sCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  Crypto::CreateCertificateConfig userParameters;
  userParameters.subjectKeys = userParameters.issuerKeys = userKeys;
  userParameters.subject.commonName = "Test X509 User";
  userParameters.serialNumber = "4170";
  userParameters.basicConstraint.cA = false;
  userParameters.keyUsage.digitalSignature = true;
  userParameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  userParameters.from = DateTime::now();
  userParameters.to = DateTime{userParameters.from.value() + std::chrono::days{30}};
  const auto userCert = pki.create_cert(userParameters);
  const auto userTokenStoreDirectory = mTempDir / "user_token_store";
  std::filesystem::create_directories(userTokenStoreDirectory);
  auto userTokenStore = CertificateStoreFiles::create(
    mThreadPool.get_executor(), sCrypto, {.trustListPath = userTokenStoreDirectory});
  ASSERT_TRUE(userTokenStore->try_add_to_trusted_certificates_sync(userCert).is_good());
  mSessDeps->set_user_token_certificate_store(userTokenStore);
  const auto signWithUserKey = [&](span<const byte> data)
  {
    const auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
    SignatureData signature;
    signature.signature() =
      sCrypto->asymmetric_sign_sync(policy->asymmetric_signature_algorithm(), userKeys, data);
    signature.algorithm() = policy->asymmetric_signature_algorithm_uri();
    return signature;
  };

  // Sessions replaced during the test are kept alive here and destroyed at end of scope, before
  // TearDown drains the pool (their inactivity timers hold pool work until they die).
  std::vector<shared_ptr<Session>> retiredSessions;

  auto recreateSessionAdvertisingX509 = [&]()
  {
    clear_response();
    retiredSessions.push_back(mSession);

    SecureChannelInfo sci(mSc->weak_from_this(),
      SecurityPolicy::create(SecurityPolicyId::Basic256Sha256),
      MessageSecurityMode::None,
      "L/Ep",
      tokenPolicies,
      sClientCert);

    CreateSessionRequest csr;
    csr.client_nonce() = sCrypto->get_entropy_sync(32);
    csr.client_certificate() = sClientCert->der_encoding();
    csr.client_description().application_uri() = "urn:test:client";
    mSession = Session::create(mSessDeps, sci, 1, std::move(csr));
    SessionTestAccess::strand_barrier(*mSession);
    wait_for_response();
    clear_response();
  };

  // The nonce is generated by the CreateSession response flow, which hops off the session strand for
  // entropy and for the certificate load. Each strand_barrier is a round trip through the pool, so
  // re-reading behind one lets that chain settle; the caller still asserts the nonce is non-empty.
  auto currentServerNonce = [&]()
  {
    ByteString nonce;
    for (int attempt = 0; attempt < 100 && nonce.empty(); ++attempt)
    {
      SessionTestAccess::strand_barrier(*mSession);
      std::ranges::copy(
        SessionTestAccess::on_strand(*mSession, [](auto& g) -> auto& { return g.server_nonce(); }),
        std::back_inserter(nonce));
    }
    return nonce;
  };

  // Drives a full ActivateSession with a correct client application signature (so the flow reaches
  // the user-token check) and an X509 identity token whose userTokenSignature covers exactly
  // `userTokenSignedData`. Returns the service result the server put on the wire.
  auto activateWithUserTokenSignatureOver = [&](const ByteString& userTokenSignedData)
  {
    ActivateSessionRequest asr;
    asr.request_header().request_handle() = 42;
    asr.client_signature() = sign_with_client_key(build_data_to_sign());

    auto token = std::make_unique<X509IdentityToken>();
    token->certificate_data() = userCert->der_encoding();
    token->policy_id() = tokenPolicies.front().policy_id();
    asr.user_identity_token() = std::move(token);
    asr.user_token_signature() = signWithUserKey(userTokenSignedData);

    mSession->activate(2, std::move(asr), {});

    wait_for_response();
    if (!mLastResponse.has_value())
      return StatusCode{Status::BadInternalError};
    if (auto* fault = dynamic_cast<ServiceFault*>(mLastResponse->second.get()))
    {
      const auto result = fault->response_header().service_result();
      clear_response();
      return result;
    }
    if (auto* ok = dynamic_cast<ActivateSessionResponse*>(mLastResponse->second.get()))
    {
      const auto result = ok->response_header().service_result();
      clear_response();
      return result;
    }
    return StatusCode{Status::BadInternalError};
  };

  const ByteString serverCertDer = sServerCert->der_encoding();
  ASSERT_FALSE(serverCertDer.empty());

  // 1. The ServerNonce alone, with the server certificate omitted: refused.
  recreateSessionAdvertisingX509();
  const ByteString nonceOnly = currentServerNonce();
  ASSERT_FALSE(nonceOnly.empty()) << "server nonce must be populated before signing over it";
  EXPECT_EQ(activateWithUserTokenSignatureOver(nonceOnly), Status::BadUserSignatureInvalid)
    << "a userTokenSignature that omits the server certificate must not activate the session";

  // 2. Both parts present but concatenated the other way round (nonce then certificate): refused,
  //    because the order is part of the signed-data definition.
  recreateSessionAdvertisingX509();
  ByteString nonceThenCertificate = currentServerNonce();
  ASSERT_FALSE(nonceThenCertificate.empty());
  std::ranges::copy(serverCertDer, std::back_inserter(nonceThenCertificate));
  EXPECT_EQ(activateWithUserTokenSignatureOver(nonceThenCertificate), Status::BadUserSignatureInvalid)
    << "userTokenSignature data is serverCertificate followed by ServerNonce, not the reverse";

  // 3. The spec construction - server certificate (DER) then the ServerNonce - is accepted.
  recreateSessionAdvertisingX509();
  ByteString certificateThenNonce = serverCertDer;
  const ByteString nonceForSpecOrder = currentServerNonce();
  ASSERT_FALSE(nonceForSpecOrder.empty());
  std::ranges::copy(nonceForSpecOrder, std::back_inserter(certificateThenNonce));
  EXPECT_TRUE(activateWithUserTokenSignatureOver(certificateThenNonce).is_good())
    << "a userTokenSignature over serverCertificate || ServerNonce must activate the session";
}

// ===================================================================
// 1.05.07 SecureChannelEnhancements: channel bound session signatures (OPC 10000-4 section 6.1.8)
// ===================================================================

// SVR-SCE-010: an X509 token policy with SecureChannelEnhancements (RSA_DH) presented over a secured
// Basic256Sha256 SignAndEncrypt channel, which has none, cannot be signed over Table 101 (there is no
// ChannelThumbprint). The ActivateSession is refused with Bad_IdentityTokenInvalid; the authentication
// failure the server reports (the fault itself carries no ErrorDetail for this code) names the token-policy
// rule.
// @relation(AC-SVR-SCE-010-ENHANCED-TOKEN-OVER-LEGACY-CHANNEL, scope=function)
TEST_F(ClientSignatureVerificationTests, AnEnhancedX509TokenPolicyOverALegacyChannelIsRefused)
{
  const auto tokenPolicy =
    ::ua::server::create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::RsaDhAesGcm);
  make_harness(SecurityPolicyId::Basic256Sha256, std::nullopt, false, "urn:test:client", {tokenPolicy});
  auto failures = std::make_shared<AuthenticationFailureObserver>();
  mSessDeps->set_observer(failures);

  // The harness's session is over a None-mode channel; this one is over a secured legacy channel.
  clear_response();
  mRetiredSessions.push_back(mSession);
  SecureChannelInfo sci(mSc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::Basic256Sha256),
    MessageSecurityMode::SignAndEncrypt,
    "L/Ep",
    {tokenPolicy},
    sClientCert);
  CreateSessionRequest csr;
  csr.client_nonce() = sCrypto->get_entropy_sync(32);
  csr.endpoint_url() = "opc.tcp://127.0.0.1:4840";
  csr.client_certificate() = sClientCert->der_encoding();
  csr.client_description().application_uri() = "urn:test:client";
  mSession = Session::create(mSessDeps, sci, 1, std::move(csr));
  SessionTestAccess::strand_barrier(*mSession);
  wait_for_response();
  clear_response();

  ActivateSessionRequest request;
  request.request_header().request_handle() = 42;
  request.client_signature() = sign_with_client_key(build_data_to_sign());
  auto token = std::make_unique<X509IdentityToken>();
  token->certificate_data() = sClientCert->der_encoding();
  token->policy_id() = tokenPolicy.policy_id();
  request.user_identity_token() = std::move(token);
  request.user_token_signature().signature() = ByteString{std::vector<byte>(256, byte{0x5A})};

  const auto status = activate_and_wait(std::move(request));
  EXPECT_EQ(status, Status::BadIdentityTokenInvalid) << to_string(status.as_status());
  const auto reasons = failures->reasons();
  ASSERT_EQ(reasons.size(), 1u) << "the server reported no authentication failure";
  EXPECT_EQ(reasons.front(), Status::BadIdentityTokenInvalid);
  bool namesTheRule = false;
  std::string chain;
  for (const auto* detail = reasons.front().shared_detail().get(); detail != nullptr;
       detail = detail->cause.get())
  {
    namesTheRule = namesTheRule || detail->code == "EnhancedTokenPolicyOverLegacyChannel";
    chain += " " + std::string{detail->code};
  }
  EXPECT_TRUE(namesTheRule) << "the refusal does not name the token-policy rule; chain:" << chain;
}

// OPC 10000-4 5.7.3.1: a re-activation keeps "the SecurityPolicy and SecurityMode ... of the original
// SecureChannel". CreateSession records them, so a Session whose channel is gone is still held to them
// (ServerActivateNewChannel.AMoveToAnotherPolicyOrModeIsRefusedAfterTheOldChannelIsGone decides on the
// recorded values).
// @relation(AC-SVR-SCE-012-POLICY-OR-MODE-CHANGE-REFUSED, scope=function)
TEST_F(ClientSignatureVerificationTests, CreateSessionRecordsTheSecurityOfItsChannel)
{
  mEnhancedChannel = true;
  make_harness(SecurityPolicyId::EccNistP256AesGcm);
  const auto recorded = SessionTestAccess::on_strand(
    *mSession, [](auto& g) { return std::pair{g.channel_security_policy_id(), g.channel_security_mode()}; });
  EXPECT_EQ(recorded.first, SecurityPolicyId::EccNistP256AesGcm);
  EXPECT_EQ(recorded.second, MessageSecurityMode::SignAndEncrypt);
}

// Over an enhanced channel the ServerSignature in the CreateSession response covers the Table 101
// ServerSignature data - ChannelThumbprint, ClientNonce, the hashes of the two channel certificates and the
// ServerNonce - and carries no algorithm (Table 174); it does not cover the legacy ClientCertificate |
// ClientNonce. The contrast is a Basic256Sha256 Session, whose ServerSignature is the legacy one with its
// algorithm URI.
// @relation(AC-SVR-SCE-011-ALGORITHM-EMPTY-AND-IGNORED, scope=function)
// @relation(AC-SVR-SCE-010-SIGNATURE-DATA, scope=function)
TEST_F(ClientSignatureVerificationTests, AnEnhancedServerSignatureIsChannelBoundWithNoAlgorithm)
{
  mEnhancedChannel = true;
  make_harness(SecurityPolicyId::EccNistP256AesGcm, std::nullopt, /*preserveCreateResponse*/ true);
  settle_create_response_path();
  const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  SignatureData serverSignature;
  ByteString serverNonce;
  {
    std::lock_guard<std::mutex> lk(mMutex);
    ASSERT_TRUE(mLastResponse.has_value());
    auto* created = dynamic_cast<CreateSessionResponse*>(mLastResponse->second.get());
    ASSERT_NE(created, nullptr) << "the CreateSession over the enhanced channel was refused";
    serverSignature = created->server_signature();
    serverNonce = created->server_nonce();
  }
  EXPECT_TRUE(serverSignature.algorithm().empty()) << "an enhanced ServerSignature names an algorithm";
  const auto data = ua::test_helpers::channel_bound_data(
    *sCrypto, *policy, ChannelBoundSignature::Server, enhanced_inputs(serverNonce));
  EXPECT_NO_THROW(sCrypto->asymmetric_verify_sync(policy->asymmetric_signature_algorithm(),
    sServerEccCert->public_key(),
    data,
    serverSignature.signature()))
    << "the ServerSignature does not cover the Table 101 data";
  ByteString legacy = sClientEccCert->der_encoding();
  std::ranges::copy(mClientNonce, std::back_inserter(legacy));
  EXPECT_THROW(sCrypto->asymmetric_verify_sync(policy->asymmetric_signature_algorithm(),
                 sServerEccCert->public_key(),
                 legacy,
                 serverSignature.signature()),
    UaException)
    << "the ServerSignature covers the legacy data";
}

// The contrast of the test above: a Basic256Sha256 Session's ServerSignature covers the legacy
// ClientCertificate | ClientNonce and names its algorithm.
// @relation(AC-SVR-SCE-011-ALGORITHM-EMPTY-AND-IGNORED, scope=function)
TEST_F(ClientSignatureVerificationTests, ALegacyServerSignatureKeepsItsLayoutAndAlgorithm)
{
  make_harness(SecurityPolicyId::Basic256Sha256, std::nullopt, /*preserveCreateResponse*/ true);
  settle_create_response_path();
  std::lock_guard<std::mutex> lk(mMutex);
  ASSERT_TRUE(mLastResponse.has_value());
  auto* legacyCreated = dynamic_cast<CreateSessionResponse*>(mLastResponse->second.get());
  ASSERT_NE(legacyCreated, nullptr);
  const auto rsa = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  EXPECT_EQ(std::string_view{legacyCreated->server_signature().algorithm()},
    std::string_view{rsa->asymmetric_signature_algorithm_uri()});
  ByteString legacyData = sClientCert->der_encoding();
  std::ranges::copy(mClientNonce, std::back_inserter(legacyData));
  EXPECT_NO_THROW(sCrypto->asymmetric_verify_sync(rsa->asymmetric_signature_algorithm(),
    sServerCert->public_key(),
    legacyData,
    legacyCreated->server_signature().signature()));
}

// Over an enhanced channel a ClientSignature over the legacy ServerCertificate | ServerNonce is refused with
// Bad_ApplicationSignatureInvalid and leaves the Session unactivated; the control signs the Table 101
// ClientSignature data and activates it.
// @relation(AC-SVR-SCE-010-LEGACY-SIGNATURE-REFUSED, scope=function)
TEST_F(ClientSignatureVerificationTests, ALegacyClientSignatureOverAnEnhancedChannelIsRefused)
{
  mEnhancedChannel = true;
  make_harness(SecurityPolicyId::EccNistP256AesGcm);
  const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  const auto serverNonce = current_server_nonce();
  ASSERT_FALSE(serverNonce.empty());

  ActivateSessionRequest legacy;
  legacy.request_header().request_handle() = 42;
  ByteString legacyData = sServerEccCert->der_encoding();
  std::ranges::copy(serverNonce, std::back_inserter(legacyData));
  legacy.client_signature() = sign_with_ecc_client_key(legacyData);
  EXPECT_EQ(activate_and_wait(std::move(legacy)), Status::BadApplicationSignatureInvalid);
  EXPECT_EQ(SessionTestAccess::on_strand(*mSession, [](auto& g) { return g.state().load(); }),
    SessionTestAccess::State::Created)
    << "the refused activation changed the Session's state";

  ActivateSessionRequest bound;
  bound.request_header().request_handle() = 43;
  bound.client_signature() = sign_with_ecc_client_key(ua::test_helpers::channel_bound_data(
    *sCrypto, *policy, ChannelBoundSignature::Client, enhanced_inputs(current_server_nonce())));
  EXPECT_TRUE(activate_and_wait(std::move(bound), 3).is_good()) << "control: the Table 101 signature";
}

// Table 174: under an enhanced policy the algorithm of a received SignatureData is ignored - a correct
// ClientSignature naming an unrelated algorithm URI activates. Under Basic256Sha256 the same URI is refused
// (ClientSignatureVerificationTests.WrongAlgorithmRejected), so the ignoring is per policy.
// @relation(AC-SVR-SCE-011-ALGORITHM-EMPTY-AND-IGNORED, scope=function)
TEST_F(ClientSignatureVerificationTests, AnEnhancedClientSignatureAlgorithmIsIgnored)
{
  mEnhancedChannel = true;
  make_harness(SecurityPolicyId::EccNistP256AesGcm);
  const auto policy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);

  ActivateSessionRequest request;
  request.request_header().request_handle() = 42;
  request.client_signature() = sign_with_ecc_client_key(
    ua::test_helpers::channel_bound_data(
      *sCrypto, *policy, ChannelBoundSignature::Client, enhanced_inputs(current_server_nonce())),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
  EXPECT_TRUE(activate_and_wait(std::move(request)).is_good());
}

// OPC 10000-4 6.1.8 (SD-6): the UserTokenPolicy's SecurityPolicy decides an X509 UserTokenSignature. Over an
// enhanced ECC_nistP256 channel, a token policy of the channel's own (enhanced) policy is signed over the
// Table 101 UserTokenSignature data, and a Basic256Sha256 token policy over ServerCertificate | ServerNonce;
// each activates. A signature over the other's layout is refused with Bad_UserSignatureInvalid. The token
// policy also decides the HASH of Table 101: an ECC_nistP384 token policy (SHA-384) activates with the
// certificate hashes taken by SHA-384, and is refused with them taken by the channel's SHA-256.
// @relation(AC-SVR-SCE-010-X509-TOKEN, scope=function)
TEST_F(ClientSignatureVerificationTests, AnX509TokenSignsTheLayoutOfItsTokenPolicy)
{
  const auto enhancedTokenPolicy =
    ::ua::server::create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::EccNistP256AesGcm);
  const auto rsaTokenPolicy =
    ::ua::server::create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::Basic256Sha256);
  const auto p384TokenPolicy =
    ::ua::server::create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::EccNistP384AesGcm);
  ASSERT_NE(std::string_view{enhancedTokenPolicy.policy_id()}, std::string_view{rsaTokenPolicy.policy_id()});
  ASSERT_NE(std::string_view{enhancedTokenPolicy.policy_id()}, std::string_view{p384TokenPolicy.policy_id()});

  // User Certificates (Part 6 Table 44: cA FALSE, digitalSignature), one per token policy family, trusted by
  // the user-token store the Session validates them against before their signature.
  TestPki pki{sCrypto};
  const auto makeUser = [&](CertificateKeyAlgorithm keyAlgorithm,
                          CertificateSignatureAlgorithm signatureAlgorithm,
                          std::string serial)
  {
    const auto keys = keyAlgorithm == CertificateKeyAlgorithm::Rsa
                        ? sCrypto->create_asymmetric_key_pair_sync(keyAlgorithm, 2048)
                        : sCrypto->create_asymmetric_key_pair_sync(keyAlgorithm, std::nullopt);
    Crypto::CreateCertificateConfig parameters;
    parameters.subjectKeys = parameters.issuerKeys = keys;
    parameters.subject.commonName = "Test X509 User " + serial;
    parameters.serialNumber = std::move(serial);
    parameters.basicConstraint.cA = false;
    parameters.keyUsage.digitalSignature = true;
    parameters.certificateSignatureAlgorithm = signatureAlgorithm;
    parameters.from = DateTime::now();
    parameters.to = DateTime{parameters.from.value() + std::chrono::days{30}};
    return std::make_pair(keys, pki.create_cert(parameters));
  };
  const auto [eccUserKeys, eccUserCert] =
    makeUser(CertificateKeyAlgorithm::EccNistP256, CertificateSignatureAlgorithm::EcDsaSha2256, "4171");
  const auto [rsaUserKeys, rsaUserCert] =
    makeUser(CertificateKeyAlgorithm::Rsa, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, "4172");
  const auto [p384UserKeys, p384UserCert] =
    makeUser(CertificateKeyAlgorithm::EccNistP384, CertificateSignatureAlgorithm::EcDsaSha2384, "4173");

  struct Arm
  {
    const UserTokenPolicy& tokenPolicy;
    shared_ptr<const AsymmetricKeyPair> userKeys;
    shared_ptr<const X509Certificate> userCert;
    bool signTable101;
    // Table 101 hashed by the channel's policy rather than the token policy's.
    bool hashAsTheChannel;
    bool expectGood;
    const char* what;
  };

  const Arm arms[] = {
    {enhancedTokenPolicy, eccUserKeys, eccUserCert, true, false, true, "enhanced token policy, Table 101"},
    {enhancedTokenPolicy,
      eccUserKeys,
      eccUserCert,
      false,
      false,
      false,
      "enhanced token policy, legacy layout"},
    {rsaTokenPolicy, rsaUserKeys, rsaUserCert, false, false, true, "RSA token policy, legacy layout"},
    {rsaTokenPolicy, rsaUserKeys, rsaUserCert, true, true, false, "RSA token policy, Table 101"},
    {p384TokenPolicy,
      p384UserKeys,
      p384UserCert,
      true,
      false,
      true,
      "ECC_nistP384 token policy, its own HASH"},
    {p384TokenPolicy,
      p384UserKeys,
      p384UserCert,
      true,
      true,
      false,
      "ECC_nistP384 token policy, the channel's HASH"},
  };
  mEnhancedChannel = true;
  const std::vector<UserTokenPolicy> tokenPolicies{enhancedTokenPolicy, rsaTokenPolicy, p384TokenPolicy};
  make_harness(SecurityPolicyId::EccNistP256AesGcm, std::nullopt, false, "urn:test:client", tokenPolicies);
  const auto userTokenStoreDirectory = mTempDir / "user_token_store";
  std::filesystem::create_directories(userTokenStoreDirectory);
  auto userTokenStore = CertificateStoreFiles::create(
    mThreadPool.get_executor(), sCrypto, {.trustListPath = userTokenStoreDirectory});
  ASSERT_TRUE(userTokenStore->try_add_to_trusted_certificates_sync(eccUserCert).is_good());
  ASSERT_TRUE(userTokenStore->try_add_to_trusted_certificates_sync(rsaUserCert).is_good());
  ASSERT_TRUE(userTokenStore->try_add_to_trusted_certificates_sync(p384UserCert).is_good());
  mSessDeps->set_user_token_certificate_store(userTokenStore);

  for (const auto& arm : arms)
  {
    SCOPED_TRACE(arm.what);
    recreate_enhanced_session(tokenPolicies);
    const auto channelPolicy = SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
    const auto tokenSecurityPolicy = SecurityPolicy::create(arm.tokenPolicy.security_policy_uri());
    const auto serverNonce = current_server_nonce();
    ASSERT_FALSE(serverNonce.empty());

    ActivateSessionRequest request;
    request.request_header().request_handle() = 42;
    request.client_signature() = sign_with_ecc_client_key(ua::test_helpers::channel_bound_data(
      *sCrypto, *channelPolicy, ChannelBoundSignature::Client, enhanced_inputs(serverNonce)));
    auto token = std::make_unique<X509IdentityToken>();
    token->certificate_data() = arm.userCert->der_encoding();
    token->policy_id() = arm.tokenPolicy.policy_id();
    request.user_identity_token() = std::move(token);
    ByteString userTokenData;
    if (arm.signTable101)
    {
      // HASH is the token policy's CertificateThumbprintAlgorithm; an RSA policy without
      // SecureChannelEnhancements has none, so its wrong-layout arm hashes as the channel does.
      const auto& hashPolicy = arm.hashAsTheChannel ? *channelPolicy : *tokenSecurityPolicy;
      userTokenData = ua::test_helpers::channel_bound_data(
        *sCrypto, hashPolicy, ChannelBoundSignature::UserToken, enhanced_inputs(serverNonce));
    }
    else
    {
      userTokenData = sServerEccCert->der_encoding();
      std::ranges::copy(serverNonce, std::back_inserter(userTokenData));
    }
    request.user_token_signature().signature() = sCrypto->asymmetric_sign_sync(
      tokenSecurityPolicy->asymmetric_signature_algorithm(), arm.userKeys, userTokenData);
    if (!tokenSecurityPolicy->secure_channel_enhancements())
      request.user_token_signature().algorithm() = tokenSecurityPolicy->asymmetric_signature_algorithm_uri();

    const auto status = activate_and_wait(std::move(request));
    if (arm.expectGood)
      EXPECT_TRUE(status.is_good()) << to_string(status.as_status());
    else
      EXPECT_EQ(status, Status::BadUserSignatureInvalid);
  }
}
