// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"

#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_security_policy.h"
#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_create_session_request.h"

#include "ua_anonymous_identity_token.h"
#include "ua_user_name_identity_token.h"
#include "ua_issued_identity_token.h"
#include "ua_service_fault.h"
#include "ua_crypto.h"

#include "ua_sec_pol_basic128_rsa15.h"
#include "ua_sec_pol_basic256.h"
#include "ua_sec_pol_basic256_sha256.h"
#include "ua_sec_pol_aes128_sha256_rsa_oaep.h"
#include "ua_sec_pol_aes256_sha256_rsa_pss.h"
#include "ua_sec_pol_none.h"
#include "ua_sec_pol_ephemeral_key.h"
#include "ua_x509_certificate.h"

#include "ua_user_token_encryption.h"
#include "ua_additional_parameters_type.h"
#include "ua_ephemeral_key_type.h"
#include "ua_key_value_pair.h"
#include "channel_bound_signature_test_data.h"
#include "fake_async_crypto.h"
#include "ua_certificate_store.h"
#include "ua_stack_utilities.h"
#include "run_async_sync.h"
#include "test_pki_helpers.h"

#include "ua_server_components.h"
#include "ua_server_observer.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <future>
#include <iterator>
#include <mutex>
#include <string_view>
#include <thread>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

namespace
{
// The strand a bound channel always carries. These entry points marshal every continuation onto it -
// they no longer accept not having one - so the pool has to be running for the blocking helpers
// below to ever see an answer.
boost::asio::strand<boost::asio::any_io_executor> crypto_test_strand()
{
  static boost::asio::thread_pool pool{2};
  return boost::asio::make_strand(boost::asio::any_io_executor{pool.get_executor()});
}
}  // namespace

using namespace ua;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace ua::server;
using SCTA = ua::server::SecureChannelTestAccess;
using namespace std::chrono_literals;
using SCTA = ua::server::SecureChannelTestAccess;

namespace
{

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

std::shared_ptr<const Crypto> create_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

ByteString make_nonce(const Crypto& crypto, size_t size)
{
  ByteString nonce;
  nonce.resize(size);
  auto entropy = crypto.get_entropy_sync(size);
  std::memcpy(nonce.data(), entropy.data(), size);
  return nonce;
}

// ---------------------------------------------------------------------------
// RecordingAuthenticator - captures AuthnRequest fields and approves.
// ---------------------------------------------------------------------------

class RecordingTokenAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    {
      std::lock_guard<std::mutex> lk(mMutex);
      mCalled = true;
      mKind = req.identity.kind;
      mUserName = req.identity.userName.value_or("");
      if (req.identity.password.has_value())
      {
        mPassword = std::string(req.identity.password->c_str());
      }
    }

    completion(
      make_authn_success(UserIdentity{.userId = "testuser", .displayName = "Test User", .claims = {}}));
  }

  bool called() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mCalled;
  }

  UserTokenKind kind() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mKind;
  }

  std::string user_name() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mUserName;
  }

  std::string password() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mPassword;
  }

private:
  mutable std::mutex mMutex;
  bool mCalled{false};
  UserTokenKind mKind{UserTokenKind::Unsupported};
  std::string mUserName;
  std::string mPassword;
};

// ---------------------------------------------------------------------------
// CryptoSessionDeps - FakeSessionDeps with real Crypto.
// ---------------------------------------------------------------------------

// The authentication deadline of a harness in which an activation is expected to succeed: the SDK's own
// default (see CryptoSessionDeps). A harness that also refuses waits this long for each refusal.
const std::chrono::milliseconds successAuthnTimeout = ::ua::server::ServerConfig{}.authnTimeout;

class CryptoSessionDeps final : public SessionDependencies
{
public:
  // The authentication deadline holds every failure until it passes, so a short one keeps the refusal
  // tests fast. A harness that expects a SUCCESS passes successAuthnTimeout: a success is answered as
  // soon as it is known, while a 4096-bit RSA decryption on a loaded CI host can take longer than 50 ms
  // and would be abandoned as a slow authenticator (measured 2026-10-16: 8 in 96 runs under 12-way load).
  CryptoSessionDeps(boost::asio::any_io_executor ex, ServerComponents hooks, shared_ptr<const Crypto> crypto,
    std::shared_ptr<ServerObserver> observer = {}, std::chrono::milliseconds authnTimeout = 50ms)
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mCrypto(std::move(crypto)), mObserver(std::move(observer))
  {
    mServerCfg.authnTimeout = authnTimeout;
  }

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
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
    return nullptr;
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
    return mObserver;
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
    return nullptr;
  }

  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() override
  {
    return nullptr;
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
  SubscriptionIdAllocator mSubscriptionIdAllocator;
  SubscriptionRouter mSubscriptionRouter;
  OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  boost::asio::any_io_executor mExecutor;
  EventBus mEventBus{AddressSpace::create("", mExecutor)};
  std::shared_ptr<const ::ua::ApplicationConfig> mAppCfg;
  ::ua::server::ServerConfig mServerCfg;
  ::ua::server::ServerComponents mHooks;
  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<ServerObserver> mObserver;
};

// ---------------------------------------------------------------------------
// DummySecureChannelDeps
// ---------------------------------------------------------------------------

class DummySecureChannelDeps : public SecureChannelDependencies
{
public:
  explicit DummySecureChannelDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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
    return nullptr;
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
  ::ua::ApplicationConfig mAppCfg{::ua::ApplicationConfig::load_default()};
  ::ua::server::ServerConfig mServerCfg;
};

// ===================================================================
// RSA parameterized tests
// ===================================================================

struct ServerRsaTokenParams
{
  SecurityPolicyId policyId;
  size_t keyBits;
  CertificateSignatureAlgorithm certSigAlg;
  std::string name;
};

class ServerActivateRsaTokenEncryption : public ::testing::TestWithParam<ServerRsaTokenParams>
{};

// End-to-end through production paths: the client (encrypt_user_token_async) encrypts a UserName token,
// then the server's ActivateSession/parse_identity_token_async recovers it. Deprecated RSA policies use
// the legacy section 7.41.2.2 form; modern policies (Basic256Sha256+) use the section 7.41.2.4
// RsaEncryptedSecret form and exercise the server's auto-detect-and-route path (falsified: neutering
// is_rsa_encrypted_secret makes the modern arms RED). CL-IDENT-005 Slice 2b.
// @verifies CL-IDENT-005
// @relation(CL-IDENT-005, SVR-IDENT-008, SVR-SESS-028, scope=function)
TEST_P(ServerActivateRsaTokenEncryption, DecryptsPasswordCorrectly)
{
  const auto& params = GetParam();
  auto crypto = create_crypto();
  auto policy = SecurityPolicy::create(params.policyId);

  // Generate server RSA key pair and certificate.
  auto serverKeyPair = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, params.keyBits);

  TestPki pki{create_crypto()};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = serverKeyPair;
  certParams.issuerKeys = serverKeyPair;
  certParams.subject.commonName = "TestServer";
  certParams.serialNumber = "1";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.certificateSignatureAlgorithm = params.certSigAlg;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  auto serverCert = pki.create_cert(certParams);

  // Generate server nonce.
  auto serverNonce = make_nonce(*crypto, 32);

  // Build and encrypt a UserNameIdentityToken.
  auto tokenPtr = std::make_shared<UserNameIdentityToken>();
  constexpr string_view passwordText = "TestPassword123!";
  ByteString originalPassword;
  originalPassword.assign(reinterpret_cast<const uint8_t*>(passwordText.data()),
    reinterpret_cast<const uint8_t*>(passwordText.data()) + passwordText.size());
  tokenPtr->password() = originalPassword;
  tokenPtr->user_name() = "testuser";

  auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(policy,
        crypto,
        crypto_test_strand(),
        tokenPtr,
        serverNonce,
        serverCert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(encResult.is_good()) << "Encrypt failed: " << to_string(encResult.status_code().as_status());
  ASSERT_NE(tokenPtr->password(), originalPassword) << "Token must be encrypted";

  // Set up the session harness.
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto authenticator = std::make_shared<RecordingTokenAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<CryptoSessionDeps>(ex, hooks, crypto, nullptr, successAuthnTimeout);

  auto scDeps = std::make_shared<DummySecureChannelDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(
        ex, "L/None", {server::create_user_token_policy(UserTokenType::UserName, params.policyId)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  // Wait for create to finish on strand.
  SessionTestAccess::strand_barrier(*session);

  // LIMITATION: The test injects server_nonce, server_certificates, and
  // selected_server_cert_and_key directly via TestAccess rather than flowing them
  // through the real CreateSession code path. This is necessary because the real
  // CreateSession requires a fully wired CertificateStore (which CryptoSessionDeps
  // does not provide). The injected state is only precondition setup for the code
  // under test (token decryption during ActivateSession), not the code being verified.
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.server_nonce() = serverNonce;
      g.server_certificates().push_back(
        CertificateStore::ApplicationCertificate{policy->certificate_type(), serverCert, serverKeyPair});
      g.selected_cert_and_key() = g.server_certificates().back();
    });

  // Build ActivateSessionRequest with encrypted token.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  auto activateToken = std::make_unique<UserNameIdentityToken>(*tokenPtr);
  // Set policy_id to match the advertised UserName policy so it passes policy matching.
  activateToken->policy_id() =
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }).front().policy_id();
  asr.user_identity_token() = std::move(activateToken);

  session->activate(2, std::move(asr), {});

  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, successAuthnTimeout + 2s, [&]() { return last.has_value(); }));

  auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get());
  const auto* fault = dynamic_cast<ServiceFault*>(last->second.get());
  ASSERT_NE(resp, nullptr) << "Expected ActivateSessionResponse, got ServiceFault "
                           << (fault != nullptr ? describe(fault->response_header().service_result()) : "");
  EXPECT_TRUE(resp->response_header().service_result().is_good())
    << "Service result: " << to_string(resp->response_header().service_result().as_status());

  // Every ActivateSession response returns a FRESH server nonce. The channel here is
  // SecurityPolicy#None, so the nonce length is resolved from the endpoint's (encrypted) user-token
  // policies - not the channel policy, whose nonce length is 0. Without this a re-ActivateSession
  // (Change User) over a None channel would have no valid nonce to encrypt its next token against and
  // be rejected as malformed. (Part 4 section 5.6.3 / section 7.41; regression for CTT Session Change User.)
  EXPECT_GE(resp->server_nonce().size(), 32u)
    << "ActivateSession over None with an encrypted user-token policy must return a >=32-byte nonce";
  EXPECT_NE(resp->server_nonce(), serverNonce)
    << "the ActivateSession nonce must be freshly generated, not the prior (CreateSession) nonce";

  ASSERT_TRUE(authenticator->called());
  EXPECT_EQ(authenticator->kind(), UserTokenKind::UserName);
  EXPECT_EQ(authenticator->user_name(), "testuser");
  EXPECT_EQ(authenticator->password(), "TestPassword123!");

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

INSTANTIATE_TEST_SUITE_P(ServerActivateRsaTokenEncryptionPolicies, ServerActivateRsaTokenEncryption,
  ::testing::Values(
    ServerRsaTokenParams{
      SecurityPolicyId::Basic128Rsa15, 1024, CertificateSignatureAlgorithm::RsaPkcs15Sha1, "Basic128Rsa15"},
    ServerRsaTokenParams{
      SecurityPolicyId::Basic256, 2048, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, "Basic256"},
    ServerRsaTokenParams{SecurityPolicyId::Basic256Sha256,
      2048,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Basic256Sha256"},
    ServerRsaTokenParams{SecurityPolicyId::Aes128Sha256RsaOaep,
      2048,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Aes128Sha256RsaOaep"},
    ServerRsaTokenParams{SecurityPolicyId::Aes256Sha256RsaPss,
      4096,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Aes256Sha256RsaPss"}),
  [](const ::testing::TestParamInfo<ServerRsaTokenParams>& info) { return info.param.name; });

// ===================================================================
// UserName token acceptance: encryption requirement and nonce binding
// ===================================================================

// Outcome of one ActivateSession round, captured after the harness has drained so every field is
// stable at the point the assertions read it.
struct TokenActivationOutcome
{
  bool gotResponse{false};
  bool isActivateResponse{false};
  bool isFault{false};
  bool authenticatorCalled{false};
  std::string password;
  StatusCode serviceResult{Status::BadInternalError};
};

// Runs one ActivateSession carrying `presentedToken` against an endpoint whose UserName
// UserTokenPolicy is `tokenPolicyId`, with `sessionNonce` standing as the nonce the server last
// issued. Identical in every respect to the harness of ServerActivateRsaTokenEncryption above, so
// the only variable between a passing and a refused activation is the token the caller supplies.
void activate_with_user_name_token(SecurityPolicyId tokenPolicyId, const shared_ptr<const Crypto>& crypto,
  const shared_ptr<const SecurityPolicy>& tokenPolicy, const shared_ptr<const X509Certificate>& serverCert,
  const shared_ptr<const AsymmetricKeyPair>& serverKeyPair, const ByteString& sessionNonce,
  const UserNameIdentityToken& presentedToken, TokenActivationOutcome& outcome)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto authenticator = std::make_shared<RecordingTokenAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<CryptoSessionDeps>(ex, hooks, crypto, nullptr, successAuthnTimeout);

  auto scDeps = std::make_shared<DummySecureChannelDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(
        ex, "L/None", {server::create_user_token_policy(UserTokenType::UserName, tokenPolicyId)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  // Same precondition injection as ServerActivateRsaTokenEncryption: CreateSession itself needs a
  // fully wired CertificateStore, which CryptoSessionDeps does not provide. Only the preconditions
  // are injected; the acceptance decision under test is left entirely to the production path.
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.server_nonce() = sessionNonce;
      g.server_certificates().push_back(
        CertificateStore::ApplicationCertificate{tokenPolicy->certificate_type(), serverCert, serverKeyPair});
      g.selected_cert_and_key() = g.server_certificates().back();
    });

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  auto activateToken = std::make_unique<UserNameIdentityToken>(presentedToken);
  activateToken->policy_id() =
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }).front().policy_id();
  asr.user_identity_token() = std::move(activateToken);

  session->activate(2, std::move(asr), {});

  {
    std::unique_lock<std::mutex> lk(mx);
    outcome.gotResponse = cv.wait_for(lk, successAuthnTimeout + 2s, [&]() { return last.has_value(); });
    if (outcome.gotResponse)
    {
      if (auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get()))
      {
        outcome.isActivateResponse = true;
        outcome.serviceResult = resp->response_header().service_result();
      }
      else if (auto* sf = dynamic_cast<ServiceFault*>(last->second.get()))
      {
        outcome.isFault = true;
        outcome.serviceResult = sf->response_header().service_result();
      }
    }
  }

  outcome.authenticatorCalled = authenticator->called();
  outcome.password = authenticator->password();

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.41 Table 193: when the matched UserTokenPolicy names a SecurityPolicy other than None,
// the UserName secret has to arrive encrypted under it. A plausible implementation keys its handling
// off the token's own encryptionAlgorithm field - empty means "not encrypted", so just read the
// password - which makes the clear password the path of least resistance and silently downgrades
// every client that gets the encryption wrong. The encrypted counterpart of this exact harness is
// ServerActivateRsaTokenEncryption/Basic256Sha256 above, which activates successfully, so a refusal
// here is attributable to the missing encryption and not to the fixture.
//
// DISABLED: the behaviour is unimplemented, and this test is correct as written - do not weaken it.
// `Session::parse_identity_token_async` (sdk/implementation/server/session/ua_server_session.cpp:2986)
// treats an empty `encryptionAlgorithm` as "plain password" and hands the cleartext straight to the
// authenticator, without ever consulting the matched UserTokenPolicy's SecurityPolicy. The only
// policy-side guard, `validate_user_token_policy`
// (sdk/implementation/core/security/ua_security_policy_compatibility.cpp:9), inspects the configured
// policy against the channel policy and mode and never looks at the presented token, so it cannot
// catch the downgrade either. The server therefore accepts an unencrypted UserName secret under a
// UserTokenPolicy that names Basic256Sha256, which is the exact case Part 4 section 7.41 Table 193 and
// SVR-IDENT-008 forbid. Re-enable once the encryption requirement is enforced against the presented
// token.
// @verifies AC-SVR-IDENT-008-UNP-ENCRYPTION-REQUIRED
TEST(ServerActivateUserNameTokenEncryption, ClearPasswordRefusedWhereTokenPolicyRequiresEncryption)
{
  auto crypto = create_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  auto serverKeyPair = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);

  TestPki pki{create_crypto()};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = serverKeyPair;
  certParams.issuerKeys = serverKeyPair;
  certParams.subject.commonName = "TestServer";
  certParams.serialNumber = "1";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  auto serverCert = pki.create_cert(certParams);

  auto serverNonce = make_nonce(*crypto, 32);

  // A well-formed UserNameIdentityToken carrying the password in the clear: encryption_algorithm is
  // left empty, exactly as a client that skipped the encryption step would send it.
  constexpr string_view passwordText = "TestPassword123!";
  UserNameIdentityToken clearToken;
  clearToken.user_name() = "testuser";
  ByteString clearPassword;
  clearPassword.assign(reinterpret_cast<const uint8_t*>(passwordText.data()),
    reinterpret_cast<const uint8_t*>(passwordText.data()) + passwordText.size());
  clearToken.password() = clearPassword;
  ASSERT_TRUE(clearToken.encryption_algorithm().empty())
    << "the stimulus requires an unencrypted token; encryption_algorithm must be empty";

  TokenActivationOutcome outcome;
  activate_with_user_name_token(SecurityPolicyId::Basic256Sha256,
    crypto,
    policy,
    serverCert,
    serverKeyPair,
    serverNonce,
    clearToken,
    outcome);

  ASSERT_TRUE(outcome.gotResponse) << "ActivateSession produced no response at all";
  EXPECT_FALSE(outcome.isActivateResponse)
    << "a cleartext UserName password under a UserTokenPolicy that names Basic256Sha256 must be "
       "refused, not activated";
  EXPECT_TRUE(outcome.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_TRUE(outcome.serviceResult == Status::BadIdentityTokenInvalid ||
              outcome.serviceResult == Status::BadIdentityTokenRejected ||
              outcome.serviceResult == Status::BadSecurityPolicyRejected ||
              outcome.serviceResult == Status::BadSecurityChecksFailed)
    << "the refusal must name the identity token or its security policy, got: "
    << to_string(outcome.serviceResult.as_status());

  // The second half of the observation: the server must not have *read* the clear password. If the
  // authenticator saw it, the server accepted the downgrade whatever it later returned.
  EXPECT_FALSE(outcome.authenticatorCalled)
    << "the server passed a password it accepted in the clear to the authenticator";
  EXPECT_NE(outcome.password, "TestPassword123!")
    << "the clear password reached the authenticator, so the encryption requirement was not applied";
}

class ServerActivateTokenNonceBinding : public ::testing::TestWithParam<ServerRsaTokenParams>
{};

// Part 4 section 7.41.2.2 (legacy secret) and section 7.41.2.4 (RsaEncryptedSecret): the client appends the
// last ServerNonce to the secret before encrypting it, and the server must compare what it recovers against
// the nonce it last issued. A plausible implementation decrypts the blob, strips a fixed-size tail and uses
// the remainder as the password without ever comparing that tail - which leaves the ciphertext replayable
// forever, because it is encrypted under the server's fixed public key and therefore decrypts identically on
// every activation. Both the omitted-nonce and the stale-nonce blob must be refused; the control arm (correct
// nonce) runs through the same harness so neither refusal can be an artefact of the fixture.
// @verifies AC-SVR-IDENT-010-NONCE-APPENDED
TEST_P(ServerActivateTokenNonceBinding, EncryptedSecretMustCarryTheLastServerNonce)
{
  const auto& params = GetParam();
  auto crypto = create_crypto();
  auto policy = SecurityPolicy::create(params.policyId);

  auto serverKeyPair = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, params.keyBits);

  TestPki pki{create_crypto()};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = serverKeyPair;
  certParams.issuerKeys = serverKeyPair;
  certParams.subject.commonName = "TestServer";
  certParams.serialNumber = "1";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.certificateSignatureAlgorithm = params.certSigAlg;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  auto serverCert = pki.create_cert(certParams);

  // currentNonce is the nonce the server last issued; staleNonce stands for one it issued in an
  // earlier exchange and has since rotated away from.
  auto currentNonce = make_nonce(*crypto, 32);
  auto staleNonce = make_nonce(*crypto, 32);
  ASSERT_NE(currentNonce, staleNonce);

  constexpr string_view passwordText = "TestPassword123!";

  // Produces the encrypted token through the production client-side encoder, so the secret really is
  // built and encrypted the way a client builds it - only the nonce fed in differs.
  auto encryptTokenAgainst = [&](const ByteString& nonce, std::shared_ptr<UserNameIdentityToken>& out)
  {
    auto tokenPtr = std::make_shared<UserNameIdentityToken>();
    tokenPtr->user_name() = "testuser";
    ByteString plainPassword;
    plainPassword.assign(reinterpret_cast<const uint8_t*>(passwordText.data()),
      reinterpret_cast<const uint8_t*>(passwordText.data()) + passwordText.size());
    tokenPtr->password() = plainPassword;

    auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
      [&](auto cb)
      {
        encrypt_user_token_async(policy,
          crypto,
          crypto_test_strand(),
          tokenPtr,
          nonce,
          serverCert,
          ByteString{},
          nullptr,
          nullptr,
          ua::Logger{},
          std::move(cb));
      });
    ASSERT_TRUE(encResult.is_good()) << "Encrypt failed: " << to_string(encResult.status_code().as_status());
    ASSERT_NE(tokenPtr->password(), plainPassword) << "Token must be encrypted";
    out = tokenPtr;
  };

  std::shared_ptr<UserNameIdentityToken> boundToken;
  std::shared_ptr<UserNameIdentityToken> omittedNonceToken;
  std::shared_ptr<UserNameIdentityToken> staleNonceToken;
  encryptTokenAgainst(currentNonce, boundToken);
  ASSERT_NE(boundToken, nullptr);
  encryptTokenAgainst(ByteString{}, omittedNonceToken);
  ASSERT_NE(omittedNonceToken, nullptr);
  encryptTokenAgainst(staleNonce, staleNonceToken);
  ASSERT_NE(staleNonceToken, nullptr);

  // Control: the secret carrying the nonce the server last issued is accepted.
  TokenActivationOutcome bound;
  activate_with_user_name_token(
    params.policyId, crypto, policy, serverCert, serverKeyPair, currentNonce, *boundToken, bound);
  ASSERT_TRUE(bound.gotResponse) << "control activation produced no response";
  ASSERT_TRUE(bound.isActivateResponse) << "control activation (correct nonce) must be accepted, got: "
                                        << to_string(bound.serviceResult.as_status());
  EXPECT_TRUE(bound.serviceResult.is_good()) << to_string(bound.serviceResult.as_status());
  EXPECT_TRUE(bound.authenticatorCalled);
  EXPECT_EQ(bound.password, "TestPassword123!");

  // First stimulus: the encrypted secret omits the nonce entirely.
  TokenActivationOutcome omitted;
  activate_with_user_name_token(
    params.policyId, crypto, policy, serverCert, serverKeyPair, currentNonce, *omittedNonceToken, omitted);
  ASSERT_TRUE(omitted.gotResponse) << "omitted-nonce activation produced no response";
  EXPECT_FALSE(omitted.isActivateResponse)
    << "an encrypted secret with no appended ServerNonce must be refused, not activated";
  EXPECT_TRUE(omitted.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_EQ(omitted.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_FALSE(omitted.authenticatorCalled)
    << "a secret with no ServerNonce must never reach the authenticator";

  // Second stimulus: the encrypted secret carries a nonce from an earlier exchange - the replay.
  TokenActivationOutcome stale;
  activate_with_user_name_token(
    params.policyId, crypto, policy, serverCert, serverKeyPair, currentNonce, *staleNonceToken, stale);
  ASSERT_TRUE(stale.gotResponse) << "stale-nonce activation produced no response";
  EXPECT_FALSE(stale.isActivateResponse)
    << "an encrypted secret carrying a superseded ServerNonce must be refused, not activated";
  EXPECT_TRUE(stale.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_EQ(stale.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_FALSE(stale.authenticatorCalled) << "a replayed secret must never reach the authenticator";
}

// Part 4 section 7.41 with section 5.6.3: the nonce appended to the encrypted secret is the one the server
// LAST issued, and every ActivateSession response issues a new one. A plausible implementation compares
// against the nonce fixed at CreateSession, or keeps honouring the previous nonce once it has
// rotated - either way the secret from an earlier exchange stays replayable, which is the whole
// reason the nonce is appended: the blob is encrypted under the server's fixed public key and
// therefore decrypts identically forever. Here the stale secret is made stale by the server's own
// rotation rather than by a nonce the server never issued, and the third round re-encrypts against
// the newly issued nonce so the middle refusal cannot be an artefact of re-activation being refused.
// @verifies AC-SVR-IDENT-010-NONCE-APPENDED
TEST_P(ServerActivateTokenNonceBinding, SecretMustCarryTheNonceFromTheLastActivateSessionResponse)
{
  const auto& params = GetParam();
  auto crypto = create_crypto();
  auto policy = SecurityPolicy::create(params.policyId);

  auto serverKeyPair = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, params.keyBits);

  TestPki pki{create_crypto()};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = serverKeyPair;
  certParams.issuerKeys = serverKeyPair;
  certParams.subject.commonName = "TestServer";
  certParams.serialNumber = "1";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.certificateSignatureAlgorithm = params.certSigAlg;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  auto serverCert = pki.create_cert(certParams);

  auto firstNonce = make_nonce(*crypto, 32);

  // Harness identical to activate_with_user_name_token above, except the session is kept alive
  // across three ActivateSession rounds - the rotation under test only happens on a live session.
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto authenticator = std::make_shared<RecordingTokenAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<CryptoSessionDeps>(ex, hooks, crypto, nullptr, successAuthnTimeout);

  auto scDeps = std::make_shared<DummySecureChannelDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(
        ex, "L/None", {server::create_user_token_policy(UserTokenType::UserName, params.policyId)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SCTA::on_strand(*sc,
    [&](auto& g)
    {
      g.set_response_sink(
        [&](const Response& r)
        {
          std::lock_guard<std::mutex> lk(mx);
          last = r;
          cv.notify_one();
        });
    });

  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  // Same precondition injection as the tests above: only the CreateSession-time state a wired
  // CertificateStore would have produced. The nonce the server compares against from the second
  // round onwards is the one the server itself generates, not this one.
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.server_nonce() = firstNonce;
      g.server_certificates().push_back(
        CertificateStore::ApplicationCertificate{policy->certificate_type(), serverCert, serverKeyPair});
      g.selected_cert_and_key() = g.server_certificates().back();
    });

  // Builds the encrypted token through the production client-side encoder, so the secret is formed
  // exactly as a client forms it; only the nonce bound into it, and the password, differ.
  auto encryptToken = [&](const ByteString& nonce, string_view secret)
  {
    auto tokenPtr = std::make_shared<UserNameIdentityToken>();
    tokenPtr->user_name() = "testuser";
    ByteString plainPassword;
    plainPassword.assign(reinterpret_cast<const uint8_t*>(secret.data()),
      reinterpret_cast<const uint8_t*>(secret.data()) + secret.size());
    tokenPtr->password() = plainPassword;

    auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
      [&](auto cb)
      {
        encrypt_user_token_async(policy,
          crypto,
          crypto_test_strand(),
          tokenPtr,
          nonce,
          serverCert,
          ByteString{},
          nullptr,
          nullptr,
          ua::Logger{},
          std::move(cb));
      });
    EXPECT_TRUE(encResult.is_good()) << "Encrypt failed: " << to_string(encResult.status_code().as_status());
    EXPECT_NE(tokenPtr->password(), plainPassword) << "Token must be encrypted";
    return tokenPtr;
  };

  // The nonce the server issued in its most recent ActivateSession response.
  ByteString issuedNonce;

  // One ActivateSession round on the live session. Returns only once the response has been observed
  // and the session strand has quiesced, so the next round cannot land while the previous
  // activation is still finishing and be rejected as an overlap rather than on its nonce.
  auto activateRound =
    [&](uint32_t requestId, const UserNameIdentityToken& token, TokenActivationOutcome& outcome)
  {
    {
      std::lock_guard<std::mutex> lk(mx);
      last.reset();
    }

    ActivateSessionRequest asr;
    asr.request_header().request_handle() = requestId;
    auto activateToken = std::make_unique<UserNameIdentityToken>(token);
    activateToken->policy_id() =
      SCTA::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); })
        .front()
        .policy_id();
    asr.user_identity_token() = std::move(activateToken);

    session->activate(requestId, std::move(asr), {});

    {
      std::unique_lock<std::mutex> lk(mx);
      outcome.gotResponse = cv.wait_for(lk, successAuthnTimeout + 2s, [&]() { return last.has_value(); });
      if (outcome.gotResponse)
      {
        if (auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get()))
        {
          outcome.isActivateResponse = true;
          outcome.serviceResult = resp->response_header().service_result();
          issuedNonce = resp->server_nonce();
        }
        else if (auto* sf = dynamic_cast<ServiceFault*>(last->second.get()))
        {
          outcome.isFault = true;
          outcome.serviceResult = sf->response_header().service_result();
        }
      }
    }

    outcome.authenticatorCalled = authenticator->called();
    outcome.password = authenticator->password();
    SessionTestAccess::strand_barrier(*session);
  };

  // Round 1: the secret carries the nonce the server last issued, so it is accepted - and the
  // response issues a new nonce, which supersedes the one this secret carries.
  auto firstToken = encryptToken(firstNonce, "FirstPassword1!");
  ASSERT_NE(firstToken, nullptr);
  TokenActivationOutcome first;
  activateRound(11, *firstToken, first);
  ASSERT_TRUE(first.gotResponse) << "the first activation produced no response";
  ASSERT_TRUE(first.isActivateResponse)
    << "the secret bound to the nonce the server last issued must be accepted, got: "
    << to_string(first.serviceResult.as_status());
  ASSERT_TRUE(first.serviceResult.is_good()) << to_string(first.serviceResult.as_status());
  ASSERT_TRUE(first.authenticatorCalled);
  ASSERT_EQ(first.password, "FirstPassword1!");
  ASSERT_GE(issuedNonce.size(), 32u)
    << "ActivateSession must issue a nonce the client can bind its next secret to";
  ASSERT_NE(issuedNonce, firstNonce) << "the issued nonce must be fresh, not the one just consumed";
  const ByteString rotatedNonce = issuedNonce;

  // Round 2: the replay. A secret bound to the nonce the server has since rotated away from -
  // precisely what an observer of round 1 could re-present - must be refused, and its password must
  // never reach the authenticator.
  auto replayedToken = encryptToken(firstNonce, "ReplayPassword2!");
  ASSERT_NE(replayedToken, nullptr);
  TokenActivationOutcome replayed;
  activateRound(12, *replayedToken, replayed);
  ASSERT_TRUE(replayed.gotResponse) << "the replay activation produced no response";
  EXPECT_FALSE(replayed.isActivateResponse)
    << "a secret carrying a ServerNonce the server has already rotated away from must be refused, "
       "not activated";
  EXPECT_TRUE(replayed.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_EQ(replayed.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_NE(replayed.password, "ReplayPassword2!")
    << "the replayed secret was decrypted and handed to the authenticator, so the superseded nonce "
       "was accepted";
  EXPECT_EQ(replayed.password, "FirstPassword1!")
    << "the authenticator's record must still hold round 1's password - anything else means the "
       "replay reached it";

  // Round 3: rebinding to the nonce the server issued in round 1's response is accepted. Without
  // this the refusal above would be satisfied by a server that simply refuses re-activation.
  auto reboundToken = encryptToken(rotatedNonce, "ThirdPassword3!");
  ASSERT_NE(reboundToken, nullptr);
  TokenActivationOutcome rebound;
  activateRound(13, *reboundToken, rebound);
  ASSERT_TRUE(rebound.gotResponse) << "the rebound activation produced no response";
  EXPECT_TRUE(rebound.isActivateResponse)
    << "a secret bound to the nonce the server issued in its last response must be accepted, got: "
    << to_string(rebound.serviceResult.as_status());
  EXPECT_TRUE(rebound.serviceResult.is_good()) << to_string(rebound.serviceResult.as_status());
  EXPECT_EQ(rebound.password, "ThirdPassword3!") << "the rebound secret must decrypt to its own password";

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 7.41: the server verifies that the nonce recovered from the secret EQUALS the one it last
// issued - the whole of it, not a prefix, and not merely a nonce-shaped tail. A plausible
// implementation compares over a truncated or mis-derived length: memcmp over the recovered nonce's
// own length, over a hard-coded 16, or a length check that is skipped because the format "always"
// carries 32 bytes. Any of those admits a near-miss nonce, and the blob is encrypted under the
// server's fixed public key, so a secret an observer can nudge past the comparison is replayable
// forever. Two near misses are exercised: a nonce differing only in its final byte (defeats a
// short-prefix compare) and one that is a strict prefix of the issued nonce (defeats a
// length-insensitive compare). The control arm runs the identical harness with the correctly bound
// secret, so neither refusal can be an artefact of the fixture.
// @verifies AC-SVR-IDENT-010-NONCE-APPENDED
TEST_P(ServerActivateTokenNonceBinding, AppendedNonceIsComparedInFullAgainstTheLastIssuedNonce)
{
  const auto& params = GetParam();
  auto crypto = create_crypto();
  auto policy = SecurityPolicy::create(params.policyId);

  auto serverKeyPair = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, params.keyBits);

  TestPki pki{create_crypto()};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = serverKeyPair;
  certParams.issuerKeys = serverKeyPair;
  certParams.subject.commonName = "TestServer";
  certParams.serialNumber = "1";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.certificateSignatureAlgorithm = params.certSigAlg;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  auto serverCert = pki.create_cert(certParams);

  // currentNonce is the nonce the server last issued and therefore the only one a secret may carry.
  auto currentNonce = make_nonce(*crypto, 32);
  ASSERT_GE(currentNonce.size(), 2u);

  // Near miss 1: identical to the issued nonce except in its very last byte.
  ByteString nearMissNonce = currentNonce;
  nearMissNonce[nearMissNonce.size() - 1] =
    static_cast<uint8_t>(nearMissNonce[nearMissNonce.size() - 1] ^ 0xFFu);
  ASSERT_EQ(nearMissNonce.size(), currentNonce.size());
  ASSERT_NE(nearMissNonce, currentNonce) << "the near-miss nonce must actually differ";

  // Near miss 2: a strict prefix of the issued nonce - every byte it does carry is correct.
  ByteString truncatedNonce = currentNonce;
  truncatedNonce.resize(currentNonce.size() / 2);
  ASSERT_LT(truncatedNonce.size(), currentNonce.size());
  ASSERT_NE(truncatedNonce, currentNonce) << "the truncated nonce must actually differ";

  // Builds the encrypted token through the production client-side encoder, so the secret is formed
  // exactly as a client forms it; only the nonce bound into it, and the password, differ.
  auto encryptToken = [&](const ByteString& nonce, string_view secret)
  {
    auto tokenPtr = std::make_shared<UserNameIdentityToken>();
    tokenPtr->user_name() = "testuser";
    ByteString plainPassword;
    plainPassword.assign(reinterpret_cast<const uint8_t*>(secret.data()),
      reinterpret_cast<const uint8_t*>(secret.data()) + secret.size());
    tokenPtr->password() = plainPassword;

    auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
      [&](auto cb)
      {
        encrypt_user_token_async(policy,
          crypto,
          crypto_test_strand(),
          tokenPtr,
          nonce,
          serverCert,
          ByteString{},
          nullptr,
          nullptr,
          ua::Logger{},
          std::move(cb));
      });
    EXPECT_TRUE(encResult.is_good()) << "Encrypt failed: " << to_string(encResult.status_code().as_status());
    EXPECT_NE(tokenPtr->password(), plainPassword) << "Token must be encrypted";
    return tokenPtr;
  };

  // Control: the secret carrying the whole of the issued nonce is accepted through this harness.
  auto boundToken = encryptToken(currentNonce, "TestPassword123!");
  ASSERT_NE(boundToken, nullptr);
  TokenActivationOutcome bound;
  activate_with_user_name_token(
    params.policyId, crypto, policy, serverCert, serverKeyPair, currentNonce, *boundToken, bound);
  ASSERT_TRUE(bound.gotResponse) << "control activation produced no response";
  ASSERT_TRUE(bound.isActivateResponse) << "control activation (whole issued nonce) must be accepted, got: "
                                        << to_string(bound.serviceResult.as_status());
  ASSERT_TRUE(bound.serviceResult.is_good()) << to_string(bound.serviceResult.as_status());
  ASSERT_TRUE(bound.authenticatorCalled);
  ASSERT_EQ(bound.password, "TestPassword123!");

  // Stimulus 1: the appended nonce differs from the issued one only in its final byte.
  auto nearMissToken = encryptToken(nearMissNonce, "NearMissPassword1!");
  ASSERT_NE(nearMissToken, nullptr);
  TokenActivationOutcome nearMiss;
  activate_with_user_name_token(
    params.policyId, crypto, policy, serverCert, serverKeyPair, currentNonce, *nearMissToken, nearMiss);
  ASSERT_TRUE(nearMiss.gotResponse) << "near-miss activation produced no response";
  EXPECT_FALSE(nearMiss.isActivateResponse)
    << "a secret whose appended nonce differs from the issued nonce in any byte must be refused, "
       "not activated";
  EXPECT_TRUE(nearMiss.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_EQ(nearMiss.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_FALSE(nearMiss.authenticatorCalled)
    << "a secret carrying a nonce the server never issued must never reach the authenticator";
  EXPECT_NE(nearMiss.password, "NearMissPassword1!")
    << "the near-miss secret was decrypted and its password handed on, so the nonce comparison does "
       "not cover the whole nonce";

  // Stimulus 2: the appended nonce is a strict prefix of the issued one.
  auto truncatedToken = encryptToken(truncatedNonce, "TruncatedNoncePwd2!");
  ASSERT_NE(truncatedToken, nullptr);
  TokenActivationOutcome truncated;
  activate_with_user_name_token(
    params.policyId, crypto, policy, serverCert, serverKeyPair, currentNonce, *truncatedToken, truncated);
  ASSERT_TRUE(truncated.gotResponse) << "truncated-nonce activation produced no response";
  EXPECT_FALSE(truncated.isActivateResponse)
    << "a secret whose appended nonce is only a prefix of the issued nonce must be refused, not "
       "activated";
  EXPECT_TRUE(truncated.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_EQ(truncated.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_FALSE(truncated.authenticatorCalled)
    << "a secret carrying a short nonce must never reach the authenticator";
  EXPECT_NE(truncated.password, "TruncatedNoncePwd2!")
    << "the truncated-nonce secret was decrypted and its password handed on, so the nonce "
       "comparison is not length-sensitive";
}

// Basic256 exercises the legacy Part 4 section 7.41.2.2 secret; Basic256Sha256 exercises the
// section 7.41.2.4 RsaEncryptedSecret form. Both carry the ServerNonce and both must check it.
INSTANTIATE_TEST_SUITE_P(ServerActivateTokenNonceBindingPolicies, ServerActivateTokenNonceBinding,
  ::testing::Values(
    ServerRsaTokenParams{
      SecurityPolicyId::Basic256, 2048, CertificateSignatureAlgorithm::RsaPkcs15Sha2256, "Basic256"},
    ServerRsaTokenParams{SecurityPolicyId::Basic256Sha256,
      2048,
      CertificateSignatureAlgorithm::RsaPkcs15Sha2256,
      "Basic256Sha256"}),
  [](const ::testing::TestParamInfo<ServerRsaTokenParams>& info) { return info.param.name; });

// Part 4 section 7.41 Table 193: where the matched UserTokenPolicy names a SecurityPolicy other than None,
// the secret has to BE encrypted under it - declaring the algorithm is not the same as applying it.
// A plausible implementation keys entirely off the token's own `encryptionAlgorithm` field: it sees
// a well-formed policy URI, resolves the policy, attempts the asymmetric decrypt of what is really
// a cleartext password, and - when that fails - falls back to treating the bytes as a plain
// password, because "be liberal in what you accept" reads like interop tolerance at exactly that
// point. That fallback reinstates the downgrade the table closes, on a path the empty-algorithm
// case never reaches: here the token looks encrypted to every field-level check and simply is not.
// The algorithm URI is taken from the production client-side encoder so it is the exact string a
// conforming client would send, and the encrypted counterpart of this harness activates
// successfully in ServerActivateRsaTokenEncryption/Basic256Sha256, so a refusal here is
// attributable to the missing encryption and not to the fixture.
// @verifies AC-SVR-IDENT-008-UNP-ENCRYPTION-REQUIRED
TEST(ServerActivateUserNameTokenEncryption, ClearPasswordRefusedWhenTheTokenOnlyDeclaresEncryption)
{
  auto crypto = create_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  auto serverKeyPair = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);

  TestPki pki{create_crypto()};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = serverKeyPair;
  certParams.issuerKeys = serverKeyPair;
  certParams.subject.commonName = "TestServer";
  certParams.serialNumber = "1";
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  auto serverCert = pki.create_cert(certParams);

  auto serverNonce = make_nonce(*crypto, 32);

  // Recover the algorithm URI a conforming client stamps on the token, by running one real
  // encryption. Only the URI is kept; the encrypted secret it produced is discarded.
  auto probeToken = std::make_shared<UserNameIdentityToken>();
  probeToken->user_name() = "testuser";
  ByteString probePassword;
  constexpr string_view probeText = "ProbePassword";
  probePassword.assign(reinterpret_cast<const uint8_t*>(probeText.data()),
    reinterpret_cast<const uint8_t*>(probeText.data()) + probeText.size());
  probeToken->password() = probePassword;

  auto probeResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      encrypt_user_token_async(policy,
        crypto,
        crypto_test_strand(),
        probeToken,
        serverNonce,
        serverCert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(probeResult.is_good()) << "Encrypt failed: "
                                     << to_string(probeResult.status_code().as_status());
  ASSERT_FALSE(probeToken->encryption_algorithm().empty())
    << "the stimulus needs the algorithm URI a conforming client would declare";

  // The stimulus: a UserNameIdentityToken that declares the policy's encryption algorithm but whose
  // password field is the plain UTF-8 password, exactly as a client that stamped the field and then
  // skipped the encryption step would send it.
  constexpr string_view passwordText = "TestPassword123!";
  UserNameIdentityToken declaredButClearToken;
  declaredButClearToken.user_name() = "testuser";
  ByteString clearPassword;
  clearPassword.assign(reinterpret_cast<const uint8_t*>(passwordText.data()),
    reinterpret_cast<const uint8_t*>(passwordText.data()) + passwordText.size());
  declaredButClearToken.password() = clearPassword;
  declaredButClearToken.encryption_algorithm() = probeToken->encryption_algorithm();
  ASSERT_FALSE(declaredButClearToken.encryption_algorithm().empty())
    << "the token must claim to be encrypted";
  ASSERT_EQ(declaredButClearToken.password(), clearPassword)
    << "the stimulus requires the secret to be the clear password despite the declared algorithm";

  TokenActivationOutcome outcome;
  activate_with_user_name_token(SecurityPolicyId::Basic256Sha256,
    crypto,
    policy,
    serverCert,
    serverKeyPair,
    serverNonce,
    declaredButClearToken,
    outcome);

  ASSERT_TRUE(outcome.gotResponse) << "ActivateSession produced no response at all";
  EXPECT_FALSE(outcome.isActivateResponse)
    << "a clear password under a UserTokenPolicy that names Basic256Sha256 must be refused however "
       "the token labels itself, not activated";
  EXPECT_TRUE(outcome.isFault) << "the refusal must surface as a ServiceFault";
  EXPECT_TRUE(outcome.serviceResult == Status::BadIdentityTokenInvalid ||
              outcome.serviceResult == Status::BadIdentityTokenRejected ||
              outcome.serviceResult == Status::BadSecurityPolicyRejected ||
              outcome.serviceResult == Status::BadSecurityChecksFailed)
    << "the refusal must name the identity token or its security policy, got: "
    << to_string(outcome.serviceResult.as_status());

  // Second half of the observation: the server must not have READ the clear password. If the
  // authenticator saw it, the decrypt failure was swallowed and the downgrade accepted.
  EXPECT_FALSE(outcome.authenticatorCalled)
    << "the server passed a password it accepted in the clear to the authenticator";
  EXPECT_NE(outcome.password, "TestPassword123!")
    << "the clear password reached the authenticator, so the encryption requirement was not applied";
}

// ===================================================================
// ECC EphemeralKey renewal on a refused ActivateSession
// ===================================================================

constexpr string_view acceptedPassword = "right-password";
constexpr string_view refusedPassword = "wrong-password";

// Accepts exactly one password and refuses everything else with Bad_UserAccessDenied, the answer an
// application authenticator gives a wrong password. An accepted token authenticates as the configured
// user id, so a test can make a re-activation authenticate a different identity. The refusal hook runs
// just before a refusal is answered, which is after every crypto step the activation needs and before
// any the refusal itself takes. The acceptance hook runs just before an acceptance is answered, which is
// after every crypto step authentication needs and before any the response build takes.
class PasswordGateAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    // The accepted secret is acceptedPassword, as a UserName password or as IssuedToken tokenData.
    const bool anonymous = !req.identity.password.has_value() && !req.identity.issuedToken.has_value();
    const bool accepted = (anonymous && acceptAnonymous.load()) ||
                          (req.identity.password.has_value() &&
                            std::string_view{req.identity.password->c_str()} == acceptedPassword) ||
                          (req.identity.issuedToken.has_value() &&
                            std::string_view{reinterpret_cast<const char*>(req.identity.issuedToken->data()),
                              req.identity.issuedToken->size()} == acceptedPassword);
    std::function<void()> beforeRefusal;
    std::function<void()> beforeAcceptance;
    std::string userId;
    {
      std::lock_guard<std::mutex> lk(mMutex);
      ++mCalls;
      beforeRefusal = mBeforeRefusal;
      beforeAcceptance = mBeforeAcceptance;
      userId = mUserId;
    }
    if (!accepted)
    {
      if (beforeRefusal)
        beforeRefusal();
      completion(make_authn_failure(StatusCode{Status::BadUserAccessDenied}, "Wrong password"));
      return;
    }
    if (beforeAcceptance)
      beforeAcceptance();
    completion(make_authn_success(UserIdentity{
      .userId = std::move(userId), .displayName = "Test User", .kind = req.identity.kind, .claims = {}}));
  }

  void set_user_id(std::string userId)
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mUserId = std::move(userId);
  }

  /// Accepts an identity that carries neither a password nor an issued token (an Anonymous token).
  std::atomic<bool> acceptAnonymous{false};

  void set_before_refusal(std::function<void()> hook)
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mBeforeRefusal = std::move(hook);
  }

  void set_before_acceptance(std::function<void()> hook)
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mBeforeAcceptance = std::move(hook);
  }

  size_t calls()
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mCalls;
  }

private:
  std::mutex mMutex;
  std::string mUserId{"testuser"};
  std::function<void()> mBeforeRefusal;
  std::function<void()> mBeforeAcceptance;
  size_t mCalls{0};
};

shared_ptr<const X509Certificate> make_ecc_certificate(const shared_ptr<const Crypto>& crypto,
  const shared_ptr<const AsymmetricKeyPair>& keys, std::string commonName, std::string serial)
{
  TestPki pki{crypto};
  Crypto::CreateCertificateConfig params;
  params.subjectKeys = keys;
  params.issuerKeys = keys;
  params.subject.commonName = std::move(commonName);
  params.serialNumber = std::move(serial);
  params.basicConstraint.cA = false;
  params.keyUsage.digitalSignature = true;
  params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::EcDsaSha2256;
  params.from = DateTime::now();
  params.to = DateTime{params.from.value() + std::chrono::days{365}};
  return pki.create_cert(params);
}

// A Session whose ActivateSession the PasswordGateAuthenticator decides. With `ecc`, the Session is on an
// ECC_nistP256 SignAndEncrypt channel, its UserName token policy is ECC_nistP256, and it holds the
// EphemeralKey a previous response issued - the state CreateSession with an ECDHPolicyUri leaves. Without
// it, the channel is None and the endpoint offers Anonymous, so the Session has no ECC token policy.
//
// Like the harnesses above, the CreateSession-produced state is injected: CreateSession needs a fully
// wired CertificateStore, which CryptoSessionDeps does not provide. The refusal and everything after it
// run on the production path.
struct RefusedActivationHarness
{
  boost::asio::thread_pool pool{2};
  shared_ptr<const Crypto> crypto = create_crypto();
  /// Set by `start(ecc, true)`: the Session's crypto, whose async steps a test can park.
  shared_ptr<ua::test_helpers::FakeAsyncCrypto> fakeCrypto;
  shared_ptr<PasswordGateAuthenticator> authenticator = std::make_shared<PasswordGateAuthenticator>();
  shared_ptr<const SecurityPolicy> eccSecurityPolicy =
    SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm);
  shared_ptr<const AsymmetricKeyPair> serverKeys;
  shared_ptr<const X509Certificate> serverCert;
  shared_ptr<const AsymmetricKeyPair> clientKeys;
  shared_ptr<const X509Certificate> clientCert;
  ByteString serverNonce;
  ByteString issuedEphemeralPublicKey;
  std::vector<UserTokenPolicy> tokenPolicies;
  /// Set before start(): the ECC Session also offers an Anonymous policy (last in tokenPolicies), whose
  /// token is not encrypted and so does not consume the stored EphemeralKey.
  bool offerAnonymous{false};
  /// Set before start(): the SecurityMode of the ECC channel the Session is on.
  MessageSecurityMode eccChannelMode{MessageSecurityMode::SignAndEncrypt};
  shared_ptr<CryptoSessionDeps> sessDeps;
  shared_ptr<DummySecureChannelDeps> scDeps;
  shared_ptr<SecureChannel> sc;
  shared_ptr<SecureChannel> secondSc;
  shared_ptr<Session> session;
  bool useEcc{false};

  std::mutex mutex;
  std::condition_variable cv;
  std::vector<Response> responses;

  // `eccTokenType` is the type of the Session's one ECC token policy (UserName unless stated).
  void start(bool ecc, bool parkableCrypto = false, UserTokenType eccTokenType = UserTokenType::UserName,
    std::shared_ptr<ServerObserver> observer = {})
  {
    useEcc = ecc;
    if (parkableCrypto)
    {
      fakeCrypto = ua::test_helpers::FakeAsyncCrypto::create();
      crypto = fakeCrypto;
    }
    auto ex = pool.get_executor();
    serverNonce = make_nonce(*crypto, 32);
    tokenPolicies = {ecc
                       ? server::create_user_token_policy(eccTokenType, SecurityPolicyId::EccNistP256AesGcm)
                       : server::create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None)};
    if (ecc && offerAnonymous)
      tokenPolicies.push_back(
        server::create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    ServerComponents hooks;
    hooks.authenticator = authenticator;
    sessDeps = std::make_shared<CryptoSessionDeps>(ex, hooks, crypto, std::move(observer));

    scDeps = std::make_shared<DummySecureChannelDeps>(ex);
    sc = make_channel();

    SecureChannelInfo createChannel(sc->weak_from_this(),
      SecurityPolicy::create(SecurityPolicyId::None),
      MessageSecurityMode::None,
      "L/Ep",
      tokenPolicies);
    session = Session::create(sessDeps, createChannel, 1, CreateSessionRequest{});
    SessionTestAccess::strand_barrier(*session);

    if (!ecc)
    {
      SessionTestAccess::on_strand(*session, [&](auto& g) { g.server_nonce() = serverNonce; });
      return;
    }

    serverKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
    serverCert = make_ecc_certificate(crypto, serverKeys, "TestServer", "1");
    clientKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::EccNistP256, std::nullopt);
    clientCert = make_ecc_certificate(crypto, clientKeys, "TestClient", "2");

    const auto* eccPolicy = dynamic_cast<const SecPolEphemeralKey*>(eccSecurityPolicy.get());
    ASSERT_NE(eccPolicy, nullptr);
    auto issued = crypto->create_ephemeral_keys_sync(eccPolicy->ephemeral_key_algorithm());
    issuedEphemeralPublicKey = issued.publicKey;

    SecureChannelInfo eccChannel(
      sc->weak_from_this(), eccSecurityPolicy, eccChannelMode, "L/Ep", tokenPolicies, clientCert);
    SessionTestAccess::on_strand(*session,
      [&](auto& g)
      {
        g.server_nonce() = serverNonce;
        g.server_certificates().push_back(CertificateStore::ApplicationCertificate{
          eccSecurityPolicy->certificate_type(), serverCert, serverKeys});
        g.selected_cert_and_key() = g.server_certificates().back();
        g.client_certificate() = clientCert;
        g.secure_channel_info() = eccChannel;
        // As if CreateSession had arrived on the ECC channel.
        g.channel_security_policy_id() = SecurityPolicyId::EccNistP256AesGcm;
        g.channel_security_mode() = eccChannelMode;
        g.ecc_user_token_policy_id() = SecurityPolicyId::EccNistP256AesGcm;
        g.ecc_ephemeral_private_key() = std::move(issued.privateKey);
        g.ecc_ephemeral_public_key() = issuedEphemeralPublicKey;
      });
  }

  // A SecureChannel whose responses land in responses.
  shared_ptr<SecureChannel> make_channel()
  {
    auto ex = pool.get_executor();
    auto sc = SecureChannel::create(
      scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
    SCTA::on_strand(*sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/Ep", tokenPolicies); });
    SCTA::on_strand(*sc,
      [&](auto& g)
      {
        g.set_response_sink(
          [this](const Response& r)
          {
            {
              std::lock_guard<std::mutex> lk(mutex);
              responses.push_back(r);
            }
            cv.notify_all();
          });
      });
    return sc;
  }

  // A second ECC SecureChannel from the same client certificate, for a re-activation over a different
  // channel (Part 4 5.6.3.1): by default of the Session's policy and mode, as 5.7.3.1 requires.
  SecureChannelInfo open_second_ecc_channel(
    shared_ptr<const SecurityPolicy> policy = nullptr, std::optional<MessageSecurityMode> mode = std::nullopt)
  {
    secondSc = make_channel();
    return SecureChannelInfo(secondSc->weak_from_this(),
      policy ? std::move(policy) : eccSecurityPolicy,
      mode.value_or(eccChannelMode),
      "L/Ep",
      tokenPolicies,
      clientCert);
  }

  // Waits until the Session's refusal has asked the parked crypto for its new ephemeral key pair.
  bool wait_for_parked_ephemeral_key_generation()
  {
    for (int attempt = 0; attempt < 500; ++attempt)
    {
      if (fakeCrypto->pending_create_ephemeral_keys_count() > 0)
        return true;
      std::this_thread::sleep_for(10ms);
    }
    return false;
  }

  // Waits until the Session's ActivateSession response build has asked the parked crypto for its new
  // server nonce.
  bool wait_for_parked_entropy()
  {
    for (int attempt = 0; attempt < 500; ++attempt)
    {
      if (fakeCrypto->pending_get_entropy_count() > 0)
        return true;
      std::this_thread::sleep_for(10ms);
    }
    return false;
  }

  // An ActivateSession presenting `password`. On the ECC Session the password is encrypted as an
  // EccEncryptedSecret against `serverEphemeralPublicKey`, and the request carries the client
  // application signature an authenticated channel requires, both bound to `serverNonce` (the nonce the
  // server last issued); on the other Session it is Anonymous.
  // With `encryptingPolicy`, the secret is encrypted by that policy object instead of the Session's ECC
  // policy, and the token still declares the Session's policy as its encryptionAlgorithm.
  void make_request(uint32_t requestHandle, string_view password, ByteString serverEphemeralPublicKey,
    ActivateSessionRequest& asr, shared_ptr<const SecurityPolicy> encryptingPolicy = nullptr)
  {
    asr.request_header().request_handle() = requestHandle;
    if (!useEcc)
    {
      auto token = std::make_unique<AnonymousIdentityToken>();
      token->policy_id() = tokenPolicies.front().policy_id();
      asr.user_identity_token() = std::move(token);
      return;
    }

    auto token = std::make_shared<UserNameIdentityToken>();
    token->user_name() = "testuser";
    ByteString passwordBytes;
    passwordBytes.assign(reinterpret_cast<const uint8_t*>(password.data()),
      reinterpret_cast<const uint8_t*>(password.data()) + password.size());
    token->password() = passwordBytes;
    auto encrypted = ua::test_helpers::run_async_function_sync<VoidResult>(
      [&](auto cb)
      {
        encrypt_user_token_async(encryptingPolicy ? encryptingPolicy : eccSecurityPolicy,
          crypto,
          crypto_test_strand(),
          token,
          serverNonce,
          serverCert,
          std::move(serverEphemeralPublicKey),
          clientCert,
          clientKeys,
          ua::Logger{},
          std::move(cb));
      });
    ASSERT_TRUE(encrypted.is_good()) << "Encrypt failed: " << to_string(encrypted.status_code().as_status());
    if (encryptingPolicy)
      token->encryption_algorithm() = eccSecurityPolicy->uri();
    token->policy_id() = tokenPolicies.front().policy_id();
    asr.user_identity_token() = std::make_unique<UserNameIdentityToken>(*token);
    asr.client_signature() = client_signature();
  }

  // The ClientSignature the ECC channel requires: over the Table 101 data (OPC 10000-4 section 6.1.8) of the
  // values the harness's SecureChannelInfo carries - no ChannelThumbprint and no server channel certificate -
  // and the empty ClientNonce of its CreateSession request, with an empty algorithm (Table 174).
  SignatureData client_signature() const
  {
    const auto data = ua::test_helpers::channel_bound_data(*crypto,
      *eccSecurityPolicy,
      ChannelBoundSignature::Client,
      ChannelBoundSignatureInputs{.serverNonce = serverNonce,
        .serverCertificate = serverCert->der_encoding(),
        .clientChannelCertificate = clientCert->der_encoding()});
    SignatureData signature;
    signature.signature() =
      crypto->asymmetric_sign_sync(eccSecurityPolicy->asymmetric_signature_algorithm(), clientKeys, data);
    return signature;
  }

  // An ActivateSession on the ECC Session presenting the Anonymous token of the policy offerAnonymous adds,
  // with the client application signature bound to `serverNonce`.
  void make_anonymous_request(uint32_t requestHandle, ActivateSessionRequest& asr)
  {
    asr.request_header().request_handle() = requestHandle;
    auto token = std::make_unique<AnonymousIdentityToken>();
    token->policy_id() = tokenPolicies.back().policy_id();
    asr.user_identity_token() = std::move(token);
    asr.client_signature() = client_signature();
  }

  // An ActivateSession presenting an IssuedIdentityToken whose tokenData is `tokenData` encrypted as an
  // EccEncryptedSecret against `serverEphemeralPublicKey` (by `encryptingPolicy` when given), with the
  // client application signature, as make_request builds for a UserName token. Part 4 7.41.6 Table 195:
  // the outer encryptionAlgorithm is empty for this wire shape.
  void make_issued_request(uint32_t requestHandle, string_view tokenData, ByteString serverEphemeralPublicKey,
    ActivateSessionRequest& asr, shared_ptr<const SecurityPolicy> encryptingPolicy = nullptr)
  {
    ActivateSessionRequest carrier;
    make_request(
      requestHandle, tokenData, std::move(serverEphemeralPublicKey), carrier, std::move(encryptingPolicy));
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    auto* encrypted = dynamic_cast<UserNameIdentityToken*>(carrier.user_identity_token().get());
    ASSERT_NE(encrypted, nullptr);
    auto issued = std::make_unique<IssuedIdentityToken>();
    issued->token_data() = encrypted->password();
    issued->encryption_algorithm().clear();
    issued->policy_id() = tokenPolicies.front().policy_id();
    asr = std::move(carrier);
    asr.user_identity_token() = std::move(issued);
  }

  shared_ptr<Structure> wait_for_answer(uint32_t requestId)
  {
    std::unique_lock<std::mutex> lk(mutex);
    shared_ptr<Structure> answer;
    cv.wait_for(lk,
      5s,
      [&]()
      {
        for (const auto& response : responses)
        {
          if (response.first == requestId)
          {
            answer = response.second;
            return true;
          }
        }
        return false;
      });
    return answer;
  }

  ~RefusedActivationHarness()
  {
    if (fakeCrypto)
      fakeCrypto->set_park_async(false);
    if (session)
      session->terminate_for_shutdown();
    ::ua::test_utils::drain_with_timeout(pool);
  }
};

const EphemeralKeyType* find_ecdh_key(const ResponseHeader& header)
{
  const auto* parameters = dynamic_cast<const AdditionalParametersType*>(header.additional_header().get());
  if (!parameters)
    return nullptr;
  for (const auto& kv : parameters->parameters().payload())
  {
    if (std::string_view{kv.key().name()} == "ECDHKey")
      return kv.value().try_as<EphemeralKeyType>();
  }
  return nullptr;
}

// @verifies AC-COMP-ECC-SECRET-USERNAME-ROUTING
// @relation(AC-COMP-ECC-SECRET-USERNAME-ROUTING, scope=function)
TEST(ServerActivateEccEncryptedUsername, EmptyOuterAlgorithmDecryptsBeforeAuthentication)
{
  RefusedActivationHarness harness;
  harness.start(true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  ActivateSessionRequest request;
  harness.make_request(42, acceptedPassword, harness.issuedEphemeralPublicKey, request);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  auto* token = dynamic_cast<UserNameIdentityToken*>(request.user_identity_token().get());
  ASSERT_NE(token, nullptr);
  token->encryption_algorithm() = String{};
  harness.session->activate(2, std::move(request), {});
  const auto answer = harness.wait_for_answer(2);
  ASSERT_NE(answer, nullptr);
  auto* response = dynamic_cast<ActivateSessionResponse*>(answer.get());
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
  EXPECT_EQ(harness.authenticator->calls(), 1u);
}

// OPC 10000-4 1.05.06 Table 188: under a SecurityPolicy with SecureChannelEnhancements, Servers "shall ignore
// any value specified" in a UserName token's encryptionAlgorithm. A valid EccEncryptedSecret naming a
// meaningless algorithm activates and reaches the authenticator once; the same name on a password sent in
// clear is refused before the authenticator, so the envelope is decoded whatever the field holds.
// @relation(AC-SVR-IDENT-008-OUTER-ALGORITHM-IGNORED-UNDER-ENHANCED-POLICY, scope=function)
TEST(ServerActivateEccEncryptedUsername, ANamedOuterAlgorithmIsIgnoredAndTheEnvelopeIsStillDecoded)
{
  for (const bool encrypted : {true, false})
  {
    SCOPED_TRACE(encrypted);
    RefusedActivationHarness harness;
    harness.start(true);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ActivateSessionRequest request;
    harness.make_request(42, acceptedPassword, harness.issuedEphemeralPublicKey, request);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    auto* token = dynamic_cast<UserNameIdentityToken*>(request.user_identity_token().get());
    ASSERT_NE(token, nullptr);
    token->encryption_algorithm() = String{"abc123"};
    if (!encrypted)
    {
      token->password() =
        ByteString{span<const byte>{utils::chars_to_bytes(acceptedPassword.data()), acceptedPassword.size()}};
    }
    harness.session->activate(2, std::move(request), {});
    const auto answer = harness.wait_for_answer(2);
    ASSERT_NE(answer, nullptr);
    auto* response = dynamic_cast<ActivateSessionResponse*>(answer.get());
    if (encrypted)
    {
      ASSERT_NE(response, nullptr) << "a valid EccEncryptedSecret naming any algorithm must activate";
      EXPECT_TRUE(response->response_header().service_result().is_good());
      EXPECT_EQ(harness.authenticator->calls(), 1u);
    }
    else
    {
      EXPECT_TRUE(response == nullptr || !response->response_header().service_result().is_good())
        << "a password in clear must be refused whatever encryptionAlgorithm names";
      EXPECT_EQ(harness.authenticator->calls(), 0u);
    }
  }
}

// Part 4 section 7.40.6 Table 191: the outer field cannot bypass ECC envelope decoding.
// @relation(AC-SVR-IDENT-018-OUTER-ALGORITHM-IGNORED, scope=function)
TEST(ServerActivateEccEncryptedUsername, IssuedTokensNamedOuterAlgorithmsStillRequireTheEncryptedEnvelope)
{
  for (const auto& algorithm :
    {String{}, String{"abc123"}, SecurityPolicy::create(SecurityPolicyId::EccNistP256AesGcm)->uri()})
  {
    SCOPED_TRACE(static_cast<std::string>(algorithm));
    for (const bool malformed : {false, true})
    {
      SCOPED_TRACE(malformed);
      RefusedActivationHarness harness;
      harness.start(true, false, UserTokenType::IssuedToken);
      ASSERT_FALSE(::testing::Test::HasFatalFailure());
      ActivateSessionRequest request;
      harness.make_issued_request(42, acceptedPassword, harness.issuedEphemeralPublicKey, request);
      ASSERT_FALSE(::testing::Test::HasFatalFailure());
      auto* token = dynamic_cast<IssuedIdentityToken*>(request.user_identity_token().get());
      ASSERT_NE(token, nullptr);
      token->encryption_algorithm() = algorithm;
      if (malformed)
      {
        token->token_data() = ByteString{
          span<const byte>{utils::chars_to_bytes(acceptedPassword.data()), acceptedPassword.size()}};
      }

      harness.session->activate(2, std::move(request), {});
      const auto answer = harness.wait_for_answer(2);
      ASSERT_NE(answer, nullptr);
      if (malformed)
      {
        auto* fault = dynamic_cast<ServiceFault*>(answer.get());
        ASSERT_NE(fault, nullptr);
        EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadIdentityTokenInvalid});
        EXPECT_EQ(harness.authenticator->calls(), 0u);
        EXPECT_FALSE(harness.session->is_activated());
      }
      else
      {
        auto* response = dynamic_cast<ActivateSessionResponse*>(answer.get());
        ASSERT_NE(response, nullptr);
        EXPECT_EQ(response->response_header().service_result(), StatusCode{Status::Good});
        EXPECT_EQ(harness.authenticator->calls(), 1u);
        EXPECT_TRUE(harness.session->is_activated());
      }
    }
  }
}

// AC-SVR-SCE-013-NONE-CHANNEL-SECRET-REFUSED: a UserName secret encrypted under an ECC policy that arrives
// over a SecureChannel whose SecurityMode is None is refused with Bad_SecurityPolicyRejected before the
// authenticator, and the Session stays unactivated (OPC 10000-4 7.41: "If the SecurityMode is None,
// SecurityPolicies based on ECC or RSA_DH are not allowed"). A conforming server never offers such a token
// policy (AC-SVR-SCE-013-ENDPOINT-TOKEN-POLICIES), so the guard every ActivateSession runs is driven here
// with the None channel set on the Session directly. Control: the same request over the ECC channel activates
// it.
// @relation(AC-SVR-SCE-013-NONE-CHANNEL-SECRET-REFUSED, scope=function)
TEST(ServerActivateEccEncryptedUsername, AnEccSecretOverANoneChannelIsRefused)
{
  for (const bool noneChannel : {true, false})
  {
    SCOPED_TRACE(noneChannel ? "None channel" : "control: the ECC channel");
    RefusedActivationHarness harness;
    harness.start(true);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ActivateSessionRequest request;
    harness.make_request(42, acceptedPassword, harness.issuedEphemeralPublicKey, request);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    if (noneChannel)
    {
      SessionTestAccess::on_strand(*harness.session,
        [&](auto& g)
        {
          g.secure_channel_info() = SecureChannelInfo(harness.sc->weak_from_this(),
            SecurityPolicy::create(SecurityPolicyId::None),
            MessageSecurityMode::None,
            "L/Ep",
            harness.tokenPolicies);
          g.channel_security_policy_id() = SecurityPolicyId::None;
          g.channel_security_mode() = MessageSecurityMode::None;
        });
    }
    harness.session->activate(2, std::move(request), {});
    const auto answer = harness.wait_for_answer(2);
    ASSERT_NE(answer, nullptr);
    if (noneChannel)
    {
      const auto* fault = dynamic_cast<const ServiceFault*>(answer.get());
      ASSERT_NE(fault, nullptr) << "the ActivateSession was answered with "
                                << std::string{answer->type_name()};
      EXPECT_EQ(fault->response_header().service_result().as_status(), Status::BadSecurityPolicyRejected)
        << to_string(fault->response_header().service_result().as_status());
      EXPECT_EQ(harness.authenticator->calls(), 0u) << "the secret reached the authenticator";
      EXPECT_EQ(SessionTestAccess::on_strand(*harness.session, [](auto& g) { return g.session_state(); }),
        SessionTestAccess::State::Created)
        << "the refused ActivateSession activated the Session";
    }
    else
    {
      const auto* response = dynamic_cast<const ActivateSessionResponse*>(answer.get());
      ASSERT_NE(response, nullptr);
      EXPECT_TRUE(response->response_header().service_result().is_good());
      EXPECT_EQ(harness.authenticator->calls(), 1u);
    }
  }
}

class FakeAuthenticationFailureObserver final : public ServerObserver
{
public:
  std::promise<StatusCode> failure;

  void on_authentication_failed(const SessionEventInfo&, StatusCode reason) override
  {
    failure.set_value(std::move(reason));
  }
};

// @verifies AC-COMP-ECC-SECRET-USERNAME-ROUTING
// @relation(AC-COMP-ECC-SECRET-USERNAME-ROUTING, scope=function)
TEST(ServerActivateEccEncryptedUsername, EmptyOuterAlgorithmCannotBypassEnvelopeOrKeyValidation)
{
  for (const auto invalidCase : {0u, 1u, 2u})
  {
    SCOPED_TRACE(invalidCase);
    RefusedActivationHarness harness;
    auto observer = std::make_shared<FakeAuthenticationFailureObserver>();
    auto failure = observer->failure.get_future();
    harness.start(true, false, UserTokenType::UserName, observer);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ActivateSessionRequest request;
    harness.make_request(42, acceptedPassword, harness.issuedEphemeralPublicKey, request);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    auto* token = dynamic_cast<UserNameIdentityToken*>(request.user_identity_token().get());
    ASSERT_NE(token, nullptr);
    token->encryption_algorithm() = String{};
    if (invalidCase == 0)
    {
      token->password() =
        ByteString{span<const byte>{utils::chars_to_bytes(acceptedPassword.data()), acceptedPassword.size()}};
    }
    else if (invalidCase == 1)
    {
      SessionTestAccess::on_strand(
        *harness.session, [](auto& guard) { guard.ecc_user_token_policy_id() = SecurityPolicyId::Invalid; });
    }
    else
    {
      SessionTestAccess::on_strand(
        *harness.session, [](auto& guard) { guard.ecc_ephemeral_private_key().clear(); });
    }
    harness.session->activate(2, std::move(request), {});
    const auto answer = harness.wait_for_answer(2);
    ASSERT_NE(answer, nullptr);
    auto* fault = dynamic_cast<ServiceFault*>(answer.get());
    ASSERT_NE(fault, nullptr);
    if (invalidCase == 0)
    {
      EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadIdentityTokenInvalid});
      EXPECT_FALSE(fault->response_header().service_result().shared_detail());
      ASSERT_EQ(failure.wait_for(0s), std::future_status::ready);
      const auto richStatus = failure.get();
      EXPECT_EQ(richStatus.as_status(), Status::BadIdentityTokenInvalid);
      auto detail = richStatus.shared_detail();
      const auto originalDetail = detail;
      while (detail && detail->code != "IdentityTokenValidationFailed")
        detail = detail->cause;
      ASSERT_TRUE(detail) << (originalDetail ? ua::to_string(*originalDetail) : "Missing fault detail");
      EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadDecodingError}.value());
      ASSERT_TRUE(detail->cause);
      EXPECT_EQ(detail->cause->code, "HeaderParseFailed");
    }
    else
      EXPECT_EQ(fault->response_header().service_result(), StatusCode{Status::BadSecurityChecksFailed});
    EXPECT_EQ(harness.authenticator->calls(), 0u);
  }
}

// Part 6 6.8.3: "The Server always returns a new EphemeralKey in the ResponseHeader which the Client saves
// for when it calls ActivateSession again ... The EphemeralKey is changed even if the Client did not
// provide an encrypted UserIdentityToken." The refused request consumed the key it was encrypted against,
// so a fault without a new one leaves the client nothing to encrypt its retry against. The fault must
// carry a new key signed by the server, and the retry encrypted against that key must activate - which it
// can only do if the server replaced its stored key with the one it sent.
// @verifies AC-SVR-SESS-ECC-FRESH-KEY-ON-FAILED-ACTIVATE
TEST(ServerActivateEccEphemeralKey, RefusedActivationFaultCarriesANewSignedKeyThatTheRetryActivatesWith)
{
  RefusedActivationHarness h;
  h.start(true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  ActivateSessionRequest refusedRequest;
  h.make_request(42, refusedPassword, h.issuedEphemeralPublicKey, refusedRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(2, std::move(refusedRequest), {});

  auto refusal = h.wait_for_answer(2);
  ASSERT_NE(refusal, nullptr) << "the refused ActivateSession was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(refusal.get());
  ASSERT_NE(fault, nullptr) << "a wrong password must be refused with a ServiceFault";
  const auto refusalStatus = fault->response_header().service_result();
  EXPECT_TRUE(refusalStatus == Status::BadUserAccessDenied)
    << "the key must not change the refusal's status, got: " << to_string(refusalStatus.as_status());

  const auto* renewed = find_ecdh_key(fault->response_header());
  ASSERT_NE(renewed, nullptr)
    << "the fault's ResponseHeader.additionalHeader carries no ECDHKey EphemeralKey";
  const ByteString renewedKey = renewed->public_key();
  EXPECT_FALSE(renewedKey.empty());
  EXPECT_NE(renewedKey, h.issuedEphemeralPublicKey) << "the fault repeated the key the refused request used";
  EXPECT_NO_THROW(h.crypto->asymmetric_verify_sync(h.eccSecurityPolicy->asymmetric_signature_algorithm(),
    h.serverKeys->public_key_der(),
    renewedKey,
    renewed->signature()))
    << "the new EphemeralKey's signature does not verify with the server certificate's key";
  EXPECT_EQ(SessionTestAccess::on_strand(
              *h.session, [](auto& g) -> ByteString { return g.ecc_ephemeral_public_key(); }),
    renewedKey)
    << "the server kept a different key from the one it sent";

  ActivateSessionRequest retryRequest;
  h.make_request(43, acceptedPassword, renewedKey, retryRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(3, std::move(retryRequest), {});

  auto retry = h.wait_for_answer(3);
  ASSERT_NE(retry, nullptr) << "the retried ActivateSession was never answered";
  if (auto* retryFault = dynamic_cast<ServiceFault*>(retry.get()))
  {
    FAIL() << "the retry encrypted against the fault's key was refused: "
           << to_string(retryFault->response_header().service_result().as_status());
  }
  auto* response = dynamic_cast<ActivateSessionResponse*>(retry.get());
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
}

// Control: a Session with no ECC token policy has no EphemeralKey to renew, so its refused ActivateSession
// fault is unchanged - the same status and no additionalHeader.
// @verifies AC-SVR-SESS-ECC-FRESH-KEY-ON-FAILED-ACTIVATE
TEST(ServerActivateEccEphemeralKey,
  RefusedActivationFaultOnASessionWithoutAnEccTokenPolicyCarriesNoAdditionalHeader)
{
  RefusedActivationHarness h;
  h.start(false);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  ActivateSessionRequest refusedRequest;
  h.make_request(42, refusedPassword, ByteString{}, refusedRequest);
  h.session->activate(2, std::move(refusedRequest), {});

  auto refusal = h.wait_for_answer(2);
  ASSERT_NE(refusal, nullptr) << "the refused ActivateSession was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(refusal.get());
  ASSERT_NE(fault, nullptr) << "the refused activation must be answered with a ServiceFault";
  const auto refusalStatus = fault->response_header().service_result();
  EXPECT_TRUE(refusalStatus == Status::BadUserAccessDenied)
    << "unexpected refusal status: " << to_string(refusalStatus.as_status());
  EXPECT_EQ(fault->response_header().additional_header().get(), nullptr)
    << "a Session without an ECC token policy must not put an additionalHeader on its fault";
}

// A refusal whose new key cannot be issued is still the refusal: the key generation fails (the parked
// crypto answers it with Bad_OutOfMemory), and the fault must carry the authenticator's status, not the
// key step's, and no additionalHeader - never a half-built or stale ECDHKey.
// @verifies AC-SVR-SESS-ECC-FRESH-KEY-ON-FAILED-ACTIVATE
TEST(ServerActivateEccEphemeralKey, RefusalWhoseNewKeyCannotBeGeneratedKeepsItsStatusAndCarriesNoKey)
{
  RefusedActivationHarness h;
  h.start(true, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  ActivateSessionRequest refusedRequest;
  h.make_request(42, refusedPassword, h.issuedEphemeralPublicKey, refusedRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.authenticator->set_before_refusal([fake = h.fakeCrypto] { fake->set_park_async(true); });
  h.session->activate(2, std::move(refusedRequest), {});

  ASSERT_TRUE(h.wait_for_parked_ephemeral_key_generation())
    << "the refusal never asked for a new ephemeral key pair";
  h.fakeCrypto->set_park_async(false);
  h.fakeCrypto->complete_pending_create_ephemeral_keys(
    0, Crypto::EphemeralKeyPairResult{StatusCode{Status::BadOutOfMemory}});

  auto refusal = h.wait_for_answer(2);
  ASSERT_NE(refusal, nullptr) << "a refusal whose key generation failed was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(refusal.get());
  ASSERT_NE(fault, nullptr) << "the refused activation must be answered with a ServiceFault";
  const auto refusalStatus = fault->response_header().service_result();
  EXPECT_TRUE(refusalStatus == Status::BadUserAccessDenied)
    << "the failed key step changed the refusal's status to: " << to_string(refusalStatus.as_status());
  EXPECT_EQ(fault->response_header().additional_header().get(), nullptr)
    << "a refusal whose new key could not be generated must not carry an additionalHeader";
}

// Part 4 5.6.3.1: a re-activation over a different SecureChannel that authenticates a different identity
// is refused with Bad_IdentityChangeNotSupported after authentication - after the token encrypted against
// the Session's EphemeralKey was received. That refusal is an ActivateSession answer like any other, so it
// carries a new signed key too (Part 6 6.8.3).
// @verifies AC-SVR-SESS-ECC-FRESH-KEY-ON-FAILED-ACTIVATE
TEST(ServerActivateEccEphemeralKey, IdentityChangeRefusalOnANewChannelCarriesANewSignedKey)
{
  RefusedActivationHarness h;
  h.start(true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  ActivateSessionRequest firstRequest;
  h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, firstRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(2, std::move(firstRequest), {});
  auto first = h.wait_for_answer(2);
  ASSERT_NE(first, nullptr) << "the first ActivateSession was never answered";
  auto* activated = dynamic_cast<ActivateSessionResponse*>(first.get());
  ASSERT_NE(activated, nullptr) << "the first activation must succeed for the re-activation to be tested";
  const auto* activatedKey = find_ecdh_key(activated->response_header());
  ASSERT_NE(activatedKey, nullptr) << "the successful ActivateSession carried no ECDHKey";
  const ByteString keyInUse = activatedKey->public_key();
  h.serverNonce = activated->server_nonce();

  // The same user name and client certificate over a new channel, but the authenticator now derives a
  // different identity from the token.
  h.authenticator->set_user_id("another-user");
  const auto secondChannel = h.open_second_ecc_channel();
  ActivateSessionRequest reactivation;
  h.make_request(43, acceptedPassword, keyInUse, reactivation);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(3, std::move(reactivation), secondChannel);

  auto refusal = h.wait_for_answer(3);
  ASSERT_NE(refusal, nullptr) << "the re-activation was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(refusal.get());
  ASSERT_NE(fault, nullptr) << "a re-activation with a changed identity must be refused with a ServiceFault";
  const auto refusalStatus = fault->response_header().service_result();
  ASSERT_TRUE(refusalStatus == Status::BadIdentityChangeNotSupported)
    << "expected the post-authentication identity-change refusal, got: "
    << to_string(refusalStatus.as_status());

  const auto* renewed = find_ecdh_key(fault->response_header());
  ASSERT_NE(renewed, nullptr) << "the identity-change refusal carries no ECDHKey EphemeralKey";
  const ByteString renewedKey = renewed->public_key();
  EXPECT_FALSE(renewedKey.empty());
  EXPECT_NE(renewedKey, keyInUse) << "the fault repeated the key the refused request used";
  EXPECT_NO_THROW(h.crypto->asymmetric_verify_sync(h.eccSecurityPolicy->asymmetric_signature_algorithm(),
    h.serverKeys->public_key_der(),
    renewedKey,
    renewed->signature()))
    << "the new EphemeralKey's signature does not verify with the server certificate's key";
  EXPECT_EQ(SessionTestAccess::on_strand(
              *h.session, [](auto& g) -> ByteString { return g.ecc_ephemeral_public_key(); }),
    renewedKey)
    << "the server kept a different key from the one it sent";
}

// While a refusal waits for its new key, the activation is still in flight: a second ActivateSession must
// be turned away with Bad_ServerTooBusy rather than start a second key step on the same Session. Once the
// key step is released, the first refusal is answered with its key.
// @verifies AC-SVR-SESS-ECC-FRESH-KEY-ON-FAILED-ACTIVATE
TEST(ServerActivateEccEphemeralKey, SecondActivationWhileTheRefusalAwaitsItsKeyIsRefusedAsServerTooBusy)
{
  RefusedActivationHarness h;
  h.start(true, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  // Both requests are built before the crypto is parked: encrypting a token uses the same crypto.
  ActivateSessionRequest refusedRequest;
  h.make_request(42, refusedPassword, h.issuedEphemeralPublicKey, refusedRequest);
  ActivateSessionRequest overlappingRequest;
  h.make_request(43, acceptedPassword, h.issuedEphemeralPublicKey, overlappingRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.authenticator->set_before_refusal([fake = h.fakeCrypto] { fake->set_park_async(true); });
  h.session->activate(2, std::move(refusedRequest), {});

  ASSERT_TRUE(h.wait_for_parked_ephemeral_key_generation())
    << "the refusal never asked for a new ephemeral key pair";

  h.session->activate(3, std::move(overlappingRequest), {});
  auto overlapping = h.wait_for_answer(3);
  ASSERT_NE(overlapping, nullptr) << "the overlapping ActivateSession was never answered";
  auto* busyFault = dynamic_cast<ServiceFault*>(overlapping.get());
  ASSERT_NE(busyFault, nullptr) << "the overlapping ActivateSession must be refused with a ServiceFault";
  const auto busyStatus = busyFault->response_header().service_result();
  EXPECT_TRUE(busyStatus == Status::BadServerTooBusy)
    << "expected Bad_ServerTooBusy, got: " << to_string(busyStatus.as_status());
  {
    std::lock_guard<std::mutex> lk(h.mutex);
    for (const auto& response : h.responses)
      EXPECT_NE(response.first, 2u) << "the refusal was answered before its key step completed";
  }
  EXPECT_EQ(h.fakeCrypto->pending_create_ephemeral_keys_count(), 1u)
    << "the overlapping request started a second key step";

  const auto* eccPolicy = dynamic_cast<const SecPolEphemeralKey*>(h.eccSecurityPolicy.get());
  ASSERT_NE(eccPolicy, nullptr);
  h.fakeCrypto->set_park_async(false);
  h.fakeCrypto->complete_pending_create_ephemeral_keys(0,
    Crypto::EphemeralKeyPairResult{
      h.crypto->create_ephemeral_keys_sync(eccPolicy->ephemeral_key_algorithm())});

  auto refusal = h.wait_for_answer(2);
  ASSERT_NE(refusal, nullptr) << "the refusal was never answered after its key step was released";
  auto* fault = dynamic_cast<ServiceFault*>(refusal.get());
  ASSERT_NE(fault, nullptr);
  const auto refusalStatus = fault->response_header().service_result();
  EXPECT_TRUE(refusalStatus == Status::BadUserAccessDenied)
    << "unexpected refusal status: " << to_string(refusalStatus.as_status());
  const auto* renewed = find_ecdh_key(fault->response_header());
  ASSERT_NE(renewed, nullptr) << "the released refusal carries no ECDHKey EphemeralKey";
  EXPECT_NE(renewed->public_key(), h.issuedEphemeralPublicKey);
  EXPECT_NO_THROW(h.crypto->asymmetric_verify_sync(h.eccSecurityPolicy->asymmetric_signature_algorithm(),
    h.serverKeys->public_key_der(),
    renewed->public_key(),
    renewed->signature()))
    << "the new EphemeralKey's signature does not verify with the server certificate's key";
}

// ===================================================================
// Security review SESS-7(e): the EncryptedSecret CommonHeader is checked
// ===================================================================

// A Basic256Sha256 policy that names another policy: every algorithm and size is Basic256Sha256's, so
// a secret it encrypts decrypts under the server's Basic256Sha256 token policy, but the RsaEncryptedSecret
// CommonHeader it writes names Aes128_Sha256_RsaOaep.
class MislabelledBasic256Sha256 final : public SecPolBasic256Sha256
{
public:
  String uri() const override
  {
    return SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep)->uri();
  }
};

// The ECC counterpart: ECC_nistP256_AesGcm in every algorithm, ECC_nistP384_AesGcm in the CommonHeader.
const EphemeralKeyPolicyParameters mislabelledEccNistP256 = []
{
  auto row = *find_ephemeral_key_policy(SecurityPolicyId::EccNistP256AesGcm);
  row.uri = find_ephemeral_key_policy(SecurityPolicyId::EccNistP384AesGcm)->uri;
  return row;
}();

// OPC 10000-4 7.41.2.3: the SecurityPolicyUri "is used to determine what algorithms were used to encrypt
// and sign the data", and for an RsaEncryptedSecret the Certificate is "The SHA1 hash of the DER form of
// the Certificate used to encrypt the KeyData" (Table 189). A server that parses both and never looks at
// them accepts a secret that was produced for another policy, or for another certificate, whenever the
// bytes happen to decrypt. Both negatives decrypt cleanly under the server's key and policy - only the
// header differs from the control - so a refusal can only come from the header check.
// @verifies AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED
TEST(ServerActivateEncryptedSecretHeader, RsaEncryptedSecretNamingAnotherPolicyOrCertificateIsRefused)
{
  auto crypto = create_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto serverKeyPair = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);

  TestPki pki{create_crypto()};
  auto makeServerCertificate = [&](std::string serialNumber)
  {
    Crypto::CreateCertificateConfig certParams;
    certParams.subjectKeys = serverKeyPair;
    certParams.issuerKeys = serverKeyPair;
    certParams.subject.commonName = "TestServer";
    certParams.serialNumber = std::move(serialNumber);
    certParams.basicConstraint.cA = false;
    certParams.keyUsage.digitalSignature = true;
    certParams.keyUsage.keyEncipherment = true;
    certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    certParams.from = DateTime::now();
    certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
    return pki.create_cert(certParams);
  };
  auto serverCert = makeServerCertificate("1");
  // The same key pair in another certificate: KeyData encrypted to it decrypts with the server's private
  // key, but its thumbprint is not the server certificate's.
  auto siblingCert = makeServerCertificate("2");
  ASSERT_NE(serverCert->thumbprint(), siblingCert->thumbprint());

  auto serverNonce = make_nonce(*crypto, 32);
  // The modern RSA envelope starts above the 64 UTF-8 byte boundary.
  const std::string passwordText(65, 'p');

  auto encrypt = [&](shared_ptr<const SecurityPolicy> encryptingPolicy,
                   shared_ptr<const X509Certificate>
                     encryptingCertificate,
                   std::shared_ptr<UserNameIdentityToken>& out)
  {
    auto tokenPtr = std::make_shared<UserNameIdentityToken>();
    tokenPtr->user_name() = "testuser";
    ByteString plainPassword;
    plainPassword.assign(reinterpret_cast<const uint8_t*>(passwordText.data()),
      reinterpret_cast<const uint8_t*>(passwordText.data()) + passwordText.size());
    tokenPtr->password() = plainPassword;
    auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
      [&](auto cb)
      {
        encrypt_user_token_async(std::move(encryptingPolicy),
          crypto,
          crypto_test_strand(),
          tokenPtr,
          serverNonce,
          std::move(encryptingCertificate),
          ByteString{},
          nullptr,
          nullptr,
          ua::Logger{},
          std::move(cb));
      });
    ASSERT_TRUE(encResult.is_good()) << "Encrypt failed: " << to_string(encResult.status_code().as_status());
    // The token declares the server's policy whatever the header says, so only the header differs.
    tokenPtr->encryption_algorithm() = policy->uri();
    out = tokenPtr;
  };

  std::shared_ptr<UserNameIdentityToken> wellFormed;
  std::shared_ptr<UserNameIdentityToken> otherPolicy;
  std::shared_ptr<UserNameIdentityToken> otherCertificate;
  encrypt(policy, serverCert, wellFormed);
  encrypt(std::make_shared<MislabelledBasic256Sha256>(), serverCert, otherPolicy);
  encrypt(policy, siblingCert, otherCertificate);
  ASSERT_NE(wellFormed, nullptr);
  ASSERT_NE(otherPolicy, nullptr);
  ASSERT_NE(otherCertificate, nullptr);

  // control: the secret whose header names the server's policy and certificate is accepted.
  TokenActivationOutcome control;
  activate_with_user_name_token(SecurityPolicyId::Basic256Sha256,
    crypto,
    policy,
    serverCert,
    serverKeyPair,
    serverNonce,
    *wellFormed,
    control);
  ASSERT_TRUE(control.gotResponse);
  ASSERT_TRUE(control.isActivateResponse)
    << "control activation must be accepted, got: " << to_string(control.serviceResult.as_status());
  EXPECT_EQ(control.password, passwordText);

  // negative: the header names Aes128_Sha256_RsaOaep while the server decrypts with Basic256Sha256.
  TokenActivationOutcome policyMismatch;
  activate_with_user_name_token(SecurityPolicyId::Basic256Sha256,
    crypto,
    policy,
    serverCert,
    serverKeyPair,
    serverNonce,
    *otherPolicy,
    policyMismatch);
  ASSERT_TRUE(policyMismatch.gotResponse);
  EXPECT_TRUE(policyMismatch.isFault) << "a secret naming another SecurityPolicy must be refused";
  EXPECT_EQ(policyMismatch.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_FALSE(policyMismatch.authenticatorCalled)
    << "a secret naming another SecurityPolicy reached the authenticator";

  // negative: the header's Certificate is the thumbprint of a certificate that is not the server's.
  TokenActivationOutcome certificateMismatch;
  activate_with_user_name_token(SecurityPolicyId::Basic256Sha256,
    crypto,
    policy,
    serverCert,
    serverKeyPair,
    serverNonce,
    *otherCertificate,
    certificateMismatch);
  ASSERT_TRUE(certificateMismatch.gotResponse);
  EXPECT_TRUE(certificateMismatch.isFault)
    << "a secret naming another encrypting certificate must be refused";
  EXPECT_EQ(certificateMismatch.serviceResult, Status::BadIdentityTokenInvalid);
  EXPECT_FALSE(certificateMismatch.authenticatorCalled)
    << "a secret naming another encrypting certificate reached the authenticator";
}

// OPC 10000-4 7.41.2.3 for the EccEncryptedSecret: a secret whose SecurityPolicyUri names a policy other
// than the one the server decrypts it with is refused, although it decrypts and its signature verifies -
// for a UserName password and for IssuedToken tokenData, which decrypt at separate sites. The refusal never
// reaches the authenticator and gives the Session no identity. Each control is the same request encrypted
// by the Session's own policy object.
// @verifies AC-SVR-IDENT-013-SESS7E-ENCRYPTED-SECRET-HEADER-CHECKED
TEST(ServerActivateEncryptedSecretHeader, EccEncryptedSecretNamingAnotherPolicyIsRefused)
{
  for (const auto tokenType : {UserTokenType::UserName, UserTokenType::IssuedToken})
  {
    SCOPED_TRACE(tokenType == UserTokenType::UserName ? "UserNameIdentityToken" : "IssuedIdentityToken");
    const auto build = [tokenType](RefusedActivationHarness& h,
                         ActivateSessionRequest& request,
                         shared_ptr<const SecurityPolicy>
                           encryptingPolicy)
    {
      if (tokenType == UserTokenType::UserName)
        h.make_request(
          42, acceptedPassword, h.issuedEphemeralPublicKey, request, std::move(encryptingPolicy));
      else
        h.make_issued_request(
          42, acceptedPassword, h.issuedEphemeralPublicKey, request, std::move(encryptingPolicy));
    };

    {
      RefusedActivationHarness control;
      control.start(true, false, tokenType);
      ASSERT_FALSE(::testing::Test::HasFatalFailure());
      ActivateSessionRequest request;
      build(control, request, nullptr);
      ASSERT_FALSE(::testing::Test::HasFatalFailure());
      control.session->activate(2, std::move(request), {});
      auto answer = control.wait_for_answer(2);
      ASSERT_NE(answer, nullptr) << "control: the ActivateSession was never answered";
      auto* response = dynamic_cast<ActivateSessionResponse*>(answer.get());
      ASSERT_NE(response, nullptr) << "control: the correctly labelled secret must activate";
      EXPECT_TRUE(response->response_header().service_result().is_good());
      EXPECT_EQ(control.authenticator->calls(), 1u);
    }

    RefusedActivationHarness h;
    h.start(true, false, tokenType);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ActivateSessionRequest request;
    build(h, request, std::make_shared<SecPolEphemeralKey>(mislabelledEccNistP256));
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    h.session->activate(2, std::move(request), {});
    auto answer = h.wait_for_answer(2);
    ASSERT_NE(answer, nullptr) << "the ActivateSession was never answered";
    auto* fault = dynamic_cast<ServiceFault*>(answer.get());
    ASSERT_NE(fault, nullptr) << "a secret naming another SecurityPolicy must be refused";
    const auto status = fault->response_header().service_result();
    EXPECT_TRUE(status == Status::BadIdentityTokenInvalid)
      << "expected Bad_IdentityTokenInvalid, got: " << to_string(status.as_status());
    EXPECT_EQ(h.authenticator->calls(), 0u) << "the mislabelled secret reached the authenticator";
    EXPECT_TRUE(SessionTestAccess::on_strand(
      *h.session, [](auto& g) { return g.session_info()->user_identity() == nullptr; }))
      << "a refused secret must not give the Session an identity";
  }
}

// ===================================================================
// Security review SESS-7(d): a re-activation decrypts with the channel it arrived on
// ===================================================================

// OPC 10000-4 5.6.3.1 lets a Session be re-activated over a different SecureChannel, and 7.41.4 makes the
// SecureChannel's SecurityPolicy the one a UserTokenPolicy with no SecurityPolicyUri uses. Both channels are
// Aes128_Sha256_RsaOaep SignAndEncrypt - since 1.05.07 (5.7.3.1) a re-activation keeps the original
// channel's policy and mode. The first endpoint's UserName policy names Basic256Sha256; the second
// endpoint's (same policyId) names no policy, so the re-activation's token is encrypted under the channel's
// Aes128_Sha256_RsaOaep. The server must match the token against the second endpoint's policies: matching
// against the CreateSession endpoint selects Basic256Sha256, the secret does not decrypt and the
// re-activation is refused.
// @verifies AC-SVR-SESS-027-SESS7D-REACTIVATION-USES-THE-NEW-CHANNELS-ENDPOINT
TEST(ServerActivateReactivationOnNewChannel, TokenIsMatchedAndDecryptedAgainstTheChannelItArrivedOn)
{
  auto crypto = create_crypto();
  auto firstPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto secondPolicy = SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep);

  TestPki pki{create_crypto()};
  auto makeCertificate =
    [&](const shared_ptr<const AsymmetricKeyPair>& keys, std::string commonName, std::string serialNumber)
  {
    Crypto::CreateCertificateConfig certParams;
    certParams.subjectKeys = keys;
    certParams.issuerKeys = keys;
    certParams.subject.commonName = std::move(commonName);
    certParams.serialNumber = std::move(serialNumber);
    certParams.basicConstraint.cA = false;
    certParams.keyUsage.digitalSignature = true;
    certParams.keyUsage.keyEncipherment = true;
    certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    certParams.from = DateTime::now();
    certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
    return pki.create_cert(certParams);
  };
  auto serverKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto serverCert = makeCertificate(serverKeys, "TestServer", "1");
  auto clientKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto clientCert = makeCertificate(clientKeys, "TestClient", "2");

  const auto firstTokenPolicy =
    server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256);
  auto secondTokenPolicy = firstTokenPolicy;
  secondTokenPolicy.security_policy_uri() = String{};
  const std::vector<UserTokenPolicy> firstEndpointPolicies{firstTokenPolicy};
  const std::vector<UserTokenPolicy> secondEndpointPolicies{secondTokenPolicy};

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  // Accepts only acceptedPassword, so an activation is Good only if the secret was recovered intact; its
  // identity records the token kind, which the re-activation's same-identity check compares.
  auto authenticator = std::make_shared<PasswordGateAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;
  auto sessDeps = std::make_shared<CryptoSessionDeps>(ex, hooks, crypto, nullptr, successAuthnTimeout);
  auto scDeps = std::make_shared<DummySecureChannelDeps>(ex);

  std::mutex mx;
  std::condition_variable cv;
  std::vector<Response> responses;
  auto makeChannel = [&](const std::vector<UserTokenPolicy>& policies)
  {
    auto sc = SecureChannel::create(
      scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
    SCTA::on_strand(*sc, [&](auto& g) { g.set_minimal_context_none(ex, "L/Ep", policies); });
    SCTA::on_strand(*sc,
      [&](auto& g)
      {
        g.set_response_sink(
          [&](const Response& r)
          {
            {
              std::lock_guard<std::mutex> lk(mx);
              responses.push_back(r);
            }
            cv.notify_all();
          });
      });
    return sc;
  };
  auto waitForAnswer = [&](uint32_t requestId) -> shared_ptr<Structure>
  {
    std::unique_lock<std::mutex> lk(mx);
    shared_ptr<Structure> answer;
    cv.wait_for(lk,
      5s,
      [&]()
      {
        for (const auto& response : responses)
        {
          if (response.first == requestId)
          {
            answer = response.second;
            return true;
          }
        }
        return false;
      });
    return answer;
  };

  auto firstSc = makeChannel(firstEndpointPolicies);
  SecureChannelInfo firstChannel(firstSc->weak_from_this(),
    secondPolicy,
    MessageSecurityMode::SignAndEncrypt,
    "L/First",
    firstEndpointPolicies,
    clientCert);
  auto session = Session::create(sessDeps, firstChannel, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);

  // CreateSession-produced state, injected as in the harnesses above (CryptoSessionDeps has no
  // CertificateStore). The client certificate is the one both channels were opened with.
  const auto firstNonce = make_nonce(*crypto, 32);
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.server_nonce() = firstNonce;
      g.server_certificates().push_back(
        CertificateStore::ApplicationCertificate{firstPolicy->certificate_type(), serverCert, serverKeys});
      g.selected_cert_and_key() = g.server_certificates().back();
      g.client_certificate() = clientCert;
    });

  auto makeToken = [&](const shared_ptr<const SecurityPolicy>& encryptingPolicy,
                     const ByteString& nonce,
                     std::unique_ptr<UserNameIdentityToken>& out)
  {
    auto tokenPtr = std::make_shared<UserNameIdentityToken>();
    tokenPtr->user_name() = "testuser";
    ByteString plainPassword;
    plainPassword.assign(reinterpret_cast<const uint8_t*>(acceptedPassword.data()),
      reinterpret_cast<const uint8_t*>(acceptedPassword.data()) + acceptedPassword.size());
    tokenPtr->password() = plainPassword;
    auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
      [&](auto cb)
      {
        encrypt_user_token_async(encryptingPolicy,
          crypto,
          crypto_test_strand(),
          tokenPtr,
          nonce,
          serverCert,
          ByteString{},
          nullptr,
          nullptr,
          ua::Logger{},
          std::move(cb));
      });
    ASSERT_TRUE(encResult.is_good()) << "Encrypt failed: " << to_string(encResult.status_code().as_status());
    tokenPtr->policy_id() = firstTokenPolicy.policy_id();
    out = std::make_unique<UserNameIdentityToken>(*tokenPtr);
  };

  // The client application signature the channels' policy requires, over (serverCertificate || serverNonce).
  const auto clientSignature = [&](const ByteString& nonce)
  {
    ByteString signedData = serverCert->der_encoding();
    std::ranges::copy(nonce, std::back_inserter(signedData));
    SignatureData signature;
    signature.signature() =
      crypto->asymmetric_sign_sync(secondPolicy->asymmetric_signature_algorithm(), clientKeys, signedData);
    signature.algorithm() = secondPolicy->asymmetric_signature_algorithm_uri();
    return signature;
  };

  // First activation on the CreateSession channel, under the first endpoint's Basic256Sha256 policy.
  ActivateSessionRequest firstRequest;
  firstRequest.request_header().request_handle() = 42;
  std::unique_ptr<UserNameIdentityToken> firstToken;
  makeToken(firstPolicy, firstNonce, firstToken);
  ASSERT_NE(firstToken, nullptr);
  firstRequest.user_identity_token() = std::move(firstToken);
  firstRequest.client_signature() = clientSignature(firstNonce);
  session->activate(2, std::move(firstRequest), {});
  auto first = waitForAnswer(2);
  ASSERT_NE(first, nullptr) << "the first ActivateSession was never answered";
  auto* activated = dynamic_cast<ActivateSessionResponse*>(first.get());
  ASSERT_NE(activated, nullptr) << "the first activation must succeed for the re-activation to be tested";
  const ByteString secondNonce = activated->server_nonce();
  ASSERT_FALSE(secondNonce.empty());

  // Re-activation over the second channel: its token encrypted under the policy that channel's endpoint
  // implies, and the client application signature that channel's policy requires.
  auto secondSc = makeChannel(secondEndpointPolicies);
  SecureChannelInfo secondChannel(secondSc->weak_from_this(),
    secondPolicy,
    MessageSecurityMode::SignAndEncrypt,
    "L/Second",
    secondEndpointPolicies,
    clientCert);
  ActivateSessionRequest reactivation;
  reactivation.request_header().request_handle() = 43;
  std::unique_ptr<UserNameIdentityToken> secondToken;
  makeToken(secondPolicy, secondNonce, secondToken);
  ASSERT_NE(secondToken, nullptr);
  reactivation.user_identity_token() = std::move(secondToken);
  reactivation.client_signature() = clientSignature(secondNonce);
  session->activate(3, std::move(reactivation), secondChannel);

  auto second = waitForAnswer(3);
  ASSERT_NE(second, nullptr) << "the re-activation was never answered";
  if (auto* fault = dynamic_cast<ServiceFault*>(second.get()))
  {
    ADD_FAILURE() << "the re-activation over the new channel was refused: "
                  << to_string(fault->response_header().service_result().as_status());
  }
  auto* reactivated = dynamic_cast<ActivateSessionResponse*>(second.get());
  ASSERT_NE(reactivated, nullptr);
  EXPECT_TRUE(reactivated->response_header().service_result().is_good())
    << "the re-activation's secret was not recovered with the new channel's policy";
  EXPECT_TRUE(SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      const auto& info = g.secure_channel_info();
      return info.has_value() && info->secure_channel().lock() == secondSc;
    }))
    << "the accepted re-activation must move the Session to the new channel";

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// ===================================================================
// Security review SESS-7(g): Activated only once the identity is committed
// ===================================================================

// OPC 10000-4 5.6.3.1: "If no errors occur the Server replaces the user identity for the Session", and a
// Session is not usable until it is activated (5.6.2). An activation whose authentication succeeded but
// whose response could not be built (here the new server nonce cannot be generated) has failed: the
// Session must stay Created, with no identity, not become Activated with none. The controls: an
// activation that completes is Activated with its identity, and a change-user re-activation whose build
// fails the same way keeps the Session Activated with the identity it had.
// @verifies AC-SVR-SESS-004-SESS7G-ACTIVATED-ONLY-ON-IDENTITY-COMMIT
TEST(ServerActivateCommit, AResponseBuildFailureAfterAuthenticationLeavesThePreviousState)
{
  using State = SessionTestAccess::State;
  const auto observe = [](RefusedActivationHarness& h)
  {
    return SessionTestAccess::on_strand(*h.session,
      [](auto& g)
      {
        const auto user = g.session_info()->user_identity();
        return std::make_pair(g.session_state(), user ? user->userId : std::string{"<none>"});
      });
  };

  // negative: a first activation whose response build fails after authentication.
  {
    RefusedActivationHarness h;
    h.start(true, true);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_EQ(observe(h).first, State::Created) << "precondition: the Session is created, not activated";
    ActivateSessionRequest request;
    h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, request);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    h.authenticator->set_before_acceptance([fake = h.fakeCrypto] { fake->set_park_async(true); });
    h.session->activate(2, std::move(request), {});

    ASSERT_TRUE(h.wait_for_parked_entropy()) << "the response build never asked for its server nonce";
    h.fakeCrypto->set_park_async(false);
    h.fakeCrypto->complete_pending_get_entropy(0, ByteStringResult{StatusCode{Status::BadOutOfMemory}});

    auto answer = h.wait_for_answer(2);
    ASSERT_NE(answer, nullptr) << "the failed activation was never answered";
    auto* fault = dynamic_cast<ServiceFault*>(answer.get());
    ASSERT_NE(fault, nullptr) << "an activation whose response could not be built must be a ServiceFault";
    EXPECT_TRUE(fault->response_header().service_result() == Status::BadOutOfMemory)
      << "got: " << to_string(fault->response_header().service_result().as_status());
    const auto [state, identity] = observe(h);
    EXPECT_EQ(state, State::Created) << "a failed first activation left the Session Activated";
    EXPECT_EQ(identity, "<none>") << "a failed first activation left the Session an identity";
    EXPECT_FALSE(h.session->is_activated());
  }

  // control: a completed activation is Activated with its identity; a change-user re-activation whose
  // build then fails keeps both.
  {
    RefusedActivationHarness h;
    h.start(true, true);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ActivateSessionRequest request;
    h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, request);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    h.session->activate(2, std::move(request), {});
    auto first = h.wait_for_answer(2);
    ASSERT_NE(first, nullptr);
    auto* activated = dynamic_cast<ActivateSessionResponse*>(first.get());
    ASSERT_NE(activated, nullptr) << "control: the activation must succeed";
    const auto* issuedKey = find_ecdh_key(activated->response_header());
    ASSERT_NE(issuedKey, nullptr);
    const ByteString keyInUse = issuedKey->public_key();
    h.serverNonce = activated->server_nonce();
    EXPECT_EQ(observe(h), std::make_pair(State::Activated, std::string{"testuser"}));

    h.authenticator->set_user_id("another-user");
    ActivateSessionRequest changeUser;
    h.make_request(43, acceptedPassword, keyInUse, changeUser);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    h.authenticator->set_before_acceptance([fake = h.fakeCrypto] { fake->set_park_async(true); });
    h.session->activate(3, std::move(changeUser), {});
    ASSERT_TRUE(h.wait_for_parked_entropy()) << "the response build never asked for its server nonce";
    h.fakeCrypto->set_park_async(false);
    h.fakeCrypto->complete_pending_get_entropy(0, ByteStringResult{StatusCode{Status::BadOutOfMemory}});
    auto second = h.wait_for_answer(3);
    ASSERT_NE(second, nullptr);
    ASSERT_NE(dynamic_cast<ServiceFault*>(second.get()), nullptr);
    EXPECT_EQ(observe(h), std::make_pair(State::Activated, std::string{"testuser"}))
      << "control: a failed change-user re-activation keeps the Session's state and identity";
  }
}

// ===================================================================
// Refused ECC activation: the new key is signed for the channel the request arrived on, and a key that
// cannot be issued does not replace the stored one (review of owner decision 8(b))
// ===================================================================

// A token whose policyId names no policy of the endpoint: refused as Bad_IdentityTokenInvalid before any
// decryption, so the Session's stored EphemeralKey is not consumed by the refused request itself.
void name_no_token_policy(ActivateSessionRequest& request)
{
  auto* token = dynamic_cast<UserIdentityToken*>(request.user_identity_token().get());
  ASSERT_NE(token, nullptr);
  token->policy_id() = "no-such-token-policy";
}

// The ServiceFault answering @p requestId, after checking it refuses with @p expected and carries no new
// EphemeralKey: the refusal comes before the token is read, so the stored key is not used and stays
// (OPC 10000-6 6.8.1: "the Server does not return anything and retains the previous EphemeralKey").
void expect_refused_before_the_token(RefusedActivationHarness& h, uint32_t requestId, StatusCode expected,
  const ByteString& keyInUse, const char* what)
{
  SCOPED_TRACE(what);
  auto answer = h.wait_for_answer(requestId);
  ASSERT_NE(answer, nullptr) << "never answered";
  auto* fault = dynamic_cast<ServiceFault*>(answer.get());
  ASSERT_NE(fault, nullptr) << "must be refused with a ServiceFault";
  EXPECT_TRUE(fault->response_header().service_result() == expected)
    << "got: " << to_string(fault->response_header().service_result().as_status());
  EXPECT_EQ(find_ecdh_key(fault->response_header()), nullptr) << "the refusal carries an EphemeralKey";
  EXPECT_EQ(SessionTestAccess::on_strand(
              *h.session, [](auto& g) -> ByteString { return g.ecc_ephemeral_public_key(); }),
    keyInUse)
    << "the refusal replaced the stored key";
}

// OPC 10000-4 5.7.3.1 (1.05.07; decision D-6, every SecurityPolicy): a re-activation over a new SecureChannel
// keeps the original channel's SecurityPolicy and SecurityMode. With the Session's ECC_nistP256
// SignAndEncrypt channel still open, a move to an ECC_nistP384 channel and one to an ECC_nistP256 Sign
// channel are refused with Bad_SecurityPolicyRejected, and the Session stays on its channel; the control
// moves it to a second ECC_nistP256 SignAndEncrypt channel. The refusal comes before the token is read, so no
// new key is issued and the stored one is kept (guess G-39).
// @relation(AC-SVR-SCE-012-POLICY-OR-MODE-CHANGE-REFUSED, scope=function)
TEST(ServerActivateNewChannel, AMoveToAnotherPolicyOrModeIsRefusedWhileTheOldChannelIsOpen)
{
  RefusedActivationHarness h;
  h.start(true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  ActivateSessionRequest firstRequest;
  h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, firstRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(2, std::move(firstRequest), {});
  auto first = h.wait_for_answer(2);
  auto* firstResponse = dynamic_cast<ActivateSessionResponse*>(first.get());
  ASSERT_NE(firstResponse, nullptr) << "the first activation must succeed for the moves to be tested";
  const auto* activatedKey = find_ecdh_key(firstResponse->response_header());
  ASSERT_NE(activatedKey, nullptr);
  const ByteString keyInUse = activatedKey->public_key();
  // Every later request is bound to the nonce this response issued.
  h.serverNonce = firstResponse->server_nonce();
  const auto onOriginalChannel = [&]
  {
    return SessionTestAccess::on_strand(*h.session,
      [&](auto& g)
      {
        return g.secure_channel_info().has_value() &&
               g.secure_channel_info()->secure_channel().lock().get() == h.sc.get();
      });
  };

  const struct
  {
    shared_ptr<const SecurityPolicy> policy;
    MessageSecurityMode mode;
    const char* what;
  } moves[] = {
    {SecurityPolicy::create(SecurityPolicyId::EccNistP384AesGcm),
      MessageSecurityMode::SignAndEncrypt,
      "another policy"},
    {h.eccSecurityPolicy, MessageSecurityMode::Sign, "another mode"},
  };

  uint32_t requestId = 3;
  for (const auto& move : moves)
  {
    ActivateSessionRequest reactivation;
    h.make_request(40 + requestId, acceptedPassword, keyInUse, reactivation);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    h.session->activate(
      requestId, std::move(reactivation), h.open_second_ecc_channel(move.policy, move.mode));
    expect_refused_before_the_token(h, requestId, Status::BadSecurityPolicyRejected, keyInUse, move.what);
    EXPECT_TRUE(onOriginalChannel()) << move.what << ": the refused move took the Session off its channel";
    ++requestId;
  }

  // Control: the same policy and mode moves the Session.
  ActivateSessionRequest sameSecurity;
  h.make_request(40 + requestId, acceptedPassword, keyInUse, sameSecurity);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(requestId, std::move(sameSecurity), h.open_second_ecc_channel());
  auto moved = h.wait_for_answer(requestId);
  ASSERT_NE(moved, nullptr);
  if (auto* movedFault = dynamic_cast<ServiceFault*>(moved.get()))
    ADD_FAILURE() << "refused: " << ua::describe(movedFault->response_header().service_result());
  auto* movedResponse = dynamic_cast<ActivateSessionResponse*>(moved.get());
  ASSERT_NE(movedResponse, nullptr) << "control: a move keeping the policy and mode must succeed";
  EXPECT_TRUE(movedResponse->response_header().service_result().is_good());
  EXPECT_FALSE(onOriginalChannel()) << "control: the Session did not take the new channel";
}

// As above with the Session's channel already gone: the Session holds no channel, so the policy and mode of
// the channel it was created on decide (CreateSession records them; ClientSignatureVerificationTests.
// CreateSessionRecordsTheSecurityOfItsChannel). Moves to an ECC_nistP384 channel and to an ECC_nistP256 Sign
// channel are refused and leave it without a channel; the control moves it to an ECC_nistP256
// SignAndEncrypt channel. The refusal comes before the token is read, so no new key is issued (guess G-39).
// @relation(AC-SVR-SCE-012-POLICY-OR-MODE-CHANGE-REFUSED, scope=function)
TEST(ServerActivateNewChannel, AMoveToAnotherPolicyOrModeIsRefusedAfterTheOldChannelIsGone)
{
  RefusedActivationHarness h;
  h.start(true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  ActivateSessionRequest firstRequest;
  h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, firstRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(2, std::move(firstRequest), {});
  auto first = h.wait_for_answer(2);
  auto* firstResponse = dynamic_cast<ActivateSessionResponse*>(first.get());
  ASSERT_NE(firstResponse, nullptr) << "the first activation must succeed for the moves to be tested";
  const auto* activatedKey = find_ecdh_key(firstResponse->response_header());
  ASSERT_NE(activatedKey, nullptr);
  const ByteString keyInUse = activatedKey->public_key();
  // Every later request is bound to the nonce this response issued.
  h.serverNonce = firstResponse->server_nonce();
  // The old channel is gone: the Session no longer holds one.
  SessionTestAccess::on_strand(*h.session, [](auto& g) { g.secure_channel_info().reset(); });
  const auto hasChannel = [&]
  {
    return SessionTestAccess::on_strand(
      *h.session, [](auto& g) { return g.secure_channel_info().has_value(); });
  };

  ActivateSessionRequest otherPolicy;
  h.make_request(43, acceptedPassword, keyInUse, otherPolicy);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(3,
    std::move(otherPolicy),
    h.open_second_ecc_channel(SecurityPolicy::create(SecurityPolicyId::EccNistP384AesGcm)));
  expect_refused_before_the_token(h, 3, Status::BadSecurityPolicyRejected, keyInUse, "another policy");
  EXPECT_FALSE(hasChannel()) << "the refused move gave the Session a channel";

  ActivateSessionRequest otherMode;
  h.make_request(44, acceptedPassword, keyInUse, otherMode);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(4, std::move(otherMode), h.open_second_ecc_channel(nullptr, MessageSecurityMode::Sign));
  expect_refused_before_the_token(h, 4, Status::BadSecurityPolicyRejected, keyInUse, "another mode");
  EXPECT_FALSE(hasChannel()) << "the refused move gave the Session a channel";

  // Control: the policy and mode the Session was created with move it.
  ActivateSessionRequest sameSecurity;
  h.make_request(45, acceptedPassword, keyInUse, sameSecurity);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(5, std::move(sameSecurity), h.open_second_ecc_channel());
  auto moved = h.wait_for_answer(5);
  ASSERT_NE(moved, nullptr);
  if (auto* movedFault = dynamic_cast<ServiceFault*>(moved.get()))
    ADD_FAILURE() << "refused: " << ua::describe(movedFault->response_header().service_result());
  auto* movedResponse = dynamic_cast<ActivateSessionResponse*>(moved.get());
  ASSERT_NE(movedResponse, nullptr) << "control: a move keeping the policy and mode must succeed";
  EXPECT_TRUE(movedResponse->response_header().service_result().is_good());
  EXPECT_TRUE(hasChannel()) << "control: the Session did not take the new channel";
}

// OPC 10000-4 5.7.3.1: "If an Anonymous UserIdentityToken is used, then ActivateSession over a new
// SecureChannel shall fail if the SecureChannel is using Sign". An Anonymous Session on an ECC_nistP256 Sign
// channel moved Anonymously to a new Sign channel is refused with Bad_IdentityTokenRejected, keeps its key
// and stays where it is; the control is the same Anonymous move between SignAndEncrypt channels. The identity
// never changes, so the refusal is the Anonymous rule's alone.
// @relation(AC-SVR-SCE-012-ANONYMOUS-OVER-SIGN-REFUSED, scope=function)
TEST(ServerActivateNewChannel, AnAnonymousMoveOverSignIsRefused)
{
  for (const auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
  {
    const bool sign = mode == MessageSecurityMode::Sign;
    SCOPED_TRACE(sign ? "Sign" : "control: SignAndEncrypt");
    RefusedActivationHarness h;
    h.offerAnonymous = true;
    h.authenticator->acceptAnonymous = true;
    h.eccChannelMode = mode;
    h.start(true);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());

    ActivateSessionRequest firstRequest;
    h.make_anonymous_request(42, firstRequest);
    h.session->activate(2, std::move(firstRequest), {});
    auto first = h.wait_for_answer(2);
    auto* firstResponse = dynamic_cast<ActivateSessionResponse*>(first.get());
    if (const auto* firstFault = dynamic_cast<ServiceFault*>(first.get()))
      ADD_FAILURE() << "refused: " << ua::describe(firstFault->response_header().service_result());
    ASSERT_NE(firstResponse, nullptr) << "the Anonymous activation must succeed for the move to be tested";
    // Every later request is bound to the nonce this response issued.
    h.serverNonce = firstResponse->server_nonce();
    const ByteString keyInUse = SessionTestAccess::on_strand(
      *h.session, [](auto& g) -> ByteString { return g.ecc_ephemeral_public_key(); });

    ActivateSessionRequest anonymous;
    h.make_anonymous_request(43, anonymous);
    h.session->activate(3, std::move(anonymous), h.open_second_ecc_channel());
    if (sign)
    {
      expect_refused_before_the_token(
        h, 3, Status::BadIdentityTokenRejected, keyInUse, "Anonymous over Sign");
      EXPECT_TRUE(SessionTestAccess::on_strand(*h.session,
        [&](auto& g)
        {
          return g.secure_channel_info().has_value() &&
                 g.secure_channel_info()->secure_channel().lock().get() == h.sc.get();
        }))
        << "the refused move took the Session off its channel";
      continue;
    }
    auto moved = h.wait_for_answer(3);
    ASSERT_NE(moved, nullptr);
    if (auto* movedFault = dynamic_cast<ServiceFault*>(moved.get()))
      ADD_FAILURE() << "refused: " << ua::describe(movedFault->response_header().service_result());
    auto* movedResponse = dynamic_cast<ActivateSessionResponse*>(moved.get());
    ASSERT_NE(movedResponse, nullptr)
      << "control: an Anonymous move between SignAndEncrypt channels must succeed";
    EXPECT_TRUE(movedResponse->response_header().service_result().is_good());
  }
}

// A refusal whose new key cannot be signed (no server key for the channel policy) must not replace the
// stored key: it goes without a key, so the client still holds the previous one, and the server must still
// be able to decrypt a token encrypted against it. The retry, with the server key back, activates.
// @verifies AC-SVR-SESS-ECC-FRESH-KEY-ON-FAILED-ACTIVATE
TEST(ServerActivateEccEphemeralKey, RefusalThatCannotSignANewKeyLeavesThePreviousKeyInPlace)
{
  RefusedActivationHarness h;
  h.start(true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  std::vector<CertificateStore::ApplicationCertificate> serverCertificates;
  SessionTestAccess::on_strand(*h.session,
    [&](auto& g)
    {
      serverCertificates = g.server_certificates();
      g.server_certificates().clear();
    });

  ActivateSessionRequest refusedRequest;
  h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, refusedRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  name_no_token_policy(refusedRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(2, std::move(refusedRequest), {});

  auto refusal = h.wait_for_answer(2);
  ASSERT_NE(refusal, nullptr) << "the refused ActivateSession was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(refusal.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_TRUE(fault->response_header().service_result() == Status::BadIdentityTokenInvalid)
    << "got: " << to_string(fault->response_header().service_result().as_status());
  EXPECT_EQ(fault->response_header().additional_header().get(), nullptr)
    << "a refusal that cannot sign a new key must not carry one";
  EXPECT_EQ(SessionTestAccess::on_strand(
              *h.session, [](auto& g) -> ByteString { return g.ecc_ephemeral_public_key(); }),
    h.issuedEphemeralPublicKey)
    << "the stored key was replaced by one the client was never given";

  SessionTestAccess::on_strand(*h.session, [&](auto& g) { g.server_certificates() = serverCertificates; });
  ActivateSessionRequest retry;
  h.make_request(43, acceptedPassword, h.issuedEphemeralPublicKey, retry);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(3, std::move(retry), {});
  auto answer = h.wait_for_answer(3);
  ASSERT_NE(answer, nullptr) << "the retry was never answered";
  if (auto* retryFault = dynamic_cast<ServiceFault*>(answer.get()))
  {
    FAIL() << "the retry encrypted against the previous key was refused: "
           << to_string(retryFault->response_header().service_result().as_status());
  }
  auto* response = dynamic_cast<ActivateSessionResponse*>(answer.get());
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
}

// The new pair is generated before it is signed, so a signature that fails AFTER generation must put the
// previous pair back: the fault goes without a key, the client still holds the previous one, and a retry
// encrypted against it activates. The parked crypto generates the new pair and then fails its signature.
// @verifies AC-SVR-SESS-ECC-FRESH-KEY-ON-FAILED-ACTIVATE
TEST(ServerActivateEccEphemeralKey, RefusalWhoseNewKeyCannotBeSignedPutsThePreviousKeyBack)
{
  RefusedActivationHarness h;
  h.start(true, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  const auto* eccPolicy = dynamic_cast<const SecPolEphemeralKey*>(h.eccSecurityPolicy.get());
  ASSERT_NE(eccPolicy, nullptr);

  ActivateSessionRequest refusedRequest;
  h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, refusedRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  name_no_token_policy(refusedRequest);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.fakeCrypto->set_park_async(true);
  h.session->activate(2, std::move(refusedRequest), {});

  // Releases whatever the request parks before its refusal (the client signature check) until the
  // refusal asks for a new pair, then answers that with a real one.
  bool generationParked = false;
  for (int attempt = 0; attempt < 500 && !generationParked; ++attempt)
  {
    while (h.fakeCrypto->pending_asymmetric_verify_count() > 0)
    {
      h.fakeCrypto->complete_pending_asymmetric_verify(0, ua::VoidResult{});
    }
    generationParked = h.fakeCrypto->pending_create_ephemeral_keys_count() > 0;
    if (!generationParked)
    {
      std::this_thread::sleep_for(10ms);
    }
  }
  ASSERT_TRUE(generationParked) << "the refusal never asked for a new ephemeral key pair";
  h.fakeCrypto->complete_pending_create_ephemeral_keys(0,
    Crypto::EphemeralKeyPairResult{
      h.crypto->create_ephemeral_keys_sync(eccPolicy->ephemeral_key_algorithm())});

  bool signParked = false;
  for (int attempt = 0; attempt < 500 && !signParked; ++attempt)
  {
    signParked = h.fakeCrypto->pending_asymmetric_sign_count() > 0;
    if (!signParked)
    {
      std::this_thread::sleep_for(10ms);
    }
  }
  ASSERT_TRUE(signParked) << "the refusal never asked for its new key to be signed";
  h.fakeCrypto->set_park_async(false);
  h.fakeCrypto->complete_pending_asymmetric_sign(
    0, ua::ByteStringResult{StatusCode{Status::BadSecurityChecksFailed}});

  auto refusal = h.wait_for_answer(2);
  ASSERT_NE(refusal, nullptr) << "a refusal whose new key could not be signed was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(refusal.get());
  ASSERT_NE(fault, nullptr);
  EXPECT_TRUE(fault->response_header().service_result() == Status::BadIdentityTokenInvalid)
    << "got: " << to_string(fault->response_header().service_result().as_status());
  EXPECT_EQ(fault->response_header().additional_header().get(), nullptr)
    << "a refusal whose new key could not be signed must not carry one";
  EXPECT_EQ(SessionTestAccess::on_strand(
              *h.session, [](auto& g) -> ByteString { return g.ecc_ephemeral_public_key(); }),
    h.issuedEphemeralPublicKey)
    << "the stored key was replaced by one the client was never given";

  ActivateSessionRequest retry;
  h.make_request(43, acceptedPassword, h.issuedEphemeralPublicKey, retry);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(3, std::move(retry), {});
  auto answer = h.wait_for_answer(3);
  ASSERT_NE(answer, nullptr) << "the retry was never answered";
  if (auto* retryFault = dynamic_cast<ServiceFault*>(answer.get()))
  {
    FAIL() << "the retry encrypted against the previous key was refused: "
           << to_string(retryFault->response_header().service_result().as_status());
  }
  auto* response = dynamic_cast<ActivateSessionResponse*>(answer.get());
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
}

// An ActivateSession that is accepted but whose new EphemeralKey cannot be signed fails: it is answered
// with a fault that carries the signing failure and no key. Nothing is put back - the previous private key
// was consumed decrypting this activation's token (single-use, OPC 10000-6 6.8.3). The crypto is real
// throughout; only the signature of the new key is made to fail.
// @verifies AC-SVR-SESS-ECC-ACTIVATE-SIGNING-FAILURE-FAILS-WITHOUT-A-KEY
// @relation(AC-SVR-SESS-ECC-ACTIVATE-SIGNING-FAILURE-FAILS-WITHOUT-A-KEY, scope=function)
TEST(ServerActivateEccEphemeralKey, AcceptedActivationWhoseNewKeyCannotBeSignedFailsWithoutAKey)
{
  RefusedActivationHarness h;
  h.start(true, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  ActivateSessionRequest request;
  h.make_request(52, acceptedPassword, h.issuedEphemeralPublicKey, request);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.fakeCrypto->set_asymmetric_sign_failure(StatusCode{Status::BadSecurityChecksFailed});
  h.session->activate(2, std::move(request), {});

  auto failed = h.wait_for_answer(2);
  ASSERT_NE(failed, nullptr) << "an activation whose new key could not be signed was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(failed.get());
  ASSERT_NE(fault, nullptr) << "an activation whose new key could not be signed must fail";
  EXPECT_TRUE(fault->response_header().service_result() == Status::BadSecurityChecksFailed)
    << "got: " << to_string(fault->response_header().service_result().as_status());
  EXPECT_EQ(find_ecdh_key(fault->response_header()), nullptr)
    << "a fault whose key could not be signed must not carry one";
  EXPECT_TRUE(SessionTestAccess::on_strand(*h.session,
    [](auto& g) -> ByteString {
      return g.ecc_ephemeral_public_key();
    }).empty())
    << "the consumed key is gone, and the unsigned new one must not take its place";
}

// The same signing failure on an activation whose token was NOT ECC-encrypted (Anonymous) leaves the
// previous EphemeralKey unconsumed, so it is put back: the fault carries no key, the stored key is the one
// the client holds, and a retry with a UserName token encrypted against it (bound to the nonce the failed
// attempt issued) activates.
// @verifies AC-SVR-SESS-ECC-ACTIVATE-SIGNING-FAILURE-FAILS-WITHOUT-A-KEY
// @relation(AC-SVR-SESS-ECC-ACTIVATE-SIGNING-FAILURE-FAILS-WITHOUT-A-KEY, scope=function)
TEST(ServerActivateEccEphemeralKey, UnencryptedActivationWhoseNewKeyCannotBeSignedKeepsThePreviousKey)
{
  RefusedActivationHarness h;
  h.offerAnonymous = true;
  h.authenticator->acceptAnonymous = true;
  h.start(true, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());

  ActivateSessionRequest request;
  h.make_anonymous_request(62, request);
  h.fakeCrypto->set_asymmetric_sign_failure(StatusCode{Status::BadSecurityChecksFailed});
  h.session->activate(2, std::move(request), {});

  auto failed = h.wait_for_answer(2);
  ASSERT_NE(failed, nullptr) << "an activation whose new key could not be signed was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(failed.get());
  ASSERT_NE(fault, nullptr) << "an activation whose new key could not be signed must fail";
  EXPECT_TRUE(fault->response_header().service_result() == Status::BadSecurityChecksFailed)
    << "got: " << to_string(fault->response_header().service_result().as_status());
  EXPECT_EQ(find_ecdh_key(fault->response_header()), nullptr);
  EXPECT_EQ(SessionTestAccess::on_strand(
              *h.session, [](auto& g) -> ByteString { return g.ecc_ephemeral_public_key(); }),
    h.issuedEphemeralPublicKey)
    << "the unconsumed key the client holds was not put back";

  h.fakeCrypto->set_asymmetric_sign_failure(StatusCode{Status::Good});
  h.serverNonce =
    SessionTestAccess::on_strand(*h.session, [](auto& g) -> ByteString { return g.server_nonce(); });
  ActivateSessionRequest retry;
  h.make_request(63, acceptedPassword, h.issuedEphemeralPublicKey, retry);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.session->activate(3, std::move(retry), {});
  auto answer = h.wait_for_answer(3);
  ASSERT_NE(answer, nullptr) << "the retry was never answered";
  if (auto* retryFault = dynamic_cast<ServiceFault*>(answer.get()))
  {
    FAIL() << "the retry encrypted against the previous key was refused: "
           << to_string(retryFault->response_header().service_result().as_status());
  }
  auto* response = dynamic_cast<ActivateSessionResponse*>(answer.get());
  ASSERT_NE(response, nullptr);
  EXPECT_TRUE(response->response_header().service_result().is_good());
}

// ===================================================================
// A crypto answer the ActivateSession response is built from is used only when it is Good
// ===================================================================

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

/// Waits until the parked crypto holds an asymmetric_sign_async call.
bool wait_for_parked_signature(ua::test_helpers::FakeAsyncCrypto& crypto)
{
  for (int attempt = 0; attempt < 500; ++attempt)
  {
    if (crypto.pending_asymmetric_sign_count() > 0)
      return true;
    std::this_thread::sleep_for(10ms);
  }
  return false;
}

/// Checks that @p answer is the ServiceFault of an activation refused because a crypto answer was Uncertain:
/// Bad_InternalError, the CryptoAnswerUncertain refusal in its detail chain carrying the provider's code, and
/// no EphemeralKey in its header.
void expect_uncertain_crypto_refusal(const shared_ptr<Structure>& answer, std::string_view stepCode)
{
  ASSERT_NE(answer, nullptr) << "the activation was never answered";
  auto* fault = dynamic_cast<ServiceFault*>(answer.get());
  ASSERT_NE(fault, nullptr) << "the activation must be answered with a ServiceFault";
  const auto status = fault->response_header().service_result();
  EXPECT_EQ(status.as_status(), Status::BadInternalError) << to_string(status);
  EXPECT_NE(find_in_cause_chain(status.shared_detail(), stepCode), nullptr)
    << "the fault does not name the step: " << to_string(status);
  const auto* refusal = find_in_cause_chain(status.shared_detail(), "CryptoAnswerUncertain");
  ASSERT_NE(refusal, nullptr) << "the fault does not carry the refusal of the Uncertain answer";
  EXPECT_EQ(refusal->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value())
    << "the refusal does not carry the provider's Uncertain code";
  EXPECT_EQ(find_ecdh_key(fault->response_header()), nullptr) << "the fault must not carry an EphemeralKey";
}

// The server nonce of the ActivateSession response is taken only from a Good entropy answer. An Uncertain one
// is refused: the client is answered with a ServiceFault of Bad_InternalError (EntropyFailed, whose cause is
// the CryptoAnswerUncertain refusal carrying the provider's code), and the Session is not activated. Passed
// on as the failure, the Uncertain code was not answered at all: the response's completion sends a fault only
// for a Bad code.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServerActivateCryptoAnswer, AnUncertainServerNonceAnswerIsRefusedWithAFault)
{
  RefusedActivationHarness h;
  h.start(true, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  ActivateSessionRequest request;
  h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, request);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.authenticator->set_before_acceptance([fake = h.fakeCrypto] { fake->set_park_async(true); });
  h.session->activate(2, std::move(request), {});

  ASSERT_TRUE(h.wait_for_parked_entropy()) << "the response build never asked for its server nonce";
  h.fakeCrypto->set_park_async(false);
  h.fakeCrypto->complete_pending_get_entropy(
    0, ByteStringResult{StatusCode{Status::UncertainLastUsableValue}});

  expect_uncertain_crypto_refusal(h.wait_for_answer(2), "EntropyFailed");
  EXPECT_FALSE(h.session->is_activated());
}

// The new EphemeralKey of an ActivateSession response is stored and sent only when the provider answered its
// generation Good. An Uncertain answer is refused: the client is answered with a ServiceFault of
// Bad_InternalError (EphemeralKeyGenerationFailed, caused by the CryptoAnswerUncertain refusal) carrying no
// key, and the Session is not activated. Taken for a success, the step signed the key the Session held, which
// the response build had just cleared, and sent it as the new EphemeralKey.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServerActivateCryptoAnswer, AnUncertainEphemeralKeyAnswerIsRefusedWithAFaultCarryingNoKey)
{
  RefusedActivationHarness h;
  h.start(true, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  ActivateSessionRequest request;
  h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, request);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.authenticator->set_before_acceptance([fake = h.fakeCrypto] { fake->set_park_async(true); });
  h.session->activate(2, std::move(request), {});

  ASSERT_TRUE(h.wait_for_parked_entropy()) << "the response build never asked for its server nonce";
  h.fakeCrypto->complete_pending_get_entropy(0, ByteStringResult{h.crypto->get_entropy_sync(32)});
  ASSERT_TRUE(h.wait_for_parked_ephemeral_key_generation()) << "the response build never asked for a new key";
  h.fakeCrypto->set_park_async(false);
  h.fakeCrypto->complete_pending_create_ephemeral_keys(
    0, Crypto::EphemeralKeyPairResult{StatusCode{Status::UncertainLastUsableValue}});

  expect_uncertain_crypto_refusal(h.wait_for_answer(2), "EphemeralKeyGenerationFailed");
  EXPECT_FALSE(h.session->is_activated());
}

// The new EphemeralKey is sent only with a signature the provider answered Good. An Uncertain signature
// answer is refused: the client is answered with a ServiceFault of Bad_InternalError
// (EphemeralKeySigningFailed, caused by the CryptoAnswerUncertain refusal) carrying no key, and the Session
// is not activated. Passed on as the failure, the Uncertain code was not answered at all.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServerActivateCryptoAnswer, AnUncertainSignatureOfTheNewKeyIsRefusedWithAFaultCarryingNoKey)
{
  RefusedActivationHarness h;
  h.start(true, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  const auto* eccPolicy = dynamic_cast<const SecPolEphemeralKey*>(h.eccSecurityPolicy.get());
  ASSERT_NE(eccPolicy, nullptr);
  ActivateSessionRequest request;
  h.make_request(42, acceptedPassword, h.issuedEphemeralPublicKey, request);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  h.authenticator->set_before_acceptance([fake = h.fakeCrypto] { fake->set_park_async(true); });
  h.session->activate(2, std::move(request), {});

  ASSERT_TRUE(h.wait_for_parked_entropy()) << "the response build never asked for its server nonce";
  h.fakeCrypto->complete_pending_get_entropy(0, ByteStringResult{h.crypto->get_entropy_sync(32)});
  ASSERT_TRUE(h.wait_for_parked_ephemeral_key_generation()) << "the response build never asked for a new key";
  h.fakeCrypto->complete_pending_create_ephemeral_keys(0,
    Crypto::EphemeralKeyPairResult{
      h.crypto->create_ephemeral_keys_sync(eccPolicy->ephemeral_key_algorithm())});
  ASSERT_TRUE(wait_for_parked_signature(*h.fakeCrypto)) << "the response build never signed its new key";
  h.fakeCrypto->set_park_async(false);
  h.fakeCrypto->complete_pending_asymmetric_sign(
    0, ByteStringResult{StatusCode{Status::UncertainLastUsableValue}});

  expect_uncertain_crypto_refusal(h.wait_for_answer(2), "EphemeralKeySigningFailed");
  EXPECT_FALSE(h.session->is_activated());
}

}  // namespace
