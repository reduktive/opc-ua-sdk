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
#include "ua_security_policy_compatibility.h"
#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_create_session_request.h"

#include "ua_anonymous_identity_token.h"
#include "ua_user_name_identity_token.h"
#include "ua_crypto.h"

#include "ua_sec_pol_basic256_sha256.h"
#include "ua_sec_pol_none.h"

#include "ua_user_token_encryption.h"
#include "ua_certificate_store.h"
#include "ua_stack_utilities.h"
#include "ua_to_string.h"
#include "ua_user_token_policy.h"
#include "ua_user_token_type.h"
#include "run_async_sync.h"
#include "test_pki_helpers.h"

// Test-only access to the client token builder (the client's policy-driven encrypt/sign decision).
#include "../sdk/implementation/client/session/ua_client_token_builder.h"

// Client SessionImpl end-to-end driving for the X509 activate branch (start_x509_user_token_signature).
#include "client_session_capture_harness.h"
#include "ua_client_session.h"
#include "ua_create_session_response.h"
#include "ua_endpoint_description.h"
#include "ua_x509_certificate.h"

#include "ua_server_components.h"

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <future>
#include <iterator>
#include <mutex>
#include <string>
#include <string_view>
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
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// ---------------------------------------------------------------------------
// Shared helpers (same as server test)
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

/// The raw bytes of @p text, taken verbatim (no re-encoding). Used to assert that the client keeps a
/// password's byte sequence as-is (a UTF-8 std::string stays UTF-8; it is not widened to UTF-16 or
/// narrowed to Latin-1 before the token is built/encrypted).
ByteString exact_bytes(std::string_view text)
{
  ByteString result;
  result.assign(reinterpret_cast<const uint8_t*>(text.data()),
    reinterpret_cast<const uint8_t*>(text.data()) + text.size());
  return result;
}

// ---------------------------------------------------------------------------
// Server-side RSA material + decrypt oracle (shared by the UNP encryption tests)
// ---------------------------------------------------------------------------

/// A 2048-bit RSA key pair and a matching self-signed certificate for the test "server".
struct ServerRsaMaterial
{
  std::shared_ptr<const AsymmetricKeyPair> keyPair;
  std::shared_ptr<const X509Certificate> cert;
};

/// A self-signed RSA certificate over @p keys suitable for Basic256Sha256 (digital-signature +
/// key-encipherment key usage), mirroring the certificate the round-trip tests build inline.
std::shared_ptr<const X509Certificate> make_self_signed_rsa_cert(const std::shared_ptr<const Crypto>& crypto,
  const std::shared_ptr<const AsymmetricKeyPair>& keys, std::string_view commonName, std::string_view serial)
{
  TestPki pki{crypto};
  Crypto::CreateCertificateConfig certParams;
  certParams.subjectKeys = keys;
  certParams.issuerKeys = keys;
  certParams.subject.commonName = std::string{commonName};
  certParams.serialNumber = std::string{serial};
  certParams.basicConstraint.cA = false;
  certParams.keyUsage.digitalSignature = true;
  certParams.keyUsage.keyEncipherment = true;
  certParams.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  // The certificate names the host the harness's endpoint serves: once the endpoint matches the
  // channel, the CreateSession certificate is checked against its HostName (Part 4 section 5.4.1).
  certParams.subjectAlternateName.hostnames.emplace_back("localhost");
  certParams.from = DateTime::now();
  certParams.to = DateTime{certParams.from.value() + std::chrono::days{365}};
  return pki.create_cert(certParams);
}

ServerRsaMaterial make_server_rsa_material(const std::shared_ptr<const Crypto>& crypto)
{
  auto keyPair = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  return ServerRsaMaterial{keyPair, make_self_signed_rsa_cert(crypto, keyPair, "TestServer", "1")};
}

/// Outcome of feeding a client-encrypted UserName token through a real server Session.
struct ServerDecryptOutcome
{
  bool responseGood{false};
  bool authenticatorCalled{false};
  std::string recoveredUserName;
  std::string recoveredPassword;
};

// ---------------------------------------------------------------------------
// RecordingTokenAuthenticator - captures AuthnRequest fields and approves.
// ---------------------------------------------------------------------------

class ClientTestRecordingAuthenticator final : public UserAuthenticator
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
// CryptoSessionDeps
// ---------------------------------------------------------------------------

class ClientTestSessionDeps final : public SessionDependencies
{
public:
  ClientTestSessionDeps(
    boost::asio::any_io_executor ex, ServerComponents hooks, shared_ptr<const Crypto> crypto)
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mCrypto(std::move(crypto))
  {
    // The deadline bounds the server's token decrypt and the authenticator together. Every activation
    // these deps back succeeds, and a success is answered as soon as it is known, so a long deadline
    // costs nothing on a pass; 50 ms was exceeded on a contended 32-bit debug build, where the server
    // then answered BadIdentityTokenInvalid.
    mServerCfg.authnTimeout = 10s;
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
    return nullptr;
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
};

// ---------------------------------------------------------------------------
// DummySecureChannelDeps
// ---------------------------------------------------------------------------

class ClientTestScDeps : public SecureChannelDependencies
{
public:
  explicit ClientTestScDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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

// ---------------------------------------------------------------------------
// Server-side decrypt oracle: drive an already-client-encrypted UserName token through a real server
// Session that holds the private key matching @p serverCert and advertises a UserName UserTokenPolicy
// for Basic256Sha256. The server session's parse_identity_token decrypt is the ORACLE - it recovers
// the exact plaintext the client encrypted (the token is ciphertext the server must be able to
// decrypt with its private key, not merely "different bytes"). This is the same harness the
// RsaBasic256Sha256RoundTrip test uses inline, factored out for reuse.
// ---------------------------------------------------------------------------
ServerDecryptOutcome run_server_username_decrypt(const std::shared_ptr<const Crypto>& crypto,
  const std::shared_ptr<UserNameIdentityToken>& encryptedToken, const ByteString& serverNonce,
  const std::shared_ptr<const X509Certificate>& serverCert,
  const std::shared_ptr<const AsymmetricKeyPair>& serverKeyPair)
{
  ServerDecryptOutcome outcome;

  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto authenticator = std::make_shared<ClientTestRecordingAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<ClientTestSessionDeps>(ex, hooks, crypto);
  auto scDeps = std::make_shared<ClientTestScDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;
  SecureChannelTestAccess::on_strand(*sc,
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
    SecureChannelTestAccess::on_strand(*sc, [](auto& g) { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);
  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.server_nonce() = serverNonce;
      g.server_certificates().push_back(CertificateStore::ApplicationCertificate{
        CertificateType::RsaSha256Application, serverCert, serverKeyPair});
      g.selected_cert_and_key() = g.server_certificates().back();
    });

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  auto activateToken = std::make_unique<UserNameIdentityToken>(*encryptedToken);
  activateToken->policy_id() =
    SecureChannelTestAccess::on_strand(*sc, [](auto& g) { return g.user_identity_tokens(); })
      .front()
      .policy_id();
  asr.user_identity_token() = std::move(activateToken);
  session->activate(2, std::move(asr), {});

  {
    // Longer than the authentication deadline, so whichever answer the server gives arrives first.
    std::unique_lock<std::mutex> lk(mx);
    cv.wait_for(lk, 20s, [&]() { return last.has_value(); });
  }
  if (last.has_value())
  {
    if (auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get()))
    {
      outcome.responseGood = resp->response_header().service_result().is_good();
    }
  }
  outcome.authenticatorCalled = authenticator->called();
  outcome.recoveredUserName = authenticator->user_name();
  outcome.recoveredPassword = authenticator->password();

  session.reset();
  sc.reset();
  sessDeps.reset();
  scDeps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
  return outcome;
}

// ---------------------------------------------------------------------------
// Crypto-enabled client harness for the X509 activate flow (CL-IDENT-011)
// ---------------------------------------------------------------------------

/// The stock null-connection client @ref ua::client::test_capture::FakeSessionDeps returns a null
/// crypto, which would make the X509 signing branch skip. This subclass supplies a real crypto so
/// @ref ua::client::SessionImpl::start_x509_user_token_signature actually signs.
class CryptoClientSessionDeps final : public ua::client::test_capture::FakeSessionDeps
{
public:
  CryptoClientSessionDeps(boost::asio::any_io_executor ex, std::shared_ptr<const ua::Crypto> crypto)
    : ua::client::test_capture::FakeSessionDeps(ex), mCrypto(std::move(crypto))
  {}

  std::shared_ptr<const ua::Crypto> crypto() override
  {
    return mCrypto;
  }

private:
  std::shared_ptr<const ua::Crypto> mCrypto;
};

/// A null-connection client SecureChannel + SessionImpl with real crypto in its deps, driven through
/// the real CreateSession handshake and capturing every outgoing service request. Mirrors the
/// capture harness but injects crypto so the ActivateSession signing branches run for real.
struct CryptoClientHarness
{
  using SCTA = ua::client::SecureChannelTestAccess;
  using STA = ua::client::SessionTestAccess;

  std::shared_ptr<CryptoClientSessionDeps> sessionDeps;
  std::shared_ptr<ua::client::test_capture::FakeChannelDeps> channelDeps;
  std::shared_ptr<ua::client::SecureChannelImpl> channel;
  std::shared_ptr<ua::client::SessionImpl> session;
  std::shared_ptr<std::vector<std::unique_ptr<ua::Structure>>> capturedRequests;

  static CryptoClientHarness create(boost::asio::any_io_executor ex, std::shared_ptr<const ua::Crypto> crypto)
  {
    CryptoClientHarness harness;
    harness.channelDeps = std::make_shared<ua::client::test_capture::FakeChannelDeps>(ex);
    harness.channel = ua::client::SecureChannelImpl::create(
      harness.channelDeps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      ua::client::SecureChannelImpl::Config{},
      [](ua::VoidResult) {},
      [](ua::VoidResult) {});
    SCTA::on_strand(*harness.channel,
      [](auto& g) { g.channel_state() = ua::client::SecureChannelImpl::ChannelState::Open; });

    harness.capturedRequests = std::make_shared<std::vector<std::unique_ptr<ua::Structure>>>();
    auto captured = harness.capturedRequests;
    SCTA::on_strand(*harness.channel,
      [captured](auto& g)
      {
        g.outgoing_request_observer() = [captured](const ua::Structure& request)
        {
          captured->push_back(request.clone());
        };
      });

    harness.sessionDeps = std::make_shared<CryptoClientSessionDeps>(ex, std::move(crypto));
    harness.session = ua::client::SessionImpl::create(
      harness.sessionDeps,
      harness.channel,
      ua::client::SessionImpl::Config{},
      // A real None channel carries the None SecurityPolicy: the endpoints the harness's responses
      // advertise (mode None, policy None) then match the channel, as the client requires since the
      // user-token policies are taken from the matching endpoint only.
      ua::client::SessionImpl::SecurityInfo{.securityPolicy = SecurityPolicy::create(SecurityPolicyId::None)},
      [](ua::VoidResult) {},
      [](ua::VoidResult) {});
    return harness;
  }

  bool wait_for_pending()
  {
    return ua::client::test_capture::wait_until(
      [this]() { return SCTA::on_strand(*channel, [](auto& g) { return !g.pending_requests().empty(); }); });
  }

  bool inject(std::shared_ptr<ua::Structure> response)
  {
    return SCTA::on_strand(*channel,
      [resp = std::move(response)](auto& g) mutable
      {
        auto& pending = g.pending_requests();
        if (pending.empty())
        {
          return false;
        }
        auto it = pending.begin();
        auto callback = std::move(it->second);
        pending.erase(it);
        callback(ua::client::SecureChannelImpl::ServiceResponseResult{std::move(resp)});
        return true;
      });
  }

  template<typename ReqT>
  std::optional<ReqT> first_captured()
  {
    return SCTA::on_strand(*channel,
      [this](auto&) -> std::optional<ReqT>
      {
        for (const auto& req : *capturedRequests)
        {
          if (const auto* typed = dynamic_cast<const ReqT*>(req.get()))
          {
            return *typed;
          }
        }
        return std::nullopt;
      });
  }

  template<typename ReqT>
  bool wait_for_captured()
  {
    return ua::client::test_capture::wait_until([this]() { return first_captured<ReqT>().has_value(); });
  }

  void cleanup()
  {
    SCTA::on_strand(*channel,
      [](auto& g)
      {
        auto pending = std::move(g.pending_requests());
        g.pending_requests().clear();
        for (auto& [handle, callback] : pending)
        {
          callback(ua::client::SecureChannelImpl::ServiceResponseResult{ua::Status::BadConnectionClosed});
        }
      });
    STA::on_strand(*session, [](auto& g) { g.inject_channel_error(ua::Status::BadConnectionClosed); });
    STA::on_strand(*session, [](auto& g) { g.inject_channel_error(ua::Status::BadConnectionClosed); });
    STA::strand_barrier(*session);
  }

  void release()
  {
    session.reset();
    channel.reset();
    sessionDeps.reset();
    channelDeps.reset();
    capturedRequests.reset();
  }
};

// ===================================================================
// Client-side encryption round-trip tests.
// These verify that client-encrypted tokens can be decrypted by
// the server session's parse_identity_token, proving the client
// wiring produces correctly encrypted output.
// ===================================================================

// The round-trip only succeeds because the client encrypts the token with the SERVER's certificate
// public key (serverCert) whose matching private key (serverKeyPair) the server session holds: an
// encoder that ignored the supplied server cert could not be decrypted by the server. This pins
// CL-SESS-016 (user token encrypted with the server's public key); it does NOT verify CL-IDENT-006
// (validate+trust the server cert BEFORE encrypting), which needs a validator + rejection path this
// test does not exercise.
// @verifies CL-SESS-016
// @relation(CL-SESS-016, scope=function)
TEST(ClientActivateTokenEncryption, RsaBasic256Sha256RoundTrip)
{
  auto crypto = create_crypto();
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  // Generate server RSA key pair and certificate (2048-bit for Basic256Sha256).
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

  // Client encrypts the token (this is what the client session would do).
  auto tokenPtr = std::make_shared<UserNameIdentityToken>();
  constexpr string_view passwordText = "ClientRsaPassword!";
  ByteString originalPassword;
  originalPassword.assign(reinterpret_cast<const uint8_t*>(passwordText.data()),
    reinterpret_cast<const uint8_t*>(passwordText.data()) + passwordText.size());
  tokenPtr->password() = originalPassword;
  tokenPtr->user_name() = "clientuser";

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
  ASSERT_TRUE(encResult.is_good()) << "Encrypt failed";

  // Feed through server session to verify decryption.
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto authenticator = std::make_shared<ClientTestRecordingAuthenticator>();
  ServerComponents hooks;
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<ClientTestSessionDeps>(ex, hooks, crypto);

  auto scDeps = std::make_shared<ClientTestScDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {server::create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256)});
    });

  std::mutex mx;
  std::condition_variable cv;
  optional<Response> last;

  SecureChannelTestAccess::on_strand(*sc,
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
    SecureChannelTestAccess::on_strand(*sc, [](auto& g) { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});

  SessionTestAccess::strand_barrier(*session);

  SessionTestAccess::on_strand(*session,
    [&](auto& g)
    {
      g.server_nonce() = serverNonce;
      g.server_certificates().push_back(CertificateStore::ApplicationCertificate{
        CertificateType::RsaSha256Application, serverCert, serverKeyPair});
      g.selected_cert_and_key() = g.server_certificates().back();
    });

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 42;
  auto activateToken = std::make_unique<UserNameIdentityToken>(*tokenPtr);
  // Set policy_id to match the advertised UserName policy so it passes policy matching.
  activateToken->policy_id() =
    SecureChannelTestAccess::on_strand(*sc, [](auto& g) { return g.user_identity_tokens(); })
      .front()
      .policy_id();
  asr.user_identity_token() = std::move(activateToken);
  session->activate(2, std::move(asr), {});

  // Longer than the authentication deadline, so whichever answer the server gives arrives first.
  std::unique_lock<std::mutex> lk(mx);
  ASSERT_TRUE(cv.wait_for(lk, 20s, [&]() { return last.has_value(); }));

  auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get());
  ASSERT_NE(resp, nullptr) << "Expected ActivateSessionResponse";
  EXPECT_TRUE(resp->response_header().service_result().is_good());

  ASSERT_TRUE(authenticator->called());
  EXPECT_EQ(authenticator->kind(), UserTokenKind::UserName);
  EXPECT_EQ(authenticator->user_name(), "clientuser");
  EXPECT_EQ(authenticator->password(), "ClientRsaPassword!");
  session.reset();
  sc.reset();
  sessDeps.reset();
  scDeps.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-IDENT-003: the CLIENT's own policy-driven decision (build_user_token) must select an encryption
// policy when the endpoint's UserName UserTokenPolicy requires it, and feeding that resolved policy into
// the encrypt step must actually replace the plaintext password with ciphertext. Existing coverage either
// stopped at "a policy was selected" (password still plaintext at that stage) or drove the encoder with a
// hardcoded policy; this exercises the full client chain end-to-end: decide-to-encrypt -> encrypt.
// Falsifiable: a client that emitted the password in plaintext (skipped encryption) or resolved no policy
// fails a concrete assertion.
// @verifies CL-IDENT-003
// @relation(CL-IDENT-003, scope=function)
TEST(ClientActivateTokenEncryption, PolicyDrivenUsernameEncryptionProducesCiphertext)
{
  auto crypto = create_crypto();

  // Server RSA material for Basic256Sha256 encryption (2048-bit).
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

  // A None SecureChannel but a UserName UserTokenPolicy whose SecurityPolicyUri is Basic256Sha256: per
  // Part 4 Table 193 this REQUIRES the client to encrypt the password.
  ua::UserTokenPolicy policy;
  policy.policy_id() = "user-1";
  policy.token_type() = ua::UserTokenType::UserName;
  policy.security_policy_uri() = std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};

  const std::string plaintextPassword = "ClientRsaPassword!";
  auto prepared =
    ua::client::build_user_token(ua::client::UsernamePasswordIdentity{"clientuser", plaintextPassword},
      "user-1",
      {policy},
      SecurityPolicy::create(SecurityPolicyId::None),
      MessageSecurityMode::None);
  ASSERT_TRUE(prepared.is_good());
  ASSERT_NE(prepared.value().encryptionPolicy, nullptr)
    << "client must decide to encrypt when the token policy requires it";
  EXPECT_EQ(prepared.value().encryptionPolicy->id(), SecurityPolicyId::Basic256Sha256);

  // Take the built UserName token (plaintext at this stage) and encrypt with the client-resolved policy.
  std::unique_ptr<UserIdentityToken> wire = std::move(prepared.value().wireToken);
  auto* rawUnp = dynamic_cast<UserNameIdentityToken*>(wire.get());
  ASSERT_NE(rawUnp, nullptr);
  const ByteString plaintextBytes = rawUnp->password();
  ASSERT_FALSE(plaintextBytes.empty());
  wire.release();
  std::shared_ptr<UserNameIdentityToken> token(rawUnp);

  auto serverNonce = make_nonce(*crypto, 32);
  auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      ua::encrypt_user_token_async(prepared.value().encryptionPolicy,
        crypto,
        crypto_test_strand(),
        token,
        serverNonce,
        serverCert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(encResult.is_good()) << "Encrypt failed";

  EXPECT_NE(token->password(), plaintextBytes)
    << "the emitted password must be ciphertext, not the plaintext";
  EXPECT_FALSE(token->password().empty());
  // The token names the AsymmetricEncryptionAlgorithm (OPC 10000-4 Table 188), not the SecurityPolicy.
  EXPECT_EQ(std::string_view{token->encryption_algorithm()},
    ua::asymmetric_encryption_algorithm_uri(
      prepared.value().encryptionPolicy->asymmetric_encryption_algorithm()));
}

// CL-IDENT-003: "This token shall be encrypted by the Client if required by the SecurityPolicy of the
// UserTokenPolicy." (Part 4 section 7.41.4 line 10515). The client's own policy-driven decision
// (build_user_token) must select an encryption policy when the UserName UserTokenPolicy advertises a
// non-None SecurityPolicyUri, and the emitted password must be genuine CIPHERTEXT - proven by the
// server (holding the matching private key) DECRYPTING it back to the exact plaintext. Merely
// asserting "different bytes" cannot distinguish real encryption from corruption; the server-decrypt
// oracle can. Falsifiable: a client that emitted the password in plaintext (skipped encryption), or
// produced bytes the server cannot decrypt, fails the recovered-plaintext assertion.
// @verifies CL-IDENT-003
// @relation(CL-IDENT-003, scope=function)
TEST(ClientActivateTokenEncryption, PolicyDrivenUsernameEncryptionServerDecryptsToPlaintext)
{
  auto crypto = create_crypto();
  auto server = make_server_rsa_material(crypto);

  // None SecureChannel, but a UserName UserTokenPolicy whose SecurityPolicyUri is Basic256Sha256:
  // Part 4 Table 193 REQUIRES the client to encrypt the password.
  ua::UserTokenPolicy policy;
  policy.policy_id() = "user-1";
  policy.token_type() = ua::UserTokenType::UserName;
  policy.security_policy_uri() = std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};

  const std::string plaintextPassword = "ClientRsaPassword!";
  auto prepared =
    ua::client::build_user_token(ua::client::UsernamePasswordIdentity{"clientuser", plaintextPassword},
      "user-1",
      {policy},
      SecurityPolicy::create(SecurityPolicyId::None),
      MessageSecurityMode::None);
  ASSERT_TRUE(prepared.is_good());
  ASSERT_NE(prepared.value().encryptionPolicy, nullptr)
    << "client must decide to encrypt when the token policy requires it";

  auto* rawUnp = dynamic_cast<UserNameIdentityToken*>(prepared.value().wireToken.get());
  ASSERT_NE(rawUnp, nullptr);
  const ByteString plaintextBytes = rawUnp->password();
  ASSERT_FALSE(plaintextBytes.empty());
  std::unique_ptr<UserIdentityToken> wire = std::move(prepared.value().wireToken);
  wire.release();
  std::shared_ptr<UserNameIdentityToken> token(rawUnp);

  auto serverNonce = make_nonce(*crypto, 32);
  auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      ua::encrypt_user_token_async(prepared.value().encryptionPolicy,
        crypto,
        crypto_test_strand(),
        token,
        serverNonce,
        server.cert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(encResult.is_good()) << "Encrypt failed";

  EXPECT_NE(token->password(), plaintextBytes)
    << "the emitted password must be ciphertext, not the plaintext";

  // ORACLE: the server decrypts the ciphertext with its private key and recovers the exact plaintext.
  auto oracle = run_server_username_decrypt(crypto, token, serverNonce, server.cert, server.keyPair);
  EXPECT_TRUE(oracle.responseGood) << "server must accept the client-encrypted UserName token";
  ASSERT_TRUE(oracle.authenticatorCalled);
  EXPECT_EQ(oracle.recoveredUserName, "clientuser");
  EXPECT_EQ(oracle.recoveredPassword, plaintextPassword)
    << "server-side decrypt must recover the client's plaintext password from the ciphertext";
}

// CL-IDENT-004 (unencrypted case): "If the SecurityPolicy is None then the password only contains the
// UTF-8 encoded password." (Part 4 section 7.41.4 lines 10531-10532). A non-ASCII password (explicit UTF-8
// bytes, independent of source charset) placed via a None token policy over a confidential channel is
// emitted verbatim as its UTF-8 byte sequence - not widened to UTF-16 nor narrowed to Latin-1.
// Falsifiable: any re-encoding changes the byte sequence (and its length) and fails the assertion.
// @verifies CL-IDENT-004
// @relation(CL-IDENT-004, scope=function)
TEST(ClientActivateTokenEncryption, UsernamePasswordEncodedUtf8WhenUnencrypted)
{
  // "P" U+00E9(e-acute = C3 A9) "ss" U+2740(floral heart = E2 9D 80) "!" - a valid UTF-8 sequence.
  const std::string utf8Password = "P\xC3\xA9ss\xE2\x9D\x80!";
  const ByteString expectedUtf8 = exact_bytes(utf8Password);

  ua::UserTokenPolicy policy;
  policy.policy_id() = "user-none";
  policy.token_type() = ua::UserTokenType::UserName;
  policy.security_policy_uri() = std::string{SecurityPolicy::create(SecurityPolicyId::None)->uri()};

  // None token policy + SignAndEncrypt channel: the channel provides confidentiality, so the client
  // does NOT per-token-encrypt and the password stays as UTF-8 plaintext in the token. This unencrypted
  // configuration is a hard opt-in (CL-IDENT-009), so the identity sets allowUnencryptedPassword.
  ua::client::UsernamePasswordIdentity utf8Identity{"utf8user", utf8Password};
  utf8Identity.allowUnencryptedPassword = true;
  auto prepared = ua::client::build_user_token(utf8Identity,
    "user-none",
    {policy},
    SecurityPolicy::create(SecurityPolicyId::Basic256Sha256),
    MessageSecurityMode::SignAndEncrypt);
  ASSERT_TRUE(prepared.is_good());
  ASSERT_EQ(prepared.value().encryptionPolicy, nullptr)
    << "a None token policy over a confidential channel must not per-token-encrypt";

  auto* unp = dynamic_cast<UserNameIdentityToken*>(prepared.value().wireToken.get());
  ASSERT_NE(unp, nullptr);
  EXPECT_EQ(unp->password(), expectedUtf8)
    << "the unencrypted password must be the UTF-8 encoding of the input (not UTF-16 / Latin-1)";
  EXPECT_EQ(unp->password().size(), expectedUtf8.size())
    << "UTF-8 encoding must not widen the byte length (UTF-16 would)";
}

// CL-IDENT-004 (encrypted case): "If the token is to be encrypted the password shall be converted to a
// UTF-8 ByteString, encrypted and then serialized..." (Part 4 section 7.41.4 lines 10524-10527). The UTF-8
// conversion must PRECEDE encryption, so after the server decrypts the RSA ciphertext the recovered
// plaintext bytes are exactly the UTF-8 encoding - not UTF-16 or Latin-1. Falsifiable: had the client
// encrypted a widened/narrowed encoding, the server-recovered bytes would differ from the UTF-8 form.
// @verifies CL-IDENT-004
// @relation(CL-IDENT-004, scope=function)
TEST(ClientActivateTokenEncryption, UsernamePasswordUtf8PreservedThroughRsaEncryption)
{
  auto crypto = create_crypto();
  auto server = make_server_rsa_material(crypto);

  const std::string utf8Password = "P\xC3\xA9ss\xE2\x9D\x80!";
  const ByteString expectedUtf8 = exact_bytes(utf8Password);

  ua::UserTokenPolicy policy;
  policy.policy_id() = "user-1";
  policy.token_type() = ua::UserTokenType::UserName;
  policy.security_policy_uri() = std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};

  auto prepared = ua::client::build_user_token(ua::client::UsernamePasswordIdentity{"utf8user", utf8Password},
    "user-1",
    {policy},
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None);
  ASSERT_TRUE(prepared.is_good());
  ASSERT_NE(prepared.value().encryptionPolicy, nullptr);

  auto* rawUnp = dynamic_cast<UserNameIdentityToken*>(prepared.value().wireToken.get());
  ASSERT_NE(rawUnp, nullptr);
  ASSERT_EQ(rawUnp->password(), expectedUtf8)
    << "the pre-encryption password must already be UTF-8, before the encryption step";
  std::unique_ptr<UserIdentityToken> wire = std::move(prepared.value().wireToken);
  wire.release();
  std::shared_ptr<UserNameIdentityToken> token(rawUnp);

  auto serverNonce = make_nonce(*crypto, 32);
  auto encResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto cb)
    {
      ua::encrypt_user_token_async(prepared.value().encryptionPolicy,
        crypto,
        crypto_test_strand(),
        token,
        serverNonce,
        server.cert,
        ByteString{},
        nullptr,
        nullptr,
        ua::Logger{},
        std::move(cb));
    });
  ASSERT_TRUE(encResult.is_good()) << "Encrypt failed";
  EXPECT_NE(token->password(), expectedUtf8) << "after encryption the password must be ciphertext";

  // ORACLE: server-side decrypt recovers the plaintext; it must be exactly the UTF-8 byte sequence.
  auto oracle = run_server_username_decrypt(crypto, token, serverNonce, server.cert, server.keyPair);
  EXPECT_TRUE(oracle.responseGood);
  ASSERT_TRUE(oracle.authenticatorCalled);
  EXPECT_EQ(exact_bytes(oracle.recoveredPassword), expectedUtf8)
    << "server-decrypted password must be the UTF-8 encoding (not UTF-16 / Latin-1)";
}

// CL-IDENT-011: "This token shall always be accompanied by a Signature in the userTokenSignature
// parameter of ActivateSession if required by the SecurityPolicy. The Server should specify a
// SecurityPolicy for the UserTokenPolicy if the SecureChannel has a SecurityPolicy of None."
// (Part 4 section 7.41.5 lines 10583-10585). This drives the real client SessionImpl X509 activate branch
// (start_x509_user_token_signature) end-to-end over a None SecureChannel whose CERTIFICATE
// UserTokenPolicy advertises a non-None SecurityPolicyUri (Basic256Sha256) - exactly the case the
// spec calls out. The captured ActivateSession must carry a non-empty userTokenSignature whose
// algorithm is the user-token policy's AsymmetricSignatureAlgorithm URI, and (server oracle) the
// signature must verify over (serverCert || serverNonce) with the USER public key. Falsifiable: an
// omitted signature (channel is None so nothing else would carry it), a wrong algorithm, or a
// signature that does not verify all fail.
// @verifies CL-IDENT-011
// @relation(CL-IDENT-011, scope=function)
TEST(ClientActivateTokenEncryption, X509NonNonePolicyOverNoneChannelCarriesUserTokenSignature)
{
  auto crypto = create_crypto();
  auto tokenPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto server = make_server_rsa_material(crypto);

  boost::asio::thread_pool tp;
  auto harness = CryptoClientHarness::create(tp.get_executor(), crypto);

  // Drive the real CreateSession handshake to Created on a None (unauthenticated) channel. The
  // synthetic response advertises a single endpoint carrying a CERTIFICATE UserTokenPolicy with a
  // non-None SecurityPolicyUri, and supplies the serverCertificate + serverNonce the client signs.
  ASSERT_TRUE(harness.wait_for_pending()) << "client must send a CreateSessionRequest";
  auto serverNonce = make_nonce(*crypto, 32);

  ua::UserTokenPolicy certPolicy;
  certPolicy.policy_id() = "cert-1";
  certPolicy.token_type() = ua::UserTokenType::Certificate;
  certPolicy.security_policy_uri() = std::string{tokenPolicy->uri()};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = "opc.tcp://localhost:4840";
  endpoint.security_mode() = MessageSecurityMode::None;
  endpoint.security_policy_uri() = std::string{SecurityPolicy::create(SecurityPolicyId::None)->uri()};
  endpoint.user_identity_tokens().payload().push_back(certPolicy);

  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  createResp->revised_session_timeout() = 600000.0;
  createResp->server_nonce() = serverNonce;
  createResp->server_certificate() = server.cert->der_encoding();
  createResp->server_endpoints().payload().push_back(std::move(endpoint));
  ASSERT_TRUE(harness.inject(std::move(createResp)));
  ASSERT_TRUE(ua::client::test_capture::wait_until([&]() { return harness.session->is_created(); }))
    << "CreateSession must reach Created";

  // A user key pair + self-signed certificate distinct from any application key.
  auto userKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto userCert = make_self_signed_rsa_cert(crypto, userKeys, "TestUser", "300");

  ua::client::Session::ActivateConfig config;
  config.policyId = "cert-1";
  config.identity = ua::client::X509Identity{userCert, userKeys};
  harness.session->activate(std::move(config), [](ua::VoidResult) {});

  ASSERT_TRUE(harness.wait_for_captured<ua::ActivateSessionRequest>())
    << "ActivateSession must be sent after Created";
  auto captured = harness.first_captured<ua::ActivateSessionRequest>();
  ASSERT_TRUE(captured.has_value());

  EXPECT_FALSE(captured->user_token_signature().signature().empty())
    << "a non-None X509 user-token policy requires a userTokenSignature (the None channel carries none)";
  EXPECT_EQ(std::string_view{captured->user_token_signature().algorithm()},
    std::string_view{tokenPolicy->asymmetric_signature_algorithm_uri()})
    << "userTokenSignature algorithm must be the user-token policy AsymmetricSignatureAlgorithm URI";

  // ORACLE (as the server validates it): the signature must verify over (serverCert || serverNonce)
  // with the USER public key.
  ByteString signedData = server.cert->der_encoding();
  std::ranges::copy(serverNonce, std::back_inserter(signedData));
  bool verifies = false;
  try
  {
    crypto->asymmetric_verify_sync(tokenPolicy->asymmetric_signature_algorithm(),
      userCert->public_key(),
      signedData,
      captured->user_token_signature().signature());
    verifies = true;
  }
  catch (...)
  {
    verifies = false;
  }
  EXPECT_TRUE(verifies)
    << "userTokenSignature must be sign(serverCert || serverNonce) with the user private key";

  harness.cleanup();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-IDENT-003: fail CLOSED when user-token encryption is REQUIRED but FAILS. When the endpoint's UserName
// UserTokenPolicy mandates encryption (a non-None SecurityPolicyUri), the client selects an encryption policy
// and must encrypt the password before ActivateSession. If that encrypt step fails, the session must REFUSE
// the activation - it must NOT fall through and ship ActivateSession carrying the password in the clear.
//
// The failure is injected by driving the encrypt path with a NULL server certificate
// (encrypt_user_token_async returns BadSecurityChecksFailed "Server certificate is null"): the CreateSession
// response omits the server certificate, and the recorded channel security is switched to a secured (Sign)
// mode so the flow SKIPS the CL-IDENT-006 None-channel cert-validation branch and reaches the encrypt step
// directly - isolating the on_user_token_encrypted failure branch under test.
//
// Falsifiable: the pre-fix fail-open path proceeds past the failed encrypt and captures an
// ActivateSessionRequest carrying the UNENCRYPTED password; the fixed fail-closed path captures NO
// ActivateSessionRequest, drives the session to Closed, and resolves the activate callback with a bad status.
// @verifies CL-IDENT-003
// @relation(CL-IDENT-003, scope=function)
TEST(ClientActivateTokenEncryption, EncryptFailureFailsClosedAndDoesNotSendUnencryptedSecret)
{
  auto crypto = create_crypto();
  auto tokenPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);

  boost::asio::thread_pool tp;
  auto harness = CryptoClientHarness::create(tp.get_executor(), crypto);

  // Drive CreateSession to Created over a None (unauthenticated) channel. The response advertises a UserName
  // UserTokenPolicy requiring Basic256Sha256 encryption and - critically - carries NO server certificate, so
  // mServerCertificate stays null and the later encrypt cannot succeed.
  ASSERT_TRUE(harness.wait_for_pending()) << "client must send a CreateSessionRequest";
  auto serverNonce = make_nonce(*crypto, 32);

  ua::UserTokenPolicy unpPolicy;
  unpPolicy.policy_id() = "unp-1";
  unpPolicy.token_type() = ua::UserTokenType::UserName;
  unpPolicy.security_policy_uri() = std::string{tokenPolicy->uri()};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = "opc.tcp://localhost:4840";
  endpoint.security_mode() = MessageSecurityMode::None;
  endpoint.security_policy_uri() = std::string{SecurityPolicy::create(SecurityPolicyId::None)->uri()};
  endpoint.user_identity_tokens().payload().push_back(unpPolicy);

  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  createResp->revised_session_timeout() = 600000.0;
  createResp->server_nonce() = serverNonce;
  // server_certificate deliberately left empty -> mServerCertificate stays null -> encrypt fails later.
  createResp->server_endpoints().payload().push_back(std::move(endpoint));
  ASSERT_TRUE(harness.inject(std::move(createResp)));
  ASSERT_TRUE(ua::client::test_capture::wait_until([&]() { return harness.session->is_created(); }))
    << "CreateSession must reach Created";

  // Switch the recorded channel security to a secured (Sign) mode so start_encrypt_user_token skips the
  // CL-IDENT-006 None-channel cert-validation branch and drives the encrypt step (which then fails on the
  // null server certificate) - isolating the on_user_token_encrypted failure branch under test.
  CryptoClientHarness::STA::on_strand(
    *harness.session, [&](auto& g) { g.security_info().messageSecurityMode = MessageSecurityMode::Sign; });

  struct ActivateOutcome
  {
    std::mutex mutex;
    bool called = false;
    ua::VoidResult result;  // default-constructed = Good
  };

  auto outcome = std::make_shared<ActivateOutcome>();

  ua::client::Session::ActivateConfig config;
  config.policyId = "unp-1";
  config.identity = ua::client::UsernamePasswordIdentity{"user-1", "s3cr3t-password", false};
  harness.session->activate(std::move(config),
    [outcome](ua::VoidResult result)
    {
      std::lock_guard<std::mutex> lk(outcome->mutex);
      outcome->called = true;
      outcome->result = std::move(result);
    });

  // The fail-closed path resolves the activate callback (with a bad status); the fail-open path would instead
  // send an ActivateSessionRequest (which we must NOT observe). Wait for whichever occurs first.
  ASSERT_TRUE(ua::client::test_capture::wait_until(
    [&]()
    {
      {
        std::lock_guard<std::mutex> lk(outcome->mutex);
        if (outcome->called)
          return true;
      }
      return harness.first_captured<ua::ActivateSessionRequest>().has_value();
    }));

  // The password must NEVER leave the client unencrypted: no ActivateSessionRequest may be sent.
  EXPECT_FALSE(harness.first_captured<ua::ActivateSessionRequest>().has_value())
    << "fail-open: ActivateSession was sent carrying the unencrypted password after encryption failed";

  {
    std::lock_guard<std::mutex> lk(outcome->mutex);
    EXPECT_TRUE(outcome->called) << "activate callback must be resolved on the fail-closed refusal";
    EXPECT_TRUE(outcome->result.is_bad()) << "activate must fail when the required encryption fails";
  }

  auto state =
    CryptoClientHarness::STA::on_strand(*harness.session, [](auto& g) { return g.session_state(); });
  EXPECT_EQ(state, ua::client::SessionTestAccess::SessionState::Closed)
    << "the session must be Closed (fail-closed) when required user-token encryption fails";

  harness.cleanup();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// CL-IDENT-003 (defense-in-depth): fail CLOSED when the user-token SecurityPolicy REQUIRES the password
// encrypted but the SDK cannot perform the encryption because NO crypto provider is available. The client
// must refuse the activation rather than fall through and ship ActivateSession carrying the plaintext
// password. (start_encrypt_user_token previously passed a GOOD result when crypto was null, silently
// SKIPPING the mandated encryption.) In a correctly-configured client CoreClient::crypto() is never null, so
// this is a latent/defense-in-depth branch; a null-crypto dependency exercises the SDK's required-encryption
// decision directly.
//
// Falsifiable: against the pre-hardening code an ActivateSessionRequest carrying the plaintext password is
// captured; the hardened path captures NONE, drives the session to Closed, and resolves the activate callback
// with the no-crypto-tagged refusal.
// @verifies CL-IDENT-003
// @relation(CL-IDENT-003, scope=function)
TEST(ClientActivateTokenEncryption, EncryptionRequiredButNoCryptoFailsClosed)
{
  boost::asio::thread_pool tp;
  // A session whose dependencies expose NO crypto provider (crypto() == nullptr).
  auto harness = CryptoClientHarness::create(tp.get_executor(), nullptr);

  ASSERT_TRUE(harness.wait_for_pending()) << "client must send a CreateSessionRequest";

  ua::UserTokenPolicy unpPolicy;
  unpPolicy.policy_id() = "unp-1";
  unpPolicy.token_type() = ua::UserTokenType::UserName;
  unpPolicy.security_policy_uri() =
    std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = "opc.tcp://localhost:4840";
  endpoint.security_mode() = MessageSecurityMode::None;
  endpoint.security_policy_uri() = std::string{SecurityPolicy::create(SecurityPolicyId::None)->uri()};
  endpoint.user_identity_tokens().payload().push_back(unpPolicy);

  ua::ByteString serverNonce;
  serverNonce.resize(32);  // fixed bytes; no crypto available to allocate one

  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  createResp->revised_session_timeout() = 600000.0;
  createResp->server_nonce() = serverNonce;
  // server_certificate left empty; no crypto to parse one anyway.
  createResp->server_endpoints().payload().push_back(std::move(endpoint));
  ASSERT_TRUE(harness.inject(std::move(createResp)));
  ASSERT_TRUE(ua::client::test_capture::wait_until([&]() { return harness.session->is_created(); }))
    << "CreateSession must reach Created";

  struct ActivateOutcome
  {
    std::mutex mutex;
    bool called = false;
    ua::VoidResult result;  // default-constructed = Good
  };

  auto outcome = std::make_shared<ActivateOutcome>();

  ua::client::Session::ActivateConfig config;
  config.policyId = "unp-1";
  config.identity = ua::client::UsernamePasswordIdentity{"user-1", "s3cr3t-password", false};
  harness.session->activate(std::move(config),
    [outcome](ua::VoidResult result)
    {
      std::lock_guard<std::mutex> lk(outcome->mutex);
      outcome->called = true;
      outcome->result = std::move(result);
    });

  ASSERT_TRUE(ua::client::test_capture::wait_until(
    [&]()
    {
      {
        std::lock_guard<std::mutex> lk(outcome->mutex);
        if (outcome->called)
          return true;
      }
      return harness.first_captured<ua::ActivateSessionRequest>().has_value();
    }));

  EXPECT_FALSE(harness.first_captured<ua::ActivateSessionRequest>().has_value())
    << "fail-open: ActivateSession was sent with the unencrypted password when no crypto was available";

  {
    std::lock_guard<std::mutex> lk(outcome->mutex);
    EXPECT_TRUE(outcome->called) << "activate callback must be resolved on the fail-closed refusal";
    EXPECT_TRUE(outcome->result.is_bad())
      << "activate must fail when required encryption cannot be performed";
    ASSERT_NE(outcome->result.shared_detail(), nullptr) << "the refusal must carry an ErrorDetail";
    EXPECT_EQ(outcome->result.shared_detail()->source, "client.session.user_token_encryption.no_crypto")
      << "the refusal must be the no-crypto fail-closed branch (not another refuse path)";
  }

  auto state =
    CryptoClientHarness::STA::on_strand(*harness.session, [](auto& g) { return g.session_state(); });
  EXPECT_EQ(state, ua::client::SessionTestAccess::SessionState::Closed)
    << "the session must be Closed (fail-closed) when required user-token encryption cannot be performed";

  harness.cleanup();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

}  // namespace

// The X509 user-token signature is over (serverCertificate || serverNonce): with an empty nonce it has
// no freshness and could be replayed across sessions, so a nonce shorter than 32 bytes refuses the
// activation (Part 4 section 5.6.3.2) and no ActivateSession is sent.
// @relation(AC-CL-SESS-008-SHORT-SERVERNONCE-IS-REJECTED, scope=function)
TEST(ClientActivateTokenEncryption, X509TokenSignatureRefusedWhenServerNonceShort)
{
  auto crypto = create_crypto();
  auto tokenPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto server = make_server_rsa_material(crypto);

  boost::asio::thread_pool tp;
  auto harness = CryptoClientHarness::create(tp.get_executor(), crypto);

  ASSERT_TRUE(harness.wait_for_pending()) << "client must send a CreateSessionRequest";
  ua::UserTokenPolicy certPolicy;
  certPolicy.policy_id() = "cert-1";
  certPolicy.token_type() = ua::UserTokenType::Certificate;
  certPolicy.security_policy_uri() = std::string{tokenPolicy->uri()};
  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = "opc.tcp://localhost:4840";
  endpoint.security_mode() = MessageSecurityMode::None;
  endpoint.security_policy_uri() = std::string{SecurityPolicy::create(SecurityPolicyId::None)->uri()};
  endpoint.user_identity_tokens().payload().push_back(certPolicy);
  auto createResp = std::make_shared<ua::CreateSessionResponse>();
  createResp->response_header().service_result() = Status::Good;
  createResp->session_id() = NodeId{1, 42};
  createResp->authentication_token() = NodeId{1, 99};
  createResp->revised_session_timeout() = 600000.0;
  createResp->server_nonce() = ByteString{};  // a None endpoint answering with no challenge
  createResp->server_certificate() = server.cert->der_encoding();
  createResp->server_endpoints().payload().push_back(std::move(endpoint));
  ASSERT_TRUE(harness.inject(std::move(createResp)));
  ASSERT_TRUE(ua::client::test_capture::wait_until([&]() { return harness.session->is_created(); }))
    << "a None channel tolerates an empty nonce at CreateSession";

  auto userKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  auto userCert = make_self_signed_rsa_cert(crypto, userKeys, "TestUser", "300");
  ua::client::Session::ActivateConfig config;
  config.policyId = "cert-1";
  config.identity = ua::client::X509Identity{userCert, userKeys};
  auto activated = std::make_shared<std::promise<ua::VoidResult>>();
  auto activateResult = activated->get_future();
  harness.session->activate(
    std::move(config), [activated](ua::VoidResult result) { activated->set_value(result); });

  ASSERT_EQ(activateResult.wait_for(std::chrono::seconds{3}), std::future_status::ready);
  const auto result = activateResult.get();
  EXPECT_EQ(result.status_code().as_status(), Status::BadNonceInvalid);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_NE(to_string(*result.shared_detail()).find("ServerNonceTooShortForUserToken"), std::string::npos)
    << to_string(*result.shared_detail());
  EXPECT_FALSE(harness.first_captured<ua::ActivateSessionRequest>().has_value())
    << "no signature over an empty challenge leaves the client";

  harness.cleanup();
  harness.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
