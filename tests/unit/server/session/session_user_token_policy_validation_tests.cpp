// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include "../sdk/implementation/server/secure_channel/ua_server_secure_channel_test_access.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"

#include "ua_security_policy_compatibility.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_security_policy.h"
#include "ua_sec_pol_ephemeral_key.h"

#include "ua_error_detail.h"
#include "ua_event_bus.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_create_session_request.h"
#include "ua_issued_identity_token.h"
#include "ua_service_fault.h"
#include "ua_crypto.h"
#include "ua_user_name_identity_token.h"

#include "ua_user_token_encryption.h"
#include "run_async_sync.h"
#include "ua_server_components.h"
#include "test_pki_helpers.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
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

namespace
{

// ===================================================================
// ECC certificate curve hooks (parametrized). Restated from the removed permitted_certificate_key_algorithms
// list (owner review 2026-10-02 item 2; OPC 10000-7 profile database: the end entity and the issuing CA use
// the policy curve, other CAs may use the larger curve). RATIFICATION PENDING: the old list let a P-256 /
// brainpoolP256r1 policy accept a P-384-type END-ENTITY certificate (Part 12 7.8.4.7/7.8.4.9).
// ===================================================================

struct EccCertificateCurvesParams
{
  SecurityPolicyId policyId;
  CertificateKeyAlgorithm endEntity;
  CertificateKeyAlgorithm higherCa;
  std::string name;
};

class EccCertificateCurves : public ::testing::TestWithParam<EccCertificateCurvesParams>
{};

TEST_P(EccCertificateCurves, ReportsTheProfileDatabaseCurves)
{
  const auto& params = GetParam();
  auto policy = SecurityPolicy::create(params.policyId);
  auto* eccPolicy = dynamic_cast<const SecPolEphemeralKey*>(policy.get());
  ASSERT_NE(eccPolicy, nullptr) << "Policy must be an EphemeralKey policy";
  EXPECT_EQ(eccPolicy->certificate_key_algorithm(), params.endEntity);
  EXPECT_EQ(eccPolicy->higher_ca_certificate_key_algorithm(), params.higherCa);
}

// Every policy with an EphemeralKey: RSA_DH uses RSA certificates throughout, so it reports Rsa for both.
INSTANTIATE_TEST_SUITE_P(EphemeralKeyPolicies, EccCertificateCurves,
  ::testing::Values(EccCertificateCurvesParams{SecurityPolicyId::EccNistP256AesGcm,
                      CertificateKeyAlgorithm::EccNistP256,
                      CertificateKeyAlgorithm::EccNistP384,
                      "NistP256"},
    EccCertificateCurvesParams{SecurityPolicyId::EccNistP384AesGcm,
      CertificateKeyAlgorithm::EccNistP384,
      CertificateKeyAlgorithm::EccNistP521,
      "NistP384"},
    EccCertificateCurvesParams{SecurityPolicyId::EccBrainpoolP256r1AesGcm,
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      "BrainpoolP256r1"},
    EccCertificateCurvesParams{SecurityPolicyId::EccBrainpoolP384r1AesGcm,
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      CertificateKeyAlgorithm::EccBrainpoolP512r1,
      "BrainpoolP384r1"},
    EccCertificateCurvesParams{SecurityPolicyId::EccCurve25519ChaChaPoly,
      CertificateKeyAlgorithm::EccCurve25519,
      CertificateKeyAlgorithm::EccCurve25519,
      "Curve25519"},
    EccCertificateCurvesParams{SecurityPolicyId::EccCurve448ChaChaPoly,
      CertificateKeyAlgorithm::EccCurve448,
      CertificateKeyAlgorithm::EccCurve448,
      "Curve448"},
    EccCertificateCurvesParams{SecurityPolicyId::EccNistP256ChaChaPoly,
      CertificateKeyAlgorithm::EccNistP256,
      CertificateKeyAlgorithm::EccNistP384,
      "NistP256ChaChaPoly"},
    EccCertificateCurvesParams{SecurityPolicyId::EccNistP384ChaChaPoly,
      CertificateKeyAlgorithm::EccNistP384,
      CertificateKeyAlgorithm::EccNistP521,
      "NistP384ChaChaPoly"},
    EccCertificateCurvesParams{SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly,
      CertificateKeyAlgorithm::EccBrainpoolP256r1,
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      "BrainpoolP256r1ChaChaPoly"},
    EccCertificateCurvesParams{SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly,
      CertificateKeyAlgorithm::EccBrainpoolP384r1,
      CertificateKeyAlgorithm::EccBrainpoolP512r1,
      "BrainpoolP384r1ChaChaPoly"},
    EccCertificateCurvesParams{SecurityPolicyId::EccCurve25519AesGcm,
      CertificateKeyAlgorithm::EccCurve25519,
      CertificateKeyAlgorithm::EccCurve25519,
      "Curve25519AesGcm"},
    EccCertificateCurvesParams{SecurityPolicyId::EccCurve448AesGcm,
      CertificateKeyAlgorithm::EccCurve448,
      CertificateKeyAlgorithm::EccCurve448,
      "Curve448AesGcm"},
    EccCertificateCurvesParams{SecurityPolicyId::RsaDhAesGcm,
      CertificateKeyAlgorithm::Rsa,
      CertificateKeyAlgorithm::Rsa,
      "RsaDhAesGcm"},
    EccCertificateCurvesParams{SecurityPolicyId::RsaDhChaChaPoly,
      CertificateKeyAlgorithm::Rsa,
      CertificateKeyAlgorithm::Rsa,
      "RsaDhChaChaPoly"}),
  [](const ::testing::TestParamInfo<EccCertificateCurvesParams>& info) { return info.param.name; });

// ===================================================================
// Targeted tests for inherited policy (empty URI) edge cases
// ===================================================================

// @relation(SVR-IDENT-015, SVR-JWT-015, SVR-SESS-037, scope=function)
TEST(ValidateUserTokenPolicyInherited, InheritedNoneOnNoneChannelIsRejected)
{
  UserTokenPolicy utp;
  utp.token_type() = UserTokenType::UserName;

  auto result = validate_user_token_policy(utp, SecurityPolicyId::None, MessageSecurityMode::None);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityPolicyRejected);
}

// @relation(SVR-IDENT-003, SVR-SESS-037, scope=function)
TEST(ValidateUserTokenPolicyInherited, InheritedAuthenticatedOnSignChannelIsAccepted)
{
  UserTokenPolicy utp;
  utp.token_type() = UserTokenType::UserName;

  auto result = validate_user_token_policy(utp, SecurityPolicyId::Basic256Sha256, MessageSecurityMode::Sign);
  EXPECT_TRUE(result.is_good());
}

// @relation(SVR-SESS-037, scope=function)
TEST(ValidateUserTokenPolicyInherited, InheritedNoneX509OnSignChannelIsRejected)
{
  UserTokenPolicy utp;
  utp.token_type() = UserTokenType::Certificate;

  auto result = validate_user_token_policy(utp, SecurityPolicyId::None, MessageSecurityMode::Sign);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityPolicyRejected);
}

// @relation(SVR-SESS-037, scope=function)
TEST(ValidateUserTokenPolicyInherited, InheritedAuthenticatedX509OnSignChannelIsAccepted)
{
  UserTokenPolicy utp;
  utp.token_type() = UserTokenType::Certificate;

  auto result = validate_user_token_policy(utp, SecurityPolicyId::Basic256Sha256, MessageSecurityMode::Sign);
  EXPECT_TRUE(result.is_good());
}

// @relation(SVR-SESS-037, scope=function)
TEST(ValidateUserTokenPolicyInherited, InheritedNoneX509OnSignAndEncryptChannelIsRejected)
{
  UserTokenPolicy utp;
  utp.token_type() = UserTokenType::Certificate;

  auto result = validate_user_token_policy(utp, SecurityPolicyId::None, MessageSecurityMode::SignAndEncrypt);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityPolicyRejected);
}

// Part 4 section 7.41.2.1: when a UserTokenPolicy's securityPolicyUri is null or empty, the policy of the
// EndpointDescription applies. The dangerous misreading is to treat the unset field as SecurityPolicy
// None - None is a legal value for the field, so an implementation that folds "unset" into it looks
// correct until a UserName secret is carried in clear over a Sign-only channel and accepted. The
// inherited policy must also follow whichever policy the channel actually carries rather than one
// assumed default, hence the two distinct channel policies below.
// @verifies AC-SVR-IDENT-003-POLICY-INHERITS-CHANNEL
TEST(ValidateUserTokenPolicyInherited, NullTokenPolicyInheritsChannelPolicyRatherThanNone)
{
  struct ChannelCase
  {
    SecurityPolicyId policyId;
    const char* name;
  };

  const std::vector<ChannelCase> channels{{SecurityPolicyId::Basic256Sha256, "Basic256Sha256"},
    {SecurityPolicyId::Aes256Sha256RsaPss, "Aes256Sha256RsaPss"}};
  ASSERT_FALSE(channels.empty());

  for (const auto& channel : channels)
  {
    // Sign alone does not encrypt, so a UserName token is admissible here only if the token itself
    // is secured with the channel's authenticated policy.
    UserTokenPolicy inherited;
    inherited.token_type() = UserTokenType::UserName;

    auto inheritedResult = validate_user_token_policy(inherited, channel.policyId, MessageSecurityMode::Sign);
    EXPECT_TRUE(inheritedResult.is_good())
      << "Null securityPolicyUri was not inherited from channel policy " << channel.name;

    // Control on the same channel: spelling None out explicitly is refused. The acceptance above is
    // therefore attributable to inheritance and not to the field being ignored altogether.
    UserTokenPolicy explicitNone;
    explicitNone.token_type() = UserTokenType::UserName;
    explicitNone.security_policy_uri() = "http://opcfoundation.org/UA/SecurityPolicy#None";

    auto explicitNoneResult =
      validate_user_token_policy(explicitNone, channel.policyId, MessageSecurityMode::Sign);
    EXPECT_TRUE(explicitNoneResult.is_bad())
      << "Explicit None token policy accepted on channel policy " << channel.name;
    EXPECT_EQ(explicitNoneResult.status_code().as_status(), Status::BadSecurityPolicyRejected)
      << "channel policy " << channel.name;
  }
}

// ===================================================================
// Endpoint configuration validation (Part 4 Table 193 cells)
// ===================================================================

// Part 4 section 7.41 Table 193 marks "Security Policy - Other / SIGN / Security Policy - None" as an
// invalid configuration that shall be rejected: Sign provides integrity but not confidentiality, so
// a None UserName token policy puts the password on the wire in clear under a channel the operator
// believes is secured. A plausible implementation reads this cell as merely weak - the channel is
// nominally secure and None is a legal token policy - and advertises the endpoint anyway.
// @verifies AC-SVR-IDENT-015-SIGN-WITH-NONE-POLICY-REJECTED
TEST(EndpointUserTokenPolicyConfiguration, SignChannelWithNoneUserNameTokenPolicyIsRejected)
{
  ServerEndpointConfig config;
  config.name = "SignWithNoneUserToken";
  config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  config.messageSecurityMode = MessageSecurityMode::Sign;
  config.userIdentityTokens = {create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::None)};
  ASSERT_FALSE(config.userIdentityTokens.empty());

  auto rejected = validate_endpoint_user_token_policies(config);
  EXPECT_TRUE(rejected.is_bad());
  EXPECT_EQ(rejected.status_code().as_status(), Status::BadSecurityPolicyRejected);

  // The identical token policy on a channel that encrypts is a permitted Table 193 cell, so the
  // refusal above is attributable to Sign-without-encryption rather than to a blanket ban on None
  // user token policies.
  config.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  auto accepted = validate_endpoint_user_token_policies(config);
  EXPECT_TRUE(accepted.is_good());
}

// ===================================================================
// JWT delivery envelope (Part 6 6.5.2)
// ===================================================================

/// Records the identity the stack hands to the application authenticator, then accepts it.
///
/// Accepting unconditionally is deliberate: the activation under test must be able to succeed, so
/// that a refusal observed by the test can only have come from the stack's own token handling and
/// never from this authenticator.
class IssuedTokenRecordingAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept override
  {
    {
      std::lock_guard<std::mutex> lk(mMutex);
      mCalled = true;
      mKind = req.identity.kind;
      mIssuedToken = req.identity.issuedToken;
    }
    completion(
      make_authn_success(UserIdentity{.userId = "jwt-user", .displayName = "JWT User", .claims = {}}));
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

  optional<ua::ByteString> issued_token() const
  {
    std::lock_guard<std::mutex> lk(mMutex);
    return mIssuedToken;
  }

private:
  mutable std::mutex mMutex;
  bool mCalled{false};
  UserTokenKind mKind{UserTokenKind::Unsupported};
  optional<ua::ByteString> mIssuedToken;
};

/// Minimal SecureChannelDependencies for the activation below; crypto lives on the session deps.
class IssuedTokenSecureDeps : public SecureChannelDependencies
{
public:
  explicit IssuedTokenSecureDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
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

/// Session dependencies carrying a real crypto provider.
///
/// A null provider is enough for refusal paths, but an activation that is ACCEPTED generates the
/// response's next server nonce through `deps->crypto()->get_entropy_async(...)` with no null check
/// whenever the endpoint publishes an authenticated user-token policy - which this one does.
class IssuedTokenSessionDeps final : public SessionDependencies
{
public:
  IssuedTokenSessionDeps(
    boost::asio::any_io_executor ex, ServerComponents hooks, shared_ptr<const Crypto> crypto)
    : mExecutor(ex),
      mAppCfg(std::make_shared<const ::ua::ApplicationConfig>(::ua::ApplicationConfig::load_default())),
      mHooks(std::move(hooks)), mCrypto(std::move(crypto))
  {}

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
  shared_ptr<const Crypto> mCrypto;
};

// Part 6 6.5.2: "JSON Web Token (JWT) UserIdentityTokens can be passed to the Server using the
// IssuedIdentityToken. The body of the token is a string that contains the JWT as defined in RFC
// 8259." The JWT is therefore not a token type of its own: it rides the standard IssuedIdentityToken
// envelope, and its tokenData is a string the server carries through untouched to whoever validates
// it. Two plausible implementations get this wrong. One reads the JWT as some bespoke identity token
// and, finding no handler, classifies the activation as an unsupported token kind - the endpoint then
// advertises a JWT policy no client can use. The other treats tokenData like the UserName token's
// password field and tries to decrypt or otherwise transform it, so what reaches the validator is no
// longer the JWT the client sent and every signature check downstream fails. The assertions below
// therefore pin both the kind the stack decided and the exact bytes it carried, not merely that the
// activation succeeded.
// @verifies AC-SVR-JWT-001-ISSUEDTOKEN-ENVELOPE
TEST(SessionIssuedTokenEnvelope, JwtArrivesInIssuedIdentityTokenWithItsTokenDataIntact)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  // A JWT in RFC 7519 compact serialization: base64url(header) '.' base64url(payload) '.'
  // base64url(signature), where both header and payload decode to RFC 8259 JSON objects.
  const std::string jwt{
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFzLWtleS0xIn0."
    "eyJhdWQiOiJ1cm46b3BjdWE6c2VydmVyIiwic2NwIjoicmVhZCJ9."
    "c2lnbmF0dXJlLXBsYWNlaG9sZGVy"};
  std::vector<uint8_t> jwtBytes(jwt.begin(), jwt.end());
  ASSERT_FALSE(jwtBytes.empty());

  auto crypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
  auto tokenPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto serverKeys = crypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  TestPki pki{crypto};
  Crypto::CreateCertificateConfig certificateParameters;
  certificateParameters.subjectKeys = serverKeys;
  certificateParameters.issuerKeys = serverKeys;
  certificateParameters.subject.commonName = "JwtEnvelopeServer";
  certificateParameters.serialNumber = "1";
  certificateParameters.basicConstraint.cA = false;
  certificateParameters.keyUsage.digitalSignature = true;
  certificateParameters.keyUsage.keyEncipherment = true;
  certificateParameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  certificateParameters.from = DateTime::now();
  certificateParameters.to = DateTime{certificateParameters.from.value() + std::chrono::days{365}};
  auto serverCertificate = pki.create_cert(certificateParameters);
  ASSERT_NE(serverCertificate, nullptr);
  ByteString serverNonce = crypto->get_entropy_sync(32);
  ASSERT_EQ(serverNonce.size(), 32u);

  auto encryptedCarrier = std::make_shared<UserNameIdentityToken>();
  encryptedCarrier->user_name() = "issued-token-carrier";
  encryptedCarrier->password() = ByteString{jwtBytes};
  auto encryptionResult = ua::test_helpers::run_async_function_sync<VoidResult>(
    [&](auto completion)
    {
      encrypt_user_token_async(tokenPolicy,
        crypto,
        crypto_test_strand(),
        encryptedCarrier,
        serverNonce,
        serverCertificate,
        ByteString{},
        nullptr,
        nullptr,
        Logger{},
        std::move(completion));
    });
  ASSERT_TRUE(encryptionResult.is_good())
    << "JWT EncryptedSecret construction failed: " << to_string(encryptionResult.status_code().as_status());
  ASSERT_NE(encryptedCarrier->password(), ByteString{jwtBytes})
    << "the fixture must traverse the real issued-token decryption path";

  auto scDeps = std::make_shared<IssuedTokenSecureDeps>(ex);
  auto sc = SecureChannel::create(
    scDeps, nullptr, ua::connection_protocol::NegotiatedLimits{}, ListenerHandle{1}, "L");

  // The endpoint publishes exactly one user-token policy: IssuedToken under Basic256Sha256.
  // Anonymous is deliberately absent, so nothing but the presented issued token can activate this
  // session.
  //
  // The JWT is carried in a real RsaEncryptedSecret under this policy. That keeps the envelope
  // criterion independent of the built-in JWT facet without weakening the token-policy protection:
  // production must decrypt first, then deliver the exact compact JWT to the host authenticator.
  SecureChannelTestAccess::on_strand(*sc,
    [&](auto& g)
    {
      g.set_minimal_context_none(ex,
        "L/None",
        {create_user_token_policy(UserTokenType::IssuedToken, SecurityPolicyId::Basic256Sha256)});
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

  ServerComponents hooks;
  auto authenticator = std::make_shared<IssuedTokenRecordingAuthenticator>();
  hooks.authenticator = authenticator;

  auto sessDeps = std::make_shared<IssuedTokenSessionDeps>(
    ex, hooks, create_default_crypto([]() { return ua::SecureString{""}; }));
  SecureChannelInfo sci(sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/None",
    SecureChannelTestAccess::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  auto session = Session::create(sessDeps, sci, 1, CreateSessionRequest{});
  SessionTestAccess::strand_barrier(*session);
  SessionTestAccess::on_strand(*session,
    [&](auto& guard)
    {
      guard.server_nonce() = serverNonce;
      guard.server_certificates().clear();
      guard.server_certificates().push_back(CertificateStore::ApplicationCertificate{
        tokenPolicy->certificate_type(), serverCertificate, serverKeys});
      guard.selected_cert_and_key() = guard.server_certificates().back();
    });

  const std::vector<UserTokenPolicy> published =
    SecureChannelTestAccess::on_strand(*sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); });
  ASSERT_FALSE(published.empty());

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 401;
  auto token = std::make_unique<IssuedIdentityToken>();
  token->policy_id() = published.front().policy_id();
  token->token_data() = encryptedCarrier->password();
  // Part 4 section 7.41.6: the RsaEncryptedSecret carries its SecurityPolicyUri internally.
  token->encryption_algorithm().clear();
  asr.user_identity_token() = std::move(token);
  session->activate(2, std::move(asr), {});

  {
    std::unique_lock<std::mutex> lk(mx);
    ASSERT_TRUE(cv.wait_for(lk, std::chrono::milliseconds(5000), [&]() { return last.has_value(); }))
      << "no response to an ActivateSession carrying a JWT in an IssuedIdentityToken";
    auto* resp = dynamic_cast<ActivateSessionResponse*>(last->second.get());
    ASSERT_NE(resp, nullptr) << "a JWT presented in the IssuedIdentityToken envelope must activate";
    EXPECT_TRUE(resp->response_header().service_result().is_good());
  }
  EXPECT_TRUE(session->is_activated()) << "an accepted token must leave the session activated";

  // The envelope was understood as an issued token, not as some bespoke or unsupported type.
  ASSERT_TRUE(authenticator->called()) << "the JWT never reached the authenticator";
  EXPECT_EQ(authenticator->kind(), UserTokenKind::IssuedToken);

  // ...and the tokenData string arrived byte for byte, so whatever validates the JWT sees the token
  // the client actually sent.
  auto carried = authenticator->issued_token();
  ASSERT_TRUE(carried.has_value()) << "IssuedIdentityToken.tokenData was dropped on the way through";
  EXPECT_EQ(carried->size(), jwtBytes.size());
  EXPECT_EQ(std::string(carried->begin(), carried->end()), jwt);

  session->terminate_for_shutdown();
  ::ua::test_utils::drain_with_timeout(tp);
}

// The three JWT rows this file carried - the endpoint-advertising row and the two validation rows - were
// retired into WV-JWT-POLICY-PUBLISHED-FACET-DEFERRED, WV-JWT-REJECTION-CODES-FACET-DEFERRED and
// WV-JWT-ALG-MATCHES-AS-FACET-DEFERRED. The User Token - JWT Server Facet is not claimed and `grep -rni jwt
// sdk/` returns nothing, so none of the three had an antecedent to stimulate. What stays under test is the
// host-pluggable interface above:
// SessionIssuedTokenEnvelope.JwtArrivesInIssuedIdentityTokenWithItsTokenDataIntact requires the client's
// bytes to reach `PresentedIdentity.issuedToken` byte-identically, which is the whole of what this SDK
// promises for a JWT today.

}  // namespace

// ---------------------------------------------------------------------------------------------------
// UserName encryptionAlgorithm against the effective SecurityPolicy (Part 4 7.41.3). The CTT's Security
// User Name Password 2 010 sends a valid password with encryptionAlgorithm "abc123" under an effective
// None policy, and 011 sends the None URI under a policy that requires encryption; both expect
// Bad_IdentityTokenInvalid, and both used to be accepted.
// ---------------------------------------------------------------------------------------------------
namespace
{
UserTokenPolicy username_policy(std::string_view securityPolicyUri)
{
  UserTokenPolicy policy;
  policy.policy_id() = String{"username"};
  policy.token_type() = UserTokenType::UserName;
  policy.security_policy_uri() = String{std::string{securityPolicyUri}};
  return policy;
}

UserNameIdentityToken username_token(std::string_view encryptionAlgorithm)
{
  UserNameIdentityToken token;
  token.policy_id() = String{"username"};
  token.user_name() = String{"user1"};
  const std::string password{"password"};
  token.password() = ByteString{std::vector<uint8_t>{password.begin(), password.end()}};
  token.encryption_algorithm() = String{std::string{encryptionAlgorithm}};
  return token;
}

constexpr std::string_view noneUri = "http://opcfoundation.org/UA/SecurityPolicy#None";
constexpr std::string_view basic256Sha256Uri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
}  // namespace

TEST(PresentedUserTokenEncryptionAlgorithm, UnderEffectiveNoneANamedAlgorithmIsInvalid)
{
  const auto result = validate_presented_user_token(
    username_policy(noneUri), SecurityPolicyId::None, MessageSecurityMode::None, username_token("abc123"));
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenInvalid});
}

TEST(PresentedUserTokenEncryptionAlgorithm, UnderEffectiveNoneAnEmptyAlgorithmIsAccepted)
{
  const auto result = validate_presented_user_token(username_policy(noneUri),
    SecurityPolicyId::None,
    MessageSecurityMode::SignAndEncrypt,
    username_token(""));
  EXPECT_TRUE(result.is_good());
}

TEST(PresentedUserTokenEncryptionAlgorithm, UnderAnEncryptingPolicyTheNoneUriIsInvalid)
{
  const auto result = validate_presented_user_token(username_policy(basic256Sha256Uri),
    SecurityPolicyId::None,
    MessageSecurityMode::None,
    username_token(noneUri));
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIdentityTokenInvalid});
}

TEST(PresentedUserTokenEncryptionAlgorithm, UnderAnEncryptingPolicyThePolicyUriIsAccepted)
{
  const auto result = validate_presented_user_token(username_policy(basic256Sha256Uri),
    SecurityPolicyId::None,
    MessageSecurityMode::None,
    username_token(basic256Sha256Uri));
  EXPECT_TRUE(result.is_good());
}

TEST(PresentedUserTokenEncryptionAlgorithm, UnderAnEncryptingPolicyTheAlgorithmUriIsAccepted)
{
  const auto result = validate_presented_user_token(username_policy(basic256Sha256Uri),
    SecurityPolicyId::None,
    MessageSecurityMode::None,
    username_token("http://www.w3.org/2001/04/xmlenc#rsa-oaep"));
  EXPECT_TRUE(result.is_good());
}

// @verifies AC-COMP-ECC-SECRET-USERNAME-ROUTING
// @relation(AC-COMP-ECC-SECRET-USERNAME-ROUTING, scope=function)
TEST(PresentedUserTokenEncryptionAlgorithm, EccEmptyOuterAlgorithmDefersToEnvelopeValidation)
{
  // The independent .NET peer puts encryption metadata inside EccEncryptedSecret.
  // This guard validates the negotiated policy; the Session must still decode and
  // authenticate the complete envelope before passing credentials to the application.
  constexpr std::string_view policyUri = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_AesGcm";
  const auto result = validate_presented_user_token(username_policy(policyUri),
    SecurityPolicyId::EccNistP256AesGcm,
    MessageSecurityMode::Sign,
    username_token(""));
  EXPECT_TRUE(result.is_good());
}

// OPC 10000-4 1.05.06 Table 188: under a SecurityPolicy with SecureChannelEnhancements, "the Client shall set
// this field to null or empty and Servers shall ignore any value specified". Whatever a UserName token names
// - another algorithm or policy, a meaningless string or the policy's own URI - the guard passes it to the
// Session, which decodes the EccEncryptedSecret under the negotiated policy. Control: under Basic256Sha256,
// which has no enhancements, the meaningless string is still refused.
// @relation(AC-SVR-IDENT-008-OUTER-ALGORITHM-IGNORED-UNDER-ENHANCED-POLICY, scope=function)
TEST(PresentedUserTokenEncryptionAlgorithm, UnderAnEnhancedPolicyAnyNamedAlgorithmIsIgnored)
{
  const std::pair<SecurityPolicyId, std::string_view> enhancedPolicies[] = {
    {SecurityPolicyId::EccNistP256AesGcm, "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_AesGcm"},
    {SecurityPolicyId::RsaDhAesGcm, "http://opcfoundation.org/UA/SecurityPolicy#RSA_DH_AesGcm"}};
  for (const auto& [id, uri] : enhancedPolicies)
  {
    for (const std::string_view named : {std::string_view{"abc123"},
           noneUri,
           basic256Sha256Uri,
           std::string_view{"http://www.w3.org/2001/04/xmlenc#rsa-oaep"},
           uri})
    {
      const auto result = validate_presented_user_token(
        username_policy(uri), id, MessageSecurityMode::Sign, username_token(named));
      EXPECT_TRUE(result.is_good()) << uri << " naming " << named;
    }
  }
  const auto control = validate_presented_user_token(username_policy(basic256Sha256Uri),
    SecurityPolicyId::None,
    MessageSecurityMode::None,
    username_token("abc123"));
  EXPECT_EQ(control.status_code(), StatusCode{Status::BadIdentityTokenInvalid});
}

// Table 191: for an IssuedIdentityToken, "the Client shall set this field to null or empty and Servers shall
// ignore any value specified", under any SecurityPolicy. The guard passes a token naming an algorithm to the
// Session, which decodes the EncryptedSecret under the negotiated policy.
// @relation(AC-SVR-IDENT-018-OUTER-ALGORITHM-IGNORED, scope=function)
TEST(PresentedUserTokenEncryptionAlgorithm, AnIssuedTokensNamedAlgorithmIsIgnored)
{
  const std::pair<SecurityPolicyId, std::string_view> policies[] = {
    {SecurityPolicyId::Basic256Sha256, basic256Sha256Uri},
    {SecurityPolicyId::EccNistP256AesGcm, "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_AesGcm"}};
  for (const auto& [id, uri] : policies)
  {
    for (const std::string_view named : {std::string_view{"abc123"}, uri})
    {
      UserTokenPolicy policy = username_policy(uri);
      policy.token_type() = UserTokenType::IssuedToken;
      IssuedIdentityToken token;
      token.policy_id() = String{"username"};
      const std::string tokenData{"issued-token"};
      token.token_data() = ByteString{std::vector<uint8_t>{tokenData.begin(), tokenData.end()}};
      token.encryption_algorithm() = String{std::string{named}};
      const auto result =
        validate_presented_user_token(policy, id, MessageSecurityMode::SignAndEncrypt, token);
      EXPECT_TRUE(result.is_good()) << uri << " naming " << named;
    }
  }
}
