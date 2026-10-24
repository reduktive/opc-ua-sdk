// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::RealConnectionEstablisher (section 8.2A) - the production tier-0 connect
// glue driven over injectable open/channel/session interfaces (no real server; testable_interfaces.md). These
// exercise the establisher's OWN logic: the open -> CreateSession -> ActivateSession sequence, the
// partial-failure cleanup ladder (a Created session is CloseSession'd when ActivateSession fails), the
// single-shot vs auto-reconnect wiring, and that the SAME open interface is reused verbatim for a reconnect
// reopen (no downgrade).
//
// Falsifiability: each test scripts one tier-0 step to fail (or succeed) and asserts the exact status
// delivered, which later step was / was not reached, and whether the created session was closed - so an
// establisher that skipped a step, leaked a Created session, or mis-wired reconnect fails a concrete
// assertion.

#include "ua_connection_establisher.h"

#include "fake_session_ops.h"
#include "stub_x509_certificate.h"

#include "ua_connect_plan.h"
#include "ua_connection_config.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "async_test_runtime.h"

#include "ua_error_detail.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_utilities.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{
using ua::client::ConnectionConfig;
using ua::client::detail::build_connect_plan;
using ua::client::detail::ChannelOps;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::ConnectPlan;
using ua::client::detail::ObserverSlots;
using ua::client::detail::RealConnectionEstablisher;
using ua::client::detail::ReopenChannelOps;
using ua::client::detail::SessionOps;
using ua::test_helpers::AsyncTestRuntime;
using ua::test_helpers::FakeSessionOps;

using EstablishResult = ua::Result<std::shared_ptr<ConnectionImpl>>;

class UriStubCertificate final : public ua::testing::StubX509Certificate
{
public:
  explicit UriStubCertificate(std::vector<std::string> uris) : mUris(std::move(uris))
  {}

  std::vector<std::string> san_uris() const override
  {
    return mUris;
  }

private:
  std::vector<std::string> mUris;
};

/// An endpoint as GetEndpoints advertises it: URL, security, the server-assigned securityLevel, and for a
/// secured policy a certificate blob for the decoder stub (`use_stub_server_certificate_decoder`).
ua::EndpointDescription advertised_endpoint(
  std::string url, ua::SecurityPolicyId policy, ua::MessageSecurityMode mode, uint8_t securityLevel)
{
  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = std::move(url);
  endpoint.server().application_uri() = "urn:server";
  endpoint.security_mode() = mode;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(policy);
  endpoint.security_level() = securityLevel;
  if (policy != ua::SecurityPolicyId::None)
  {
    endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
  }
  return endpoint;
}

std::string detail_code_of(const EstablishResult& result)
{
  const auto detail = result.shared_detail();
  return detail ? detail->code : std::string{};
}

/// The ErrorDetail named @p code on @p status or in its cause chain; null when there is none.
const ua::ErrorDetail* detail_named(const ua::StatusCode& status, std::string_view code)
{
  for (const ua::ErrorDetail* detail = status.detail(); detail != nullptr; detail = detail->cause.get())
  {
    if (detail->code == code)
    {
      return detail;
    }
  }
  return nullptr;
}

/// Checks that @p result is the refusal of the server's Uncertain @p answer: Bad_InternalError whose
/// ErrorDetail chain holds ServiceAnswerUncertain, with its summary and @p answer as its inner status.
void expect_uncertain_answer_refused(const EstablishResult& result, ua::Status answer)
{
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadInternalError);
  const ua::ErrorDetail* refusal = detail_named(result.status_code(), "ServiceAnswerUncertain");
  ASSERT_NE(refusal, nullptr) << "the refusal must name the Uncertain answer; top detail: "
                              << detail_code_of(result);
  EXPECT_EQ(refusal->summary, "The SDK does not act on an answer the server is uncertain of");
  EXPECT_EQ(refusal->innerStatus, ua::StatusCode{answer}.value());
}

// An advertised UserTokenPolicy: the pair (id, kind) is all the policy-id selection tests need.
ua::UserTokenPolicy make_token_policy(std::string_view policyId, ua::UserTokenType type)
{
  ua::UserTokenPolicy policy;
  policy.policy_id() = std::string{policyId};
  policy.token_type() = type;
  return policy;
}

// A channel interface the test fully controls: yields a caller-owned FakeSessionOps (so the test pre-scripts
// its activate / close) under the scripted CreateSession status, or no Session for a Bad status or when
// `createHoldsSession` is false (a ServiceFault).
class ControllableChannelOps : public ChannelOps
{
public:
  ua::StatusCode createStatus{ua::Status::Good};
  bool createHoldsSession = true;
  std::shared_ptr<FakeSessionOps> session = std::make_shared<FakeSessionOps>();
  std::atomic<std::size_t> createCalls{0};
  std::atomic<std::size_t> getEndpointsCalls{0};
  std::atomic<std::size_t> closeCalls{0};
  ua::GetEndpointsResponse getEndpointsResponse;
  ua::StatusCode getEndpointsStatus{ua::Status::Good};
  ua::StatusCode closeStatus{ua::Status::Good};
  std::optional<ua::client::SecureChannel::CreateSessionConfig> createConfig;

  void create_session_async(ua::client::SecureChannel::CreateSessionConfig config,
    std::function<void(ua::Result<std::shared_ptr<SessionOps>>)> callback) override
  {
    ++createCalls;
    createConfig = std::move(config);
    if (createStatus.is_bad() || !createHoldsSession)
    {
      callback(ua::Result<std::shared_ptr<SessionOps>>{createStatus});
      return;
    }
    callback(
      ua::Result<std::shared_ptr<SessionOps>>{std::static_pointer_cast<SessionOps>(session), createStatus});
  }

  void get_endpoints_async(ua::GetEndpointsRequest /*request*/,
    std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) override
  {
    ++getEndpointsCalls;
    if (!getEndpointsStatus.is_good())
    {
      callback(ua::Result<ua::GetEndpointsResponse>{getEndpointsStatus});
      return;
    }
    callback(ua::Result<ua::GetEndpointsResponse>{getEndpointsResponse});
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    ++closeCalls;
    if (closeStatus.is_bad())
    {
      callback(ua::VoidResult{closeStatus});
      return;
    }
    callback(ua::VoidResult{});
  }

  [[nodiscard]] bool is_open() const override
  {
    return true;
  }
};

// An open interface the test fully controls: yields its channel under the scripted open status (no channel
// for a Bad one) and counts opens. The establisher builds ONE ReopenChannelOps from this and reuses it for
// the initial open AND reconnect reopens, so a shared counter across copies proves the reuse.
class ControllableOpenFixture
{
public:
  ua::StatusCode openStatus{ua::Status::Good};
  std::shared_ptr<ControllableChannelOps> channel = std::make_shared<ControllableChannelOps>();
  std::atomic<std::size_t> openCalls{0};

  ReopenChannelOps as_ops()
  {
    return [this](std::function<void(ua::Result<std::shared_ptr<ChannelOps>>)> yield)
    {
      ++openCalls;
      if (openStatus.is_bad())
      {
        yield(ua::Result<std::shared_ptr<ChannelOps>>{openStatus});
        return;
      }
      yield(
        ua::Result<std::shared_ptr<ChannelOps>>{std::static_pointer_cast<ChannelOps>(channel), openStatus});
    };
  }
};

ConnectPlan valid_plan(bool autoReconnect = true)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  if (!autoReconnect)
  {
    config.reconnect = std::nullopt;
  }
  ConnectPlan plan = build_connect_plan(config);
  EXPECT_TRUE(plan.valid);
  return plan;
}

struct EstablisherFixture : ::testing::Test
{
  AsyncTestRuntime runtime;
  ControllableOpenFixture openFixture;
  std::vector<ua::client::CoreClient::OpenChannelConfig> openConfigs;
  RealConnectionEstablisher::ServerCertificateDecoder certificateDecoder;
  bool allowDeprecatedSecurityPolicies = false;  // the application's mAllowDeprecatedSecurityPolicies

  RealConnectionEstablisher make_establisher()
  {
    return RealConnectionEstablisher(
      runtime.executor(),
      ua::Logger{},
      [this](const ua::client::CoreClient::OpenChannelConfig& config)
      {
        openConfigs.push_back(config);
        return openFixture.as_ops();
      },
      {},
      certificateDecoder,
      allowDeprecatedSecurityPolicies);
  }

  // Runs establish_async and returns the delivered result (the fakes complete inline).
  EstablishResult establish(ConnectPlan plan)
  {
    EstablishResult captured{ua::StatusCode{ua::Status::BadInternalError}};
    bool fired = false;
    make_establisher().establish_async(std::move(plan),
      ObserverSlots{},
      [&](EstablishResult result)
      {
        captured = std::move(result);
        fired = true;
      });
    EXPECT_TRUE(fired) << "establish must complete (the injected tier-0 interfaces complete inline)";
    return captured;
  }

  /// Decodes every advertised certificate blob to a stub whose SAN names `urn:server`, the ApplicationUri
  /// `advertised_endpoint` claims, so a secured endpoint passes the CL-DISC-012 binding.
  void use_stub_server_certificate_decoder()
  {
    certificateDecoder = [](const ua::ByteString&)
    {
      std::shared_ptr<const ua::X509Certificate> certificate =
        std::make_shared<UriStubCertificate>(std::vector<std::string>{"urn:server"});
      return ua::Result<std::shared_ptr<const ua::X509Certificate>>{std::move(certificate)};
    };
  }

  /// Connects AutoBest with a UserName identity to the one endpoint of `channelPolicy` (SignAndEncrypt) that
  /// advertises a UserName token policy with `tokenPolicyUri`, and returns the ECDHPolicyUri the plan put
  /// into CreateSession (empty when the connect failed or carried none).
  std::string planned_ecdh_policy_uri(ua::SecurityPolicyId channelPolicy, std::string tokenPolicyUri)
  {
    ConnectionConfig config;
    config.endpointUrl = "opc.tcp://server.example:4840";
    config.endpointSelection = ua::client::EndpointSelection::AutoBest;
    config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};

    auto endpoint =
      advertised_endpoint(config.endpointUrl, channelPolicy, ua::MessageSecurityMode::SignAndEncrypt, 10);
    auto tokenPolicy = make_token_policy("username", ua::UserTokenType::UserName);
    tokenPolicy.security_policy_uri() = std::move(tokenPolicyUri);
    endpoint.user_identity_tokens().push_back(std::move(tokenPolicy));
    openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));
    use_stub_server_certificate_decoder();

    const EstablishResult result = establish(build_connect_plan(config));
    EXPECT_TRUE(result.is_good()) << result.status_code().value();
    if (!result.is_good() || !openFixture.channel->createConfig.has_value())
      return {};
    return openFixture.channel->createConfig->ecdhPolicyUri;
  }

  /// Connects AutoBest with an Anonymous identity to the one ECC_nistP256_AesGcm SignAndEncrypt endpoint,
  /// which advertises a token policy of each of `tokenTypes`, and returns whether the plan's CreateSession
  /// asks for an EphemeralKey (nullopt when the connect failed).
  std::optional<bool> anonymous_connect_requests_ephemeral_key(std::vector<ua::UserTokenType> tokenTypes)
  {
    ConnectionConfig config;
    config.endpointUrl = "opc.tcp://server.example:4840";
    config.endpointSelection = ua::client::EndpointSelection::AutoBest;

    auto endpoint = advertised_endpoint(config.endpointUrl,
      ua::SecurityPolicyId::EccNistP256AesGcm,
      ua::MessageSecurityMode::SignAndEncrypt,
      10);
    for (const auto type : tokenTypes)
      endpoint.user_identity_tokens().push_back(make_token_policy(ua::to_string(type), type));
    openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));
    use_stub_server_certificate_decoder();

    const EstablishResult result = establish(build_connect_plan(config));
    EXPECT_TRUE(result.is_good()) << result.status_code().value();
    if (!result.is_good() || !openFixture.channel->createConfig.has_value())
      return std::nullopt;
    return openFixture.channel->createConfig->requestEphemeralKey;
  }

  void expect_auto_best_rejects_policy(std::string policyUri)
  {
    ConnectionConfig config;
    config.endpointUrl = "opc.tcp://server.example:4840";
    config.endpointSelection = ua::client::EndpointSelection::AutoBest;

    ua::EndpointDescription endpoint;
    endpoint.endpoint_url() = config.endpointUrl;
    endpoint.security_mode() = ua::MessageSecurityMode::None;
    endpoint.security_policy_uri() = policyUri;
    endpoint.security_level() = 255;
    openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

    const EstablishResult result = establish(build_connect_plan(config));

    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadSecurityPolicyRejected});
    EXPECT_EQ(openFixture.openCalls.load(), 1u)
      << "only the None discovery channel may open; the rejected endpoint must not reach final OPN";
    ASSERT_NE(result.shared_detail(), nullptr);
    const auto context = std::ranges::find_if(result.shared_detail()->context,
      [](const ua::NamedValue& value) { return value.key == ua::ContextKeys::securityPolicy.value(); });
    ASSERT_NE(context, result.shared_detail()->context.end())
      << "the rejection must carry structured security.policy context, including for an empty URI";
    EXPECT_EQ(context->value, policyUri);
  }
};

TEST_F(EstablisherFixture, HappyPathBuildsUnstartedConnectingConnection)
{
  openFixture.channel->session->set_session_id(ua::NodeId{2, 77});

  const EstablishResult result = establish(valid_plan());

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  const auto connection = result.value();
  ASSERT_NE(connection, nullptr);
  EXPECT_EQ(connection->info()->state, ua::client::detail::ConnectionState::Connecting)
    << "the establisher constructs but does NOT start the connection";
  EXPECT_EQ(connection->info()->sessionId, ua::NodeId(2, 77));
  EXPECT_EQ(openFixture.openCalls.load(), 1u);
  EXPECT_EQ(openFixture.channel->createCalls.load(), 1u);
  EXPECT_EQ(openFixture.channel->session->activateOnBound.call_count(), 1u);
  EXPECT_EQ(openFixture.channel->session->close.call_count(), 0u) << "no cleanup close on the happy path";
}

// @verifies CL-DISC-004
// A discovery-driven managed connect must retain the complete unauthenticated GetEndpoints set and forward
// it to the real CreateSession verification boundary. If the establisher dropped the evidence, the captured
// config would be empty and SessionImpl could not perform the mandatory authenticated comparison.
// @relation(CL-DISC-004, scope=function)
TEST_F(EstablisherFixture, AutoBestForwardsDiscoveryEvidenceToCreateSession)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint =
    true;  // the None endpoint is incidental (anonymous identity): the subject is the policy id

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.security_mode() = ua::MessageSecurityMode::None;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None);
  endpoint.security_level() = 1;
  openFixture.channel->getEndpointsResponse.endpoints().push_back(endpoint);

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(openFixture.openCalls.load(), 2u) << "one discovery channel plus one selected endpoint channel";
  EXPECT_EQ(openFixture.channel->getEndpointsCalls.load(), 1u);
  EXPECT_EQ(openFixture.channel->closeCalls.load(), 1u);
  ASSERT_TRUE(openFixture.channel->createConfig.has_value());
  ASSERT_EQ(openFixture.channel->createConfig->discoveryEndpoints.size(), 1u);
  EXPECT_EQ(openFixture.channel->createConfig->discoveryEndpoints.front(), endpoint);
}

TEST_F(EstablisherFixture, AutoBestPlansEcdhForSelectedUserTokenPolicy)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};
  config.userTokenPolicyId = "username-p256";

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.server().application_uri() = "urn:server";
  endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.security_policy_uri() =
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::EccNistP384AesGcm);
  endpoint.security_level() = 10;
  endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
  ua::UserTokenPolicy tokenPolicy;
  tokenPolicy.policy_id() = config.userTokenPolicyId;
  tokenPolicy.token_type() = ua::UserTokenType::UserName;
  tokenPolicy.security_policy_uri() =
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::EccNistP256AesGcm);
  endpoint.user_identity_tokens().push_back(std::move(tokenPolicy));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(endpoint);
  certificateDecoder = [](const ua::ByteString&)
  {
    std::shared_ptr<const ua::X509Certificate> certificate =
      std::make_shared<UriStubCertificate>(std::vector<std::string>{"urn:server"});
    return ua::Result<std::shared_ptr<const ua::X509Certificate>>{std::move(certificate)};
  };

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_TRUE(openFixture.channel->createConfig.has_value());
  EXPECT_EQ(openFixture.channel->createConfig->ecdhPolicyUri,
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::EccNistP256AesGcm))
    << "CreateSession must request the planned UserTokenPolicy's ECC key, not the channel's curve";
}

// RSA_DH agrees keys in the ffdhe3072 group, not on a curve, but asks for its EphemeralKey through the same
// ECDHPolicyUri (Part 6 Table 63): a UserName token policy naming the other RSA_DH policy than the channel's
// needs that policy's key (Part 4 7.41 lets a token policy differ from the channel's only within one public
// key algorithm), and a token policy that inherits an RSA_DH channel's policy needs the channel's.
// @relation(AC-CL-SCE-009-EPHEMERAL-KEY-REQUESTED-FOR-RSA-DH, scope=function)
TEST_F(EstablisherFixture, AutoBestPlansTheKeyOfTheTokenPolicyNotOfTheRsaDhChannel)
{
  EXPECT_EQ(planned_ecdh_policy_uri(ua::SecurityPolicyId::RsaDhChaChaPoly,
              std::string{ua::utils::get_security_policy_uri(ua::SecurityPolicyId::RsaDhAesGcm)}),
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::RsaDhAesGcm));
}

// @relation(AC-CL-SCE-009-EPHEMERAL-KEY-REQUESTED-FOR-RSA-DH, scope=function)
TEST_F(EstablisherFixture, AutoBestPlansTheRsaDhChannelsKeyForATokenPolicyThatInheritsIt)
{
  EXPECT_EQ(planned_ecdh_policy_uri(ua::SecurityPolicyId::RsaDhChaChaPoly, std::string{}),
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::RsaDhChaChaPoly))
    << "an empty token-policy URI inherits the channel's policy (Part 4 7.42)";
}

// Control: a token policy without key agreement over an RSA_DH channel (the same RSA key, Part 4 7.41) still
// names the channel's policy, so
// the Server returns the next EphemeralKey for a later activation instead of refusing ECDHPolicyUri=None.
// @relation(AC-CL-SCE-009-EPHEMERAL-KEY-REQUESTED-FOR-RSA-DH, scope=function)
TEST_F(EstablisherFixture, AutoBestPlansTheRsaDhChannelsKeyForALegacyTokenPolicy)
{
  EXPECT_EQ(planned_ecdh_policy_uri(ua::SecurityPolicyId::RsaDhAesGcm,
              std::string{ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256)}),
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::RsaDhAesGcm));
}

// OPC 10000-6 6.8.2 (interoperability finding 021): the EphemeralKey a CreateSession over a key-agreement
// channel asks for encrypts a UserName or IssuedToken secret. An endpoint that offers neither can never use
// it, and a Server may fault the request instead of answering Bad_SecurityPolicyRejected in the ECDHKey slot
// (Eclipse Milo 1.2.0-RC1), so the managed connect does not ask there. Falsifiable: the former client asked
// on every key-agreement channel.
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST_F(EstablisherFixture, AnEndpointOfferingNoSecretTokenPolicyIsAskedForNoEphemeralKey)
{
  EXPECT_EQ(
    anonymous_connect_requests_ephemeral_key({ua::UserTokenType::Anonymous, ua::UserTokenType::Certificate}),
    std::optional<bool>{false});
}

// control: an endpoint that also offers a UserName policy is asked even for an Anonymous connect, so that a
// later Connection::reactivate with a UserName identity has its key (CL-ECC-003 NOTES).
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST_F(EstablisherFixture, AnEndpointOfferingAUserNamePolicyIsAskedForAnEphemeralKey)
{
  EXPECT_EQ(
    anonymous_connect_requests_ephemeral_key({ua::UserTokenType::Anonymous, ua::UserTokenType::UserName}),
    std::optional<bool>{true});
}

// control: the same for an IssuedToken policy, whose secret the EphemeralKey also protects.
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST_F(EstablisherFixture, AnEndpointOfferingAnIssuedTokenPolicyIsAskedForAnEphemeralKey)
{
  EXPECT_EQ(
    anonymous_connect_requests_ephemeral_key({ua::UserTokenType::Anonymous, ua::UserTokenType::IssuedToken}),
    std::optional<bool>{true});
}

// The discovery-driven managed path is the only place on that path that holds the endpoint's advertised
// UserTokenPolicies, so it is the one that must name the policy an authenticated identity activates under.
// Part 4 section 7.42 forbids the client inventing a policyId, and tier-0 refuses a non-anonymous identity
// carrying none (client.tier0.token_builder.missing_policy_id) - so without this the whole AutoBest /
// FirstMatching path could not open an authenticated Session, exactly as easy_connect could not.
//
// Falsifiability: the endpoint advertises an ANONYMOUS policy FIRST, so an establisher that named the first
// entry rather than the one matching the identity fails on the value, not on emptiness.
// Traceability: deliberately uncited. qa_process.md section 1.1 freezes new requirement-level
// citations, and no AC-CL-IDENT-* criterion exists yet for R10 to have authored. Re-point these
// rows onto their criteria when it does; the neighbouring ECDH row is uncited for the same reason.
TEST_F(EstablisherFixture, AutoBestNamesTheAdvertisedUsernamePolicyForAnAuthenticatedIdentity)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();  // the endpoint is incidental (secured, so a user name may travel)
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.server().application_uri() = "urn:server";
  endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);
  endpoint.security_level() = 1;
  endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
  endpoint.user_identity_tokens().push_back(make_token_policy("anon-1", ua::UserTokenType::Anonymous));
  endpoint.user_identity_tokens().push_back(make_token_policy("user-1", ua::UserTokenType::UserName));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(openFixture.channel->session->captured_activate_config().policyId, "user-1")
    << "the discovery-driven path must name the advertised USERNAME policy the identity activates under";
}

// FirstMatching resolves its endpoint from the same discovery response, so it carries the same obligation.
TEST_F(EstablisherFixture, FirstMatchingNamesTheAdvertisedCertificatePolicyForAnX509Identity)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::FirstMatching;
  config.securityMode = ua::MessageSecurityMode::None;
  config.securityPolicyId = ua::SecurityPolicyId::None;
  config.identity = ua::client::X509Identity{
    std::make_shared<UriStubCertificate>(std::vector<std::string>{"urn:user"}), nullptr};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.security_mode() = ua::MessageSecurityMode::None;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None);
  endpoint.security_level() = 1;
  endpoint.user_identity_tokens().push_back(make_token_policy("user-1", ua::UserTokenType::UserName));
  endpoint.user_identity_tokens().push_back(make_token_policy("cert-2", ua::UserTokenType::Certificate));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(openFixture.channel->session->captured_activate_config().policyId, "cert-2");
}

// section 3.1 finding, fixed here: first-match is not good enough when an endpoint advertises more than one
// policy of the required kind. A UserName policy whose own SecurityPolicy is None presents the password as
// plaintext, which the token builder refuses outright unless the application set `allowUnencryptedPassword`
// - so naming it would hand the caller a policy that cannot be used, purely because the Server happened to
// list it first. The derivation must prefer a policy that protects the secret.
//
// Falsifiability: the plaintext policy is advertised FIRST, so a first-match resolver picks "user-plain"
// and fails on the value.
TEST_F(EstablisherFixture, DiscoveryPrefersASecuredUserTokenPolicyOverAPlaintextOne)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();  // the endpoint is incidental (secured, so a user name may travel)
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.server().application_uri() = "urn:server";
  endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);
  endpoint.security_level() = 1;
  endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
  auto plain = make_token_policy("user-plain", ua::UserTokenType::UserName);
  plain.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None);
  endpoint.user_identity_tokens().push_back(std::move(plain));
  auto secured = make_token_policy("user-secured", ua::UserTokenType::UserName);
  secured.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);
  endpoint.user_identity_tokens().push_back(std::move(secured));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(openFixture.channel->session->captured_activate_config().policyId, "user-secured")
    << "advertised order must not decide whether the password travels in the clear";
}

// The fallback still stands: when a plaintext policy is the ONLY one of the required kind, name it, so the
// refusal comes from the token builder's opt-in gate with its own diagnosis rather than from an empty id.
// A policy with an EMPTY SecurityPolicy URI inherits the channel's, so it is not plaintext and is eligible.
TEST_F(EstablisherFixture, DiscoveryStillNamesAPlaintextPolicyWhenItIsTheOnlyOne)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();  // the endpoint is incidental (secured, so a user name may travel)
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.server().application_uri() = "urn:server";
  endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);
  endpoint.security_level() = 1;
  endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
  auto plain = make_token_policy("user-plain", ua::UserTokenType::UserName);
  plain.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None);
  endpoint.user_identity_tokens().push_back(std::move(plain));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(openFixture.channel->session->captured_activate_config().policyId, "user-plain")
    << "the token builder owns the opt-in refusal; leaving the id empty would replace its diagnosis";
}

// A caller who named a policy id owns the choice: discovery must not overwrite it. The endpoint advertises
// two USERNAME policies so a resolver that re-derived by token type alone would pick the wrong one.
TEST_F(EstablisherFixture, DiscoveryKeepsACallerSuppliedUserTokenPolicyId)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();  // the endpoint is incidental (secured, so a user name may travel)
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};
  config.userTokenPolicyId = "user-legacy";

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.server().application_uri() = "urn:server";
  endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);
  endpoint.security_level() = 1;
  endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
  endpoint.user_identity_tokens().push_back(make_token_policy("user-modern", ua::UserTokenType::UserName));
  endpoint.user_identity_tokens().push_back(make_token_policy("user-legacy", ua::UserTokenType::UserName));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_EQ(openFixture.channel->session->captured_activate_config().policyId, "user-legacy")
    << "an explicit caller choice must survive discovery";
}

// A caller who supplied a server certificate owns the choice, as for userTokenPolicyId (owner decision
// 2026-10-03, BR-21): discovery fills it only when empty, so a pinned certificate reaches the
// OpenSecureChannel (which still validates it). Control: with none supplied, the discovered certificate is
// used. Falsifiable: the former establisher always replaced it with the discovered one.
TEST_F(EstablisherFixture, DiscoveryKeepsACallerSuppliedServerCertificate)
{
  for (const bool supplied : {true, false})
  {
    SCOPED_TRACE(supplied ? "a certificate supplied by the caller" : "none supplied");
    openConfigs.clear();
    ConnectionConfig config;
    config.endpointUrl = "opc.tcp://server.example:4840";
    config.endpointSelection = ua::client::EndpointSelection::FirstMatching;
    config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
    config.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    use_stub_server_certificate_decoder();
    const std::shared_ptr<const ua::X509Certificate> pinned =
      std::make_shared<UriStubCertificate>(std::vector<std::string>{"urn:server"});
    if (supplied)
      config.serverCertificate = pinned;

    ua::EndpointDescription endpoint;
    endpoint.endpoint_url() = config.endpointUrl;
    endpoint.server().application_uri() = "urn:server";
    endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
    endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);
    endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
    openFixture.channel->getEndpointsResponse.endpoints().payload() = {endpoint};

    const EstablishResult result = establish(build_connect_plan(config));

    ASSERT_TRUE(result.is_good()) << result.status_code().value();
    ASSERT_FALSE(openConfigs.empty());
    ASSERT_NE(openConfigs.back().serverCertificate, nullptr);
    if (supplied)
      EXPECT_EQ(openConfigs.back().serverCertificate.get(), pinned.get()) << "the caller's certificate wins";
    else
      EXPECT_NE(openConfigs.back().serverCertificate.get(), pinned.get()) << "discovery fills an empty field";
  }
}

// The first of two deliberate no-ops: an anonymous identity's ANONYMOUS policy is tier-0's to select at
// activation, so discovery naming it here would change nothing and would widen the scope of change of this
// selection to the one case that already works.
TEST_F(EstablisherFixture, DiscoveryLeavesThePolicyIdEmptyForAnAnonymousIdentity)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint =
    true;  // the None endpoint is incidental (anonymous identity): the subject is the policy id
  config.identity = ua::client::AnonymousIdentity{};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.security_mode() = ua::MessageSecurityMode::None;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None);
  endpoint.security_level() = 1;
  endpoint.user_identity_tokens().push_back(make_token_policy("anon-1", ua::UserTokenType::Anonymous));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_TRUE(openFixture.channel->session->captured_activate_config().policyId.empty())
    << "an anonymous identity's ANONYMOUS policy is tier-0's to select at activation";
}

// The second: an endpoint advertising no policy of the required kind must leave the field empty, so the
// refusal comes from the token builder with its own diagnosis rather than from a policy id the server never
// offered. Part 4 section 7.42 - the client may not invent one.
TEST_F(EstablisherFixture, DiscoveryLeavesThePolicyIdEmptyWhenNoPolicyOfTheRequiredKindIsAdvertised)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();  // the endpoint is incidental (secured, so a user name may travel)
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.server().application_uri() = "urn:server";
  endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);
  endpoint.security_level() = 1;
  endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
  endpoint.user_identity_tokens().push_back(make_token_policy("anon-1", ua::UserTokenType::Anonymous));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_TRUE(openFixture.channel->session->captured_activate_config().policyId.empty())
    << "no advertised USERNAME policy means there is no id to name, and tier-0 owns the diagnosis";
}

// @verifies CL-DISC-011
// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// @relation(CL-DISC-011, scope=function)
// Restated with CL-DISC-019 (AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED): the earlier form of this arm had a
// None endpoint at the highest advertised securityLevel win, which is the downgrade the requirement forbids.
// Its purpose is kept - the unknown policy at level 255 is never opened and the strongest SUPPORTED endpoint
// is - with "strongest" now the client's own ordering of policy and mode. The winner sits on another host on
// purpose: a secured endpoint keeps its advertised URL, which the OPN trust decision binds.
TEST_F(EstablisherFixture, AutoBestChoosesTheStrongestSupportedEndpointAndIgnoresUnknownPolicy)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();

  const auto low = advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::Sign, 1);
  auto unknown = low;
  unknown.security_policy_uri() = "urn:unsupported:policy";
  unknown.security_level() = 255;
  const auto high = advertised_endpoint("opc.tcp://selected.example:4840",
    ua::SecurityPolicyId::Basic256Sha256,
    ua::MessageSecurityMode::SignAndEncrypt,
    10);
  openFixture.channel->getEndpointsResponse.endpoints().payload() = {low, unknown, high};

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().endpointUrl, "opc.tcp://selected.example:4840");
  EXPECT_EQ(openConfigs.back().securityMode, ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_EQ(openConfigs.back().securityPolicyId, ua::SecurityPolicyId::Basic256Sha256);
}

// @verifies AC-CL-DISC-019-AUTOBEST-REFUSES-AN-UNSECURED-ENDPOINT-WITHOUT-THE-OPT-IN
// The list a stripped GetEndpoints leaves behind: one None/None endpoint at the top level. Without the
// per-connection opt-in nothing is selectable, and the refusal happens before any OPN to the endpoint.
TEST_F(EstablisherFixture, AutoBestRefusesAnUnsecuredOnlyListWithoutTheOptIn)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  openFixture.channel->getEndpointsResponse.endpoints().push_back(
    advertised_endpoint(config.endpointUrl, ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, 255));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityModeRejected);
  EXPECT_EQ(detail_code_of(result), "AutoBestUnsecuredEndpointRefused");
  EXPECT_EQ(openFixture.openCalls.load(), 1u) << "only the discovery channel may open";
  EXPECT_EQ(openFixture.channel->createCalls.load(), 0u) << "no Session is created over the refused endpoint";
}

// @verifies AC-CL-DISC-019-AUTOBEST-REFUSES-AN-UNSECURED-ENDPOINT-WITHOUT-THE-OPT-IN
// The control: one field differs from the arm above.
TEST_F(EstablisherFixture, AutoBestSelectsAnUnsecuredEndpointOnlyWhenOptedIn)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint = true;
  openFixture.channel->getEndpointsResponse.endpoints().push_back(
    advertised_endpoint(config.endpointUrl, ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, 255));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().securityMode, ua::MessageSecurityMode::None);
  EXPECT_EQ(openConfigs.back().securityPolicyId, ua::SecurityPolicyId::None);
}

// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// The None endpoint is a candidate here (opted in) so that only the ranking excludes it: a selector that
// still sorts on the advertised level opens the None endpoint at 255 instead of SignAndEncrypt at 1.
TEST_F(EstablisherFixture, AutoBestIgnoresAServerInflatedSecurityLevel)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint = true;
  use_stub_server_certificate_decoder();
  openFixture.channel->getEndpointsResponse.endpoints().payload() = {
    advertised_endpoint(config.endpointUrl, ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, 255),
    advertised_endpoint(
      config.endpointUrl, ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt, 1)};

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().securityMode, ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_EQ(openConfigs.back().securityPolicyId, ua::SecurityPolicyId::Basic256Sha256);
}

// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// Two secured endpoints: the client's table ranks ECC above Basic256Sha256; the advertised level says the
// opposite by a wide margin.
TEST_F(EstablisherFixture, AutoBestPrefersTheClientRankingOverSecurityLevel)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();
  openFixture.channel->getEndpointsResponse.endpoints().payload() = {
    advertised_endpoint(
      config.endpointUrl, ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt, 200),
    advertised_endpoint(config.endpointUrl,
      ua::SecurityPolicyId::EccNistP256AesGcm,
      ua::MessageSecurityMode::SignAndEncrypt,
      1)};

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().securityPolicyId, ua::SecurityPolicyId::EccNistP256AesGcm);
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-STAYS-ON-THE-DIALLED-HOST
// Opted in, so the gate is open; what refuses the endpoint is the host it names.
TEST_F(EstablisherFixture, AutoBestRefusesAnUnsecuredEndpointOnAnotherHost)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint = true;
  openFixture.channel->getEndpointsResponse.endpoints().push_back(advertised_endpoint(
    "opc.tcp://elsewhere.example:4840", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, 1));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityChecksFailed);
  EXPECT_EQ(detail_code_of(result), "UnsecuredEndpointHostChanged");
  EXPECT_EQ(openFixture.openCalls.load(), 1u) << "nothing is opened to the advertised host";
  ASSERT_NE(result.shared_detail(), nullptr);
  const auto context = std::ranges::find_if(result.shared_detail()->context,
    [](const ua::NamedValue& value) { return value.key == ua::ContextKeys::endpointUrl.value(); });
  ASSERT_NE(context, result.shared_detail()->context.end());
  EXPECT_EQ(context->value, "opc.tcp://elsewhere.example:4840");
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-IS-ANONYMOUS-ONLY
// Opted in and on the dialled host, so both other gates are open; the identity is what refuses the endpoint.
TEST_F(EstablisherFixture, AutoBestRefusesAnUnsecuredEndpointForANonAnonymousIdentity)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint = true;
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};
  auto endpoint =
    advertised_endpoint(config.endpointUrl, ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, 1);
  endpoint.user_identity_tokens().push_back(make_token_policy("user-1", ua::UserTokenType::UserName));
  openFixture.channel->getEndpointsResponse.endpoints().push_back(std::move(endpoint));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityModeRejected);
  EXPECT_EQ(detail_code_of(result), "AutoBestUnsecuredRequiresAnonymous");
  EXPECT_EQ(openFixture.openCalls.load(), 1u) << "the password must never reach an unsecured channel";
}

// @verifies AC-CL-DISC-019-AUTOBEST-REFUSES-AN-UNSECURED-ENDPOINT-WITHOUT-THE-OPT-IN
// "Unsecured" is mode None OR policy None. A hostile list can carry policy None under a signing mode; the
// ranker scores it above zero, so only the policy half of the rule keeps it out.
TEST_F(EstablisherFixture, AutoBestTreatsAPolicyNoneEndpointAsUnsecuredWhateverItsMode)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  openFixture.channel->getEndpointsResponse.endpoints().push_back(advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::None, ua::MessageSecurityMode::SignAndEncrypt, 1));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(detail_code_of(result), "AutoBestUnsecuredEndpointRefused");
  EXPECT_EQ(openFixture.openCalls.load(), 1u);
}

// @verifies AC-CL-DISC-019-AUTOBEST-REFUSES-AN-UNSECURED-ENDPOINT-WITHOUT-THE-OPT-IN
// The other half: a secured policy under mode None is unsecured too (nothing is signed or encrypted).
TEST_F(EstablisherFixture, AutoBestTreatsAModeNoneEndpointAsUnsecuredWhateverItsPolicy)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();
  openFixture.channel->getEndpointsResponse.endpoints().push_back(advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::None, 1));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(detail_code_of(result), "AutoBestUnsecuredEndpointRefused");
  EXPECT_EQ(openFixture.openCalls.load(), 1u);
}

// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// Where the client's table cannot separate two endpoints, the advertised level still may: two identical
// secured offers on different paths, and the higher level is the one opened.
TEST_F(EstablisherFixture, AutoBestBreaksATieOnTheAdvertisedSecurityLevel)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();
  openFixture.channel->getEndpointsResponse.endpoints().payload() = {
    advertised_endpoint("opc.tcp://server.example:4840/low",
      ua::SecurityPolicyId::Basic256Sha256,
      ua::MessageSecurityMode::SignAndEncrypt,
      1),
    advertised_endpoint("opc.tcp://server.example:4840/high",
      ua::SecurityPolicyId::Basic256Sha256,
      ua::MessageSecurityMode::SignAndEncrypt,
      10)};

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().endpointUrl, "opc.tcp://server.example:4840/high");
}

// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// A policy the client's table scores zero (deprecated Basic128Rsa15) is implemented but never selected, the
// same as under easy_connect; the refusal names the ranking rather than opening the deprecated endpoint.
TEST_F(EstablisherFixture, AutoBestNeverSelectsADeprecatedPolicy)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();
  openFixture.channel->getEndpointsResponse.endpoints().push_back(advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::Basic128Rsa15, ua::MessageSecurityMode::SignAndEncrypt, 255));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityPolicyRejected);
  EXPECT_EQ(detail_code_of(result), "NoSupportedDiscoveryEndpoint");
  EXPECT_EQ(openFixture.openCalls.load(), 1u) << "the deprecated endpoint is never opened";
}

// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// Basic256 is deprecated yet keeps a non-zero score, so a list that offers nothing else, at the highest
// level a server can set, would have AutoBest open it and the open then refuse it. The application's
// default keeps deprecated policies out of the candidate set, as the Discovery facade does, so the selection
// itself refuses the list.
TEST_F(EstablisherFixture, AutoBestSkipsADeprecatedPolicyWhateverItsLevel)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();
  openFixture.channel->getEndpointsResponse.endpoints().push_back(advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::Basic256, ua::MessageSecurityMode::SignAndEncrypt, 255));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), ua::Status::BadSecurityPolicyRejected);
  EXPECT_EQ(detail_code_of(result), "NoSupportedDiscoveryEndpoint");
  EXPECT_EQ(openFixture.openCalls.load(), 1u) << "the deprecated endpoint is never opened";
}

// @verifies AC-CL-DISC-019-SECURITYLEVEL-IS-NOT-TRUSTED
// The control: with the application's opt-in the same list opens the deprecated policy.
TEST_F(EstablisherFixture, AutoBestRanksADeprecatedPolicyOnlyWhenTheApplicationAllowsIt)
{
  allowDeprecatedSecurityPolicies = true;
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();
  openFixture.channel->getEndpointsResponse.endpoints().push_back(advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::Basic256, ua::MessageSecurityMode::SignAndEncrypt, 255));

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().securityPolicyId, ua::SecurityPolicyId::Basic256);
}

// @verifies AC-CL-DISC-019-AN-UNSECURED-WINNER-STAYS-ON-THE-DIALLED-HOST
// A multi-homed server lists one unsecured copy per host name. The copy on another host is listed first
// and ties with the dialled-host copy on every ranking key; it must not shadow the usable one.
TEST_F(EstablisherFixture, AutoBestPrefersTheUnsecuredCopyOnTheDialledHost)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint = true;
  openFixture.channel->getEndpointsResponse.endpoints().payload() = {
    advertised_endpoint(
      "opc.tcp://plc-a.example:4840", ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, 1),
    advertised_endpoint(config.endpointUrl, ua::SecurityPolicyId::None, ua::MessageSecurityMode::None, 1)};

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().endpointUrl, "opc.tcp://server.example:4840");
}

// @verifies AC-CL-DISC-019-AUTOBEST-REFUSES-AN-UNSECURED-ENDPOINT-WITHOUT-THE-OPT-IN
// Opted in, with a user name: an unauthenticated list labels an unsecured endpoint with an ECC policy, which
// the table would score above RSA SignAndEncrypt. An unsecured endpoint scores as None/None whatever its
// policy, so the secured offer wins and the user name travels encrypted; the connect completes.
TEST_F(EstablisherFixture, AutoBestPrefersASecuredEndpointOverAnOptedInUnsecuredEccEndpoint)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  config.allowUnsecuredEndpoint = true;
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};
  use_stub_server_certificate_decoder();
  auto secured = advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt, 1);
  secured.user_identity_tokens().push_back(make_token_policy("user-1", ua::UserTokenType::UserName));
  auto unsecured = advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::EccNistP256AesGcm, ua::MessageSecurityMode::None, 255);
  unsecured.user_identity_tokens().push_back(make_token_policy("user-1", ua::UserTokenType::UserName));
  openFixture.channel->getEndpointsResponse.endpoints().payload() = {unsecured, secured};

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().securityMode, ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_EQ(openConfigs.back().securityPolicyId, ua::SecurityPolicyId::Basic256Sha256);
}

// @verifies CL-DISC-011
// @relation(CL-DISC-011, scope=function)
TEST_F(EstablisherFixture, AutoBestRejectsEmptySecurityPolicyUri)
{
  expect_auto_best_rejects_policy("");
}

// @verifies CL-DISC-011
// @relation(CL-DISC-011, scope=function)
TEST_F(EstablisherFixture, AutoBestRejectsMalformedSecurityPolicyUri)
{
  expect_auto_best_rejects_policy("not-a-valid-uri");
}

// @verifies CL-DISC-011
// @relation(CL-DISC-011, scope=function)
TEST_F(EstablisherFixture, AutoBestRejectsUnsupportedSecurityPolicyUri)
{
  expect_auto_best_rejects_policy("http://opcfoundation.org/UA/SecurityPolicy#NotARealPolicy");
}

// The ECC policy URIs that 1.05.07 removed are unknown to the client: an endpoint offering one is rejected
// with Bad_SecurityPolicyRejected before any final OpenSecureChannel, as any unsupported URI is. Each URI is
// offered alone, by a fresh GetEndpoints response.
// @relation(AC-CL-SCE-001-REMOVED-URI-UNKNOWN, scope=function)
TEST_F(EstablisherFixture, AutoBestRejectsEveryRemovedEccPolicyUri)
{
  for (const char* removed : {
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_ChaCha20Poly1305",
         "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448_ChaCha20Poly1305",
       })
  {
    SCOPED_TRACE(removed);
    openFixture.channel->getEndpointsResponse.endpoints().payload().clear();
    openFixture.openCalls.store(0);
    expect_auto_best_rejects_policy(removed);
  }
}

// A single-shot plan (no automatic reconnect) installs the channel's error hook, so the Connection learns of
// a lost channel; an auto-reconnect plan leaves it to keep-alive and Publish (owner decision 2026-10-03,
// BR-19). Falsifiable: the former plan never installed it, so a single-shot Connection was never told.
// @relation(AC-CL-SESS-021-A-SINGLE-SHOT-CONNECTION-REPORTS-A-LOST-CHANNEL, scope=function)
TEST_F(EstablisherFixture, OnlyASingleShotPlanInstallsTheLostChannelHook)
{
  for (const bool singleShot : {true, false})
  {
    SCOPED_TRACE(singleShot ? "single-shot" : "auto-reconnect");
    openConfigs.clear();
    ConnectionConfig config;
    config.endpointUrl = "opc.tcp://server.example:4840";
    if (singleShot)
      config.reconnect = std::nullopt;
    else
      config.reconnect = ua::client::ReconnectPolicy{};
    const EstablishResult result = establish(build_connect_plan(config));
    ASSERT_TRUE(result.is_good()) << result.status_code().value();
    ASSERT_FALSE(openConfigs.empty());
    EXPECT_EQ(static_cast<bool>(openConfigs.back().onChannelError), singleShot);
  }
}

TEST_F(EstablisherFixture, FirstMatchingUsesRequestedModeAndPolicy)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::FirstMatching;
  config.securityMode = ua::MessageSecurityMode::None;
  config.securityPolicyId = ua::SecurityPolicyId::None;

  ua::EndpointDescription wrong;
  wrong.endpoint_url() = "opc.tcp://wrong.example:4840";
  wrong.security_mode() = ua::MessageSecurityMode::Sign;
  wrong.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None);
  ua::EndpointDescription match = wrong;
  match.endpoint_url() = "opc.tcp://match.example:4840";
  match.security_mode() = ua::MessageSecurityMode::None;
  openFixture.channel->getEndpointsResponse.endpoints().payload() = {wrong, match};

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(openConfigs.size(), 2u);
  EXPECT_EQ(openConfigs.back().endpointUrl, "opc.tcp://match.example:4840");
}

TEST_F(EstablisherFixture, DiscoveryChannelCloseFailureStopsBeforeFinalOpen)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  openFixture.channel->closeStatus = ua::StatusCode{ua::Status::BadConnectionClosed};

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadConnectionClosed});
  EXPECT_EQ(openFixture.openCalls.load(), 1u);
  ASSERT_NE(result.shared_detail(), nullptr);
}

// @verifies CL-DISC-012
// @relation(CL-DISC-012, scope=function)
TEST_F(EstablisherFixture, DiscoveryApplicationUriMismatchRejectedBeforeSecureOpen)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.server().application_uri() = "urn:claimed";
  endpoint.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);
  endpoint.security_level() = 10;
  endpoint.server_certificate() = ua::ByteString{std::vector<std::byte>{std::byte{0x01}}};
  openFixture.channel->getEndpointsResponse.endpoints().push_back(endpoint);
  certificateDecoder = [](const ua::ByteString&)
  {
    std::shared_ptr<const ua::X509Certificate> certificate =
      std::make_shared<UriStubCertificate>(std::vector<std::string>{"urn:certificate"});
    return ua::Result<std::shared_ptr<const ua::X509Certificate>>{std::move(certificate)};
  };

  const EstablishResult result = establish(build_connect_plan(config));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadCertificateUriInvalid});
  EXPECT_EQ(openFixture.openCalls.load(), 1u) << "mismatch must fail before the selected endpoint OPN";
  ASSERT_NE(result.shared_detail(), nullptr);
  const auto applicationUri = std::ranges::find_if(result.shared_detail()->context,
    [](const ua::NamedValue& value) { return value.key == ua::ContextKeys::applicationUri.value(); });
  ASSERT_NE(applicationUri, result.shared_detail()->context.end());
  EXPECT_EQ(applicationUri->value, "urn:claimed");
}

TEST_F(EstablisherFixture, OpenChannelFailurePropagatesWithoutCreatingSession)
{
  openFixture.openStatus = ua::StatusCode{ua::Status::BadConnectionRejected};

  const EstablishResult result = establish(valid_plan());

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{ua::Status::BadConnectionRejected}.value());
  EXPECT_EQ(openFixture.channel->createCalls.load(), 0u) << "CreateSession must not run after a failed open";
}

TEST_F(EstablisherFixture, CreateSessionFailurePropagatesWithoutActivating)
{
  openFixture.channel->createStatus = ua::StatusCode{ua::Status::BadTooManySessions};

  const EstablishResult result = establish(valid_plan());

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{ua::Status::BadTooManySessions}.value());
  EXPECT_EQ(openFixture.channel->createCalls.load(), 1u);
  EXPECT_EQ(openFixture.channel->session->activateOnBound.call_count(), 0u)
    << "ActivateSession must not run after a failed CreateSession";
}

TEST_F(EstablisherFixture, ActivateSessionFailureClosesTheCreatedSessionAndPropagates)
{
  openFixture.channel->session->activateOnBound.set_result(
    ua::VoidResult{ua::Status::BadIdentityTokenRejected});

  const EstablishResult result = establish(valid_plan());

  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{ua::Status::BadIdentityTokenRejected}.value())
    << "the ActivateSession failure status is what the user sees, not the close outcome";
  EXPECT_EQ(openFixture.channel->session->activateOnBound.call_count(), 1u);
  EXPECT_EQ(openFixture.channel->session->close.call_count(), 1u)
    << "a Created-but-not-Activated session must be CloseSession'd so it does not linger to session-timeout";
}

// The channel an Uncertain OpenSecureChannel answer opened is not used: no Session is created on it.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EstablisherFixture, UncertainOpenSecureChannelIsRefusedWithoutCreatingASession)
{
  openFixture.openStatus = ua::StatusCode{ua::Status::UncertainInitialValue};

  const EstablishResult result = establish(valid_plan());

  expect_uncertain_answer_refused(result, ua::Status::UncertainInitialValue);
  EXPECT_EQ(openFixture.channel->createCalls.load(), 0u) << "CreateSession must not run on a refused channel";
}

// An Uncertain CreateSession answer holding a Session is refused before ActivateSession, and the Session the
// server created is closed.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EstablisherFixture, UncertainCreateSessionIsRefusedAndTheCreatedSessionClosed)
{
  openFixture.channel->createStatus = ua::StatusCode{ua::Status::UncertainLastUsableValue};

  const EstablishResult result = establish(valid_plan());

  expect_uncertain_answer_refused(result, ua::Status::UncertainLastUsableValue);
  EXPECT_EQ(openFixture.channel->session->activateOnBound.call_count(), 0u)
    << "ActivateSession must not run on a refused Session";
  EXPECT_EQ(openFixture.channel->session->close.call_count(), 1u)
    << "the Session the server created must be closed";
}

// A ServiceFault with an Uncertain code on CreateSession carries no Session; the connect is refused as for
// one that does.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EstablisherFixture, UncertainCreateSessionFaultIsRefused)
{
  openFixture.channel->createStatus = ua::StatusCode{ua::Status::UncertainLastUsableValue};
  openFixture.channel->createHoldsSession = false;

  const EstablishResult result = establish(valid_plan());

  expect_uncertain_answer_refused(result, ua::Status::UncertainLastUsableValue);
  EXPECT_EQ(openFixture.channel->session->activateOnBound.call_count(), 0u);
}

// An Uncertain ActivateSession answer is refused, and the created Session is closed as for a Bad one.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EstablisherFixture, UncertainActivateSessionIsRefusedAndTheCreatedSessionClosed)
{
  openFixture.channel->session->activateOnBound.set_result(ua::VoidResult{ua::Status::UncertainSubNormal});

  const EstablishResult result = establish(valid_plan());

  expect_uncertain_answer_refused(result, ua::Status::UncertainSubNormal);
  EXPECT_EQ(openFixture.channel->session->close.call_count(), 1u)
    << "the Created-but-refused Session must be closed";
}

// Control for the refusals above: a Good subcode on ActivateSession is Good, so the Connection is built.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EstablisherFixture, GoodSubcodeOnActivateSessionBuildsTheConnection)
{
  openFixture.channel->session->activateOnBound.set_result(
    ua::VoidResult{ua::Status::GoodCompletesAsynchronously});

  const EstablishResult result = establish(valid_plan());

  ASSERT_TRUE(result.is_good()) << result.status_code().value();
  EXPECT_NE(result.value(), nullptr);
  EXPECT_EQ(openFixture.channel->session->close.call_count(), 0u);
}

// An Uncertain open of the session-less discovery channel is refused before GetEndpoints is sent.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EstablisherFixture, UncertainDiscoveryChannelOpenIsRefusedBeforeGetEndpoints)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  openFixture.openStatus = ua::StatusCode{ua::Status::UncertainInitialValue};

  const EstablishResult result = establish(build_connect_plan(config));

  expect_uncertain_answer_refused(result, ua::Status::UncertainInitialValue);
  EXPECT_EQ(openFixture.channel->getEndpointsCalls.load(), 0u);
}

// The endpoint is not selected from a GetEndpoints response whose ServiceResult is Uncertain: no secured
// channel is opened.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EstablisherFixture, UncertainGetEndpointsServiceResultIsRefusedBeforeTheSecureOpen)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  use_stub_server_certificate_decoder();
  openFixture.channel->getEndpointsResponse.response_header().service_result() =
    ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};
  openFixture.channel->getEndpointsResponse.endpoints().push_back(advertised_endpoint(
    config.endpointUrl, ua::SecurityPolicyId::Basic256Sha256, ua::MessageSecurityMode::SignAndEncrypt, 10));

  const EstablishResult result = establish(build_connect_plan(config));

  expect_uncertain_answer_refused(result, ua::Status::UncertainNotAllNodesAvailable);
  EXPECT_EQ(openFixture.openCalls.load(), 1u) << "only the discovery channel may open";
  EXPECT_EQ(openFixture.channel->createCalls.load(), 0u);
}

// A ServiceFault with an Uncertain code on GetEndpoints carries no endpoints; the connect is refused as for a
// response that does.
// @relation(AC-CL-STATUS-ROUTING-02-AN-UNCERTAIN-SERVICE-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED, scope=function)
TEST_F(EstablisherFixture, UncertainGetEndpointsFaultIsRefused)
{
  ConnectionConfig config;
  config.endpointUrl = "opc.tcp://server.example:4840";
  config.endpointSelection = ua::client::EndpointSelection::AutoBest;
  openFixture.channel->getEndpointsStatus = ua::StatusCode{ua::Status::UncertainNotAllNodesAvailable};

  const EstablishResult result = establish(build_connect_plan(config));

  expect_uncertain_answer_refused(result, ua::Status::UncertainNotAllNodesAvailable);
  EXPECT_EQ(openFixture.openCalls.load(), 1u) << "only the discovery channel may open";
}

TEST_F(EstablisherFixture, SingleShotPlanStillBuildsConnection)
{
  const EstablishResult result = establish(valid_plan(/*autoReconnect=*/false));

  ASSERT_TRUE(result.is_good());
  ASSERT_NE(result.value(), nullptr);
  EXPECT_EQ(result.value()->info()->state, ua::client::detail::ConnectionState::Connecting);
}

TEST_F(EstablisherFixture, AutoReconnectPlanReusesOpenFixtureForReconnectReopen)
{
  const EstablishResult result = establish(valid_plan(/*autoReconnect=*/true));
  ASSERT_TRUE(result.is_good());
  const auto connection = result.value();
  ASSERT_NE(connection, nullptr);
  ASSERT_EQ(openFixture.openCalls.load(), 1u) << "the initial open";

  // Drive the reconnect open-channel primitive: it must reuse the SAME open interface the establisher
  // threaded into the reconnect wiring, so the open counter advances (proving reopen is not a fresh /
  // downgraded path).
  std::promise<ua::VoidResult> reopened;
  ConnectionImplTestAccess::reconnect_open_secure_channel(
    *connection, [&reopened](ua::VoidResult done) { reopened.set_value(std::move(done)); });
  EXPECT_TRUE(reopened.get_future().get().is_good());
  EXPECT_EQ(openFixture.openCalls.load(), 2u) << "a reconnect reopen must reuse the initial open interface";
}

// Builds an establisher WITH a serverCertValidatorFactory and drives a single establish through to a bad/good
// result while recording each interface invocation. Used by the two wiring tests below.
using ValidatorInterface = std::function<void(std::function<void(ua::VoidResult)>)>;

// CL-SECADMIN-004 / CL-PULLCRT-006: an auto-reconnect plan threads the factory-produced server-cert validator
// into the Connection, so ConnectionImpl::revalidate_server_cert_async invokes it. Falsifiable: an
// establisher that dropped the factory would leave the connection with no validator and the interface would
// never be called.
TEST_F(EstablisherFixture, AutoReconnectPlanThreadsServerCertValidatorIntoTheConnection)
{
  auto validatorCalls = std::make_shared<std::atomic<int>>(0);
  RealConnectionEstablisher establisher(
    runtime.executor(),
    ua::Logger{},
    [this](const ua::client::CoreClient::OpenChannelConfig&) { return openFixture.as_ops(); },
    [validatorCalls](const ua::client::CoreClient::OpenChannelConfig&) -> ValidatorInterface
    {
      return [validatorCalls](std::function<void(ua::VoidResult)> verdict)
      {
        ++(*validatorCalls);
        verdict(
          ua::VoidResult{});  // Good: still trusted (no CertRotated side effect for a clean threading pin)
      };
    });

  EstablishResult captured{ua::StatusCode{ua::Status::BadInternalError}};
  bool fired = false;
  establisher.establish_async(valid_plan(/*autoReconnect=*/true),
    ObserverSlots{},
    [&](EstablishResult result)
    {
      captured = std::move(result);
      fired = true;
    });
  ASSERT_TRUE(fired);
  ASSERT_TRUE(captured.is_good());
  const auto connection = captured.value();
  ASSERT_NE(connection, nullptr);

  std::promise<ua::VoidResult> acked;
  ConnectionImplTestAccess::revalidate_server_cert_async(
    *connection, [&acked](ua::VoidResult r) { acked.set_value(std::move(r)); });
  acked.get_future().get();
  EXPECT_EQ(validatorCalls->load(), 1)
    << "the establisher must thread the factory-produced server-cert validator into the reconnect wiring";
}

// A single-shot plan has no reconnect wiring, so the validator interface is not installed (revalidate is a
// Good no-op). Falsifiable: wiring it onto a single-shot connection would bump the counter.
TEST_F(EstablisherFixture, SingleShotPlanInstallsNoServerCertValidator)
{
  auto validatorCalls = std::make_shared<std::atomic<int>>(0);
  RealConnectionEstablisher establisher(
    runtime.executor(),
    ua::Logger{},
    [this](const ua::client::CoreClient::OpenChannelConfig&) { return openFixture.as_ops(); },
    [validatorCalls](const ua::client::CoreClient::OpenChannelConfig&) -> ValidatorInterface
    {
      return [validatorCalls](std::function<void(ua::VoidResult)> verdict)
      {
        ++(*validatorCalls);
        verdict(ua::VoidResult{});
      };
    });

  EstablishResult captured{ua::StatusCode{ua::Status::BadInternalError}};
  bool fired = false;
  establisher.establish_async(valid_plan(/*autoReconnect=*/false),
    ObserverSlots{},
    [&](EstablishResult result)
    {
      captured = std::move(result);
      fired = true;
    });
  ASSERT_TRUE(fired);
  ASSERT_TRUE(captured.is_good());
  const auto connection = captured.value();
  ASSERT_NE(connection, nullptr);

  std::promise<ua::VoidResult> acked;
  ConnectionImplTestAccess::revalidate_server_cert_async(
    *connection, [&acked](ua::VoidResult r) { acked.set_value(std::move(r)); });
  acked.get_future().get();
  EXPECT_EQ(validatorCalls->load(), 0) << "a single-shot connection has no reconnect wiring -> no validator";
}
}  // namespace
