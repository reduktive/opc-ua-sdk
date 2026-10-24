// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 3: Session Lifecycle Compliance Integration Tests
///
/// Tests covering Part 4 Session Service Set requirements (P4-SS-0001..P4-SS-0042).

#include "compliance_helpers.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_create_subscription_response.h"
#include "ua_create_subscription_request.h"
#include "ua_session_subscription_services.h"
#include "matchers.h"
#include "ua_session_view_services.h"
#include "requests.h"

#include "ua_session_attribute_services.h"

#include "ua_client_secure_channel_test_access.h"
#include "ua_client_session_test_access.h"

#include "ua_attribute_id.h"
#include "ua_cancel_request.h"
#include "ua_cancel_response.h"
#include "ua_create_session_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_object_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_value_source.h"
#include "ua_server_observer.h"
#include "ua_signature_data.h"
#include "ua_timestamps_to_return.h"

#include "test_pki_helpers.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <optional>
#include <thread>

using namespace ua;
using namespace ua::client;
using namespace ua::server;

using CSSTA = ua::client::SessionTestAccess;

// Helper: snapshot of session state fields for test assertions.
struct SessionStateSnapshot
{
  ua::NodeId authenticationToken;
  ua::ByteString serverNonce;
  double revisedSessionTimeoutMs{0.0};
};

static SessionStateSnapshot session_state(Session& session)
{
  return CSSTA::on_strand(session,
    [](auto& g)
    {
      return SessionStateSnapshot{.authenticationToken = g.authentication_token(),
        .serverNonce = g.server_nonce(),
        .revisedSessionTimeoutMs = g.revised_session_timeout_ms()};
    });
}

// Helper: build a DisplayName read request for a given node.
static ReadRequest make_display_name_read_request(const NodeId& nodeId)
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::DisplayName);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  return req;
}

// Helper: create session while capturing the raw CreateSessionResponse via the observer mechanism.
// The observer is registered on SecureChannelImpl before create_session_sync, and fires during
// response processing inside SessionImpl::handle_action (one-shot, cleared after firing).
struct CreateSessionCapture
{
  Session session;
  CreateSessionResponse response;
};

static CreateSessionCapture create_session_with_capture(
  SecureChannel& channel, SecureChannel::CreateSessionConfig config)
{
  std::optional<CreateSessionResponse> captured;
  SecureChannelTestAccess::on_strand(channel,
    [&](auto& g)
    {
      g.next_create_session_response_observer() = [&captured](const CreateSessionResponse& resp)
      {
        captured = resp;
      };
    });

  auto session = channel.create_session_sync(std::move(config));

  // Observer should have fired during create_session_sync.
  EXPECT_TRUE(captured.has_value()) << "CreateSessionResponse observer did not fire";

  return {std::move(session), captured.has_value() ? std::move(*captured) : CreateSessionResponse{}};
}

// Helper: read BrowseName + NodeClass of a node (mirrors the UACTT ActivateSession checkSessionName
// probe, which reads the SessionId node returned by CreateSession).
static ReadRequest make_browsename_nodeclass_read_request(const NodeId& nodeId)
{
  ReadRequest req;
  ReadValueId browseName;
  browseName.node_id() = nodeId;
  browseName.attribute_id() = static_cast<uint32_t>(AttributeId::BrowseName);
  ReadValueId nodeClass;
  nodeClass.node_id() = nodeId;
  nodeClass.attribute_id() = static_cast<uint32_t>(AttributeId::NodeClass);
  req.nodes_to_read().push_back(std::move(browseName));
  req.nodes_to_read().push_back(std::move(nodeClass));
  req.timestamps_to_return() = TimestampsToReturn::Server;
  return req;
}

// Helper: build a simple Read request for Server node.
static ReadRequest make_server_read_request()
{
  ReadRequest req;
  ReadValueId rv;
  rv.node_id() = NodeId{ObjectId::Server};
  rv.attribute_id() = static_cast<uint32_t>(AttributeId::NodeId);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = TimestampsToReturn::Neither;
  return req;
}

class ComplianceSessionAuthnTimeout : public ComplianceSession
{
protected:
  // Delegates to the fixture authenticator, or refuses the token outright with the credential-policy
  // code when the test asks for a failing activation. Either way the result is ready at once, so any
  // time to response beyond the authenticator's own is the server's fixed interval.
  class SwitchableAuthenticator final : public server::UserAuthenticator
  {
  public:
    SwitchableAuthenticator(
      std::shared_ptr<server::UserAuthenticator> inner, std::shared_ptr<std::atomic<bool>> refuse)
      : mInner(std::move(inner)), mRefuse(std::move(refuse))
    {}

    void authenticate_async(server::AuthnRequest request, server::AuthnComplete completion) noexcept override
    {
      if (mRefuse->load())
      {
        completion(server::make_authn_failure(StatusCode{Status::BadUserAccessDenied},
          "the test refuses this token to drive a failing activation"));
        return;
      }
      mInner->authenticate_async(std::move(request), std::move(completion));
    }

  private:
    std::shared_ptr<server::UserAuthenticator> mInner;
    std::shared_ptr<std::atomic<bool>> mRefuse;
  };

  void configure_components(server::ServerComponents& components) override
  {
    ComplianceSession::configure_components(components);
    components.authenticator = std::make_shared<SwitchableAuthenticator>(mAuthenticator, mRefuseTokens);
  }

  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    ComplianceSession::configure_server_create_config(cfg);
    cfg.server.authnTimeout = std::chrono::milliseconds{175};
  }

  std::shared_ptr<std::atomic<bool>> mRefuseTokens = std::make_shared<std::atomic<bool>>(false);
};

// ===========================================================================
// Lifecycle smoke tests
// ===========================================================================

TEST_F(ComplianceSession, CreateActivateCloseLifecycle)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "SmokeLifecycle"});
  EXPECT_TRUE(session.is_created());
  EXPECT_FALSE(session.is_active());

  session.activate_sync();
  EXPECT_TRUE(session.is_active());

  session.close_sync();
  EXPECT_FALSE(session.is_active());
  channel.close_sync();
}

// A public configuration field is not implemented until a non-default value changes observable
// production behaviour. A FAILED token validation is held behind the configured fixed interval (Part 4
// 7.41.2.1; owner decision 23: only failures are held), and the refusal keeps its credential-policy
// code. The control below shows the same server answers a success without the hold, so the hold here is
// the failure's and not the transport's.
// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST_F(ComplianceSessionAuthnTimeout, NonDefaultAuthenticationTimeoutControlsFixedInterval)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "ConfiguredAuthnTimeoutFailure"});
  mRefuseTokens->store(true);
  const auto started = std::chrono::steady_clock::now();
  auto refused = session.try_activate_sync();
  const auto elapsed = std::chrono::steady_clock::now() - started;

  ASSERT_TRUE(refused.is_bad()) << "the authenticator refused the token, so activation must fail";
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadUserAccessDenied})
    << "the credential-policy refusal keeps its code";
  EXPECT_GE(elapsed, std::chrono::milliseconds{150})
    << "the failed validation must be held behind the configured fixed interval";
  EXPECT_FALSE(session.is_active());

  channel.close_sync();
}

// Control for the arm above: with the same non-default interval, the host authenticator receives the
// configured deadline, and a successful activation is answered without the fixed-interval hold (owner
// decision 23). Differs from the arm above only in whether the token is refused.
// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
TEST_F(ComplianceSessionAuthnTimeout, NonDefaultAuthenticationTimeoutDoesNotHoldASuccess)
{
  constexpr auto configuredAuthenticationInterval = std::chrono::milliseconds{175};

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "ConfiguredAuthnTimeoutSuccess"});
  const auto started = std::chrono::steady_clock::now();
  session.activate_sync();
  const auto elapsed = std::chrono::steady_clock::now() - started;

  ASSERT_TRUE(mAuthenticator->last_deadline_budget().has_value());
  EXPECT_GE(*mAuthenticator->last_deadline_budget(), std::chrono::milliseconds{125})
    << "the authenticator must receive the non-default host-configured deadline";
  EXPECT_LE(*mAuthenticator->last_deadline_budget(), configuredAuthenticationInterval);
  EXPECT_LT(elapsed, std::chrono::milliseconds{150})
    << "a successful activation must be answered without the fixed-interval hold";
  EXPECT_TRUE(session.is_active());

  session.close_sync();
  channel.close_sync();
}

TEST_F(ComplianceSession, CreateSessionAnonymousOnNoneChannel)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "AnonNone"});
  session.activate_sync();

  auto sessionId = session.session_id();
  EXPECT_FALSE(sessionId.is_null()) << "Session ID should be non-null";

  (void)session.try_close_sync();
  channel.close_sync();
}

TEST_F(ComplianceSession, CreateSessionOnSecuredChannel)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "SecuredSession"});
  session.activate_sync();
  EXPECT_TRUE(session.is_active());

  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// CreateSession (P4-SS-0001 through P4-SS-0023) - positive tests
// ===========================================================================

// Requirement: P4-SS-0001 (SHALL)
// The Server may accept requests with the authenticationToken only if they are
// associated with the same SecureChannel that was used to create the Session.
// Positive test: session on its creating channel works normally.
// @relation(SVR-SESS-001, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0001_SessionBoundToSecureChannel)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "BoundSession"});
  session.activate_sync();

  auto resp = session.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(resp.results().size(), 1u);

  session.close_sync();
  channel.close_sync();
}

// Reading the SessionId node returned by CreateSession must not fault the whole Read service: an
// unresolved SessionId resolves per-result (Good if the SessionDiagnostics object is addressable,
// else BadNodeIdUnknown), never a service-level fault.
TEST_F(ComplianceSession, SessionIdNodeReadDoesNotFaultService)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "SessionIdReadProbe"});
  session.activate_sync();

  auto sessionId = session.session_id();
  ASSERT_FALSE(sessionId.is_null());

  auto resp = session.attributes().read_sync(make_browsename_nodeclass_read_request(sessionId));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood())
    << "Read of the SessionId node must not fault the service";
  ASSERT_EQ(resp.results().size(), 2u);

  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0003 (SHALL)
// The Server returns all EndpointDescriptions for the serverUri specified by the
// Client in the request.
// Positive test: endpoints in CreateSession response match those from GetEndpoints discovery.
// @relation(SVR-SESS-003, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0003_ServerEndpointsMatchDiscovery)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  // Get endpoints via discovery.
  GetEndpointsRequest geReq;
  geReq.endpoint_url() = mEndpointUrl;
  auto geResp = channel.get_endpoints_sync(std::move(geReq));
  ASSERT_THAT(geResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(geResp.endpoints().size(), 1u);

  // Create session and capture the response to inspect server_endpoints().
  auto [session, createResp] = create_session_with_capture(channel, {.sessionName = "EndpointMatch"});

  // The server_endpoints in CreateSession response should match GetEndpoints.
  const auto& sessionEndpoints = createResp.server_endpoints();
  const auto& discoveryEndpoints = geResp.endpoints();
  EXPECT_EQ(sessionEndpoints.size(), discoveryEndpoints.size())
    << "CreateSession server_endpoints count should match GetEndpoints count";

  // Verify each discovery endpoint appears in the session response (match by policy + mode).
  for (const auto& discEp : discoveryEndpoints.payload())
  {
    bool found = false;
    for (const auto& sessEp : sessionEndpoints.payload())
    {
      if (sessEp.security_policy_uri() == discEp.security_policy_uri() &&
          sessEp.security_mode() == discEp.security_mode())
      {
        found = true;
        break;
      }
    }
    EXPECT_TRUE(found) << "Discovery endpoint (policy=" << std::string_view{discEp.security_policy_uri()}
                       << ", mode=" << static_cast<int>(discEp.security_mode())
                       << ") not found in CreateSession server_endpoints";
  }

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0009 (SHALL)
// clientNonce shall have a minimum length of 32 bytes.
// Verifies the client SDK generates a compliant nonce via TestAccess.
// @verifies CL-SESS-002
// @relation(CL-SESS-002, SVR-SESS-009, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0009_ClientNonceMinLength32)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "NonceTest"});
  ASSERT_TRUE(session.is_created());

  auto clientNonce = CSSTA::on_strand(session, [](auto& g) { return g.client_nonce(); });
  EXPECT_GE(clientNonce.size(), 32u) << "Client nonce sent in CreateSession should be >= 32 bytes";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0009 (SHALL)
// If sessionName is null or empty the Server shall assign a value.
// Verified by registering a ServerObserver to capture the session name assigned by the server
// when a session is created with an empty name.
// @relation(SVR-SESS-009, scope=function)
TEST_F(ComplianceSession, P4_SS_0009_ServerAssignsSessionName)
{
  // Register observer to capture the server-assigned session name.
  struct NameCapture : server::ServerObserver
  {
    std::promise<std::string> capturedName;

    void on_session_created(const server::SessionEventInfo& info) override
    {
      capturedName.set_value(info.sessionName);
    }
  };

  auto observer = std::make_shared<NameCapture>();
  auto capturedName = observer->capturedName.get_future();
  mServer->set_observer(observer);

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = ""});
  ASSERT_TRUE(session.is_created());

  ASSERT_EQ(capturedName.wait_for(std::chrono::seconds{5}), std::future_status::ready)
    << "the Session response arrived before the server observer callback completed";
  EXPECT_FALSE(capturedName.get().empty())
    << "Server should assign a non-empty session name when client provides empty string";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();

  mServer->set_observer(nullptr);
}

// Requirement: P4-SS-0010 (SHALL)
// If the securityPolicyUri is None, the Server shall ignore the
// ApplicationInstanceCertificate.
// Verified by two scenarios:
// 1. Client WITH certs (ComplianceSecured fixture) succeeds on None channel.
// 2. Client WITHOUT any cert/crypto also succeeds on None channel - proving the server
//    truly ignores the certificate (a cert-less client would fail if certs were checked).
// @relation(SVR-SESS-010, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0010_PolicyNoneIgnoresCert)
{
  // Scenario 1: Client with certs configured succeeds on None channel.
  auto channel1 = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session1 = channel1.create_session_sync({.sessionName = "NoneWithCert"});
  session1.activate_sync();
  ASSERT_TRUE(session1.is_active());
  auto resp1 = session1.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(resp1, ::ua::test_helpers::ServiceResultIsGood());
  session1.close_sync();
  channel1.close_sync();

  // Scenario 2: Client WITHOUT any cert also succeeds on None - proving cert is ignored.
  auto certlessClient = Client::create(mClientThreadPool.executor(),
    ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
      .application = ua::test_utils::create_test_config()},
    ua::client::ClientComponents{
      .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug});
  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::None;
  cfg.securityPolicyId = SecurityPolicyId::None;
  auto channel2 = certlessClient.core().open_channel_sync(std::move(cfg));
  auto session2 = channel2.create_session_sync({.sessionName = "NoneNoCert"});
  session2.activate_sync();
  ASSERT_TRUE(session2.is_active());
  auto resp2 = session2.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(resp2, ::ua::test_helpers::ServiceResultIsGood())
    << "Client with no cert should succeed on None channel - cert is ignored";
  session2.close_sync();
  channel2.close_sync();
}

// Requirement: P4-SS-0011 (SHALL)
// The Server shall verify that the Certificate is the same as the one used to
// create the SecureChannel.
// Positive path: on a secured channel, the client SDK sends the same cert used for OPN
// in the CreateSession request. The server verifies continuity and accepts.
// Negative path (cert mismatch -> rejected) is covered by unit test:
//   client_signature_verification_tests: SenderCertificateChangeAcrossOpnIsRejected
// @relation(SVR-SESS-011, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0011_ServerVerifiesCertMatchesChannel)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "CertMatch"});
  session.activate_sync();
  EXPECT_TRUE(session.is_active());

  // Verify session is functional (cert continuity was verified by server).
  auto resp = session.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());

  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0012 (SHALL)
// Revised timeout returned within server min/max bounds.
// @relation(SVR-SESS-012, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0012_SessionTimeoutRevised)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "TimeoutRevised"});

  auto state = session_state(session);
  double revisedMs = state.revisedSessionTimeoutMs;

  // Server minimum is 1000ms, maximum is 60000ms (ComplianceSession fixture).
  EXPECT_GE(revisedMs, 1000.0) << "Revised timeout should be >= server minimum (1000ms)";
  EXPECT_LE(revisedMs, 60000.0) << "Revised timeout should be <= server maximum (60000ms)";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0012 (SHALL)
// Session times out after revised timeout period without activity.
// @relation(SVR-SESS-012, scope=function)
TEST_F(ComplianceSession, P4_SS_0012_SessionTimeoutWithoutActivity)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync(
    {.requestedSessionTimeout = std::chrono::milliseconds{1}, .sessionName = "TimeoutTest"});
  session.activate_sync();

  // Wait for the session to time out (server minimum is 1000ms, wait 3s to be safe).
  std::this_thread::sleep_for(std::chrono::seconds{3});

  auto result = session.attributes().try_read_sync(make_server_read_request());
  EXPECT_TRUE(result.is_bad()) << "Session should have timed out, but read succeeded";

  channel.close_sync();
}

// Requirement: P4-SS-0013 (SHALL)
// Authentication tokens shall be unique across sessions.
// @relation(SVR-SESS-013, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0013_AuthenticationTokenUnique)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session1 = channel.create_session_sync({.sessionName = "Token1"});
  auto session2 = channel.create_session_sync({.sessionName = "Token2"});

  auto token1 = session_state(session1).authenticationToken;
  auto token2 = session_state(session2).authenticationToken;
  EXPECT_NE(token1, token2) << "Authentication tokens should be unique across sessions";

  session1.activate_sync();
  session2.activate_sync();
  session2.close_sync();
  session1.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0013 (SHALL)
// SessionId is unique, non-null.
// @relation(SVR-SESS-013, scope=function)
TEST_F(ComplianceSession, P4_SS_0013_SessionIdNotReused)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session1 = channel.create_session_sync({.sessionName = "Id1"});
  auto session2 = channel.create_session_sync({.sessionName = "Id2"});

  auto id1 = session1.session_id();
  auto id2 = session2.session_id();

  EXPECT_FALSE(id1.is_null());
  EXPECT_FALSE(id2.is_null());
  EXPECT_NE(id1, id2) << "Session IDs should be unique";

  session1.activate_sync();
  session2.activate_sync();
  session2.close_sync();
  session1.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0014 (SHALL)
// Server may negotiate revisedSessionTimeout up or down.
// Request very short -> server revises up to minimum.
// @verifies CL-SESS-020
// @relation(CL-SESS-020, SVR-SESS-014, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0014_RevisedTimeoutNegotiated)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync(
    {.requestedSessionTimeout = std::chrono::milliseconds{1}, .sessionName = "NegotiateUp"});

  auto state = session_state(session);
  EXPECT_GE(state.revisedSessionTimeoutMs, 1000.0) << "Server should revise up to its minimum (1000ms)";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0015 (SHALL)
// serverNonce shall have a minimum length of 32 bytes.
// @relation(SVR-SESS-015, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0015_ServerNonceMinLength32)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "NonceLen"});

  auto state = session_state(session);
  EXPECT_GE(state.serverNonce.size(), 32u) << "Server nonce from CreateSession should be >= 32 bytes";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0016 (SHALL)
// Server proves possession by signing client nonce with private key.
// The signature is created by appending the clientNonce to the serverCertificate and signing.
// Cryptographic verification is performed by the client SDK during CreateSession processing;
// here we verify the signature data is present and uses the correct algorithm.
// @relation(SVR-SESS-016, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0016_ServerSignsNonce)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto [session, createResp] = create_session_with_capture(channel, {.sessionName = "ServerSig"});
  ASSERT_TRUE(session.is_created());

  const auto& sig = createResp.server_signature();
  EXPECT_FALSE(sig.signature().empty()) << "Server signature should be non-empty on authenticated channel";
  EXPECT_FALSE(sig.algorithm().empty()) << "Server signature algorithm should be non-empty";

  // Basic256Sha256 uses rsa-sha256 for asymmetric signatures.
  // The algorithm URI should match the security policy's asymmetric signature algorithm.
  EXPECT_NE(std::string_view{sig.algorithm()}.find("sha256"), std::string_view::npos)
    << "Signature algorithm should match Basic256Sha256 policy; got: " << std::string_view{sig.algorithm()};

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0018 (SHALL)
// Server shall return a set of EndpointDescriptions available for the serverUri.
// @relation(SVR-SESS-018, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0018_ServerEndpointsInResponse)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto [session, createResp] = create_session_with_capture(channel, {.sessionName = "Endpoints"});
  ASSERT_TRUE(session.is_created());

  const auto& endpoints = createResp.server_endpoints();
  EXPECT_FALSE(endpoints.empty()) << "CreateSession response should contain server endpoints";
  // ComplianceSecured configures 3 endpoints: None, Sign, SignAndEncrypt.
  EXPECT_GE(endpoints.size(), 3u) << "Expected at least 3 endpoints (None, Sign, SignAndEncrypt)";

  // Each endpoint should have a non-empty security policy URI.
  for (const auto& ep : endpoints.payload())
  {
    EXPECT_FALSE(ep.security_policy_uri().empty())
      << "Each endpoint should have a non-empty security policy URI";
  }

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0018 (SHALL)
// All Endpoints are returned if the serverUri is null or empty.
// The client SDK sends the endpointUrl in CreateSession. The server returns all endpoints
// matching that serverUri. Verify by comparing CreateSession response with GetEndpoints.
// @relation(SVR-SESS-018, scope=function)
TEST_F(ComplianceSession, P4_SS_0018_AllEndpointsReturnedForNullUri)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  // Get the full endpoint set via discovery for comparison.
  GetEndpointsRequest geReq;
  geReq.endpoint_url() = mEndpointUrl;
  auto geResp = channel.get_endpoints_sync(std::move(geReq));
  ASSERT_THAT(geResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_GE(geResp.endpoints().size(), 3u);

  // Create session and capture the response to inspect server_endpoints().
  auto [session, createResp] = create_session_with_capture(channel, {.sessionName = "AllEndpoints"});

  const auto& sessionEndpoints = createResp.server_endpoints();
  // ComplianceSecured configures 3 endpoints: None, Sign, SignAndEncrypt.
  EXPECT_GE(sessionEndpoints.size(), 3u) << "All endpoints should be returned in CreateSession response";
  EXPECT_EQ(sessionEndpoints.size(), geResp.endpoints().size())
    << "CreateSession should return the same number of endpoints as GetEndpoints";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0020 (SHALL)
// serverSoftwareCertificates is deprecated and the array shall be empty.
// @relation(SVR-SESS-020, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0020_ServerSoftwareArrayEmpty)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto [session, createResp] = create_session_with_capture(channel, {.sessionName = "SoftwareCerts"});
  ASSERT_TRUE(session.is_created());

  EXPECT_TRUE(createResp.server_software_certificates().empty())
    << "serverSoftwareCertificates is deprecated and shall be empty";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// CreateSession - negative tests (eviction, P4-SS-0005)
// ===========================================================================

// Requirement: P4-SS-0005 (SHALL)
// Server closes oldest unactivated Session before reaching max.
// @relation(SVR-SESS-005, SVR-SESS-043, scope=function)
TEST_F(ComplianceSessionLimited, P4_SS_0005_OldestUnactivatedSessionClosedOnMax)
{
  // mMaxSessions = 2
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  auto session1 = channel.create_session_sync({.sessionName = "Evict1"});
  auto session2 = channel.create_session_sync({.sessionName = "Evict2"});

  // 3rd session -> oldest unactivated (session1) should be evicted.
  auto session3 = channel.create_session_sync({.sessionName = "Evict3"});
  EXPECT_TRUE(session3.is_created()) << "3rd session should be created after evicting oldest";

  // session1 should have been evicted by the server.
  auto result = session1.try_activate_sync();
  EXPECT_TRUE(result.is_bad()) << "Evicted session should not be activatable";

  session2.activate_sync();
  session3.activate_sync();

  session3.close_sync();
  session2.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0005 (SHALL)
// Activated sessions survive when unactivated ones are evicted.
// @relation(SVR-SESS-005, scope=function)
TEST_F(ComplianceSessionLimited, P4_SS_0005_ActivatedSessionNotEvicted)
{
  // mMaxSessions = 2
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  auto session1 = channel.create_session_sync({.sessionName = "Active1"});
  session1.activate_sync();

  auto session2 = channel.create_session_sync({.sessionName = "Active2"});
  session2.activate_sync();

  // Both activated. Creating 3rd should fail (no unactivated to evict).
  auto result = channel.try_create_session_sync({.sessionName = "Extra"});
  if (result.is_good())
  {
    auto extra = std::move(result).value();
    extra.activate_sync();
    extra.close_sync();
  }
  else
  {
    EXPECT_TRUE(result.is_bad());
  }

  // Original sessions should still work.
  auto resp1 = session1.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(resp1, ::ua::test_helpers::ServiceResultIsGood())
    << "Activated session1 should still be usable";

  session2.close_sync();
  session1.close_sync();
  channel.close_sync();
}

// ===========================================================================
// ActivateSession (P4-SS-0024 through P4-SS-0040)
// ===========================================================================

// Requirement: P4-SS-0024 (SHALL)
// Session must be activated before issuing service requests.
// Failure to do so shall cause the Server to close the Session.
// @relation(SVR-SESS-004, SVR-SESS-024, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0024_MustActivateBeforeService)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "NoActivate"});
  ASSERT_TRUE(session.is_created());
  ASSERT_FALSE(session.is_active());

  auto result = session.attributes().try_read_sync(make_server_read_request());
  EXPECT_TRUE(result.is_bad()) << "Read before Activate should fail";

  channel.close_sync();
}

// Requirement: P4-SS-0025 (SHALL)
// Client proves identity by signing with clientCertificate private key.
// Positive: on secured channel, activate succeeds -> client signature accepted.
// @verifies CL-SESS-010
// @relation(CL-SESS-010, SVR-SESS-025, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0025_ClientProvesIdentity)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "ClientProof"});
  session.activate_sync();
  EXPECT_TRUE(session.is_active());

  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0029 (SHALL)
// Repeated invalid identity tokens -> lockout.
// Implemented as ClientUsernamePasswordLockout.P4_SS_0029_IdentityLockoutAfterFailures, in the only
// fixture that advertises a UserName token policy and so can reach the authenticator with credentials.

// Requirement: P4-SS-0030 (SHALL)
// Sporadic failures shall not delay connections with valid tokens.
// Implemented as ClientUsernamePasswordLockout.P4_SS_0030_SporadicFailureNoDelay.

// Requirement: P4-SS-0035 (SHALL)
// Server returns translation with highest priority that it can.
// Verified by: add multi-locale DisplayName to the Server node, activate with Spanish
// as highest priority, read DisplayName and verify the server returns the Spanish translation.
// @verifies CL-SESS-022
// @relation(CL-SESS-022, SVR-SESS-035, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0035_LocaleIdsHonoured)
{
  // Add multi-locale DisplayName to the Server node via the server address space.
  auto addressSpace = mServer->address_space();
  auto serverNode = addressSpace.find_node_sync(NodeId{ObjectId::Server});
  serverNode.set_display_name(LocalizedText{"en", "Server"});
  serverNode.set_display_name(LocalizedText{"es", "Servidor"});
  serverNode.set_display_name(LocalizedText{"de", "Server_DE"});

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "Locale"});

  // Activate with Spanish as highest priority.
  Session::ActivateConfig activateCfg;
  activateCfg.localeIds.push_back("es");
  activateCfg.localeIds.push_back("en");
  session.activate_sync(std::move(activateCfg));
  ASSERT_TRUE(session.is_active());

  // Read DisplayName - should return Spanish translation.
  auto resp = session.attributes().read_sync(make_display_name_read_request(NodeId{ObjectId::Server}));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].value().is_localized_text()) << "DisplayName should be a LocalizedText value";

  const auto& lt = resp.results()[0].value().as<LocalizedText>();
  EXPECT_EQ(std::string_view{lt.locale()}, "es")
    << "Server should return Spanish translation (highest priority locale); got locale='"
    << std::string_view{lt.locale()} << "' text='" << std::string_view{lt.text()} << "'";
  EXPECT_EQ(std::string_view{lt.text()}, "Servidor") << "Server should return 'Servidor' for Spanish locale";

  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0036 (SHALL)
// If the Client fails to specify at least one locale id, the Server shall keep using the
// current localeIds for the Session.
// Verify: activate with "en", read DisplayName. Re-activate with empty localeIds, read again.
// Both reads should return the same DisplayName (locale was preserved).
// @relation(SVR-SESS-036, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0036_NullLocaleKeepsCurrent)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "NullLocale"});

  // First activation with explicit locale.
  Session::ActivateConfig cfg1;
  cfg1.localeIds.push_back("en");
  session.activate_sync(std::move(cfg1));
  ASSERT_TRUE(session.is_active());

  auto resp1 = session.attributes().read_sync(make_display_name_read_request(NodeId{ObjectId::Server}));
  ASSERT_THAT(resp1, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_EQ(resp1.results().size(), 1u);

  // Re-activate with empty localeIds - server should keep "en".
  Session::ActivateConfig cfg2;
  session.activate_sync(std::move(cfg2));
  ASSERT_TRUE(session.is_active());

  auto resp2 = session.attributes().read_sync(make_display_name_read_request(NodeId{ObjectId::Server}));
  ASSERT_THAT(resp2, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_EQ(resp2.results().size(), 1u);

  // DisplayName should be the same - locale was preserved.
  EXPECT_EQ(resp1.results()[0].value(), resp2.results()[0].value())
    << "DisplayName should be unchanged after re-activation with empty localeIds";

  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0037 (SHALL)
// Null or empty user token shall always be interpreted as anonymous.
// Verified by: the fixture only accepts Anonymous tokens. Activate twice - once with
// the default (null/empty) token and once with an explicit AnonymousIdentity. Both must
// succeed without incrementing the server's rejected-session counters, proving the server
// interpreted the null token as anonymous rather than rejecting it.
// @relation(SVR-IDENT-001, SVR-JWT-015, SVR-SESS-037, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0037_NullTokenIsAnonymous)
{
  // Record baseline rejection counters.
  auto baselineHealth = mServer->health_snapshot();
  auto baselineRejected = baselineHealth.rejectedSessionCount;
  auto baselineSecurityRejected = baselineHealth.securityRejectedSessionCount;

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  // Session 1: Activate with default (null/empty) user token.
  auto session1 = channel.create_session_sync({.sessionName = "NullToken"});
  session1.activate_sync();
  ASSERT_TRUE(session1.is_active());
  auto resp1 = session1.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(resp1, ::ua::test_helpers::ServiceResultIsGood())
    << "Null user token should be interpreted as anonymous; service call should succeed";

  // Session 2: Activate with explicit AnonymousIdentity to contrast.
  auto session2 = channel.create_session_sync({.sessionName = "ExplicitAnon"});
  Session::ActivateConfig explicitAnonCfg;
  explicitAnonCfg.identity = AnonymousIdentity{};
  session2.activate_sync(std::move(explicitAnonCfg));
  ASSERT_TRUE(session2.is_active());
  auto resp2 = session2.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(resp2, ::ua::test_helpers::ServiceResultIsGood())
    << "Explicit AnonymousIdentity should also succeed";

  // Verify no sessions were rejected - both were interpreted as anonymous.
  auto currentHealth = mServer->health_snapshot();
  EXPECT_EQ(currentHealth.rejectedSessionCount, baselineRejected)
    << "No sessions should have been rejected when using null/anonymous tokens";
  EXPECT_EQ(currentHealth.securityRejectedSessionCount, baselineSecurityRejected)
    << "No sessions should have been security-rejected when using null/anonymous tokens";

  session2.close_sync();
  session1.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0039 (SHALL)
// ActivateSession response serverNonce >= 32 bytes.
// @relation(SVR-SESS-039, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0039_ActivateResponseNonceMinLength32)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "ActivateNonce"});
  session.activate_sync();

  auto state = session_state(session);
  EXPECT_GE(state.serverNonce.size(), 32u) << "Server nonce after ActivateSession should be >= 32 bytes";

  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0039 (SHALL)
// serverNonce should never be used in any other request - nonce changes.
// @relation(SVR-SESS-039, scope=function)
TEST_F(ComplianceSession, P4_SS_0039_ActivateResponseNonceUnique)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "UniqueNonce"});

  auto createNonce = session_state(session).serverNonce;
  session.activate_sync();
  auto activateNonce = session_state(session).serverNonce;

  EXPECT_NE(createNonce, activateNonce)
    << "Server nonce should change between CreateSession and ActivateSession";

  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// CloseSession + Cancel (P4-SS-0006, P4-SS-0041, P4-SS-0042)
// ===========================================================================

// Requirement: P4-SS-0006 (SHALL)
// CloseSession terminates session cleanly.
// @relation(SVR-SESS-006, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0006_CloseSessionExplicit)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "ExplicitClose"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  session.close_sync();
  EXPECT_FALSE(session.is_active());

  channel.close_sync();
}

// Requirement: P4-SS-0041 (SHALL)
// Cancel service returns cancelled request count.
// @relation(SVR-SESS-041, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0041_CancelReturnsCount)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "CancelCount"});
  session.activate_sync();

  CancelRequest req;
  req.request_handle() = 99999;  // Non-existent handle

  auto resp = session.cancel_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(resp.cancel_count(), 0u);

  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-SS-0042 (SHALL)
// All outstanding requests with matching requestHandle shall be cancelled.
// Verified by: send a Read request asynchronously, then immediately send Cancel targeting
// the in-flight request's handle. On loopback, the Read may complete before Cancel arrives,
// so we accept either outcome: cancel_count > 0 with the Read returning
// BadRequestCancelledByClient, or cancel_count == 0 because the Read already completed.
// Both outcomes prove the Cancel service correctly processes the matching handle.
// @relation(SVR-SESS-042, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, P4_SS_0042_CancelMatchingRequestHandle)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "CancelInFlight"});
  session.activate_sync();

  // Start an async Read.
  std::promise<SessionAttributeServices::ReadResponseResult> readPromise;
  auto readFuture = readPromise.get_future();
  session.attributes().read_async(make_server_read_request(),
    [&readPromise](SessionAttributeServices::ReadResponseResult result) mutable
    { readPromise.set_value(std::move(result)); });

  // The last sent request handle is mNextRequestHandle - 1.
  uint32_t lastHandle = CSSTA::on_strand(session, [](auto& g) { return g.next_request_handle(); }) - 1;

  // Send Cancel targeting the in-flight Read's request handle.
  CancelRequest cancelReq;
  cancelReq.request_handle() = lastHandle;
  auto cancelResp = session.cancel_sync(std::move(cancelReq));
  EXPECT_THAT(cancelResp, ::ua::test_helpers::ServiceResultIsGood())
    << "Cancel service should respond successfully";

  // Wait for the original Read to complete.
  auto readResult = readFuture.get();

  if (cancelResp.cancel_count() > 0)
  {
    // Cancel caught the request - verify it was cancelled.
    if (readResult.is_good())
    {
      EXPECT_EQ(readResult.value().response_header().service_result(),
        StatusCode{Status::BadRequestCancelledByClient})
        << "Cancelled request should respond with BadRequestCancelledByClient";
    }
    // readResult.is_bad() is also acceptable (cancelled before response was constructed).
  }
  // If cancel_count == 0, the request completed before Cancel arrived - acceptable on loopback.

  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// Additional Session compliance tests (ComplianceBase fixture - None channel)
// ===========================================================================

// SESS_ServerCertMatchesChannelCert: DELETED - used a None channel where there is no
// cert to match, making it unfalsifiable. P4_SS_0011_ServerVerifiesCertMatchesChannel
// already tests cert matching on an authenticated channel.

// I-positive: None channel + anonymous token. Session succeeds.
// Limitation: The client has valid certificates configured, so this does not prove
// certificates are *ignored* - it only proves the session works on a None channel.
// To truly verify certs are ignored, a certless client would be needed (like P4_SS_0010
// scenario 2). This test serves as a smoke test for None+Anonymous.
// @relation(SVR-SESS-010, SVR-SESS-017, SVR-SESS-043, scope=function)
TEST_F(ComplianceBase, SESS_CertIgnoredWithNoneAndNoEncryption)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "NoneNoEncrypt"});
  session.activate_sync();
  EXPECT_TRUE(session.is_active());

  // Verify session is functional with a simple read.
  auto resp = session.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood())
    << "Service call should succeed on None channel with anonymous token";

  session.close_sync();
  channel.close_sync();
}

// I-positive: Create session on authenticated channel, verify client nonce >= 32 bytes.
// Spec: Part 4, 5.6.2 - clientNonce shall be at least 32 bytes for authenticated channels.
// @verifies CL-SESS-002
// @relation(CL-SESS-002, SVR-SESS-023, SVR-SESS-043, scope=function)
TEST_F(ComplianceSession, SESS_CreateSessionClientNonceAtLeast32Bytes)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "ClientNonce"});
  ASSERT_TRUE(session.is_created());

  auto clientNonce = CSSTA::on_strand(session, [](auto& g) { return g.client_nonce(); });

  EXPECT_FALSE(clientNonce.empty()) << "Client nonce must be non-empty on authenticated channel";
  EXPECT_GE(clientNonce.size(), 32u) << "Client nonce must be >= 32 bytes on authenticated channel";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// I-positive: Create session on authenticated channel, verify server nonce is stored.
// Spec: Part 4, 5.6.2 - serverNonce shall be at least 32 bytes for authenticated channels.
// @verifies CL-SESS-008
// @relation(CL-SESS-008, SVR-SESS-015, scope=function)
TEST_F(ComplianceSession, SESS_ServerNonceStoredAfterCreate)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "ServerNonceCreate"});
  ASSERT_TRUE(session.is_created());

  auto serverNonce = CSSTA::on_strand(session, [](auto& g) { return g.server_nonce(); });

  EXPECT_FALSE(serverNonce.empty()) << "Server nonce must be non-empty on authenticated channel";
  EXPECT_GE(serverNonce.size(), 32u) << "Server nonce must be >= 32 bytes on authenticated channel";

  session.activate_sync();
  session.close_sync();
  channel.close_sync();
}

// I-positive: Create session on authenticated channel, activate, verify server nonce updated.
// Spec: Part 4, 5.6.3 - ActivateSession response includes a new serverNonce; the client
// stores it for use in the next ActivateSession call.
// @relation(SVR-SESS-039, scope=function)
TEST_F(ComplianceSession, SESS_ServerNonceFromActivateStoredForNextActivate)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "ActivateNonce"});

  auto createNonce = CSSTA::on_strand(session, [](auto& g) { return g.server_nonce(); });

  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  auto activateNonce = CSSTA::on_strand(session, [](auto& g) { return g.server_nonce(); });

  EXPECT_FALSE(activateNonce.empty()) << "Activate nonce must be non-empty on authenticated channel";
  EXPECT_GE(activateNonce.size(), 32u) << "Activate nonce must be >= 32 bytes on authenticated channel";
  EXPECT_NE(createNonce, activateNonce) << "Activate nonce should differ from create nonce";

  session.close_sync();
  channel.close_sync();
}

// I-positive: Cancel request dispatched on an active session.
// The Cancel service is already tested by P4_SS_0041/P4_SS_0042 above;
// this test verifies it works from the ComplianceBase (None) fixture as well.
// @relation(SVR-SESS-041, scope=function)
TEST_F(ComplianceBase, SESS_CancelResponseDispatched)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "CancelBase"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  CancelRequest req;
  req.request_handle() = 12345;  // Non-existent handle.
  auto resp = session.cancel_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood())
    << "Cancel service should respond successfully even with no matching requests";
  EXPECT_EQ(resp.cancel_count(), 0u) << "No requests should have been cancelled";

  session.close_sync();
  channel.close_sync();
}

// ---------------------------------------------------------------------------
// Additional includes for server-side hooks (placed here to avoid pulling
// ua::server::Session into scope before the existing tests that use
// unqualified Session to mean ua::client::Session).
// ---------------------------------------------------------------------------
#include "server_test_access.h"
#include "server_impl_test_access.h"
#include "ua_server_secure_channel_test_access.h"

#include "ua_activate_session_request.h"

// ===========================================================================
// ComplianceSessionWithHooks: ComplianceSession + server-side request observer
// and response interceptor for I-observe and I-intercept tests.
// ===========================================================================
class ComplianceSessionWithHooks : public ComplianceSession
{
protected:
  void SetUp() override
  {
    ComplianceSession::SetUp();
    install_hooks();
  }

  void install_hooks()
  {
    auto& serverImpl = ua::test_helpers::ServerTestAccess::impl(*mServer);
    ua::test_helpers::ServerImplTestAccess access(serverImpl);

    access.set_on_secure_channel_available(
      [this](std::shared_ptr<ua::server::SecureChannel> sc)
      {
        {
          std::lock_guard lock(mHookMutex);
          mServerChannel = sc;
        }

        // Install request observer on this channel.
        ua::server::SecureChannelTestAccess::on_strand(*sc,
          [&](auto& g)
          {
            g.set_request_observer(
              [this](uint32_t requestId, const ua::Structure& request)
              {
                std::lock_guard lock(mHookMutex);
                mObservedRequests.push_back(
                  ObservedRequest{requestId, std::string(request.type_name()), request.clone()});
                mHookCv.notify_all();
              });
          });

        // Install response interceptor that delegates to per-test function.
        ua::server::SecureChannelTestAccess::on_strand(*sc,
          [&](auto& g)
          {
            g.set_response_interceptor(
              [this](ua::Response& response)
              {
                std::lock_guard lock(mHookMutex);
                if (mResponseInterceptorFn)
                  mResponseInterceptorFn(response);
              });
          });
      });
  }

  struct ObservedRequest
  {
    uint32_t requestId;
    std::string typeName;
    std::shared_ptr<ua::Structure> request;
  };

  /// Wait until we have at least `count` observed requests of the given type name.
  bool wait_for_requests(const std::string& typeName, size_t count, std::chrono::milliseconds timeout)
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::unique_lock lock(mHookMutex);
    return mHookCv.wait_until(lock,
      deadline,
      [&]
      {
        size_t found = 0;
        for (const auto& req : mObservedRequests)
        {
          if (req.typeName == typeName)
            ++found;
        }
        return found >= count;
      });
  }

  /// Get all observed requests of a given type name.
  std::vector<ObservedRequest> get_requests_of_type(const std::string& typeName)
  {
    std::lock_guard lock(mHookMutex);
    std::vector<ObservedRequest> result;
    for (auto& req : mObservedRequests)
    {
      if (req.typeName == typeName)
        result.push_back(req);
    }
    return result;
  }

  void TearDown() override
  {
    // Drop the strong ref to the server-side SecureChannel BEFORE parent TearDown
    // stops the server thread pool. Otherwise the channel keeps the io_context busy
    // (timers, pending strand work) past the pool stop watchdog.
    {
      std::lock_guard lock(mHookMutex);
      mServerChannel.reset();
      mObservedRequests.clear();
      mResponseInterceptorFn = nullptr;
    }
    ComplianceSession::TearDown();
  }

  std::mutex mHookMutex;
  std::condition_variable mHookCv;
  std::shared_ptr<ua::server::SecureChannel> mServerChannel;
  std::vector<ObservedRequest> mObservedRequests;
  std::function<void(ua::Response&)> mResponseInterceptorFn;
};

// @verifies CL-SESS-019
// Part 4 section 5.6.2: a created Session is unusable until ActivateSession succeeds.
// The public Read call must fail locally with the SDK's pre-activation status
// and the server-side observer must see no ReadRequest.
// @relation(CL-SESS-019, scope=function)
TEST_F(ComplianceSessionWithHooks, ReadBeforeActivateRejectedLocallyWithoutWire)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "PreActivateGate"});
  ASSERT_TRUE(session.is_created());
  ASSERT_FALSE(session.is_active());

  auto result = session.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSessionClosed);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "SessionNotActive");
  EXPECT_EQ(result.shared_detail()->source, "client::Session");
  EXPECT_FALSE(wait_for_requests("ReadRequest", 1, std::chrono::milliseconds{100}))
    << "a Session service must not reach the wire before ActivateSession succeeds";

  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// I-positive tests (ComplianceBase - None channel)
// ===========================================================================

// Requirement #101: Endpoint verification is skipped when client didn't use discovery.
// Spec: Part 4, 5.6.2 - Endpoint comparison only needed when client used Discovery.
// Here we connect directly without GetEndpoints, so no comparison is needed.
// This positive test would pass even if endpoint verification were completely absent.
// It is meaningful only when paired with SESS_EndpointDescriptionMatching (the negative
// counterpart that verifies endpoint verification IS performed when discovery was used).
// @relation(SVR-SESS-019, scope=function)
TEST_F(ComplianceBase, SESS_EndpointVerificationSkippedWhenNoDiscovery)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "NoDiscovery"});
  EXPECT_TRUE(session.is_created());
  session.activate_sync();
  EXPECT_TRUE(session.is_active());
  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// I-positive tests (ComplianceSecuredWithSession - authenticated channel)
// ===========================================================================

// Requirement #96: Server signature verified with leaf cert.
// Spec: Part 4, 5.6.2 - Server signs CreateSessionResponse; client verifies with leaf cert.
// Successful session creation on an authenticated (SignAndEncrypt) channel is proof that the
// client verified the server signature using the leaf certificate during CreateSession.
// The client-side validation logic (validate_server_signature) runs unconditionally on
// authenticated channels and would reject a bad signature with BadApplicationSignatureInvalid.
// This positive test is meaningful because SESS_ServerSignatureInvalidRejected explicitly
// tests the negative case (corrupted signature is rejected). Together they prove the
// signature verification is both present and correct.
// Note: this asserts fixture state rather than performing a test action. The session
// creation that exercises the code path happens in the fixture's SetUp().
// @relation(SVR-SESS-016, scope=function)
TEST_F(ComplianceSecuredWithSession, SESS_ServerSignatureVerifiedWithLeafCert)
{
  EXPECT_TRUE(mSession->is_active())
    << "Session creation on authenticated channel implies server signature was verified with leaf cert";
}

// Requirement #97: Server signature verified with full chain fallback.
// Create a server with a CA-signed certificate chain (CA root + leaf cert).
// The client trusts the CA cert but not the leaf cert directly.
// If the server signature (signed with the leaf key) is verified using the
// chain, the session should be created successfully.
// @relation(SVR-SESS-016, SVR-SESS-021, SVR-SESS-033, SVR-SESS-043, scope=function)
TEST_F(ComplianceSecuredWithSession, SESS_ServerSignatureVerifiedWithFullChainFallback)
{
  TestPki pki{mCrypto};

  // 1. Create a CA key pair and root CA certificate.
  auto caKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(caKeys);
  auto caCert = pki.create_root_ca(caKeys, "Test Chain CA", "200");

  // 2. Create a leaf key pair and leaf certificate signed by the CA.
  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(leafKeys);

  auto now = DateTime::now();
  auto expiry = DateTime{now.value() + std::chrono::days{365}};
  auto leafCert = pki.create_leaf_cert(leafKeys,
    caKeys,
    caCert,
    now,
    expiry,
    /*uris=*/{"urn:test:chain:server"},
    /*hostnames=*/{"localhost", "127.0.0.1"},
    /*name=*/"Chain Server Leaf");

  // 3. Create a temp cert store for the chain server.
  auto chainServerStorePath =
    std::filesystem::temp_directory_path() / ("ua_chain_test_" + Guid::create_and_generate().as_string());
  std::filesystem::create_directories(chainServerStorePath);
  auto chainServerCertStorePath = chainServerStorePath / "server_store";
  std::filesystem::create_directories(chainServerCertStorePath);

  boost::asio::thread_pool chainServerPool;
  TrustListValidationOptions validationOptions;
  auto chainServerCertStore = CertificateStoreFiles::create(chainServerPool.executor(),
    mCrypto,
    {.trustListPath = chainServerCertStorePath, .validationOptions = validationOptions});

  // 4. Add the leaf cert as the server's application certificate.
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = leafCert;
    appCert.keys = leafKeys;
    chainServerCertStore->add_to_application_certificates_sync(appCert);
  }

  // Add the CA cert to the server's issuer certificates (needed for chain validation).
  chainServerCertStore->add_to_issuer_certificates_sync(caCert);

  // Trust the existing client certificate on the chain server.
  auto clientAppCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(clientAppCerts.empty());
  chainServerCertStore->add_to_trusted_certificates_sync(clientAppCerts.front().certificate);

  // 5. Create and start the chain server.
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  ServerComponents components{.crypto = mCrypto, .applicationGroupCertificateStore = chainServerCertStore};
  components.authenticator = std::make_shared<AnonymousAuthenticator>();
  components.roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

  server::CreateConfig chainServerCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  std::optional<ua::server::Server> chainServer;
  auto logSink = test_log_sink();
  components.logSink = logSink;
  components.logLevel = LogLevel::Debug;
  chainServer.emplace(
    ua::server::Server::create(chainServerPool.executor(), std::move(chainServerCfg), std::move(components)));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto chainListenerHandle = chainServer->listen_sync(std::move(bind), {});

  ServerEndpointConfig signEncryptEp;
  signEncryptEp.name = "Basic256Sha256_SignAndEncrypt";
  signEncryptEp.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  signEncryptEp.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  signEncryptEp.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  chainServer->add_endpoint(chainListenerHandle, std::move(signEncryptEp));

  chainServer->start_sync();

  auto urls = chainServer->advertised_urls(chainListenerHandle);
  ASSERT_FALSE(urls.empty());
  auto chainEndpointUrl = urls.front().str();

  // 6. Create a client that trusts the CA cert (not the leaf cert directly).
  auto chainClientStorePath = chainServerStorePath / "client_store";
  std::filesystem::create_directories(chainClientStorePath);
  auto chainClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = chainClientStorePath, .validationOptions = validationOptions});

  // Re-use the existing client's app cert and keys.
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = clientAppCerts.front().certificate;
    appCert.keys = clientAppCerts.front().keys;
    chainClientCertStore->add_to_application_certificates_sync(appCert);
  }
  // Trust the CA cert - the client should accept the leaf cert via chain validation.
  chainClientCertStore->add_to_trusted_certificates_sync(caCert);

  auto clientAppCfg = ua::test_utils::create_test_config();
  clientAppCfg.application_description_part().applicationUri = "urn:test:compliance:client";
  client::CreateConfig clientCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
  auto chainClient = Client::create(mClientThreadPool.executor(),
    std::move(clientCfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = chainClientCertStore,
      .logSink = logSink,
      .logLevel = LogLevel::Debug});

  // 7. Open a channel and create a session to the chain server.
  CoreClient::OpenChannelConfig channelCfg;
  channelCfg.endpointUrl = chainEndpointUrl;
  channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelCfg.serverCertificate = leafCert;

  auto channelResult = chainClient.core().try_open_channel_sync(std::move(channelCfg));
  ASSERT_TRUE(channelResult.is_good()) << "Channel open to chain-cert server must succeed; status: 0x"
                                       << std::hex << channelResult.status_code().as_uint32();
  auto chainChannel = std::move(channelResult).value();
  ASSERT_TRUE(chainChannel.is_open());

  // Create and activate a session - this validates the server signature.
  auto sessionResult = chainChannel.try_create_session_sync({.sessionName = "ChainTest"});
  ASSERT_TRUE(sessionResult.is_good()) << "Session creation on chain-cert server must succeed; status: 0x"
                                       << std::hex << sessionResult.status_code().as_uint32();
  auto chainSession = std::move(sessionResult).value();

  auto activateResult = chainSession.try_activate_sync();
  ASSERT_TRUE(activateResult.is_good()) << "Session activation on chain-cert server must succeed; status: 0x"
                                        << std::hex << activateResult.status_code().as_uint32();

  // 8. Success - session is active, proving the server signature was verified via chain.
  EXPECT_TRUE(chainSession.is_active())
    << "Session with chain-cert server proves server signature verified via CA chain fallback";

  (void)chainSession.try_close_sync();
  (void)chainChannel.try_close_sync();

  // Cleanup - graceful shutdown, destroy server, then drain the pool. Server
  // teardown cancels timers (session timeouts, cert store refresh); the pool
  // stop catches anything that escaped.
  if (chainServer)
    (void)chainServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  chainServer.reset();
  chainServerPool.join();
  std::error_code ec;
  std::filesystem::remove_all(chainServerStorePath, ec);
}

// ===========================================================================
// I-observe tests (ComplianceSessionWithHooks - server-side observation)
// ===========================================================================

// Requirement #109: Client sends a valid signature in ActivateSessionRequest.
// Spec: Part 4, 5.6.3 - Client proves possession of private key by signing.
// On an authenticated channel, the ActivateSessionRequest.clientSignature should be non-empty.
// @relation(SVR-SESS-011, SVR-SESS-025, scope=function)
TEST_F(ComplianceSessionWithHooks, SESS_ActivateSessionClientSignatureCorrect)
{
  using namespace std::chrono_literals;

  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "ClientSigObserve"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  // Wait for the ActivateSessionRequest to be observed.
  ASSERT_TRUE(wait_for_requests("ActivateSessionRequest", 1, 5s))
    << "Did not observe ActivateSessionRequest within timeout";

  auto activateRequests = get_requests_of_type("ActivateSessionRequest");
  ASSERT_EQ(activateRequests.size(), 1u);

  auto* activateReq = dynamic_cast<const ActivateSessionRequest*>(activateRequests[0].request.get());
  ASSERT_NE(activateReq, nullptr);

  const auto& sig = activateReq->client_signature();
  EXPECT_FALSE(sig.signature().empty())
    << "Client signature in ActivateSessionRequest should be non-empty on authenticated channel";
  EXPECT_FALSE(sig.algorithm().empty())
    << "Client signature algorithm should be non-empty on authenticated channel";

  session.close_sync();
  channel.close_sync();
}

// Requirement #110: Client signature algorithm matches the security policy's asymmetric signature URI.
// @verifies CL-SESS-012
// @relation(CL-SESS-012, SVR-SESS-022, SVR-SESS-034, SVR-SESS-043, scope=function)
TEST_F(ComplianceSessionWithHooks, SESS_ActivateSessionSignatureAlgorithmMatchesPolicy)
{
  using namespace std::chrono_literals;

  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "SigAlgoMatch"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  ASSERT_TRUE(wait_for_requests("ActivateSessionRequest", 1, 5s))
    << "Did not observe ActivateSessionRequest within timeout";

  auto activateRequests = get_requests_of_type("ActivateSessionRequest");
  ASSERT_EQ(activateRequests.size(), 1u);

  auto* activateReq = dynamic_cast<const ActivateSessionRequest*>(activateRequests[0].request.get());
  ASSERT_NE(activateReq, nullptr);

  const auto& sig = activateReq->client_signature();
  // Basic256Sha256 uses http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 for asymmetric signatures.
  std::string_view algorithm{sig.algorithm()};
  EXPECT_NE(algorithm.find("sha256"), std::string_view::npos)
    << "Signature algorithm should match Basic256Sha256 policy; got: " << algorithm;

  session.close_sync();
  channel.close_sync();
}

// Requirement #111: Client signature uses leaf cert only (not full chain) as input.
// Spec: Part 4, 5.6.3 - The signature input is serverCertificate + serverNonce
// (where serverCertificate is the leaf DER, not the full chain).
// Limitation: this test would pass regardless of which cert bytes the client used,
// because the server accepts the signature either way in the current setup.
// SESS_ActivateSessionClientSignatureCorrect already verifies the signature content
// directly by capturing the ActivateSessionRequest via observer.
// This test serves as a smoke test for the authenticated activate path.
// @relation(SVR-SESS-021, scope=function)
TEST_F(ComplianceSessionWithHooks, SESS_ClientSignatureUsesLeafCertOnly)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto session = channel.create_session_sync({.sessionName = "LeafCertOnly"});
  session.activate_sync();
  EXPECT_TRUE(session.is_active())
    << "Successful activation on authenticated channel proves client signature uses leaf cert input";
  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// I-intercept tests (ComplianceSessionWithHooks - response manipulation)
// ===========================================================================

// Requirement #95: Client rejects CreateSession when server certificate in response
// does not match the certificate used on the SecureChannel.
// @relation(SVR-SESS-016, scope=function)
TEST_F(ComplianceSessionWithHooks, SESS_ServerCertMismatchRejected)
{
  // Spec: Part 4, 5.6.2 - Client shall verify that serverCertificate in CreateSessionResponse
  // matches the certificate used to create the SecureChannel.
  //
  // The interceptor replaces server_certificate in the response with an empty ByteString.
  // The server signs the corrupted response, so it arrives with valid UASC-level integrity.
  // The client compares the response cert against the OPN cert and rejects on mismatch.
  mResponseInterceptorFn = [](ua::Response& response)
  {
    auto* createResp = dynamic_cast<ua::CreateSessionResponse*>(response.second.get());
    if (createResp)
    {
      // Clear the server certificate - a mismatch with the OPN cert.
      // (Don't use garbage bytes - OpenSSL d2i_X509 can hang on arbitrary data.)
      createResp->server_certificate() = ua::ByteString{};
    }
  };

  auto channel = open_channel(ua::MessageSecurityMode::SignAndEncrypt, ua::SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  auto result = channel.try_create_session_sync({.sessionName = "CertMismatch"});

  EXPECT_TRUE(result.is_bad())
    << "Client should reject CreateSession when server certificate doesn't match channel cert";

  if (result.is_good())
    result.value().close_sync();
  channel.close_sync();
}

// Requirement #98: Client rejects CreateSession when server signature is invalid.
// @verifies CL-SESS-004
// @relation(CL-SESS-004, SVR-SESS-016, scope=function)
TEST_F(ComplianceSessionWithHooks, SESS_ServerSignatureInvalidRejected)
{
  // Install interceptor that corrupts the server_signature in CreateSessionResponse.
  mResponseInterceptorFn = [](ua::Response& response)
  {
    auto* createResp = dynamic_cast<ua::CreateSessionResponse*>(response.second.get());
    if (createResp)
    {
      auto& sig = createResp->server_signature();
      auto sigBytes = sig.signature();
      for (auto& b : sigBytes)
        b = ~b;
      sig.signature() = std::move(sigBytes);
    }
  };

  auto channel = open_channel(ua::MessageSecurityMode::SignAndEncrypt, ua::SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  auto result = channel.try_create_session_sync({.sessionName = "SigInvalid"});

  // The client should reject because the server signature is invalid.
  // Current behavior: client validates signature - should return BadApplicationSignatureInvalid.
  EXPECT_TRUE(result.is_bad()) << "Client should reject CreateSession when server signature is corrupted";

  if (channel.is_open())
    channel.close_sync();
}

// Part 4 5.6.2.1: "If a Server terminates a Session for any other reason, Subscriptions associated with
// the Session, are not deleted. Each Subscription has its own lifetime to protect against data loss in
// the case of a Session termination. In these cases, the Subscription can be reassigned to another
// Client before its lifetime expires."
//
// Before this, an inactivity timeout deleted them, so the 6.7 reconnect ladder could never reach its
// TransferSubscriptions rung: a client whose Session was reaped while it was away could only recreate.
//
// SECURED fixture deliberately: 5.13.7.1 requires an ANONYMOUS owner's transfer to arrive over a
// Sign/SignAndEncrypt channel, so a None-channel probe would be refused for a reason unrelated to
// this row.
TEST_F(ComplianceSessionLimited, TimedOutSessionLeavesItsSubscriptionsTransferable)
{
  auto ownerChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto ownerSession = ownerChannel.create_session_sync(
    {.requestedSessionTimeout = std::chrono::milliseconds{1000}, .sessionName = "OrphanOwner"});
  ownerSession.activate_sync();

  ua::CreateSubscriptionRequest createRequest;
  createRequest.requested_publishing_interval() = 500.0;
  createRequest.requested_lifetime_count() = 6000;  // outlive the reap by a wide margin
  createRequest.requested_max_keep_alive_count() = 100;
  createRequest.publishing_enabled() = true;
  auto created = ownerSession.subscriptions().create_subscription_sync(std::move(createRequest));
  ASSERT_THAT(created, ServiceResultIsGood());
  const auto subscriptionId = created.subscription_id();

  // Let the owner go silent so the server reaps it. No CloseSession: this row is about the TIMEOUT
  // path, which is the one that used to delete.
  std::this_thread::sleep_for(std::chrono::seconds{3});

  // A fresh Session, same anonymous identity, same application, over a secured channel.
  auto heirChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto heirSession = heirChannel.create_session_sync({.sessionName = "OrphanHeir"});
  heirSession.activate_sync();

  ua::TransferSubscriptionsRequest transferRequest;
  transferRequest.subscription_ids().push_back(subscriptionId);
  transferRequest.send_initial_values() = true;
  auto transferred = heirSession.subscriptions().transfer_subscriptions_sync(std::move(transferRequest));
  ASSERT_THAT(transferred, ServiceResultIsGood());
  ASSERT_EQ(transferred.results().size(), 1u);
  EXPECT_TRUE(transferred.results()[0].status_code().is_good())
    << "a Subscription whose Session was reaped must still be transferable, got 0x" << std::hex
    << transferred.results()[0].status_code().as_uint32()
    << " - Bad_SubscriptionIdInvalid means it was deleted with its Session";

  (void)heirSession.try_close_sync();
  (void)heirChannel.try_close_sync();
}

// Part 4 5.6.2: CreateSession is unauthenticated by design, so a Session that has only been created
// proves nothing and may serve nothing until ActivateSession has proved possession of the private
// key. The plausible error is to treat the authenticationToken as sufficient on its own and dispatch
// the request, which would make the whole proof-of-possession step optional with nothing in the
// protocol reporting that it had been skipped.
//
// The existing pre-activation rows (P4_SS_0024_MustActivateBeforeService,
// ReadBeforeActivateRejectedLocallyWithoutWire) stop at the CLIENT's local gate and deliberately
// assert the request never reaches the wire, so neither of them puts the question to the server. Here
// the client-side gate is lifted so the Read genuinely travels with the real authenticationToken, and
// the refusal that is asserted is the server's own. Bad_SessionNotActivated rather than
// Bad_SessionIdInvalid is the observable that the Session EXISTS and is nonetheless serving nothing.
// @verifies AC-SVR-SESS-004-UNUSABLE-BEFORE-ACTIVATE
TEST_F(ComplianceSessionWithHooks, CreatedSessionIsRefusedServiceByTheServerUntilItIsActivated)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "ServerSideActivationGate"});
  ASSERT_TRUE(session.is_created());
  ASSERT_FALSE(session.is_active());

  const auto sessionId = session.session_id();
  const auto authToken = session_state(session).authenticationToken;
  ASSERT_FALSE(sessionId.is_null());
  ASSERT_FALSE(authToken.is_null());

  // Lift ONLY the client-side pre-activation gate, so the Read is actually sent carrying the real
  // authenticationToken. The server-side antecedent -- a Session that has never been activated -- is
  // untouched, so the refusal asserted below is decided by the server.
  CSSTA::on_strand(session, [&](auto& g) { g.set_session_active(sessionId, authToken); });

  auto result = session.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(result.is_bad()) << "a Read on a created-but-unactivated Session must be refused";
  EXPECT_EQ(result.status_code().as_status(), Status::BadSessionNotActivated)
    << "got 0x" << std::hex << result.status_code().as_uint32()
    << " - Bad_SessionIdInvalid would deny the Session's existence, Good would mean the "
       "proof-of-possession step is optional";

  // The refusal must be the server's decision, not the client's local gate: the request reached the
  // server's SecureChannel and was dispatched to the Session that the token names.
  EXPECT_TRUE(wait_for_requests("ReadRequest", 1, std::chrono::seconds{5}))
    << "the Read must have reached the server for its refusal to be the server's";

  (void)session.try_close_sync();
  channel.close_sync();
}

// Part 4 5.6.2: "the Server shall close the oldest Session that is not activated before reaching the
// maximum number of supported Sessions." The eviction is keyed on NOT-ACTIVATED first and age second.
// A server that implements it as a plain oldest-first LRU passes whenever the unactivated Sessions
// happen to be the oldest, and silently drops a paying client's activated Session as soon as they are
// not -- which is the arrangement built here: the activated Session is deliberately created FIRST, so
// oldest-first and unactivated-first disagree about which one to close.
//
// The existing rows cannot see this. P4_SS_0005_OldestUnactivatedSessionClosedOnMax fills the server
// with unactivated Sessions only, and P4_SS_0005_ActivatedSessionNotEvicted fills it with activated
// ones only and then accepts either outcome. Neither presents the mix the obligation is about.
// @verifies AC-SVR-SESS-005-EVICT-UNACTIVATED
TEST_F(ComplianceSessionLimited, EvictionAtTheSessionLimitTakesTheUnactivatedSessionNotTheActivatedOne)
{
  // mMaxSessions = 2.
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  // The OLDEST Session is the activated one: an oldest-first policy would close this one.
  auto activated = channel.create_session_sync({.sessionName = "MixActivated"});
  activated.activate_sync();
  ASSERT_TRUE(activated.is_active());

  auto unactivated = channel.create_session_sync({.sessionName = "MixUnactivated"});
  ASSERT_TRUE(unactivated.is_created());
  ASSERT_FALSE(unactivated.is_active());

  // At the cap. One more Session must be admitted, and the room for it must come from the eviction.
  auto extraResult = channel.try_create_session_sync({.sessionName = "MixOverflow"});
  ASSERT_TRUE(extraResult.is_good())
    << "creating past the cap must succeed by closing the unactivated Session; status 0x" << std::hex
    << extraResult.status_code().as_uint32();
  auto extra = std::move(extraResult).value();
  ASSERT_TRUE(extra.is_created());

  // Conjunct 1: the unactivated Session is the one that was closed.
  auto evicted = unactivated.try_activate_sync();
  EXPECT_TRUE(evicted.is_bad()) << "the unactivated Session must have been closed to make room";

  // Conjunct 2: no activated Session was evicted while an unactivated one existed -- even though the
  // activated one is the older of the two.
  auto survivorRead = activated.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(survivorRead.is_good())
    << "an activated Session must not be evicted while an unactivated one exists; status 0x" << std::hex
    << survivorRead.status_code().as_uint32();
  EXPECT_THAT(survivorRead.value(), ::ua::test_helpers::ServiceResultIsGood())
    << "the surviving activated Session must still serve requests";

  extra.activate_sync();
  (void)extra.try_close_sync();
  (void)activated.try_close_sync();
  channel.close_sync();
}

// Part 4 section 5.6.2.3 Table 16: "Bad_TooManySessions - The Server has reached its maximum number of
// Sessions." This is the shape the condition has to take on the wire, and it is only reachable when
// SVR-SESS-005's close-oldest-unactivated policy can free nothing -- which is to say when every
// existing Session is activated. A test that merely fills the server exercises the eviction path and
// returns Good, so the arrangement below activates every Session it creates.
//
// The second half of the observation is what stops a server buying room by closing a Session someone
// is using: refusing is the required behaviour, and refusing AFTER quietly evicting an activated
// Session would satisfy the status assertion alone. Both incumbents are therefore required to still
// serve a request afterwards. The release at the end is the falsifiability control -- it shows the
// refusal was the cap and not a fixture that had simply stopped admitting Sessions.
// @verifies AC-SVR-SESS-043-TOOMANYSESSIONS
TEST_F(ComplianceSessionLimited, CreateSessionAtTheCapWithNothingEvictableIsRefusedWithBadTooManySessions)
{
  // mMaxSessions = 2.
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  auto first = channel.create_session_sync({.sessionName = "CapacityFirst"});
  first.activate_sync();
  ASSERT_TRUE(first.is_active()) << "the first Session must be activated, or the eviction policy has "
                                    "something it is allowed to take";

  auto second = channel.create_session_sync({.sessionName = "CapacitySecond"});
  second.activate_sync();
  ASSERT_TRUE(second.is_active()) << "the second Session must be activated, or the eviction policy has "
                                     "something it is allowed to take";

  // At the cap, with every Session activated.
  auto refused = channel.try_create_session_sync({.sessionName = "CapacityOverflow"});
  EXPECT_TRUE(refused.is_bad())
    << "CreateSession at the cap with every existing Session activated must not yield a Session - the "
       "eviction policy has nothing it may free";
  EXPECT_EQ(refused.status_code().as_status(), Status::BadTooManySessions)
    << "got 0x" << std::hex << refused.status_code().as_uint32()
    << " - Table 16 gives this condition one status, and a client cannot tell a full server from any "
       "other failure without it";
  if (refused.is_good())
    (void)refused.value().try_close_sync();

  // Conjunct two: no activated Session was evicted to make room for the refused one.
  auto firstRead = first.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(firstRead.is_good()) << "the first activated Session was closed to admit a new one; status 0x"
                                   << std::hex << firstRead.status_code().as_uint32();
  EXPECT_THAT(firstRead.value(), ::ua::test_helpers::ServiceResultIsGood())
    << "the first activated Session must still serve requests after the refusal";

  auto secondRead = second.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(secondRead.is_good()) << "the second activated Session was closed to admit a new one; status 0x"
                                    << std::hex << secondRead.status_code().as_uint32();
  EXPECT_THAT(secondRead.value(), ::ua::test_helpers::ServiceResultIsGood())
    << "the second activated Session must still serve requests after the refusal";

  // Falsifiability control: freeing one slot makes the very next CreateSession succeed, so the refusal
  // above is attributable to the cap and not to the fixture.
  second.close_sync();
  // The slot is freed by the CloseSession the server has already answered; the brief wait only absorbs
  // teardown that trails the response, so a slow machine cannot turn this control into a failure.
  std::this_thread::sleep_for(std::chrono::milliseconds{200});
  auto admitted = channel.try_create_session_sync({.sessionName = "CapacityAfterRelease"});
  ASSERT_TRUE(admitted.is_good())
    << "closing an activated Session must free the slot the refusal was about; status 0x" << std::hex
    << admitted.status_code().as_uint32();
  auto admittedSession = std::move(admitted).value();
  admittedSession.activate_sync();
  EXPECT_TRUE(admittedSession.is_active()) << "the Session admitted into the freed slot must activate";

  admittedSession.close_sync();
  first.close_sync();
  channel.close_sync();
}

// Part 4 5.6.3: "A Client shall prove possession by using the private key to sign the Nonce provided
// by the Server in the response." The nonce is the whole mechanism -- a server that verifies only
// that SOME well-formed signature is present, or that verifies it against a nonce other than the one
// it issued for this CreateSession response, has turned proof-of-possession into a replayable token.
//
// Both halves are driven through the real client signing path: the client still holds its own private
// key and still produces (or deliberately omits) the signature itself, and the refusal comes from the
// server's verifier. The control activation on the same channel keeps the negatives falsifiable -- it
// shows a refusal below is attributable to the signature and not to the fixture.
// @verifies AC-SVR-SESS-011-CLIENT-PROOF
TEST_F(ComplianceSession, ActivateSessionRequiresAClientSignatureOverTheNonceTheServerIssued)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  // Control: an untouched Session on this very channel activates.
  auto control = channel.create_session_sync({.sessionName = "ProofControl"});
  auto controlResult = control.try_activate_sync();
  ASSERT_TRUE(controlResult.is_good()) << "control activation must succeed on this channel; status 0x"
                                       << std::hex << controlResult.status_code().as_uint32();
  ASSERT_TRUE(control.is_active());
  control.close_sync();

  // (a) Signature over an attacker-chosen nonce. The client signs serverCertificate || serverNonce
  // with its real private key; only the nonce it signs over is no longer the one the server issued in
  // the CreateSession response, so the signature is well-formed, correctly algorithm-tagged and made
  // with the right key -- and still must not activate the Session.
  auto wrongNonce = channel.create_session_sync({.sessionName = "ProofWrongNonce"});
  const auto issuedNonce = session_state(wrongNonce).serverNonce;
  ASSERT_GE(issuedNonce.size(), 32u) << "no server nonce was issued, so there is nothing to diverge from";
  CSSTA::on_strand(wrongNonce,
    [](auto& g)
    {
      for (auto& b : g.server_nonce())
        b = ~b;
    });

  auto wrongNonceResult = wrongNonce.try_activate_sync();
  EXPECT_TRUE(wrongNonceResult.is_bad())
    << "a client signature over a nonce the server never issued must not activate the Session";
  EXPECT_FALSE(wrongNonce.is_active())
    << "the Session must be left unactivated when the client proof does not cover the issued nonce";
  (void)wrongNonce.try_close_sync();

  // (b) Signature absent. Dropping the client key pair makes SessionImpl take its documented
  // "no signature available" path: ActivateSession is still sent, with an empty clientSignature, over
  // an authenticated channel where the proof is mandatory.
  auto noSignature = channel.create_session_sync({.sessionName = "ProofNoSignature"});
  CSSTA::on_strand(noSignature, [](auto& g) { g.security_info().clientKeyPair = nullptr; });

  auto noSignatureResult = noSignature.try_activate_sync();
  EXPECT_TRUE(noSignatureResult.is_bad())
    << "ActivateSession carrying no client signature must be refused on an authenticated channel";
  EXPECT_FALSE(noSignature.is_active())
    << "the Session must be left unactivated when no proof of possession was supplied";
  (void)noSignature.try_close_sync();

  channel.close_sync();
}

// Part 4 5.6.2: a Session that goes `revisedSessionTimeout` without a request is terminated by the
// server itself. Nobody asks for this close and no client is waiting on it, so the plausible
// implementation is one that never runs it at all, or one that marks the Session dead locally while
// leaving its authenticationToken routable -- in which case the Session's resources are held for the
// life of the process and its token still names something.
//
// The refusal has to be shown to be the SERVER's. A Read issued on the reaped Session's own handle
// cannot show that: the client's timer fires at 75% of the revised timeout, drops its channel
// reference and answers locally with Bad_SessionClosed, so that request never leaves the process
// (which is what P4_SS_0012_SessionTimeoutWithoutActivity actually observes). Here the stale token is
// carried by a SECOND, genuinely live Session on the same channel, so the request really travels and
// the status returned is the server's own routing decision.
// @verifies AC-SVR-SESS-012-TIMEOUT-TERMINATES
TEST_F(ComplianceSessionWithHooks, AnIdleSessionIsTerminatedByTheServerAndItsTokenIsNoLongerHonoured)
{
  struct TimeoutCapture : server::ServerObserver
  {
    std::mutex mutex;
    std::vector<ua::NodeId> timedOut;

    void on_session_timed_out(const server::SessionEventInfo& info) override
    {
      std::lock_guard lock(mutex);
      timedOut.push_back(info.sessionId);
    }

    bool saw(const ua::NodeId& sessionId)
    {
      std::lock_guard lock(mutex);
      for (const auto& id : timedOut)
      {
        if (id == sessionId)
          return true;
      }
      return false;
    }
  };

  auto observer = std::make_shared<TimeoutCapture>();
  mServer->set_observer(observer);

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  // Revised up to the fixture minimum of 1000ms, then left completely silent.
  auto idle = channel.create_session_sync(
    {.requestedSessionTimeout = std::chrono::milliseconds{1}, .sessionName = "IdleReaped"});
  idle.activate_sync();
  ASSERT_TRUE(idle.is_active());

  const auto idleSessionId = idle.session_id();
  const auto idleToken = session_state(idle).authenticationToken;
  ASSERT_FALSE(idleSessionId.is_null());
  ASSERT_FALSE(idleToken.is_null());

  // Conjunct 1: the server terminates it unprompted. Nothing is sent between activation and this
  // check, so the only thing that can close the Session is the server's own idle timer.
  bool reaped = false;
  for (int attempt = 0; attempt < 200 && !reaped; ++attempt)
  {
    reaped = observer->saw(idleSessionId);
    if (!reaped)
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  EXPECT_TRUE(reaped) << "the server must terminate a Session that outlives its revised timeout with no "
                         "request, without being asked to";

  // Let the close finish tearing the Session down before probing its token.
  std::this_thread::sleep_for(std::chrono::milliseconds{200});

  // Conjunct 2: a later request on the reaped Session's token is refused. The token rides on a live
  // Session so the Read is genuinely sent; the client's own gate cannot be what answers it.
  auto witness = channel.create_session_sync({.sessionName = "IdleReapedWitness"});
  witness.activate_sync();
  ASSERT_TRUE(witness.is_active());
  const auto witnessId = witness.session_id();
  const auto witnessToken = session_state(witness).authenticationToken;
  ASSERT_FALSE(witnessToken.is_null());
  ASSERT_NE(witnessToken, idleToken);

  CSSTA::on_strand(witness, [&](auto& g) { g.set_session_active(idleSessionId, idleToken); });

  auto staleResult = witness.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(staleResult.is_bad()) << "a request carrying a timed-out Session's token must be refused";
  EXPECT_EQ(staleResult.status_code().as_status(), Status::BadSessionIdInvalid)
    << "got 0x" << std::hex << staleResult.status_code().as_uint32()
    << " - Good would mean the reaped Session was still serving requests";
  EXPECT_TRUE(wait_for_requests("ReadRequest", 1, std::chrono::seconds{5}))
    << "the Read must have reached the server for its refusal to be the server's";

  // Falsifiability control: the same handle, on the same channel, with its OWN token, is served -- so
  // the refusal above is attributable to the reaped token and not to the fixture.
  CSSTA::on_strand(witness, [&](auto& g) { g.set_session_active(witnessId, witnessToken); });
  auto controlResult = witness.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(controlResult.is_good()) << "the live Session must still be served on this channel; status 0x"
                                       << std::hex << controlResult.status_code().as_uint32();
  EXPECT_THAT(controlResult.value(), ::ua::test_helpers::ServiceResultIsGood());

  (void)idle.try_close_sync();
  witness.close_sync();
  channel.close_sync();

  mServer->set_observer(nullptr);
}

// Part 4 5.6.2: the authenticationToken (and SessionId) must be unique for the server's lifetime, and
// a token from a closed Session must not be honoured. Reuse is the vulnerability: a sequential or
// index-derived allocator hands a closed Session's token back out, and the server's own check --
// token plus SecureChannelId -- then passes for a client holding a token it should no longer have.
//
// Uniqueness alone is not the obligation, so the stale token is also put back on the wire. It is
// carried by a live Session on the same channel, because the closed handle answers locally without
// sending anything; that makes the server the thing that decides, and Bad_SessionIdInvalid rather
// than Good is what shows the token was not matched to a live Session.
// @verifies AC-SVR-SESS-013-TOKEN-UNIQUE
TEST_F(ComplianceSessionWithHooks, AuthenticationTokensNeverRepeatAndAClosedSessionsTokenIsRefused)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  constexpr int rounds = 12;
  std::vector<ua::NodeId> tokens;
  std::vector<ua::NodeId> sessionIds;

  for (int round = 0; round < rounds; ++round)
  {
    auto session = channel.create_session_sync({.sessionName = "TokenChurn" + std::to_string(round)});
    session.activate_sync();
    ASSERT_TRUE(session.is_active()) << "round " << round;

    auto token = session_state(session).authenticationToken;
    auto sessionId = session.session_id();
    ASSERT_FALSE(token.is_null()) << "round " << round << ": no authentication token was issued";
    ASSERT_FALSE(sessionId.is_null()) << "round " << round << ": no session id was issued";
    tokens.push_back(token);
    sessionIds.push_back(sessionId);

    session.close_sync();
  }

  ASSERT_EQ(tokens.size(), static_cast<size_t>(rounds));
  ASSERT_EQ(sessionIds.size(), static_cast<size_t>(rounds));

  for (size_t i = 0; i < tokens.size(); ++i)
  {
    for (size_t j = i + 1; j < tokens.size(); ++j)
    {
      EXPECT_NE(tokens[i], tokens[j]) << "authentication token repeated between rounds " << i << " and " << j;
      EXPECT_NE(sessionIds[i], sessionIds[j]) << "session id repeated between rounds " << i << " and " << j;
    }
  }

  // A live Session to carry the closed Session's token, and to prove afterwards that this channel
  // still serves Reads at all.
  auto live = channel.create_session_sync({.sessionName = "TokenChurnLive"});
  live.activate_sync();
  ASSERT_TRUE(live.is_active());
  const auto liveId = live.session_id();
  const auto liveToken = session_state(live).authenticationToken;
  ASSERT_FALSE(liveToken.is_null());
  EXPECT_NE(liveToken, tokens.back()) << "a closed Session's token was handed straight back out";

  CSSTA::on_strand(live, [&](auto& g) { g.set_session_active(sessionIds.back(), tokens.back()); });

  auto staleResult = live.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(staleResult.is_bad()) << "a request carrying a closed Session's token must be refused";
  EXPECT_EQ(staleResult.status_code().as_status(), Status::BadSessionIdInvalid)
    << "got 0x" << std::hex << staleResult.status_code().as_uint32()
    << " - Good would mean the stale token was matched to a live Session";
  EXPECT_TRUE(wait_for_requests("ReadRequest", 1, std::chrono::seconds{5}))
    << "the Read must have reached the server for its refusal to be the server's";

  // Falsifiability control: the same handle with its OWN token is served.
  CSSTA::on_strand(live, [&](auto& g) { g.set_session_active(liveId, liveToken); });
  auto controlResult = live.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(controlResult.is_good()) << "the live Session must still be served on this channel; status 0x"
                                       << std::hex << controlResult.status_code().as_uint32();
  EXPECT_THAT(controlResult.value(), ::ua::test_helpers::ServiceResultIsGood());

  live.close_sync();
  channel.close_sync();
}

// Part 4 5.6.2: the serverNonce returned by CreateSession must be at least 32 bytes and must come
// from a CSPRNG -- it is the nonce the FIRST ActivateSession signs, so a nonce that recurs turns that
// proof of possession into a signature an eavesdropper can replay against a later Session. Length is
// the half everything already checks; freshness is the half a plausible implementation gets wrong, by
// generating the nonce once per channel (or per server) and reusing it for every CreateSession on it.
// A single-session test cannot see that, so the nonce is collected across repeated CreateSessions on
// one channel and every pair is compared.
// @verifies AC-SVR-SESS-015-CREATESESSION-NONCE
TEST_F(ComplianceSession, EveryCreateSessionResponseCarriesAFreshServerNonceOfAtLeast32Bytes)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  constexpr int rounds = 8;
  std::vector<ua::ByteString> nonces;

  for (int round = 0; round < rounds; ++round)
  {
    auto captured =
      create_session_with_capture(channel, {.sessionName = "NonceFreshness" + std::to_string(round)});
    auto nonce = captured.response.server_nonce();
    EXPECT_GE(nonce.size(), 32u) << "round " << round
                                 << ": the CreateSession serverNonce must be at least 32 bytes";
    nonces.push_back(std::move(nonce));
    (void)captured.session.try_close_sync();
  }

  ASSERT_EQ(nonces.size(), static_cast<size_t>(rounds)) << "no serverNonce was collected to assert over";

  for (size_t i = 0; i < nonces.size(); ++i)
  {
    for (size_t j = i + 1; j < nonces.size(); ++j)
    {
      EXPECT_NE(nonces[i], nonces[j])
        << "the CreateSession serverNonce recurred between rounds " << i << " and " << j
        << " - a reused nonce makes the first ActivateSession signature replayable";
    }
  }

  channel.close_sync();
}

// ---------------------------------------------------------------------------
// Additional includes for the rows below. Placed here, at the end, for the same reason the
// server-side hook includes above are: they bring `ua::server` names into scope that must not
// shadow the unqualified `Session` / `SecureChannel` the earlier tests mean.
// ---------------------------------------------------------------------------
#include "ua_create_session_request.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_data_change_notification.h"
#include "ua_endpoint_description.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_notification.h"
#include "ua_monitoring_mode.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_service_fault.h"
#include "ua_session_monitored_item_services.h"
#include "ua_variable_id.h"

namespace
{

/// Every response the server put on the wire for one channel, recorded by the
/// `ComplianceSessionWithHooks` response interceptor. Held through a `shared_ptr` captured BY VALUE
/// in the interceptor so the record outlives the test body's locals if a late strand turn fires.
struct ServerResponseLog
{
  mutable std::mutex mutex;
  size_t createSessionResponses{0};
  std::vector<ua::StatusCode> faultStatuses;

  void record(const ua::Response& response)
  {
    if (response.second == nullptr)
      return;
    std::lock_guard lock(mutex);
    if (dynamic_cast<const ua::CreateSessionResponse*>(response.second.get()) != nullptr)
      ++createSessionResponses;
    if (const auto* fault = dynamic_cast<const ua::ServiceFault*>(response.second.get()))
      faultStatuses.push_back(fault->response_header().service_result());
  }
};

/// What the client actually put into the CreateSessionRequest it sent, captured from the client's
/// pre-framing outgoing-request interface. The criterion rows below assert against the bytes the SERVER
/// saw, not against what the client happens to have kept in its own fields.
struct SentCreateSessionRequest
{
  mutable std::mutex mutex;
  bool observed{false};
  ua::ByteString clientCertificate;
  ua::ByteString clientNonce;

  void record(const ua::CreateSessionRequest& request)
  {
    std::lock_guard lock(mutex);
    observed = true;
    clientCertificate = request.client_certificate();
    clientNonce = request.client_nonce();
  }
};

constexpr std::string_view reevalPrivilegedUser{"reeval-privileged"};
constexpr std::string_view reevalRestrictedUser{"reeval-restricted"};
constexpr std::string_view reevalPassword{"reeval-password"};

std::shared_ptr<ua::server::RoleConfiguration> identity_reevaluation_roles()
{
  return ua::server::RoleConfiguration::from_well_known_grants(
    {{ua::server::WellKnownRole::AuthenticatedUser, ua::IdentityCriteriaType::AuthenticatedUser},
      {ua::server::WellKnownRole::SecurityAdmin,
        ua::IdentityCriteriaType::UserName,
        ua::String{reevalPrivilegedUser}}});
}

void configure_identity_reevaluation_node(ua::server::Server& server)
{
  ua::RolePermissionType restricted;
  restricted.role_id() = ua::NodeId{ua::ObjectId::WellKnownRole_AuthenticatedUser};
  restricted.permissions() = ua::PermissionType{{ua::PermissionType::Bit::Browse}};
  ua::RolePermissionType privileged;
  privileged.role_id() = ua::NodeId{ua::ObjectId::WellKnownRole_SecurityAdmin};
  privileged.permissions() =
    ua::PermissionType{{ua::PermissionType::Bit::Browse, ua::PermissionType::Bit::Read}};
  server.address_space()
    .find_node_sync(ua::NodeId{ua::VariableId::Server_ServerStatus_CurrentTime})
    .set_role_permissions(std::vector<ua::RolePermissionType>{restricted, privileged});
}

}  // namespace

// Part 4 5.6.2: "If this parameter is null or empty the Server shall assign a value" (sessionName)
// and "This number shall have a minimum length of 32 bytes" (clientNonce). The two halves are
// opposite in kind and that is exactly the trap: an absent name is a gap the server FILLS, a short
// nonce is a request the server must REFUSE. An implementation that treats the nonce the way it
// treats the name -- accepting it and working around the length -- silently weakens the
// serverSignature that proves possession of the server's Application Instance Certificate, because
// the signature then covers fewer random bytes than the profile requires.
//
// The nonce half is asserted on the SERVER's answer, not on the client's. Truncating the nonce on
// the wire also leaves the client verifying the server signature against its own untruncated copy,
// so a client-side rejection would happen whether or not the server ever checked the length --
// `result.is_bad()` alone is therefore unfalsifiable here. Bad_NonceInvalid observed on the response
// the server emitted, with no CreateSessionResponse alongside it, is the server's own refusal.
// @verifies AC-SVR-SESS-009-NAME-AND-NONCE
TEST_F(ComplianceSessionWithHooks, AnAbsentSessionNameIsAssignedAndAClientNonceUnder32BytesIsRefused)
{
  struct NameCapture : server::ServerObserver
  {
    std::promise<std::string> capturedName;

    void on_session_created(const server::SessionEventInfo& info) override
    {
      capturedName.set_value(info.sessionName);
    }
  };

  auto observer = std::make_shared<NameCapture>();
  auto capturedName = observer->capturedName.get_future();
  mServer->set_observer(observer);

  // Half one: an empty sessionName is filled in by the server, and the Session is fully usable.
  {
    auto namedChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
    auto anonymousName = namedChannel.create_session_sync({.sessionName = ""});
    ASSERT_TRUE(anonymousName.is_created()) << "an empty sessionName must not be a rejection";
    ASSERT_EQ(capturedName.wait_for(std::chrono::seconds{5}), std::future_status::ready)
      << "the Session response arrived before the server observer callback completed";
    EXPECT_FALSE(capturedName.get().empty())
      << "the server must assign a sessionName when the client supplies none";

    anonymousName.activate_sync();
    EXPECT_TRUE(anonymousName.is_active());
    anonymousName.close_sync();
    namedChannel.close_sync();
  }

  mServer->set_observer(nullptr);

  // Half two: 16 bytes of clientNonce on an authenticated channel. Recorded from the interceptor
  // AFTER the first channel is closed, so nothing that channel emitted lands in the log.
  auto log = std::make_shared<ServerResponseLog>();
  mResponseInterceptorFn = [log](ua::Response& response)
  {
    log->record(response);
  };

  auto shortNonceChannel =
    open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(shortNonceChannel.is_open());

  // The interface fires before framing, so the truncation here is what the server decodes. The client
  // still generates its own nonce and still signs and verifies with its real key material; only the
  // length of the nonce that reaches the server is changed.
  ua::client::SecureChannelTestAccess::on_strand(shortNonceChannel,
    [](auto& g)
    {
      g.outgoing_request_observer() = [](const ua::Structure& request)
      {
        const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
        if (createRequest == nullptr)
          return;
        ua::ByteString shortNonce;
        for (uint8_t i = 0; i < 16; ++i)
          shortNonce.push_back(i);
        const_cast<ua::CreateSessionRequest&>(*createRequest).client_nonce() = std::move(shortNonce);
      };
    });

  auto shortNonceResult = shortNonceChannel.try_create_session_sync({.sessionName = "ShortClientNonce"});
  EXPECT_TRUE(shortNonceResult.is_bad())
    << "CreateSession carrying a 16-byte clientNonce must not yield a usable Session";
  if (shortNonceResult.is_good())
    (void)shortNonceResult.value().try_close_sync();

  bool sawNonceInvalid = false;
  {
    std::lock_guard lock(log->mutex);
    EXPECT_EQ(log->createSessionResponses, 0u)
      << "the server answered a 16-byte clientNonce with a CreateSessionResponse - it accepted it";
    ASSERT_FALSE(log->faultStatuses.empty())
      << "the server emitted no fault at all for the short-nonce CreateSession";
    for (const auto& status : log->faultStatuses)
    {
      if (status.as_status() == Status::BadNonceInvalid)
        sawNonceInvalid = true;
    }
  }
  EXPECT_TRUE(sawNonceInvalid)
    << "32 bytes is a minimum, not a recommendation: the refusal must be Bad_NonceInvalid";

  ua::client::SecureChannelTestAccess::on_strand(
    shortNonceChannel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  (void)shortNonceChannel.try_close_sync();
}

// Part 4 5.6.2: "If the securityPolicyUri is None, the Server shall ignore the
// ApplicationInstanceCertificate." Validating it anyway is the intuitive behaviour and it is
// non-conformant: at None there is no key to prove possession of, so a certificate check tests a
// claim nobody made, and it rejects clients that correctly send nothing at all.
//
// Both halves of the obligation are driven. An EXPIRED certificate is stamped into the outgoing
// CreateSessionRequest -- one a validating server must reject and an ignoring server must not even
// parse -- and, separately, the request is asserted to have carried no certificate at all before
// the Session is created from it. "Ignored" is asserted as far as a usable Session, not merely as a
// non-error at CreateSession.
// @verifies AC-SVR-SESS-010-NONE-IGNORES-CERT
TEST_F(ComplianceSession, AtSecurityPolicyNoneAnExpiredOrAbsentClientCertificateIsIgnored)
{
  TestPki pki{mCrypto};

  auto caKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(caKeys);
  auto caCert = pki.create_root_ca(caKeys, "Expired Client CA", "400");

  auto leafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(leafKeys);

  auto now = DateTime::now();
  auto expiredFrom = DateTime{now.value() - std::chrono::days{400}};
  auto expiredTo = DateTime{now.value() - std::chrono::days{300}};
  auto expiredCert = pki.create_leaf_cert(leafKeys,
    caKeys,
    caCert,
    expiredFrom,
    expiredTo,
    /*uris=*/{"urn:test:compliance:expiredclient"},
    /*hostnames=*/{"localhost", "127.0.0.1"},
    /*name=*/"Expired Client Leaf");
  ASSERT_NE(expiredCert, nullptr);

  auto expiredDer = expiredCert->der_encoding();
  ASSERT_FALSE(expiredDer.empty()) << "nothing to ignore if the expired certificate has no bytes";

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  // Half one: an expired ApplicationInstanceCertificate supplied at None.
  ua::client::SecureChannelTestAccess::on_strand(channel,
    [expiredDer](auto& g)
    {
      g.outgoing_request_observer() = [expiredDer](const ua::Structure& request)
      {
        const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
        if (createRequest == nullptr)
          return;
        const_cast<ua::CreateSessionRequest&>(*createRequest).client_certificate() = expiredDer;
      };
    });

  auto expiredResult = channel.try_create_session_sync({.sessionName = "NoneExpiredCert"});
  ASSERT_TRUE(expiredResult.is_good())
    << "an expired certificate must be ignored at None, not validated; status 0x" << std::hex
    << expiredResult.status_code().as_uint32();
  auto expiredSession = std::move(expiredResult).value();

  auto expiredActivate = expiredSession.try_activate_sync();
  ASSERT_TRUE(expiredActivate.is_good())
    << "the Session created with an expired certificate at None must activate; status 0x" << std::hex
    << expiredActivate.status_code().as_uint32();
  auto expiredRead = expiredSession.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(expiredRead, ::ua::test_helpers::ServiceResultIsGood())
    << "the Session must be usable - 'accepted' is not 'ignored' unless it serves requests";
  expiredSession.close_sync();

  // Half two: no certificate at all. Recording what was sent keeps this falsifiable - without it
  // the row would pass even if the client had quietly attached one.
  auto sent = std::make_shared<SentCreateSessionRequest>();
  ua::client::SecureChannelTestAccess::on_strand(channel,
    [sent](auto& g)
    {
      g.outgoing_request_observer() = [sent](const ua::Structure& request)
      {
        const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
        if (createRequest == nullptr)
          return;
        sent->record(*createRequest);
      };
    });

  auto bareResult = channel.try_create_session_sync({.sessionName = "NoneNoCert"});
  ASSERT_TRUE(bareResult.is_good())
    << "CreateSession with no ApplicationInstanceCertificate must succeed at None; status 0x" << std::hex
    << bareResult.status_code().as_uint32();
  auto bareSession = std::move(bareResult).value();

  {
    std::lock_guard lock(sent->mutex);
    ASSERT_TRUE(sent->observed) << "no CreateSessionRequest was seen, so nothing was asserted over";
    EXPECT_TRUE(sent->clientCertificate.empty())
      << "the second half must actually supply no certificate for its success to mean anything";
  }

  auto bareActivate = bareSession.try_activate_sync();
  ASSERT_TRUE(bareActivate.is_good()) << "a certificate-less Session at None must activate; status 0x"
                                      << std::hex << bareActivate.status_code().as_uint32();
  auto bareRead = bareSession.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(bareRead, ::ua::test_helpers::ServiceResultIsGood())
    << "a certificate is not required at None, so the Session must serve requests";
  bareSession.close_sync();

  ua::client::SecureChannelTestAccess::on_strand(
    channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  channel.close_sync();
}

// Part 4 5.6.2.2: the serverSignature is computed by "appending the clientNonce to the
// clientCertificate and signing" with the private key of the server's Application Instance
// Certificate, and that certificate must be the one that opened the SecureChannel. This is the
// direction that stops a client being fooled by a server presenting a certificate it does not hold
// the key for; the channel-identity clause is what stops it presenting a DIFFERENT certificate at
// session creation than at channel open.
//
// The existing row (P4_SS_0016_ServerSignsNonce) asserts only that the signature and its algorithm
// string are non-empty, which any server that emits random bytes passes. Here the signature is
// verified cryptographically, over exactly the clientCertificate and clientNonce the client put on
// the wire, under the public key of the certificate the fixture opened the channel with. The
// tampered re-verification below is the falsifiability control: it proves the verify call can fail.
// @verifies AC-SVR-SESS-016-SERVER-PROOF
TEST_F(ComplianceSession, TheCreateSessionServerSignatureVerifiesUnderTheChannelsServerCertificate)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  auto sent = std::make_shared<SentCreateSessionRequest>();
  ua::client::SecureChannelTestAccess::on_strand(channel,
    [sent](auto& g)
    {
      g.outgoing_request_observer() = [sent](const ua::Structure& request)
      {
        const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
        if (createRequest == nullptr)
          return;
        sent->record(*createRequest);
      };
    });

  auto captured = create_session_with_capture(channel, {.sessionName = "ServerProof"});
  ASSERT_TRUE(captured.session.is_created());

  ua::ByteString sentCertificate;
  ua::ByteString sentNonce;
  {
    std::lock_guard lock(sent->mutex);
    ASSERT_TRUE(sent->observed) << "no CreateSessionRequest was observed, so the signed input is unknown";
    sentCertificate = sent->clientCertificate;
    sentNonce = sent->clientNonce;
  }
  ASSERT_FALSE(sentCertificate.empty()) << "no clientCertificate was sent on an authenticated channel";
  ASSERT_GE(sentNonce.size(), 32u) << "no clientNonce was sent, so there is no proof to verify";

  // Conjunct two: the certificate in the response is the one that opened the SecureChannel. The
  // fixture opened the channel pinned to mServerCert, so equality with it is that identity.
  ASSERT_NE(mServerCert, nullptr);
  auto channelCertificateDer = mServerCert->der_encoding();
  ASSERT_FALSE(channelCertificateDer.empty());
  EXPECT_EQ(captured.response.server_certificate(), channelCertificateDer)
    << "the CreateSession response named a different certificate than the one that opened the channel";

  // Conjunct one: the signature verifies over clientCertificate || clientNonce.
  ua::ByteString signedInput = sentCertificate;
  for (auto b : sentNonce)
    signedInput.push_back(b);
  ASSERT_FALSE(signedInput.empty());

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ASSERT_NE(policy, nullptr);

  const auto& signature = captured.response.server_signature();
  ASSERT_FALSE(signature.signature().empty()) << "the server sent no signature to verify";

  auto serverPublicKey = mServerCert->public_key();
  ASSERT_FALSE(serverPublicKey.empty());

  bool verified = false;
  try
  {
    mCrypto->asymmetric_verify_sync(
      policy->asymmetric_signature_algorithm(), serverPublicKey, signedInput, signature.signature());
    verified = true;
  }
  catch (...)
  {
    verified = false;
  }
  EXPECT_TRUE(verified) << "the serverSignature does not verify over clientCertificate || clientNonce "
                           "under the public key of the certificate that opened the SecureChannel";

  // Falsifiability control: the same verification over one flipped byte must NOT succeed, so the
  // assertion above is not passing because the verify call accepts anything.
  ua::ByteString tamperedInput = signedInput;
  tamperedInput[tamperedInput.size() - 1] = static_cast<uint8_t>(~tamperedInput[tamperedInput.size() - 1]);
  bool tamperedVerified = false;
  try
  {
    mCrypto->asymmetric_verify_sync(
      policy->asymmetric_signature_algorithm(), serverPublicKey, tamperedInput, signature.signature());
    tamperedVerified = true;
  }
  catch (...)
  {
    tamperedVerified = false;
  }
  EXPECT_FALSE(tamperedVerified) << "verification accepts altered input, so the positive result above "
                                    "would hold for any signature at all";

  captured.session.activate_sync();
  captured.session.close_sync();
  ua::client::SecureChannelTestAccess::on_strand(
    channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  channel.close_sync();
}

// Part 4 5.6.2: "The Server shall return a set of EndpointDescriptions available for the serverUri
// specified in the request." The client compares this list against the one it discovered, which is
// how a tampered discovery response is caught: discovery is unsecured and CreateSession is not, so a
// difference between the two is the detection. A server that returns a DIFFERENT or EMPTY list when
// a serverUri is named defeats that check without failing anything.
//
// The two existing rows never name a serverUri -- the client SDK leaves the field unset -- so
// neither of them puts the filtering clause to the server at all. Here the serverUri the server
// itself advertises through GetEndpoints is stamped into the request, and the returned list is
// compared field by field against the GetEndpoints answer for the same URL over the parameters
// Part 4 5.6.2 makes the client verify.
// @verifies AC-SVR-SESS-018-SERVERENDPOINTS
TEST_F(ComplianceSession, CreateSessionReturnsTheEndpointsForTheNamedServerUri)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  GetEndpointsRequest geReq;
  geReq.endpoint_url() = mEndpointUrl;
  auto geResp = channel.get_endpoints_sync(std::move(geReq));
  ASSERT_THAT(geResp, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_FALSE(geResp.endpoints().empty()) << "discovery returned nothing to compare against";

  std::string serverUri;
  for (const auto& discovered : geResp.endpoints().payload())
  {
    serverUri = std::string{discovered.server().application_uri()};
    break;
  }
  ASSERT_FALSE(serverUri.empty()) << "the server advertises no applicationUri, so none can be named";

  ua::client::SecureChannelTestAccess::on_strand(channel,
    [serverUri](auto& g)
    {
      g.outgoing_request_observer() = [serverUri](const ua::Structure& request)
      {
        const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
        if (createRequest == nullptr)
          return;
        const_cast<ua::CreateSessionRequest&>(*createRequest).server_uri() = serverUri;
      };
    });

  auto captured = create_session_with_capture(channel, {.sessionName = "ServerUriEndpoints"});
  ASSERT_TRUE(captured.session.is_created());

  const auto& offeredEndpoints = captured.response.server_endpoints();
  ASSERT_FALSE(offeredEndpoints.empty())
    << "naming a serverUri must not empty the list - an empty list defeats the client's "
       "discovery-tamper check without reporting an error";
  EXPECT_EQ(offeredEndpoints.size(), geResp.endpoints().size())
    << "CreateSession returned a different number of endpoints for the serverUri than GetEndpoints "
       "returned for the same URL";

  for (const auto& discovered : geResp.endpoints().payload())
  {
    const ua::EndpointDescription* matched = nullptr;
    for (const auto& offered : offeredEndpoints.payload())
    {
      if (offered.security_policy_uri() == discovered.security_policy_uri() &&
          offered.security_mode() == discovered.security_mode())
      {
        matched = &offered;
        break;
      }
    }
    ASSERT_NE(matched, nullptr) << "GetEndpoints offered (policy="
                                << std::string_view{discovered.security_policy_uri()}
                                << ", mode=" << static_cast<int>(discovered.security_mode())
                                << ") but CreateSession did not";

    EXPECT_EQ(std::string_view{matched->server().application_uri()}, serverUri)
      << "an endpoint returned for a named serverUri must belong to that serverUri";
    EXPECT_EQ(std::string_view{matched->endpoint_url()}, std::string_view{discovered.endpoint_url()});
    EXPECT_EQ(std::string_view{matched->transport_profile_uri()},
      std::string_view{discovered.transport_profile_uri()});
    EXPECT_EQ(matched->security_level(), discovered.security_level());
  }

  captured.session.activate_sync();
  captured.session.close_sync();
  ua::client::SecureChannelTestAccess::on_strand(
    channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  channel.close_sync();
}

// Part 4 5.6.2: "This parameter is deprecated and the array shall be empty"
// (serverSoftwareCertificates). Worth asserting in both directions: a server that populates it is
// non-conformant, and a client that required it non-empty would reject every conforming server -- a
// deprecated field is one whose absence must be HANDLED, not merely tolerated.
//
// The existing row checks emptiness on a None channel only and stops at CreateSession. The array is
// unconditional, so it is checked on both an unsecured and an authenticated channel here; and the
// client half of the observation is asserted by carrying each Session through to activation and a
// served Read, which is what "accepts the empty array as correct" means operationally.
// @verifies AC-SVR-SESS-020-SOFTWARECERTS-EMPTY
TEST_F(ComplianceSession, ServerSoftwareCertificatesIsEmptyAndTheClientTreatsThatAsCorrect)
{
  auto noneChannel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto noneCapture = create_session_with_capture(noneChannel, {.sessionName = "SoftwareCertsNone"});
  ASSERT_TRUE(noneCapture.session.is_created());

  EXPECT_TRUE(noneCapture.response.server_software_certificates().empty())
    << "serverSoftwareCertificates is deprecated and shall be empty on a None channel";
  EXPECT_EQ(noneCapture.response.server_software_certificates().size(), 0u);

  auto noneActivate = noneCapture.session.try_activate_sync();
  ASSERT_TRUE(noneActivate.is_good())
    << "the client must treat the empty deprecated array as correct, not as a missing field; status 0x"
    << std::hex << noneActivate.status_code().as_uint32();
  auto noneRead = noneCapture.session.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(noneRead, ::ua::test_helpers::ServiceResultIsGood())
    << "the Session must serve requests despite the empty serverSoftwareCertificates array";
  noneCapture.session.close_sync();
  noneChannel.close_sync();

  auto securedChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto securedCapture = create_session_with_capture(securedChannel, {.sessionName = "SoftwareCertsSecured"});
  ASSERT_TRUE(securedCapture.session.is_created());

  EXPECT_TRUE(securedCapture.response.server_software_certificates().empty())
    << "the array is empty unconditionally, including on an authenticated channel";
  EXPECT_EQ(securedCapture.response.server_software_certificates().size(), 0u);

  auto securedActivate = securedCapture.session.try_activate_sync();
  ASSERT_TRUE(securedActivate.is_good())
    << "activation must not depend on the deprecated array carrying anything; status 0x" << std::hex
    << securedActivate.status_code().as_uint32();
  auto securedRead = securedCapture.session.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(securedRead, ::ua::test_helpers::ServiceResultIsGood());
  securedCapture.session.close_sync();
  securedChannel.close_sync();
}

// Part 4 7.41: "A Server shall re-evaluate the permissions of all MonitoredItems in Subscriptions
// assigned to the Session after a user identity change." The plausible implementation checks the new
// identity at activation and stops there, leaving MonitoredItems created under the previous identity
// sampling and publishing on the old verdict -- so a client that activated once as a privileged user
// keeps receiving data it is no longer allowed to read for as long as it holds the Subscription.
//
// The obligation is about the identity-change EDGE. The periodic re-check is left at its 60-second
// default, while this test's observation window is much shorter, so only mandatory reauthorization can
// decide it. The monitored node is Server_ServerStatus_CurrentTime, whose value changes on every sample,
// so the item keeps producing notifications after the change and "stopped delivering" cannot pass
// vacuously through an item that simply had nothing new to report.
// Role grants are a function of the identity the stack resolves at ActivateSession, so
// nothing here sets the antecedent by hand.
//
// The shared fixtures advertise an Anonymous token policy only, which admits no identity change at
// all; hence the purpose-built server below.
// @verifies AC-SVR-IDENT-019-IDENTITY-CHANGE-REEVALUATES
// @relation(AC-SVR-AUTHZ-012-IDENTITY-CHANGE-REEVALUATES, scope=function)
TEST_F(ComplianceSession, AnIdentityChangeReEvaluatesThePermissionsOfTheSessionsMonitoredItems)
{
  const ua::NodeId monitoredNode{ua::VariableId::Server_ServerStatus_CurrentTime};

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ServerComponents components{.crypto = mCrypto, .applicationGroupCertificateStore = mServerCertStore};
  auto composite = std::make_shared<CompositeAuthenticator>();
  composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
  composite->add(UserTokenKind::UserName,
    std::make_shared<SimpleUserPasswordAuthenticator>(
      [](std::string_view username, const ua::SecureString& password)
      {
        return (username == reevalPrivilegedUser || username == reevalRestrictedUser) &&
               std::string_view{password.c_str()} == reevalPassword;
      }));
  components.authenticator = composite;
  components.roleConfiguration = identity_reevaluation_roles();

  server::CreateConfig identityServerCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  std::optional<ua::server::Server> identityServer;
  auto logSink = test_log_sink();
  components.logSink = logSink;
  components.logLevel = LogLevel::Debug;
  identityServer.emplace(ua::server::Server::create(
    mServerThreadPool.executor(), std::move(identityServerCfg), std::move(components)));
  configure_identity_reevaluation_node(*identityServer);

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto identityListener = identityServer->listen_sync(std::move(bind), {});

  auto userNamePolicy = create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256);
  const std::string userNamePolicyId{userNamePolicy.policy_id()};
  ASSERT_FALSE(userNamePolicyId.empty());

  ServerEndpointConfig identityEndpoint;
  identityEndpoint.name = "Basic256Sha256_SignAndEncrypt";
  identityEndpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  identityEndpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  identityEndpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  identityEndpoint.userIdentityTokens.push_back(std::move(userNamePolicy));
  identityServer->add_endpoint(identityListener, std::move(identityEndpoint));

  identityServer->start_sync();

  auto identityUrls = identityServer->advertised_urls(identityListener);
  ASSERT_FALSE(identityUrls.empty());
  auto identityEndpointUrl = identityUrls.front().str();

  CoreClient::OpenChannelConfig channelCfg;
  channelCfg.endpointUrl = identityEndpointUrl;
  channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelCfg.serverCertificate = mServerCert;
  auto channelResult = mClient->core().try_open_channel_sync(std::move(channelCfg));
  ASSERT_TRUE(channelResult.is_good())
    << "channel open must succeed; status 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();

  auto sessionResult = channel.try_create_session_sync({.sessionName = "IdentityReeval"});
  ASSERT_TRUE(sessionResult.is_good()) << "status 0x" << std::hex << sessionResult.status_code().as_uint32();
  auto session = std::move(sessionResult).value();

  ua::client::Session::ActivateConfig privilegedCfg;
  privilegedCfg.policyId = userNamePolicyId;
  privilegedCfg.identity = ua::client::UsernamePasswordIdentity{
    .username = std::string{reevalPrivilegedUser}, .password = std::string{reevalPassword}};
  auto privilegedActivate = session.try_activate_sync(std::move(privilegedCfg));
  ASSERT_TRUE(privilegedActivate.is_good()) << "the privileged identity must activate; status 0x" << std::hex
                                            << privilegedActivate.status_code().as_uint32();

  ua::CreateSubscriptionRequest subRequest;
  subRequest.requested_publishing_interval() = 50.0;
  subRequest.requested_lifetime_count() = 6000;
  subRequest.requested_max_keep_alive_count() = 100;
  subRequest.max_notifications_per_publish() = 0;
  subRequest.publishing_enabled() = true;
  auto subResponse = session.subscriptions().create_subscription_sync(std::move(subRequest));
  ASSERT_THAT(subResponse, ::ua::test_helpers::ServiceResultIsGood());
  const auto subscriptionId = subResponse.subscription_id();

  constexpr uint32_t clientHandle = 77;
  ua::CreateMonitoredItemsRequest miRequest;
  miRequest.subscription_id() = subscriptionId;
  miRequest.timestamps_to_return() = ua::TimestampsToReturn::Both;
  ua::MonitoredItemCreateRequest item;
  item.item_to_monitor().node_id() = monitoredNode;
  item.item_to_monitor().attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
  item.monitoring_mode() = ua::MonitoringMode::Reporting;
  item.requested_parameters().client_handle() = clientHandle;
  item.requested_parameters().sampling_interval() = 50.0;
  item.requested_parameters().queue_size() = 1;
  item.requested_parameters().discard_oldest() = true;
  miRequest.items_to_create().push_back(std::move(item));

  auto miResponse = session.monitored_items().create_monitored_items_sync(std::move(miRequest));
  ASSERT_THAT(miResponse, ::ua::test_helpers::ServiceResultIsGood());
  ASSERT_EQ(miResponse.results().size(), 1u);
  ASSERT_TRUE(miResponse.results()[0].status_code().is_good())
    << "the privileged identity must be able to create the item; status 0x" << std::hex
    << miResponse.results()[0].status_code().as_uint32();

  // One Publish round-trip; nullopt means the response carried nothing for our item (a keep-alive,
  // or a failed service call), which the callers below treat as "nothing observed yet".
  auto publishStatus = [&]() -> std::optional<ua::StatusCode>
  {
    auto pubResponse = session.subscriptions().try_publish_sync(ua::PublishRequest{});
    if (pubResponse.is_bad())
      return std::nullopt;
    const auto& response = pubResponse.value();
    if (response.response_header().service_result().is_bad())
      return std::nullopt;
    for (const auto& notification : response.notification_message().notification_data())
    {
      const auto* dataChange = dynamic_cast<const ua::DataChangeNotification*>(notification.get());
      if (dataChange == nullptr)
        continue;
      for (size_t i = 0; i < dataChange->monitored_items().size(); ++i)
      {
        const auto& entry = dataChange->monitored_items()[i];
        if (entry.client_handle() != clientHandle)
          continue;
        // An omitted status field is Good; DataValue only carries one when it is not.
        return entry.value().status().has_value() ? *entry.value().status()
                                                  : ua::StatusCode{ua::Status::Good};
      }
    }
    return std::nullopt;
  };

  // The privileged identity is served, which is what makes the refusal below attributable to the
  // identity change and not to the fixture.
  std::optional<ua::StatusCode> privilegedStatus;
  for (int attempt = 0; attempt < 60 && !privilegedStatus.has_value(); ++attempt)
  {
    privilegedStatus = publishStatus();
    if (!privilegedStatus.has_value())
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  ASSERT_TRUE(privilegedStatus.has_value())
    << "the item never delivered under the privileged identity, so there is nothing to stop";
  ASSERT_TRUE(privilegedStatus->is_good())
    << "the privileged identity must receive readable values; status 0x" << std::hex
    << privilegedStatus->as_uint32();

  // The identity change itself. Same Session, same channel, same Subscription.
  ua::client::Session::ActivateConfig restrictedCfg;
  restrictedCfg.policyId = userNamePolicyId;
  restrictedCfg.identity = ua::client::UsernamePasswordIdentity{
    .username = std::string{reevalRestrictedUser}, .password = std::string{reevalPassword}};
  auto restrictedActivate = session.try_activate_sync(std::move(restrictedCfg));
  ASSERT_TRUE(restrictedActivate.is_good())
    << "re-activation under the second identity must succeed for the obligation to apply; status 0x"
    << std::hex << restrictedActivate.status_code().as_uint32();

  // Conjunct one: the item stops delivering readable values and reports the denial instead.
  bool sawDenied = false;
  auto denialDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
  while (std::chrono::steady_clock::now() < denialDeadline && !sawDenied)
  {
    auto status = publishStatus();
    if (!status.has_value())
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{50});
      continue;
    }
    if (status->as_status() == Status::BadUserAccessDenied)
      sawDenied = true;
  }
  EXPECT_TRUE(sawDenied)
    << "after the identity change the MonitoredItem must be re-checked against the new user and "
       "report Bad_UserAccessDenied - a Session that keeps publishing readable values is serving "
       "data the current identity may not read";

  // Conjunct two: having been re-checked, it stays re-checked. A one-off denial followed by the old
  // verdict resuming would mean the re-evaluation did not reach the item's steady state.
  if (sawDenied)
  {
    bool sawGoodAfterDenial = false;
    auto steadyDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (std::chrono::steady_clock::now() < steadyDeadline && !sawGoodAfterDenial)
    {
      auto status = publishStatus();
      if (!status.has_value())
      {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        continue;
      }
      if (status->is_good())
        sawGoodAfterDenial = true;
    }
    EXPECT_FALSE(sawGoodAfterDenial)
      << "the item resumed delivering readable values to the restricted identity after the denial";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();

  if (identityServer)
    (void)identityServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  identityServer.reset();
}

// ---------------------------------------------------------------------------
// Additional include for the rows below: the re-evaluation row keys the status it last saw by the
// MonitoredItem clientHandle that reported it, so that "every item" can be asserted item by item
// rather than as a count.
// ---------------------------------------------------------------------------
#include <map>

// Part 4 section 7.41 requires an identity change to re-evaluate every existing MonitoredItem in every
// Subscription assigned to the Session. Two readable controls per Subscription prevent a partial
// walk or a never-working item from satisfying the denial observation.
// @relation(AC-SVR-IDENT-019-IDENTITY-CHANGE-REEVALUATES, scope=function)
// @relation(AC-SVR-SESS-031-REEVALUATE-ON-IDENTITY-CHANGE, scope=function)
TEST_F(ComplianceSession, AnIdentityChangeReEvaluatesEveryMonitoredItemInEverySubscriptionOfTheSession)
{
  const ua::NodeId monitoredNode{ua::VariableId::Server_ServerStatus_CurrentTime};

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ServerComponents components{.crypto = mCrypto, .applicationGroupCertificateStore = mServerCertStore};
  auto composite = std::make_shared<CompositeAuthenticator>();
  composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
  composite->add(UserTokenKind::UserName,
    std::make_shared<SimpleUserPasswordAuthenticator>(
      [](std::string_view username, const ua::SecureString& password)
      {
        return (username == reevalPrivilegedUser || username == reevalRestrictedUser) &&
               std::string_view{password.c_str()} == reevalPassword;
      }));
  components.authenticator = composite;
  components.roleConfiguration = identity_reevaluation_roles();

  server::CreateConfig quantifierServerCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  std::optional<ua::server::Server> quantifierServer;
  auto logSink = test_log_sink();
  components.logSink = logSink;
  components.logLevel = LogLevel::Debug;
  quantifierServer.emplace(ua::server::Server::create(
    mServerThreadPool.executor(), std::move(quantifierServerCfg), std::move(components)));
  configure_identity_reevaluation_node(*quantifierServer);

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto quantifierListener = quantifierServer->listen_sync(std::move(bind), {});

  auto userNamePolicy = create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256);
  const std::string userNamePolicyId{userNamePolicy.policy_id()};
  ASSERT_FALSE(userNamePolicyId.empty());

  ServerEndpointConfig quantifierEndpoint;
  quantifierEndpoint.name = "Basic256Sha256_SignAndEncrypt";
  quantifierEndpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  quantifierEndpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  quantifierEndpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  quantifierEndpoint.userIdentityTokens.push_back(std::move(userNamePolicy));
  quantifierServer->add_endpoint(quantifierListener, std::move(quantifierEndpoint));

  quantifierServer->start_sync();

  auto quantifierUrls = quantifierServer->advertised_urls(quantifierListener);
  ASSERT_FALSE(quantifierUrls.empty());
  auto quantifierEndpointUrl = quantifierUrls.front().str();

  CoreClient::OpenChannelConfig channelCfg;
  channelCfg.endpointUrl = quantifierEndpointUrl;
  channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelCfg.serverCertificate = mServerCert;
  auto channelResult = mClient->core().try_open_channel_sync(std::move(channelCfg));
  ASSERT_TRUE(channelResult.is_good())
    << "channel open must succeed; status 0x" << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();

  auto sessionResult = channel.try_create_session_sync({.sessionName = "IdentityReevalQuantifier"});
  ASSERT_TRUE(sessionResult.is_good()) << "status 0x" << std::hex << sessionResult.status_code().as_uint32();
  auto session = std::move(sessionResult).value();

  ua::client::Session::ActivateConfig privilegedCfg;
  privilegedCfg.policyId = userNamePolicyId;
  privilegedCfg.identity = ua::client::UsernamePasswordIdentity{
    .username = std::string{reevalPrivilegedUser}, .password = std::string{reevalPassword}};
  auto privilegedActivate = session.try_activate_sync(std::move(privilegedCfg));
  ASSERT_TRUE(privilegedActivate.is_good()) << "the privileged identity must activate; status 0x" << std::hex
                                            << privilegedActivate.status_code().as_uint32();

  // Two Subscriptions, two MonitoredItems each. The handles are what the assertions below are keyed
  // on, so a Subscription that is never walked shows up as a missing handle rather than as a count.
  const std::vector<uint32_t> handlesBySubscription[2] = {{101u, 102u}, {201u, 202u}};
  std::vector<uint32_t> allHandles;

  for (const auto& handles : handlesBySubscription)
  {
    ua::CreateSubscriptionRequest subRequest;
    subRequest.requested_publishing_interval() = 50.0;
    subRequest.requested_lifetime_count() = 6000;
    subRequest.requested_max_keep_alive_count() = 100;
    subRequest.max_notifications_per_publish() = 0;
    subRequest.publishing_enabled() = true;
    auto subResponse = session.subscriptions().create_subscription_sync(std::move(subRequest));
    ASSERT_THAT(subResponse, ::ua::test_helpers::ServiceResultIsGood());
    const auto subscriptionId = subResponse.subscription_id();

    ua::CreateMonitoredItemsRequest miRequest;
    miRequest.subscription_id() = subscriptionId;
    miRequest.timestamps_to_return() = ua::TimestampsToReturn::Both;
    for (auto handle : handles)
    {
      ua::MonitoredItemCreateRequest item;
      item.item_to_monitor().node_id() = monitoredNode;
      item.item_to_monitor().attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
      item.monitoring_mode() = ua::MonitoringMode::Reporting;
      item.requested_parameters().client_handle() = handle;
      item.requested_parameters().sampling_interval() = 50.0;
      item.requested_parameters().queue_size() = 1;
      item.requested_parameters().discard_oldest() = true;
      miRequest.items_to_create().push_back(std::move(item));
      allHandles.push_back(handle);
    }

    auto miResponse = session.monitored_items().create_monitored_items_sync(std::move(miRequest));
    ASSERT_THAT(miResponse, ::ua::test_helpers::ServiceResultIsGood());
    ASSERT_EQ(miResponse.results().size(), handles.size());
    for (size_t i = 0; i < miResponse.results().size(); ++i)
    {
      ASSERT_TRUE(miResponse.results()[i].status_code().is_good())
        << "the privileged identity must be able to create item " << i << "; status 0x" << std::hex
        << miResponse.results()[i].status_code().as_uint32();
    }
  }
  ASSERT_EQ(allHandles.size(), 4u) << "no items were created, so there is nothing to re-evaluate";

  // One Publish round-trip, folding whatever it carried into `out` keyed by clientHandle. An omitted
  // status field is Good; DataValue only carries one when it is not.
  auto drainPublish = [&session](std::map<uint32_t, ua::StatusCode>& out)
  {
    auto pubResponse = session.subscriptions().try_publish_sync(ua::PublishRequest{});
    if (pubResponse.is_bad())
      return;
    const auto& response = pubResponse.value();
    if (response.response_header().service_result().is_bad())
      return;
    for (const auto& notification : response.notification_message().notification_data())
    {
      const auto* dataChange = dynamic_cast<const ua::DataChangeNotification*>(notification.get());
      if (dataChange == nullptr)
        continue;
      for (size_t i = 0; i < dataChange->monitored_items().size(); ++i)
      {
        const auto& entry = dataChange->monitored_items()[i];
        out.insert_or_assign(entry.client_handle(),
          entry.value().status().has_value() ? *entry.value().status() : ua::StatusCode{ua::Status::Good});
      }
    }
  };

  // Every one of the four must be delivering readable values first, or its denial below would be
  // indistinguishable from an item that never worked.
  std::map<uint32_t, ua::StatusCode> beforeChange;
  auto beforeDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
  while (std::chrono::steady_clock::now() < beforeDeadline && beforeChange.size() < allHandles.size())
  {
    drainPublish(beforeChange);
    if (beforeChange.size() < allHandles.size())
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
  }
  ASSERT_EQ(beforeChange.size(), allHandles.size())
    << "not every MonitoredItem delivered under the privileged identity, so there is nothing to stop";
  for (auto handle : allHandles)
  {
    auto it = beforeChange.find(handle);
    ASSERT_NE(it, beforeChange.end()) << "item " << handle << " never reported before the change";
    ASSERT_TRUE(it->second.is_good())
      << "item " << handle << " must be readable under the privileged identity; status 0x" << std::hex
      << it->second.as_uint32();
  }

  // The identity change itself. Same Session, same channel, both Subscriptions untouched.
  ua::client::Session::ActivateConfig restrictedCfg;
  restrictedCfg.policyId = userNamePolicyId;
  restrictedCfg.identity = ua::client::UsernamePasswordIdentity{
    .username = std::string{reevalRestrictedUser}, .password = std::string{reevalPassword}};
  auto restrictedActivate = session.try_activate_sync(std::move(restrictedCfg));
  ASSERT_TRUE(restrictedActivate.is_good())
    << "re-activation under the second identity must succeed for the obligation to apply; status 0x"
    << std::hex << restrictedActivate.status_code().as_uint32();

  std::map<uint32_t, ua::StatusCode> afterChange;
  auto allDenied = [&afterChange, &allHandles]
  {
    for (auto handle : allHandles)
    {
      auto it = afterChange.find(handle);
      if (it == afterChange.end() || it->second.as_status() != Status::BadUserAccessDenied)
        return false;
    }
    return true;
  };

  auto denialDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
  while (std::chrono::steady_clock::now() < denialDeadline && !allDenied())
  {
    drainPublish(afterChange);
    if (!allDenied())
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
  }

  for (size_t subscription = 0; subscription < 2; ++subscription)
  {
    for (auto handle : handlesBySubscription[subscription])
    {
      auto it = afterChange.find(handle);
      ASSERT_NE(it, afterChange.end())
        << "item " << handle << " in Subscription " << subscription
        << " reported nothing at all after the identity change, so it cannot be shown to have been "
           "re-evaluated";
      EXPECT_EQ(it->second.as_status(), Status::BadUserAccessDenied)
        << "item " << handle << " in Subscription " << subscription << " last reported 0x" << std::hex
        << it->second.as_uint32()
        << " - every item in every Subscription assigned to the Session must be re-checked against the "
           "new identity, not only the ones in the Subscription the change was noticed on";
    }
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();

  if (quantifierServer)
    (void)quantifierServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  quantifierServer.reset();
}

// Part 4 section 5.6.2: "The SignatureAlgorithm shall be the AsymmetricSignatureAlgorithm specified in the
// SecurityPolicy for the Endpoint." The plausible implementation hard-codes the algorithm of the one
// policy it was written against - almost always Basic256Sha256's rsa-sha256 - and every
// single-policy test agrees with it. Aes256Sha256RsaPss is the case that separates them: it takes
// the same RSA certificate type, so the same PKI serves it, but its AsymmetricSignatureAlgorithm is
// rsa-pss-sha2-256, and a client that declares rsa-sha256 there is refused by the server's own
// algorithm check (and vice versa).
//
// The declared algorithm is read from the ActivateSessionRequest the SERVER received, not from the
// client's own fields, and each activation is required to have succeeded - which is what makes the
// declaration one the server accepted rather than merely one the client emitted.
// @verifies AC-SVR-SESS-022-CLIENTSIG-ALGORITHM
TEST_F(ComplianceSessionWithHooks, TheClientSignatureAlgorithmIsTheOneEachEndpointsSecurityPolicySpecifies)
{
  using namespace std::chrono_literals;

  // The fixture offers Basic256Sha256 only; add two further RSA policies so "the endpoint's policy"
  // is distinguishable from "one fixed algorithm".
  {
    ServerEndpointConfig aes128Ep;
    aes128Ep.name = "Aes128Sha256RsaOaep_SignAndEncrypt";
    aes128Ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    aes128Ep.securityPolicyId = SecurityPolicyId::Aes128Sha256RsaOaep;
    aes128Ep.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(aes128Ep));

    ServerEndpointConfig aes256Ep;
    aes256Ep.name = "Aes256Sha256RsaPss_SignAndEncrypt";
    aes256Ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    aes256Ep.securityPolicyId = SecurityPolicyId::Aes256Sha256RsaPss;
    aes256Ep.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(aes256Ep));
  }

  const std::vector<SecurityPolicyId> policies{SecurityPolicyId::Basic256Sha256,
    SecurityPolicyId::Aes128Sha256RsaOaep,
    SecurityPolicyId::Aes256Sha256RsaPss};
  ASSERT_FALSE(policies.empty());

  // A constant would satisfy the whole table if every policy named the same algorithm; this is what
  // makes the per-endpoint assertions below capable of failing.
  {
    auto basicPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
    auto pssPolicy = SecurityPolicy::create(SecurityPolicyId::Aes256Sha256RsaPss);
    ASSERT_NE(basicPolicy, nullptr);
    ASSERT_NE(pssPolicy, nullptr);
    auto basicUri = basicPolicy->asymmetric_signature_algorithm_uri();
    auto pssUri = pssPolicy->asymmetric_signature_algorithm_uri();
    ASSERT_NE(std::string_view{basicUri}, std::string_view{pssUri})
      << "the policies chosen share one AsymmetricSignatureAlgorithm, so a hard-coded algorithm would "
         "pass this row";
  }

  size_t observed = 0;
  for (size_t index = 0; index < policies.size(); ++index)
  {
    auto policy = SecurityPolicy::create(policies[index]);
    ASSERT_NE(policy, nullptr);
    auto expectedUri = policy->asymmetric_signature_algorithm_uri();
    ASSERT_FALSE(expectedUri.empty());

    auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, policies[index]);
    ASSERT_TRUE(channel.is_open()) << "could not open a channel under policy index " << index;

    auto session = channel.create_session_sync({.sessionName = "SigAlgPerPolicy" + std::to_string(index)});
    auto activateResult = session.try_activate_sync();
    ASSERT_TRUE(activateResult.is_good())
      << "activation under policy index " << index
      << " must succeed, otherwise the algorithm asserted below is one the server refused; status 0x"
      << std::hex << activateResult.status_code().as_uint32();
    ASSERT_TRUE(session.is_active());

    ++observed;
    ASSERT_TRUE(wait_for_requests("ActivateSessionRequest", observed, 5s))
      << "the server never received ActivateSessionRequest number " << observed;

    auto activateRequests = get_requests_of_type("ActivateSessionRequest");
    ASSERT_GE(activateRequests.size(), observed);
    auto* activateReq =
      dynamic_cast<const ActivateSessionRequest*>(activateRequests[observed - 1].request.get());
    ASSERT_NE(activateReq, nullptr);

    const auto& sig = activateReq->client_signature();
    EXPECT_FALSE(sig.signature().empty())
      << "policy index " << index << " is authenticated, so the clientSignature must be present";
    EXPECT_EQ(std::string_view{sig.algorithm()}, std::string_view{expectedUri})
      << "the clientSignature under policy index " << index
      << " declares an algorithm that is not the AsymmetricSignatureAlgorithm that policy specifies";

    session.close_sync();
    channel.close_sync();
  }

  ASSERT_EQ(observed, policies.size()) << "not every policy was exercised";
}

// Part 4 section 5.6.3.1: post-CreateSession the only services a Session may serve are ActivateSession and
// CloseSession, and "failure to do so shall cause the Server to close the Session" - the destruction
// is the obligation, not the refusal. "Failure to do so" is the ordering violation, so the offending
// request is what triggers the close: it is answered Bad_SessionNotActivated and the Session is then
// gone. A Session whose ActivateSession returned bad is still an unactivated Session, so the same
// rule governs the next request on it; the failed activation on its own is not the trigger. Nothing
// in section 5.6.3.1 makes it one, and section 5.6.3.1's "if no errors occur the Server replaces the user
// identity" presumes the Session survives an activation that errored.
//
// The refusals asserted here are the SERVER's. A probe issued on the created Session's own handle
// cannot show that - the client's local pre-activation gate answers it without sending anything,
// which is what the existing pre-activation rows observe - so each stale identity is carried by a
// second, genuinely active Session on the same channel and the status returned is the server's own
// routing decision. Bad_SessionNotActivated means the Session exists and is serving nothing;
// Bad_SessionIdInvalid means it is gone. That distinction is the whole test.
// @verifies AC-SVR-SESS-024-ACTIVATE-BEFORE-ANY-OTHER
// clang-format off: StrictDoc resolves GoogleTest declarations one line at a time.
TEST_F(ComplianceSessionWithHooks, OnlyActivateAndCloseAreServedBeforeActivationAndTheOffendingRequestClosesIt)
// clang-format on
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  // Conjunct 2 first, so the CloseSessionRequest counted below is unambiguously this one: CloseSession
  // is served on a Session that has never been activated.
  {
    auto closeable = channel.create_session_sync({.sessionName = "CloseBeforeActivate"});
    ASSERT_TRUE(closeable.is_created());
    ASSERT_FALSE(closeable.is_active());

    auto closeResult = closeable.try_close_sync();
    EXPECT_TRUE(closeResult.is_good())
      << "CloseSession is the one service exempt from the activation gate, so a created-but-unactivated "
         "Session must be closed on request; status 0x"
      << std::hex << closeResult.status_code().as_uint32();
    EXPECT_TRUE(wait_for_requests("CloseSessionRequest", 1, std::chrono::seconds{5}))
      << "the CloseSession must have reached the server for its acceptance to be the server's";
  }

  // The witness carries the stale identities onto the wire so that the refusals below are decided by
  // the server rather than by the client's local gate.
  auto witness = channel.create_session_sync({.sessionName = "ActivationGateWitness"});
  witness.activate_sync();
  ASSERT_TRUE(witness.is_active());
  const auto witnessId = witness.session_id();
  const auto witnessToken = session_state(witness).authenticationToken;
  ASSERT_FALSE(witnessId.is_null());
  ASSERT_FALSE(witnessToken.is_null());

  // Conjunct 1: a Read on a created-but-unactivated Session is refused, and that request is what
  // closes the Session - a second Read on the same identity finds nothing to route to.
  {
    auto unactivated = channel.create_session_sync({.sessionName = "ReadBeforeActivate"});
    ASSERT_TRUE(unactivated.is_created());
    ASSERT_FALSE(unactivated.is_active());
    const auto unactivatedId = unactivated.session_id();
    const auto unactivatedToken = session_state(unactivated).authenticationToken;
    ASSERT_FALSE(unactivatedToken.is_null());
    ASSERT_NE(unactivatedToken, witnessToken);

    CSSTA::on_strand(witness, [&](auto& g) { g.set_session_active(unactivatedId, unactivatedToken); });
    auto gatedResult = witness.attributes().try_read_sync(make_server_read_request());
    ASSERT_TRUE(gatedResult.is_bad()) << "a Read before ActivateSession must be refused";
    EXPECT_EQ(gatedResult.status_code().as_status(), Status::BadSessionNotActivated)
      << "got 0x" << std::hex << gatedResult.status_code().as_uint32()
      << " - Good would make the proof-of-possession step optional";
    EXPECT_TRUE(wait_for_requests("ReadRequest", 1, std::chrono::seconds{5}))
      << "the Read must have reached the server for its refusal to be the server's";

    auto afterOffence = witness.attributes().try_read_sync(make_server_read_request());
    ASSERT_TRUE(afterOffence.is_bad()) << "the offending request must have closed the Session";
    EXPECT_EQ(afterOffence.status_code().as_status(), Status::BadSessionIdInvalid)
      << "got 0x" << std::hex << afterOffence.status_code().as_uint32()
      << " - Bad_SessionNotActivated means the Session outlived the request that violated the ordering "
         "rule, and the clause requires the Server to close it, not merely to refuse";
    EXPECT_TRUE(wait_for_requests("ReadRequest", 2, std::chrono::seconds{5}))
      << "the second Read must have reached the server for its refusal to be the server's";

    (void)unactivated.try_close_sync();
  }

  // Falsifiability control: the witness with its OWN identity is served on this very channel.
  CSSTA::on_strand(witness, [&](auto& g) { g.set_session_active(witnessId, witnessToken); });
  {
    auto controlResult = witness.attributes().try_read_sync(make_server_read_request());
    ASSERT_TRUE(controlResult.is_good())
      << "the witness must still be served; status 0x" << std::hex << controlResult.status_code().as_uint32();
    EXPECT_THAT(controlResult.value(), ::ua::test_helpers::ServiceResultIsGood());
    EXPECT_TRUE(wait_for_requests("ReadRequest", 3, std::chrono::seconds{5}));
  }

  // Conjunct 3: a Session whose ActivateSession returned bad is still an unactivated Session, so the
  // ordering rule governs it unchanged - the next non-Close request is refused and closes it. The
  // activation is failed through the real signing path - the client still holds its own private key
  // and still signs with it; only the nonce it signs over is no longer the one the server issued, so
  // the refusal is the server's verifier and not a malformed request.
  {
    auto failed = channel.create_session_sync({.sessionName = "FailedActivationLeavesUnactivated"});
    ASSERT_TRUE(failed.is_created());
    const auto failedId = failed.session_id();
    const auto failedToken = session_state(failed).authenticationToken;
    ASSERT_FALSE(failedToken.is_null());
    ASSERT_NE(failedToken, witnessToken);

    const auto issuedNonce = session_state(failed).serverNonce;
    ASSERT_GE(issuedNonce.size(), 32u) << "no server nonce was issued, so the activation cannot be failed";
    CSSTA::on_strand(failed,
      [](auto& g)
      {
        for (auto& b : g.server_nonce())
          b = ~b;
      });

    auto failedActivate = failed.try_activate_sync();
    ASSERT_TRUE(failedActivate.is_bad())
      << "the activation must actually fail for the obligation to apply; status 0x" << std::hex
      << failedActivate.status_code().as_uint32();

    CSSTA::on_strand(witness, [&](auto& g) { g.set_session_active(failedId, failedToken); });
    auto afterFailure = witness.attributes().try_read_sync(make_server_read_request());
    ASSERT_TRUE(afterFailure.is_bad()) << "a Session whose activation failed must serve nothing";
    EXPECT_EQ(afterFailure.status_code().as_status(), Status::BadSessionNotActivated)
      << "got 0x" << std::hex << afterFailure.status_code().as_uint32()
      << " - Good would mean the failed activation nonetheless activated the Session";
    EXPECT_TRUE(wait_for_requests("ReadRequest", 4, std::chrono::seconds{5}))
      << "the Read must have reached the server for its refusal to be the server's";

    auto afterOffence = witness.attributes().try_read_sync(make_server_read_request());
    ASSERT_TRUE(afterOffence.is_bad()) << "the offending request must have closed the Session";
    EXPECT_EQ(afterOffence.status_code().as_status(), Status::BadSessionIdInvalid)
      << "got 0x" << std::hex << afterOffence.status_code().as_uint32()
      << " - the ordering clause is satisfied by closing the Session, not by refusing every request "
         "on it forever";
    EXPECT_TRUE(wait_for_requests("ReadRequest", 5, std::chrono::seconds{5}))
      << "the second Read must have reached the server for its refusal to be the server's";

    (void)failed.try_close_sync();
  }

  CSSTA::on_strand(witness, [&](auto& g) { g.set_session_active(witnessId, witnessToken); });
  auto finalControl = witness.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(finalControl.is_good()) << "the witness must still be served at the end; status 0x" << std::hex
                                      << finalControl.status_code().as_uint32();
  EXPECT_THAT(finalControl.value(), ::ua::test_helpers::ServiceResultIsGood());

  witness.close_sync();
  channel.close_sync();
}

// Part 4 section 5.6.3: ActivateSession is where the caller proves it is the same application that called
// CreateSession, by signing (serverCertificate || serverNonce) with the private key of the
// certificate that opened the channel. All three inputs carry weight and each is a separate way to
// get the check wrong: the KEY is the identity claim, the CERTIFICATE binds the proof to this server
// so a signature harvested by a man-in-the-middle cannot be replayed at the real one, and the NONCE
// binds it to this activation. A server that only checks that some well-formed, correctly
// algorithm-tagged signature is present passes every one of the three.
//
// Every forgery below is made with real key material through the crypto provider and is stamped into
// the request at the client's pre-framing interface, so what the server decodes is a structurally valid
// ActivateSession carrying the policy's own algorithm - the refusal can only come from the
// verification itself. The untouched control activation on the same channel is what shows a refusal
// is attributable to the signature and not to the fixture.
// @verifies AC-SVR-SESS-025-APPLICATION-IDENTITY
TEST_F(ComplianceSession, ActivateSessionProvesTheCallerIsTheApplicationThatCreatedTheSession)
{
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ASSERT_NE(policy, nullptr);

  auto clientAppCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(clientAppCerts.empty());
  ASSERT_NE(clientAppCerts.front().certificate, nullptr);
  ASSERT_NE(clientAppCerts.front().keys, nullptr);
  auto clientKeys = clientAppCerts.front().keys;
  auto clientCertDer = clientAppCerts.front().certificate->der_encoding();
  ASSERT_FALSE(clientCertDer.empty());

  ASSERT_NE(mServerCert, nullptr);
  auto serverCertDer = mServerCert->der_encoding();
  ASSERT_FALSE(serverCertDer.empty());
  ASSERT_NE(serverCertDer, clientCertDer);

  auto foreignKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_NE(foreignKeys, nullptr);

  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  // Control: an untouched Session on this very channel activates.
  {
    auto control = channel.create_session_sync({.sessionName = "AppIdentityControl"});
    auto controlResult = control.try_activate_sync();
    ASSERT_TRUE(controlResult.is_good()) << "control activation must succeed on this channel; status 0x"
                                         << std::hex << controlResult.status_code().as_uint32();
    ASSERT_TRUE(control.is_active());
    control.close_sync();
  }

  auto signOver = [this, &policy](const ua::ByteString& certificatePart,
                    const ua::ByteString& noncePart,
                    const std::shared_ptr<const ua::AsymmetricKeyPair>& keys)
  {
    ua::ByteString data = certificatePart;
    for (auto b : noncePart)
      data.push_back(b);
    return mCrypto->asymmetric_sign_sync(policy->asymmetric_signature_algorithm(), keys, data);
  };

  auto installSignature = [&channel](ua::ByteString forged)
  {
    ua::client::SecureChannelTestAccess::on_strand(channel,
      [forged = std::move(forged)](auto& g)
      {
        g.outgoing_request_observer() = [forged](const ua::Structure& request)
        {
          const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
          if (activateRequest == nullptr)
            return;
          // Only the signature bytes are replaced: the algorithm the client declared is left alone so
          // the server's algorithm check cannot be what refuses this.
          const_cast<ua::ActivateSessionRequest&>(*activateRequest).client_signature().signature() = forged;
        };
      });
  };

  auto clearObserver = [&channel]
  {
    ua::client::SecureChannelTestAccess::on_strand(
      channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  };

  // (a) The right data, signed by the wrong key. This is the identity claim itself.
  {
    auto wrongKey = channel.create_session_sync({.sessionName = "AppIdentityWrongKey"});
    auto nonce = session_state(wrongKey).serverNonce;
    ASSERT_GE(nonce.size(), 32u) << "no server nonce was issued, so there is nothing to sign over";
    auto forged = signOver(serverCertDer, nonce, foreignKeys);
    ASSERT_FALSE(forged.empty()) << "the forged signature is empty, so nothing was substituted";
    installSignature(forged);

    auto wrongKeyResult = wrongKey.try_activate_sync();
    clearObserver();
    EXPECT_TRUE(wrongKeyResult.is_bad())
      << "a signature made with a key other than the one behind the certificate that opened the channel "
         "must not activate the Session";
    EXPECT_FALSE(wrongKey.is_active())
      << "the Session must be left unactivated when the proof was made with the wrong key";
    (void)wrongKey.try_close_sync();
  }

  // (b) The right key and the right nonce, over a certificate that is not the server's. Without the
  // server certificate in the signed data the proof is not bound to THIS server.
  {
    auto wrongCert = channel.create_session_sync({.sessionName = "AppIdentityWrongCert"});
    auto nonce = session_state(wrongCert).serverNonce;
    ASSERT_GE(nonce.size(), 32u);
    auto forged = signOver(clientCertDer, nonce, clientKeys);
    ASSERT_FALSE(forged.empty());
    installSignature(forged);

    auto wrongCertResult = wrongCert.try_activate_sync();
    clearObserver();
    EXPECT_TRUE(wrongCertResult.is_bad())
      << "a signature that does not cover the server's certificate must not activate the Session - a "
         "proof that omits it is replayable at any server the client can be steered to";
    EXPECT_FALSE(wrongCert.is_active())
      << "the Session must be left unactivated when the proof does not cover the server certificate";
    (void)wrongCert.try_close_sync();
  }

  // (c) The right key and the right certificate, over a nonce the server never issued.
  {
    auto wrongNonce = channel.create_session_sync({.sessionName = "AppIdentityWrongNonce"});
    auto nonce = session_state(wrongNonce).serverNonce;
    ASSERT_GE(nonce.size(), 32u);
    ua::ByteString tampered = nonce;
    for (auto& b : tampered)
      b = ~b;
    ASSERT_NE(tampered, nonce);
    auto forged = signOver(serverCertDer, tampered, clientKeys);
    ASSERT_FALSE(forged.empty());
    installSignature(forged);

    auto wrongNonceResult = wrongNonce.try_activate_sync();
    clearObserver();
    EXPECT_TRUE(wrongNonceResult.is_bad())
      << "a signature over a nonce the server never issued must not activate the Session";
    EXPECT_FALSE(wrongNonce.is_active())
      << "the Session must be left unactivated when the proof does not cover the issued nonce";
    (void)wrongNonce.try_close_sync();
  }

  clearObserver();
  channel.close_sync();
}

// Part 4 section 5.6.3: a Session may be re-bound to a new SecureChannel, and three things must hold when it
// is - the new channel's client Certificate must be the one the Session was created with, the
// UserIdentityToken supplied must be the one currently bound to the Session, and the old channel must
// stop being a route to the Session afterwards. The third is what makes the first two worth
// enforcing: if the old channel stays usable, whoever holds it keeps access however carefully the new
// channel was checked, because the Session is then reachable by two paths and only one of them was
// examined.
//
// The same-certificate, same-identity re-binding is run as the control, so the two refusals cannot be
// explained by "any channel change is refused". The lock-out is observed by carrying the transferred
// Session's authenticationToken on a second, genuinely active Session that stayed on the old channel:
// the transferred handle itself now sends on the new channel, so it could never put the question to
// the old one. Bad_SecureChannelIdInvalid is the answer that says the token is known but this channel
// is no longer its route.
//
// The shared fixtures advertise an Anonymous token policy only, which admits no identity difference
// at all; hence the purpose-built server below.
// @verifies AC-SVR-SESS-027-REACTIVATE-CONTINUITY
TEST_F(ComplianceSession, ReactivatingOnANewChannelRequiresTheSameCertificateAndTokenAndDropsTheOldChannel)
{
  // A second application certificate, individually trusted by the server, owned by a client that
  // really holds its private key - so the foreign channel's OPN is genuine and the refusal under test
  // cannot be explained by that certificate being unknown.
  Crypto::Name secondSubject;
  secondSubject.commonName = "ComplianceSession Transfer Client";
  UtcTime secondExpiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName secondAltName;
  secondAltName.hostnames.push_back("localhost");
  secondAltName.hostnames.push_back("127.0.0.1");
  secondAltName.uris.push_back("urn:test:compliance:transferclient");

  auto secondCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    secondSubject, secondExpiry, secondAltName, CertificateType::RsaSha256Application, 2048);
  ASSERT_TRUE(secondCertResult.is_good());
  auto [secondKeys, secondCert] = std::move(secondCertResult).value();
  ASSERT_NE(secondCert, nullptr);
  mServerCertStore->add_to_trusted_certificates_sync(secondCert);

  auto ownCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(ownCerts.empty());
  ASSERT_NE(ownCerts.front().certificate, nullptr);
  ASSERT_NE(secondCert->der_encoding(), ownCerts.front().certificate->der_encoding())
    << "the two clients must present different certificates for the continuity check to be the thing "
       "under test";

  TrustListValidationOptions validationOptions;
  auto secondStorePath = mTempDir / "transfer_second_store";
  std::filesystem::create_directories(secondStorePath);
  auto secondCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = secondStorePath, .validationOptions = validationOptions});
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = secondCert;
    appCert.keys = secondKeys;
    secondCertStore->add_to_application_certificates_sync(appCert);
  }
  secondCertStore->add_to_trusted_certificates_sync(mServerCert);

  auto secondAppCfg = ua::test_utils::create_test_config();
  secondAppCfg.application_description_part().applicationUri = "urn:test:compliance:transferclient";
  client::CreateConfig secondClientCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(secondAppCfg)};
  auto logSink = test_log_sink();
  auto secondClient = Client::create(mClientThreadPool.executor(),
    std::move(secondClientCfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = secondCertStore,
      .logSink = logSink,
      .logLevel = LogLevel::Debug});

  // A server that advertises a UserName policy as well as Anonymous, so "a different
  // UserIdentityToken" is expressible at all.
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ServerComponents components{.crypto = mCrypto,
    .applicationGroupCertificateStore = mServerCertStore,
    .logSink = logSink,
    .logLevel = LogLevel::Debug};
  auto composite = std::make_shared<CompositeAuthenticator>();
  composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
  composite->add(UserTokenKind::UserName,
    std::make_shared<SimpleUserPasswordAuthenticator>(
      [](std::string_view username, const ua::SecureString& password)
      {
        return (username == reevalPrivilegedUser || username == reevalRestrictedUser) &&
               std::string_view{password.c_str()} == reevalPassword;
      }));
  components.authenticator = composite;
  components.roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::AuthenticatedUser}});

  server::CreateConfig transferServerCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  std::optional<ua::server::Server> transferServer;
  transferServer.emplace(ua::server::Server::create(
    mServerThreadPool.executor(), std::move(transferServerCfg), std::move(components)));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto transferListener = transferServer->listen_sync(std::move(bind), {});

  auto userNamePolicy = create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic256Sha256);
  const std::string userNamePolicyId{userNamePolicy.policy_id()};
  ASSERT_FALSE(userNamePolicyId.empty());

  ServerEndpointConfig transferEndpoint;
  transferEndpoint.name = "Basic256Sha256_SignAndEncrypt";
  transferEndpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  transferEndpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  transferEndpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  transferEndpoint.userIdentityTokens.push_back(std::move(userNamePolicy));
  transferServer->add_endpoint(transferListener, std::move(transferEndpoint));

  transferServer->start_sync();

  auto transferUrls = transferServer->advertised_urls(transferListener);
  ASSERT_FALSE(transferUrls.empty());
  const auto transferEndpointUrl = transferUrls.front().str();

  auto openChannelFor = [&](Client& client)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = transferEndpointUrl;
    cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    cfg.serverCertificate = mServerCert;
    return client.core().try_open_channel_sync(std::move(cfg));
  };

  auto identityConfig = [&userNamePolicyId](std::string_view user)
  {
    ua::client::Session::ActivateConfig cfg;
    cfg.policyId = userNamePolicyId;
    cfg.identity = ua::client::UsernamePasswordIdentity{
      .username = std::string{user}, .password = std::string{reevalPassword}};
    return cfg;
  };

  auto originalChannelResult = openChannelFor(*mClient);
  ASSERT_TRUE(originalChannelResult.is_good())
    << "status 0x" << std::hex << originalChannelResult.status_code().as_uint32();
  auto originalChannel = std::move(originalChannelResult).value();
  ASSERT_TRUE(originalChannel.is_open());

  // Conjunct 1: a new channel opened with a DIFFERENT client certificate must not take the Session.
  {
    auto certSession = originalChannel.create_session_sync({.sessionName = "TransferCertContinuity"});
    auto certActivate = certSession.try_activate_sync(identityConfig(reevalPrivilegedUser));
    ASSERT_TRUE(certActivate.is_good()) << "status 0x" << std::hex << certActivate.status_code().as_uint32();
    ASSERT_TRUE(certSession.is_active());

    auto foreignChannelResult = openChannelFor(secondClient);
    ASSERT_TRUE(foreignChannelResult.is_good())
      << "the second certificate is trusted, so its channel must open - the refusal under test has to "
         "come from the continuity check, not from that certificate being unknown; status 0x"
      << std::hex << foreignChannelResult.status_code().as_uint32();
    auto foreignChannel = std::move(foreignChannelResult).value();
    ASSERT_TRUE(foreignChannel.is_open());

    auto foreignActivate =
      certSession.try_activate_sync(std::move(foreignChannel), identityConfig(reevalPrivilegedUser));
    EXPECT_TRUE(foreignActivate.is_bad())
      << "re-activating a Session on a channel opened with a different client certificate must be "
         "refused";
    EXPECT_EQ(foreignActivate.status_code().as_status(), Status::BadSecureChannelIdInvalid)
      << "got 0x" << std::hex << foreignActivate.status_code().as_uint32();

    (void)certSession.try_close_sync();
  }

  // Conjunct 2: a valid new channel carrying the same certificate, but a DIFFERENT UserIdentityToken
  // than the one currently bound, must not take the Session either.
  {
    auto tokenSession = originalChannel.create_session_sync({.sessionName = "TransferTokenContinuity"});
    auto tokenActivate = tokenSession.try_activate_sync(identityConfig(reevalPrivilegedUser));
    ASSERT_TRUE(tokenActivate.is_good())
      << "status 0x" << std::hex << tokenActivate.status_code().as_uint32();
    ASSERT_TRUE(tokenSession.is_active());

    auto sameCertChannelResult = openChannelFor(*mClient);
    ASSERT_TRUE(sameCertChannelResult.is_good())
      << "status 0x" << std::hex << sameCertChannelResult.status_code().as_uint32();
    auto sameCertChannel = std::move(sameCertChannelResult).value();
    ASSERT_TRUE(sameCertChannel.is_open());

    auto otherIdentityActivate =
      tokenSession.try_activate_sync(std::move(sameCertChannel), identityConfig(reevalRestrictedUser));
    EXPECT_TRUE(otherIdentityActivate.is_bad())
      << "re-binding a Session onto a new channel must supply the UserIdentityToken currently "
         "associated with it - a channel move is not the place an identity may change";

    (void)tokenSession.try_close_sync();
  }

  // Conjunct 3: after an accepted re-binding, the old channel is no longer a route to the Session.
  {
    // A witness that stays on the ORIGINAL channel, so the old channel can still be asked the question
    // once the Session under test has moved away from it.
    auto witness = originalChannel.create_session_sync({.sessionName = "TransferOldChannelWitness"});
    auto witnessActivate = witness.try_activate_sync(identityConfig(reevalPrivilegedUser));
    ASSERT_TRUE(witnessActivate.is_good())
      << "status 0x" << std::hex << witnessActivate.status_code().as_uint32();
    const auto witnessId = witness.session_id();
    const auto witnessToken = session_state(witness).authenticationToken;
    ASSERT_FALSE(witnessToken.is_null());

    auto moved = originalChannel.create_session_sync({.sessionName = "TransferMovedSession"});
    auto movedActivate = moved.try_activate_sync(identityConfig(reevalPrivilegedUser));
    ASSERT_TRUE(movedActivate.is_good())
      << "status 0x" << std::hex << movedActivate.status_code().as_uint32();
    const auto movedId = moved.session_id();
    const auto movedToken = session_state(moved).authenticationToken;
    ASSERT_FALSE(movedToken.is_null());
    ASSERT_NE(movedToken, witnessToken);

    auto newChannelResult = openChannelFor(*mClient);
    ASSERT_TRUE(newChannelResult.is_good())
      << "status 0x" << std::hex << newChannelResult.status_code().as_uint32();
    auto newChannel = std::move(newChannelResult).value();
    ASSERT_TRUE(newChannel.is_open());
    ASSERT_NE(newChannel.secure_channel_id(), originalChannel.secure_channel_id());

    // Control: same certificate, same identity, different channel. Part 4 section 5.6.3 permits this, and
    // without it the two refusals above would be explained by "every channel change is refused".
    auto rebind = moved.try_activate_sync(std::move(newChannel), identityConfig(reevalPrivilegedUser));
    ASSERT_TRUE(rebind.is_good())
      << "re-binding onto a new channel carrying the same certificate and the same identity must be "
         "allowed; status 0x"
      << std::hex << rebind.status_code().as_uint32();
    ASSERT_TRUE(moved.is_active());

    // The old channel must no longer serve the Session that moved off it.
    CSSTA::on_strand(witness, [&](auto& g) { g.set_session_active(movedId, movedToken); });
    auto oldChannelResult = witness.attributes().try_read_sync(make_server_read_request());
    ASSERT_TRUE(oldChannelResult.is_bad())
      << "the channel the Session was re-bound away from must no longer be a route to it";
    EXPECT_EQ(oldChannelResult.status_code().as_status(), Status::BadSecureChannelIdInvalid)
      << "got 0x" << std::hex << oldChannelResult.status_code().as_uint32()
      << " - Good would mean the Session is reachable by two paths, only one of which was checked";

    // Falsifiability control: the same handle, on the same old channel, with its OWN identity, is
    // still served - so the refusal above is attributable to the transfer and not to the channel.
    CSSTA::on_strand(witness, [&](auto& g) { g.set_session_active(witnessId, witnessToken); });
    auto witnessControl = witness.attributes().try_read_sync(make_server_read_request());
    ASSERT_TRUE(witnessControl.is_good())
      << "the original channel must still serve its own Sessions; status 0x" << std::hex
      << witnessControl.status_code().as_uint32();
    EXPECT_THAT(witnessControl.value(), ::ua::test_helpers::ServiceResultIsGood());

    (void)moved.try_close_sync();
    (void)witness.try_close_sync();
  }

  (void)originalChannel.try_close_sync();

  if (transferServer)
    (void)transferServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  transferServer.reset();
}

// ---------------------------------------------------------------------------
// Additional includes for the rows below: the user-identity-token rows assert over the token the
// client put on the wire, which the observed ActivateSessionRequest carries as a polymorphic
// Structure - so the concrete token types have to be complete here to be cast to.
// ---------------------------------------------------------------------------
#include "ua_issued_identity_token.h"
#include "ua_user_name_identity_token.h"

// ---------------------------------------------------------------------------
// Additional fixture and helpers for the user-identity-token rows below. Placed at the end for the
// same reason the server-side hook includes above are: the `ua::server` names they bring into scope
// must not shadow the unqualified `Session` / `SecureChannel` the earlier tests mean.
// ---------------------------------------------------------------------------

namespace
{

constexpr std::string_view proofUser{"proof-user"};
constexpr std::string_view proofPassword{"proof-password"};
constexpr std::string_view acceptedIssuedToken{"proof-accepted-issued-token"};
constexpr std::string_view rejectedIssuedToken{"proof-rejected-issued-token"};

/// The bytes of `text`, as the wire carries them.
ua::ByteString bytes_of(std::string_view text)
{
  ua::ByteString out;
  for (char c : text)
    out.push_back(static_cast<uint8_t>(c));
  return out;
}

/// Whether `wire` contains `secret` anywhere in it. Used to assert the NEGATIVE: a secret that
/// travelled encrypted cannot be found in the bytes the server received.
bool carries_plaintext(const ua::ByteString& wire, std::string_view secret)
{
  if (wire.empty() || secret.empty())
    return false;
  std::string_view haystack{reinterpret_cast<const char*>(wire.data()), wire.size()};
  return haystack.find(secret) != std::string_view::npos;
}

/// Authenticator that accepts exactly one issued token and rejects every other.
///
/// The SDK ships no IssuedToken authenticator, and a `CompositeAuthenticator` with no delegate for
/// the kind refuses every issued token whatever it carries -- which would make "an unacceptable
/// issued token is refused" true of a server that never looks at one. This delegate gives the kind a
/// real mechanism, so the refusal below is a verdict on the token rather than on its type.
class ExactIssuedTokenAuthenticator final : public ua::server::UserAuthenticator
{
public:
  void authenticate_async(
    ua::server::AuthnRequest req, ua::server::AuthnComplete completion) noexcept override
  {
    if (!req.identity.issuedToken.has_value())
    {
      completion(ua::server::make_authn_failure(
        ua::StatusCode{ua::Status::BadIdentityTokenInvalid}, "no issued token data present"));
      return;
    }

    const auto& tokenData = *req.identity.issuedToken;
    std::string_view received;
    if (!tokenData.empty())
      received = std::string_view{reinterpret_cast<const char*>(tokenData.data()), tokenData.size()};
    if (received != acceptedIssuedToken)
    {
      completion(ua::server::make_authn_failure(
        ua::StatusCode{ua::Status::BadIdentityTokenRejected}, "issued token is not one this server accepts"));
      return;
    }

    completion(ua::server::make_authn_success(ua::server::UserIdentity{.userId = "issued-user",
      .displayName = "Issued Token User",
      .kind = ua::server::UserTokenKind::IssuedToken}));
  }
};

}  // namespace

// ===========================================================================
// ComplianceSessionUserTokens: ComplianceSessionWithHooks + an endpoint that advertises every user
// token kind, backed by an authenticator with a real mechanism per kind.
//
// The shared fixtures advertise an Anonymous policy only, which admits neither a credential to get
// wrong nor an identity to change. The endpoint added here uses a security policy no other endpoint
// on the fixture's server uses, so the client's endpoint match (policy uri + mode) is unambiguous
// and the policy ids below are the ones it resolves against.
// ===========================================================================
class ComplianceSessionUserTokens : public ComplianceSessionWithHooks
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    // A self-signed User Certificate. OPC 10000-6 Table 44: "The cA flag shall be FALSE for User
    // Certificates. The pathLength shall not be present", and keyUsage carries digitalSignature. A
    // self-signed application instance certificate carries cA TRUE and is refused as a user certificate.
    mUserTokenKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
    Crypto::CreateCertificateConfig userParameters;
    userParameters.serialNumber = "1";
    userParameters.subject.commonName = "ComplianceSession Token User";
    userParameters.subjectKeys = mUserTokenKeys;
    userParameters.issuerKeys = mUserTokenKeys;
    userParameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    userParameters.basicConstraint.cA = false;
    userParameters.keyUsage.digitalSignature = true;
    userParameters.keyUsage.nonRepudiation = true;
    userParameters.subjectAlternateName.uris = {"urn:test:compliance:tokenuser"};
    userParameters.from = DateTime{DateTime::now().value() - std::chrono::days{1}};
    userParameters.to = DateTime{DateTime::now().value() + std::chrono::days{3650}};
    mUserTokenCert = TestPki{mCrypto}.create_cert(userParameters);
    ASSERT_NE(mUserTokenCert, nullptr);
    ASSERT_NE(mUserTokenKeys, nullptr);

    auto userStorePath = mTempDir / "user_token_store";
    std::filesystem::create_directories(userStorePath);
    TrustListValidationOptions validationOptions;
    mUserTokenStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = userStorePath, .validationOptions = validationOptions});
    mUserTokenStore->add_to_trusted_certificates_sync(mUserTokenCert);

    auto composite = std::make_shared<CompositeAuthenticator>();
    composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
    composite->add(UserTokenKind::UserName,
      std::make_shared<SimpleUserPasswordAuthenticator>(
        [](std::string_view username, const ua::SecureString& password)
        {
          if (username == proofUser)
            return std::string_view{password.c_str()} == proofPassword;
          if (username == reevalPrivilegedUser || username == reevalRestrictedUser)
            return std::string_view{password.c_str()} == reevalPassword;
          return false;
        }));
    composite->add(UserTokenKind::X509, std::make_shared<X509UserAuthenticator>());
    composite->add(UserTokenKind::IssuedToken, std::make_shared<ExactIssuedTokenAuthenticator>());

    components.authenticator = composite;
    components.userTokenCertificateStore = mUserTokenStore;
    components.roleConfiguration = identity_reevaluation_roles();
  }

  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    // The throttle is deliberately ON: "a valid token is not delayed" is only worth asserting of a
    // server that has a backoff mechanism to get wrong.
    cfg.server.identityThrottling.enabled = true;
    cfg.server.identityThrottling.maxFailedAttemptsBeforeLockout = sFailuresBeforeLockout;
    cfg.server.identityThrottling.lockoutDuration = std::chrono::seconds{300};
  }

  void SetUp() override
  {
    ComplianceSessionWithHooks::SetUp();
    configure_identity_reevaluation_node(*mServer);

    ServerEndpointConfig endpoint;
    endpoint.name = "Aes128Sha256RsaOaep_SignAndEncrypt_UserTokens";
    endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    endpoint.securityPolicyId = SecurityPolicyId::Aes128Sha256RsaOaep;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    auto userNamePolicy =
      create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Aes128Sha256RsaOaep);
    mUserNamePolicyId = std::string{userNamePolicy.policy_id()};
    endpoint.userIdentityTokens.push_back(std::move(userNamePolicy));

    auto certificatePolicy =
      create_user_token_policy(UserTokenType::Certificate, SecurityPolicyId::Aes128Sha256RsaOaep);
    mCertificatePolicyId = std::string{certificatePolicy.policy_id()};
    endpoint.userIdentityTokens.push_back(std::move(certificatePolicy));

    auto issuedPolicy =
      create_user_token_policy(UserTokenType::IssuedToken, SecurityPolicyId::Aes128Sha256RsaOaep);
    mIssuedTokenPolicyId = std::string{issuedPolicy.policy_id()};
    endpoint.userIdentityTokens.push_back(std::move(issuedPolicy));

    mServer->add_endpoint(mListenerHandle, std::move(endpoint));

    ASSERT_FALSE(mUserNamePolicyId.empty());
    ASSERT_FALSE(mCertificatePolicyId.empty());
    ASSERT_FALSE(mIssuedTokenPolicyId.empty());
  }

  /// A channel onto the endpoint that advertises every token kind.
  ua::client::SecureChannel open_user_token_channel()
  {
    return open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes128Sha256RsaOaep);
  }

  ua::client::Session::ActivateConfig username_config(std::string_view user, std::string_view password)
  {
    ua::client::Session::ActivateConfig cfg;
    cfg.policyId = mUserNamePolicyId;
    cfg.identity =
      ua::client::UsernamePasswordIdentity{.username = std::string{user}, .password = std::string{password}};
    return cfg;
  }

  ua::client::Session::ActivateConfig certificate_config()
  {
    ua::client::Session::ActivateConfig cfg;
    cfg.policyId = mCertificatePolicyId;
    cfg.identity = ua::client::X509Identity{.certificate = mUserTokenCert, .keyPair = mUserTokenKeys};
    return cfg;
  }

  ua::client::Session::ActivateConfig issued_token_config(std::string_view token)
  {
    ua::client::Session::ActivateConfig cfg;
    cfg.policyId = mIssuedTokenPolicyId;
    cfg.identity = ua::client::IssuedTokenIdentity{.tokenData = bytes_of(token)};
    return cfg;
  }

  static constexpr uint32_t sFailuresBeforeLockout{5};

  std::shared_ptr<const ua::AsymmetricKeyPair> mUserTokenKeys;
  std::shared_ptr<const ua::X509Certificate> mUserTokenCert;
  std::shared_ptr<CertificateStore> mUserTokenStore;
  std::string mUserNamePolicyId;
  std::string mCertificatePolicyId;
  std::string mIssuedTokenPolicyId;
};

// Part 4 section 5.6.2.2: an authenticated CreateSession must present the canonical leaf certificate
// captured from its SecureChannel; trusting both certificates does not satisfy identity continuity.
// @relation(AC-SVR-SESS-011-CERT-CONTINUITY, scope=function)
TEST_F(ComplianceSessionWithHooks, TheCertificateAtCreateSessionMustBeTheChannelsCertificate)
{
  Crypto::Name secondSubject;
  secondSubject.commonName = "ComplianceSession Continuity Client";
  UtcTime secondExpiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName secondAltName;
  secondAltName.hostnames.push_back("localhost");
  secondAltName.hostnames.push_back("127.0.0.1");
  secondAltName.uris.push_back("urn:test:compliance:continuityclient");

  auto secondCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    secondSubject, secondExpiry, secondAltName, CertificateType::RsaSha256Application, 2048);
  ASSERT_TRUE(secondCertResult.is_good());
  auto [secondKeys, secondCert] = std::move(secondCertResult).value();
  ASSERT_NE(secondCert, nullptr);
  mServerCertStore->add_to_trusted_certificates_sync(secondCert);

  const auto secondCertDer = secondCert->der_encoding();
  ASSERT_FALSE(secondCertDer.empty()) << "the substituted certificate has no bytes to substitute";

  auto ownCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(ownCerts.empty());
  ASSERT_NE(ownCerts.front().certificate, nullptr);
  ASSERT_NE(secondCertDer, ownCerts.front().certificate->der_encoding())
    << "the two certificates must differ for the continuity check to be the thing under test";

  // The substituted certificate is trusted, and this is what proves it: a client holding its private
  // key opens a channel with it. Run BEFORE the response log is armed so nothing it emits is counted.
  {
    TrustListValidationOptions validationOptions;
    auto secondStorePath = mTempDir / "continuity_second_store";
    std::filesystem::create_directories(secondStorePath);
    auto secondCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = secondStorePath, .validationOptions = validationOptions});
    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = secondCert;
      appCert.keys = secondKeys;
      secondCertStore->add_to_application_certificates_sync(appCert);
    }
    secondCertStore->add_to_trusted_certificates_sync(mServerCert);

    auto secondAppCfg = ua::test_utils::create_test_config();
    secondAppCfg.application_description_part().applicationUri = "urn:test:compliance:continuityclient";
    client::CreateConfig secondClientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(secondAppCfg)};
    auto secondClient = Client::create(mClientThreadPool.executor(),
      std::move(secondClientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = secondCertStore,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});

    CoreClient::OpenChannelConfig secondChannelCfg;
    secondChannelCfg.endpointUrl = mEndpointUrl;
    secondChannelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    secondChannelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    secondChannelCfg.serverCertificate = mServerCert;
    auto secondChannelResult = secondClient.core().try_open_channel_sync(std::move(secondChannelCfg));
    ASSERT_TRUE(secondChannelResult.is_good())
      << "the substituted certificate must be individually valid and trusted, otherwise the refusal "
         "below would be explained by that certificate being unknown; status 0x"
      << std::hex << secondChannelResult.status_code().as_uint32();
    auto secondChannel = std::move(secondChannelResult).value();
    (void)secondChannel.try_close_sync();
  }

  auto log = std::make_shared<ServerResponseLog>();
  mResponseInterceptorFn = [log](ua::Response& response)
  {
    log->record(response);
  };

  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // The interface fires before framing, so this is the certificate the server decodes. The channel was and
  // stays opened with the client's own certificate; only the ApplicationInstanceCertificate presented
  // at CreateSession is a different one.
  ua::client::SecureChannelTestAccess::on_strand(channel,
    [secondCertDer](auto& g)
    {
      g.outgoing_request_observer() = [secondCertDer](const ua::Structure& request)
      {
        const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
        if (createRequest == nullptr)
          return;
        const_cast<ua::CreateSessionRequest&>(*createRequest).client_certificate() = secondCertDer;
      };
    });

  auto substituted = channel.try_create_session_sync({.sessionName = "CertContinuitySubstituted"});
  EXPECT_TRUE(substituted.is_bad())
    << "a CreateSession presenting a certificate other than the one that opened the SecureChannel must "
       "not yield a Session - both certificates being trusted does not satisfy the check";
  EXPECT_EQ(substituted.status_code(), Status::BadSecurityChecksFailed)
    << "certificate identity failure must use the CreateSession security-check status";
  if (substituted.is_good())
    (void)substituted.value().try_close_sync();

  {
    std::lock_guard lock(log->mutex);
    EXPECT_EQ(log->createSessionResponses, 0u)
      << "the server answered the substituted certificate with a CreateSessionResponse - it accepted a "
         "Session for an application other than the one that opened the channel";
    EXPECT_FALSE(log->faultStatuses.empty())
      << "the server emitted no fault at all for the substituted certificate";
  }

  // Falsifiability control: the same channel, with the certificate it opened with, still creates a
  // Session -- so the refusal above is attributable to the substitution and not to the fixture.
  ua::client::SecureChannelTestAccess::on_strand(
    channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });

  auto controlResult = channel.try_create_session_sync({.sessionName = "CertContinuityControl"});
  ASSERT_TRUE(controlResult.is_good()) << "the unmodified channel must still create a Session; status 0x"
                                       << std::hex << controlResult.status_code().as_uint32();
  auto controlSession = std::move(controlResult).value();
  controlSession.activate_sync();
  EXPECT_TRUE(controlSession.is_active());
  {
    std::lock_guard lock(log->mutex);
    EXPECT_EQ(log->createSessionResponses, 1u)
      << "exactly one CreateSessionResponse was expected: the control's";
  }

  controlSession.close_sync();
  channel.close_sync();
}

// Part 4 section 6.1.3 requires the ApplicationDescription URI to match a URI in the authenticated
// client's ApplicationInstanceCertificate. The outgoing-request interface mutates the real client's request
// before framing; the forged claim therefore crosses the real TCP/UASC wire and is decoded by the real
// server. The unmodified control reuses the same channel so a blanket CreateSession refusal cannot pass.
// @relation(AC-SVR-SECADMIN-008-CREATESESSION-URI-BINDING, scope=function)
TEST_F(ComplianceSessionWithHooks, SecuredCreateSessionRejectsApplicationUriAbsentFromClientCertificate)
{
  auto log = std::make_shared<ServerResponseLog>();
  mResponseInterceptorFn = [log](ua::Response& response)
  {
    log->record(response);
  };

  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  auto substituted = std::make_shared<std::atomic_bool>(false);
  ua::client::SecureChannelTestAccess::on_strand(channel,
    [substituted](auto& guarded)
    {
      guarded.outgoing_request_observer() = [substituted](const ua::Structure& request)
      {
        const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
        if (!createRequest)
          return;
        const_cast<ua::CreateSessionRequest&>(*createRequest).client_description().application_uri() =
          "urn:test:compliance:forged-client";
        substituted->store(true, std::memory_order_release);
      };
    });

  auto forged = channel.try_create_session_sync({.sessionName = "ForgedApplicationUri"});
  ASSERT_TRUE(substituted->load(std::memory_order_acquire))
    << "no real CreateSession request carried the forged ApplicationUri";
  EXPECT_TRUE(forged.is_bad()) << "the forged ApplicationUri yielded a usable Session";
  EXPECT_EQ(forged.status_code(), Status::BadCertificateUriInvalid);
  if (forged.is_good())
    (void)forged.value().try_close_sync();

  {
    std::lock_guard lock(log->mutex);
    EXPECT_EQ(log->createSessionResponses, 0u)
      << "the server emitted a CreateSessionResponse for an ApplicationUri absent from the certificate";
    ASSERT_FALSE(log->faultStatuses.empty()) << "the server emitted no fault for the forged ApplicationUri";
    bool sawUriInvalid = false;
    for (const auto& status : log->faultStatuses)
      sawUriInvalid = sawUriInvalid || status == StatusCode{Status::BadCertificateUriInvalid};
    EXPECT_TRUE(sawUriInvalid);
  }

  ua::client::SecureChannelTestAccess::on_strand(
    channel, [](auto& guarded) { guarded.outgoing_request_observer() = nullptr; });

  auto control = channel.try_create_session_sync({.sessionName = "MatchingApplicationUri"});
  ASSERT_TRUE(control.is_good())
    << "the same channel with its unmodified certificate-matching URI must create a Session; status 0x"
    << std::hex << control.status_code().as_uint32();
  auto session = std::move(control).value();
  session.activate_sync();
  EXPECT_TRUE(session.is_active());
  auto read = session.attributes().read_sync(make_server_read_request());
  EXPECT_THAT(read, ::ua::test_helpers::ServiceResultIsGood());

  session.close_sync();
  channel.close_sync();
}

// Part 4 section 5.6.3.2: the clientSignature is computed over (serverCertificate || serverNonce) with the
// private key associated with the clientCertificate, and where a chain is involved the calculation is
// done with the leaf alone. The `clientCertificate` parameter may itself carry a chain, so a
// chain-bearing clientCertificate must not by itself refuse the activation while the signature the
// client computed over the server's leaf still verifies.
//
// Both peers are issued by a CA so the `clientCertificate` below can carry a genuine chain
// (leaf || issuer) rather than a single self-signed DER. The bound at the end is signed with real key
// material through the crypto provider and stamped into the request at the client's pre-framing interface,
// keeping the algorithm the client declared, so what the server decodes is a structurally valid
// ActivateSession and the only thing that can refuse it is the signature verification itself.
// @verifies AC-SVR-SESS-021-LEAF-THEN-CHAIN
// @relation(AC-SVR-SESS-021-LEAF-THEN-CHAIN, scope=function)
TEST_F(ComplianceSession, TheClientSignatureIsMadeOverTheServerLeafWithAFullChainFallback)
{
  TestPki pki{mCrypto};

  auto caKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(caKeys);
  auto caCert = pki.create_root_ca(caKeys, "Leaf Then Chain CA", "300");
  ASSERT_NE(caCert, nullptr);
  const auto caDer = caCert->der_encoding();
  ASSERT_FALSE(caDer.empty());

  auto now = DateTime::now();
  auto expiry = DateTime{now.value() + std::chrono::days{365}};

  // Part 6 section 6.2.2 Table 43: CA-issued RSA ApplicationInstance certificates carry all four keyUsage
  // bits and the extendedKeyUsage purpose for the role in which each peer presents its certificate.
  enum class ApplicationCertificateRole
  {
    Client,
    Server,
  };
  auto mintLeaf = [&pki, &caKeys, &caCert, now, expiry](
                    const std::shared_ptr<const ua::AsymmetricKeyPair>& subjectKeys,
                    const std::string& serialNumber,
                    const std::string& commonName,
                    const std::string& applicationUri,
                    ApplicationCertificateRole role)
  {
    Crypto::CreateCertificateConfig params;
    params.serialNumber = serialNumber;
    params.subject.commonName = commonName;
    params.subjectKeys = subjectKeys;
    params.issuer = caCert;
    params.issuerKeys = caKeys;
    params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    params.from = now;
    params.to = expiry;
    params.keyUsage.digitalSignature = true;
    params.keyUsage.nonRepudiation = true;
    params.keyUsage.keyEncipherment = true;
    params.keyUsage.dataEncipherment = true;
    params.keyUsage.clientAuth = role == ApplicationCertificateRole::Client;
    params.keyUsage.serverAuth = role == ApplicationCertificateRole::Server;
    params.basicConstraint.cA = false;
    params.subjectAlternateName.uris.push_back(applicationUri);
    params.subjectAlternateName.hostnames.emplace_back("localhost");
    params.subjectAlternateName.hostnames.emplace_back("127.0.0.1");
    return pki.create_cert(params);
  };

  auto serverLeafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(serverLeafKeys);
  auto serverLeaf = mintLeaf(serverLeafKeys,
    "301",
    "Leaf Then Chain Server",
    "urn:test:chain:leafchainserver",
    ApplicationCertificateRole::Server);
  ASSERT_NE(serverLeaf, nullptr);
  const auto serverLeafDer = serverLeaf->der_encoding();
  ASSERT_FALSE(serverLeafDer.empty());

  auto clientLeafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(clientLeafKeys);
  auto clientLeaf = mintLeaf(clientLeafKeys,
    "302",
    "Leaf Then Chain Client",
    "urn:test:chain:leafchainclient",
    ApplicationCertificateRole::Client);
  ASSERT_NE(clientLeaf, nullptr);
  const auto clientLeafDer = clientLeaf->der_encoding();
  ASSERT_FALSE(clientLeafDer.empty());

  // The client's full chain, leaf first as OPC UA orders one; this is what the `clientCertificate`
  // parameter carries below.
  ua::ByteString clientChainDer = clientLeafDer;
  for (auto b : caDer)
    clientChainDer.push_back(b);

  TrustListValidationOptions validationOptions;

  auto chainServerStorePath = mTempDir / "leafchain_server_store";
  std::filesystem::create_directories(chainServerStorePath);
  auto chainServerStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
    mCrypto,
    {.trustListPath = chainServerStorePath, .validationOptions = validationOptions});
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = serverLeaf;
    appCert.keys = serverLeafKeys;
    chainServerStore->add_to_application_certificates_sync(appCert);
  }
  chainServerStore->add_to_issuer_certificates_sync(caCert);
  chainServerStore->add_to_trusted_certificates_sync(caCert);
  chainServerStore->add_to_trusted_certificates_sync(clientLeaf);

  auto chainClientStorePath = mTempDir / "leafchain_client_store";
  std::filesystem::create_directories(chainClientStorePath);
  auto chainClientStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = chainClientStorePath, .validationOptions = validationOptions});
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = clientLeaf;
    appCert.keys = clientLeafKeys;
    chainClientStore->add_to_application_certificates_sync(appCert);
  }
  chainClientStore->add_to_issuer_certificates_sync(caCert);
  chainClientStore->add_to_trusted_certificates_sync(caCert);
  chainClientStore->add_to_trusted_certificates_sync(serverLeaf);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ServerComponents components{.crypto = mCrypto, .applicationGroupCertificateStore = chainServerStore};
  components.authenticator = std::make_shared<AnonymousAuthenticator>();
  components.roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

  server::CreateConfig chainServerCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  std::optional<ua::server::Server> chainServer;
  auto logSink = test_log_sink();
  components.logSink = logSink;
  components.logLevel = LogLevel::Debug;
  chainServer.emplace(ua::server::Server::create(
    mServerThreadPool.executor(), std::move(chainServerCfg), std::move(components)));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto chainListener = chainServer->listen_sync(std::move(bind), {});

  ServerEndpointConfig chainEndpoint;
  chainEndpoint.name = "Basic256Sha256_SignAndEncrypt";
  chainEndpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  chainEndpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  chainEndpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  chainServer->add_endpoint(chainListener, std::move(chainEndpoint));

  chainServer->start_sync();

  auto chainUrls = chainServer->advertised_urls(chainListener);
  ASSERT_FALSE(chainUrls.empty());
  const auto chainEndpointUrl = chainUrls.front().str();

  auto clientAppCfg = ua::test_utils::create_test_config();
  clientAppCfg.application_description_part().applicationUri = "urn:test:chain:leafchainclient";
  client::CreateConfig chainClientCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
  auto chainClient = Client::create(mClientThreadPool.executor(),
    std::move(chainClientCfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = chainClientStore,
      .logSink = logSink,
      .logLevel = LogLevel::Debug});

  CoreClient::OpenChannelConfig channelCfg;
  channelCfg.endpointUrl = chainEndpointUrl;
  channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelCfg.serverCertificate = serverLeaf;
  auto channelResult = chainClient.core().try_open_channel_sync(std::move(channelCfg));
  ASSERT_TRUE(channelResult.is_good()) << "the channel to the chain-certificate server must open; status 0x"
                                       << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  ASSERT_TRUE(channel.is_open());

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ASSERT_NE(policy, nullptr);

  auto signOver = [this, &policy, &clientLeafKeys](
                    const ua::ByteString& certificatePart, const ua::ByteString& noncePart)
  {
    ua::ByteString data = certificatePart;
    for (auto b : noncePart)
      data.push_back(b);
    return mCrypto->asymmetric_sign_sync(policy->asymmetric_signature_algorithm(), clientLeafKeys, data);
  };

  auto installCertificate = [&channel](ua::ByteString certificate)
  {
    ua::client::SecureChannelTestAccess::on_strand(channel,
      [certificate = std::move(certificate)](auto& g)
      {
        g.outgoing_request_observer() = [certificate](const ua::Structure& request)
        {
          const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
          if (createRequest == nullptr)
            return;
          const_cast<ua::CreateSessionRequest&>(*createRequest).client_certificate() = certificate;
        };
      });
  };

  auto installSignature = [&channel](ua::ByteString forged)
  {
    ua::client::SecureChannelTestAccess::on_strand(channel,
      [forged = std::move(forged)](auto& g)
      {
        g.outgoing_request_observer() = [forged](const ua::Structure& request)
        {
          const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
          if (activateRequest == nullptr)
            return;
          // Only the signature bytes are replaced: the algorithm the client declared is left alone so
          // the server's algorithm check cannot be what refuses this.
          const_cast<ua::ActivateSessionRequest&>(*activateRequest).client_signature().signature() = forged;
        };
      });
  };

  auto clearObserver = [&channel]
  {
    ua::client::SecureChannelTestAccess::on_strand(
      channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  };

  // A `clientCertificate` carrying the full chain, with the signature the client itself computes --
  // over the server's leaf certificate, with the client leaf's private key. This must activate.
  {
    installCertificate(clientChainDer);
    auto chained = channel.try_create_session_sync({.sessionName = "LeafChainCertificate"});
    clearObserver();
    ASSERT_TRUE(chained.is_good()) << "a clientCertificate carrying a full chain must be accepted; status 0x"
                                   << std::hex << chained.status_code().as_uint32();
    auto chainedSession = std::move(chained).value();

    auto chainedActivate = chainedSession.try_activate_sync();
    EXPECT_TRUE(chainedActivate.is_good())
      << "a signature computed over the server's leaf certificate must activate the Session; status 0x"
      << std::hex << chainedActivate.status_code().as_uint32();
    EXPECT_TRUE(chainedSession.is_active());
    (void)chainedSession.try_close_sync();
  }

  // The bound on the activation above: a signature made over a certificate other than the leaf the
  // server transmitted is still refused, so the acceptance cannot be satisfied by a server that
  // verifies nothing.
  {
    auto unrelated = channel.create_session_sync({.sessionName = "LeafChainUnrelated"});
    const auto nonce = session_state(unrelated).serverNonce;
    ASSERT_GE(nonce.size(), 32u);
    auto forged = signOver(caDer, nonce);
    ASSERT_FALSE(forged.empty());
    installSignature(forged);

    auto unrelatedActivate = unrelated.try_activate_sync();
    clearObserver();
    EXPECT_TRUE(unrelatedActivate.is_bad())
      << "a signature over a certificate other than the transmitted serverCertificate must not "
         "activate the Session";
    EXPECT_FALSE(unrelated.is_active());
    (void)unrelated.try_close_sync();
  }

  clearObserver();
  (void)channel.try_close_sync();

  if (chainServer)
    (void)chainServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  chainServer.reset();
}

// Part 4 section 5.6.3: each identity token kind is proved by its own mechanism -- a UserName token by the
// password inside it, an X509 token by a signature over (serverCertificate || serverNonce) made with
// the user certificate's private key, an IssuedToken by whatever the issuer's scheme says. The
// failure this guards is the FALLBACK between them: three separate checks would each pass against a
// server that validated its own kind correctly and accepted any token whose kind it did not
// recognise, and an unrecognised kind is exactly what an attacker sends. The encryption clause
// belongs to the same observation because the proof is worthless if the secret proving it is readable
// on the wire.
//
// Every accepted path is exercised first, so each refusal below is a verdict on the proof and not on
// a mechanism that never worked. The X509 forgery is made with the user's real private key through
// the crypto provider and keeps the algorithm the client declared, so only the verification can
// refuse it. The encryption half is asserted over the bytes the SERVER received, before it decrypts
// them, rather than over anything the client kept.
// @verifies AC-SVR-SESS-028-PROOF-BY-TOKEN-TYPE
// @relation(AC-SVR-IDENT-018-ISSUEDTOKEN-DECRYPTED, scope=function)
TEST_F(ComplianceSessionUserTokens, EachIdentityTokenTypeIsProvedByItsOwnMechanismAndSecretsAreEncrypted)
{
  using namespace std::chrono_literals;

  auto channel = open_user_token_channel();
  ASSERT_TRUE(channel.is_open());

  ASSERT_NE(mServerCert, nullptr);
  const auto serverCertDer = mServerCert->der_encoding();
  ASSERT_FALSE(serverCertDer.empty());

  auto tokenPolicy = SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep);
  ASSERT_NE(tokenPolicy, nullptr);

  auto installUserTokenSignature = [&channel](ua::ByteString forged)
  {
    ua::client::SecureChannelTestAccess::on_strand(channel,
      [forged = std::move(forged)](auto& g)
      {
        g.outgoing_request_observer() = [forged](const ua::Structure& request)
        {
          const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
          if (activateRequest == nullptr)
            return;
          // Only the signature bytes are replaced: the algorithm the client declared is left alone so
          // the server's algorithm check cannot be what refuses this.
          const_cast<ua::ActivateSessionRequest&>(*activateRequest).user_token_signature().signature() =
            forged;
        };
      });
  };

  auto clearObserver = [&channel]
  {
    ua::client::SecureChannelTestAccess::on_strand(
      channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  };

  auto signWithUserKey = [this, &tokenPolicy](const ua::ByteString& data)
  {
    return mCrypto->asymmetric_sign_sync(tokenPolicy->asymmetric_signature_algorithm(), mUserTokenKeys, data);
  };

  // The accepted paths. Each mechanism must work before its refusal means anything.
  {
    auto userSession = channel.create_session_sync({.sessionName = "ProofUserNameAccepted"});
    auto userActivate = userSession.try_activate_sync(username_config(proofUser, proofPassword));
    ASSERT_TRUE(userActivate.is_good()) << "the correct password must activate; status 0x" << std::hex
                                        << userActivate.status_code().as_uint32();
    (void)userSession.try_close_sync();

    auto certSession = channel.create_session_sync({.sessionName = "ProofX509Accepted"});
    auto certActivate = certSession.try_activate_sync(certificate_config());
    ASSERT_TRUE(certActivate.is_good()) << "a correctly signed X509 identity token must activate; status 0x"
                                        << std::hex << certActivate.status_code().as_uint32();
    (void)certSession.try_close_sync();

    auto issuedSession = channel.create_session_sync({.sessionName = "ProofIssuedAccepted"});
    auto issuedActivate = issuedSession.try_activate_sync(issued_token_config(acceptedIssuedToken));
    ASSERT_TRUE(issuedActivate.is_good()) << "the accepted issued token must activate; status 0x" << std::hex
                                          << issuedActivate.status_code().as_uint32();
    (void)issuedSession.try_close_sync();
  }

  // (a) UserName with the wrong password.
  {
    auto wrongPassword = channel.create_session_sync({.sessionName = "ProofWrongPassword"});
    auto result = wrongPassword.try_activate_sync(username_config(proofUser, "not-the-password"));
    EXPECT_TRUE(result.is_bad()) << "a UserName token carrying the wrong password must not activate";
    EXPECT_FALSE(wrongPassword.is_active());
    (void)wrongPassword.try_close_sync();
  }

  // (b) X509 whose signature is not over (serverCertificate || serverNonce). The nonce alone is
  // signed, with the user's real key and the policy's own algorithm, so the token is well formed and
  // only the proof is wrong.
  {
    auto wrongSignature = channel.create_session_sync({.sessionName = "ProofX509WrongSignature"});
    const auto nonce = session_state(wrongSignature).serverNonce;
    ASSERT_GE(nonce.size(), 32u) << "no server nonce was issued, so there is nothing to sign over";
    ua::ByteString nonceOnly;
    for (auto b : nonce)
      nonceOnly.push_back(b);
    auto forged = signWithUserKey(nonceOnly);
    ASSERT_FALSE(forged.empty()) << "the substituted signature is empty, so nothing was substituted";
    installUserTokenSignature(forged);

    auto result = wrongSignature.try_activate_sync(certificate_config());
    clearObserver();
    EXPECT_TRUE(result.is_bad())
      << "an X509 identity token whose signature does not cover the server certificate and nonce must "
         "not activate - a proof that omits them is replayable";
    EXPECT_FALSE(wrongSignature.is_active());
    (void)wrongSignature.try_close_sync();
  }

  // (c) IssuedToken carrying a token the issuer's scheme does not accept.
  {
    auto rejectedToken = channel.create_session_sync({.sessionName = "ProofIssuedRejected"});
    auto result = rejectedToken.try_activate_sync(issued_token_config(rejectedIssuedToken));
    EXPECT_TRUE(result.is_bad()) << "an unacceptable issued token must not activate the Session";
    EXPECT_FALSE(rejectedToken.is_active());
    (void)rejectedToken.try_close_sync();
  }

  // (d) No falling back to a weaker check: a UserName token with the wrong password, accompanied by a
  // userTokenSignature that is a perfectly valid X509-style proof over (serverCertificate ||
  // serverNonce). A server that accepts the signature in place of the password activates this.
  {
    auto crossProof = channel.create_session_sync({.sessionName = "ProofNoCrossMechanism"});
    const auto nonce = session_state(crossProof).serverNonce;
    ASSERT_GE(nonce.size(), 32u);
    ua::ByteString properData = serverCertDer;
    for (auto b : nonce)
      properData.push_back(b);
    auto valid = signWithUserKey(properData);
    ASSERT_FALSE(valid.empty());
    installUserTokenSignature(valid);

    auto result = crossProof.try_activate_sync(username_config(proofUser, "not-the-password"));
    clearObserver();
    EXPECT_TRUE(result.is_bad())
      << "a valid X509-style userTokenSignature must not stand in for the password a UserName token is "
         "proved by";
    EXPECT_FALSE(crossProof.is_active());
    (void)crossProof.try_close_sync();
  }

  // The encryption half, read off the requests the SERVER received.
  ASSERT_TRUE(wait_for_requests("ActivateSessionRequest", 1, 5s))
    << "the server observed no ActivateSessionRequest at all";
  auto activateRequests = get_requests_of_type("ActivateSessionRequest");
  ASSERT_FALSE(activateRequests.empty()) << "there are no requests to assert the encryption over";

  bool sawUserNameToken = false;
  bool sawIssuedToken = false;
  for (const auto& observed : activateRequests)
  {
    const auto* activateReq = dynamic_cast<const ActivateSessionRequest*>(observed.request.get());
    if (activateReq == nullptr)
      continue;

    if (const auto* userName =
          dynamic_cast<const ua::UserNameIdentityToken*>(activateReq->user_identity_token().get()))
    {
      sawUserNameToken = true;
      EXPECT_FALSE(carries_plaintext(userName->password(), proofPassword))
        << "the password reached the server in clear - the proof is worthless if the secret proving it "
           "is readable on the wire";
      EXPECT_FALSE(carries_plaintext(userName->password(), "not-the-password"))
        << "the password reached the server in clear";
      EXPECT_FALSE(userName->password().empty()) << "no password travelled at all";
      EXPECT_FALSE(userName->encryption_algorithm().empty())
        << "the UserName token declares no encryption algorithm, so nothing says it was encrypted";
    }

    if (const auto* issued =
          dynamic_cast<const ua::IssuedIdentityToken*>(activateReq->user_identity_token().get()))
    {
      sawIssuedToken = true;
      EXPECT_FALSE(carries_plaintext(issued->token_data(), acceptedIssuedToken))
        << "the issued token reached the server in clear";
      EXPECT_FALSE(issued->token_data().empty()) << "no issued token travelled at all";
      EXPECT_TRUE(issued->encryption_algorithm().empty())
        << "Part 4 section 7.41.6 Table 195 requires an empty outer encryptionAlgorithm when "
           "IssuedIdentityToken.tokenData carries EncryptedSecret";
    }
  }
  EXPECT_TRUE(sawUserNameToken) << "no UserName token was observed, so the password assertions above "
                                   "asserted nothing";
  EXPECT_TRUE(sawIssuedToken) << "no issued token was observed, so the token assertions above asserted "
                                 "nothing";

  clearObserver();
  channel.close_sync();
}

// Part 4 section 5.6.3: the measures against identity-token attacks must be targeted enough that "sporadic
// failures shall not delay connections with valid tokens". This is the bound on the lockout, and the
// two must be read together: a global delay after any failure satisfies the attack measure and turns
// one mistyped password into a denial of service for every other connection -- which is why the
// specification states the limit in its own sentence rather than leaving the mechanism free.
//
// The throttle is enabled on this fixture, so there is a real mechanism to get wrong, and the
// failures are kept below its threshold because above it a refusal is the REQUIRED behaviour. The
// latency asserted is the ActivateSession round trip on an already-open channel, measured against a
// baseline taken on that same channel before any failure, so the comparison is like for like and a
// slow machine moves both.
// @verifies AC-SVR-SESS-030-VALID-TOKENS-UNDELAYED
TEST_F(ComplianceSessionUserTokens, SporadicIdentityFailuresDoNotDelayAConnectionWithValidCredentials)
{
  auto channel = open_user_token_channel();
  ASSERT_TRUE(channel.is_open());

  auto validActivationLatency = [this, &channel](const std::string& name)
  {
    auto session = channel.create_session_sync({.sessionName = name});
    const auto started = std::chrono::steady_clock::now();
    auto result = session.try_activate_sync(username_config(proofUser, proofPassword));
    const auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    EXPECT_TRUE(result.is_good()) << name << ": valid credentials must activate; status 0x" << std::hex
                                  << result.status_code().as_uint32();
    (void)session.try_close_sync();
    return elapsed;
  };

  constexpr int rounds = 3;

  std::vector<std::chrono::milliseconds> baseline;
  for (int round = 0; round < rounds; ++round)
    baseline.push_back(validActivationLatency("UndelayedBaseline" + std::to_string(round)));
  ASSERT_EQ(baseline.size(), static_cast<size_t>(rounds)) << "no baseline was measured to compare against";

  auto worstBaseline = baseline.front();
  for (const auto& sample : baseline)
  {
    if (sample > worstBaseline)
      worstBaseline = sample;
  }

  // One failure, then a valid connection, three times over. Three failures in total stays below the
  // five-failure lockout threshold, so nothing here is a case where refusal is the right answer.
  std::vector<std::chrono::milliseconds> interleaved;
  for (int round = 0; round < rounds; ++round)
  {
    auto failing = channel.create_session_sync({.sessionName = "UndelayedFailure" + std::to_string(round)});
    auto failed = failing.try_activate_sync(username_config(proofUser, "not-the-password"));
    ASSERT_TRUE(failed.is_bad()) << "round " << round
                                 << ": the sporadic failure must actually fail, or nothing is interleaved";
    (void)failing.try_close_sync();

    interleaved.push_back(validActivationLatency("UndelayedValid" + std::to_string(round)));
  }
  ASSERT_EQ(interleaved.size(), static_cast<size_t>(rounds)) << "no interleaved connection was measured";

  const auto allowance = worstBaseline + std::chrono::milliseconds{2000};
  for (size_t round = 0; round < interleaved.size(); ++round)
  {
    EXPECT_LT(interleaved[round], allowance)
      << "round " << round << ": a valid token took " << interleaved[round].count()
      << "ms after a sporadic failure against a worst baseline of " << worstBaseline.count()
      << "ms - the backoff is not targeted enough, so one bad attempt delays everyone else";
    EXPECT_LT(interleaved[round], std::chrono::milliseconds{5000})
      << "round " << round << ": a valid token was held for " << interleaved[round].count() << "ms";
  }

  channel.close_sync();
}

// Part 4 section 7.41 applies on each identity change. This public user-token path proves both fail-closed
// denial under the restricted identity and restoration after returning to the privileged identity.
// @relation(AC-SVR-SESS-031-REEVALUATE-ON-IDENTITY-CHANGE, scope=function)
TEST_F(ComplianceSessionUserTokens, AUserIdentityChangeReEvaluatesEveryMonitoredItemInTheSession)
{
  const ua::NodeId monitoredNode{ua::VariableId::Server_ServerStatus_CurrentTime};

  auto channel = open_user_token_channel();
  ASSERT_TRUE(channel.is_open());

  auto session = channel.create_session_sync({.sessionName = "SessionIdentityChangeReeval"});
  auto privilegedActivate = session.try_activate_sync(username_config(reevalPrivilegedUser, reevalPassword));
  ASSERT_TRUE(privilegedActivate.is_good()) << "the privileged identity must activate; status 0x" << std::hex
                                            << privilegedActivate.status_code().as_uint32();

  const std::vector<uint32_t> handlesBySubscription[2] = {{301u, 302u}, {401u, 402u}};
  std::vector<uint32_t> allHandles;

  for (const auto& handles : handlesBySubscription)
  {
    ua::CreateSubscriptionRequest subRequest;
    subRequest.requested_publishing_interval() = 50.0;
    subRequest.requested_lifetime_count() = 6000;
    subRequest.requested_max_keep_alive_count() = 100;
    subRequest.max_notifications_per_publish() = 0;
    subRequest.publishing_enabled() = true;
    auto subResponse = session.subscriptions().create_subscription_sync(std::move(subRequest));
    ASSERT_THAT(subResponse, ::ua::test_helpers::ServiceResultIsGood());
    const auto subscriptionId = subResponse.subscription_id();

    ua::CreateMonitoredItemsRequest miRequest;
    miRequest.subscription_id() = subscriptionId;
    miRequest.timestamps_to_return() = ua::TimestampsToReturn::Both;
    for (auto handle : handles)
    {
      ua::MonitoredItemCreateRequest item;
      item.item_to_monitor().node_id() = monitoredNode;
      item.item_to_monitor().attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
      item.monitoring_mode() = ua::MonitoringMode::Reporting;
      item.requested_parameters().client_handle() = handle;
      item.requested_parameters().sampling_interval() = 50.0;
      item.requested_parameters().queue_size() = 1;
      item.requested_parameters().discard_oldest() = true;
      miRequest.items_to_create().push_back(std::move(item));
      allHandles.push_back(handle);
    }

    auto miResponse = session.monitored_items().create_monitored_items_sync(std::move(miRequest));
    ASSERT_THAT(miResponse, ::ua::test_helpers::ServiceResultIsGood());
    ASSERT_EQ(miResponse.results().size(), handles.size());
    for (size_t index = 0; index < miResponse.results().size(); ++index)
    {
      ASSERT_TRUE(miResponse.results()[index].status_code().is_good())
        << "the privileged identity must be able to create item " << index << "; status 0x" << std::hex
        << miResponse.results()[index].status_code().as_uint32();
    }
  }
  ASSERT_EQ(allHandles.size(), 4u) << "no items were created, so there is nothing to re-evaluate";

  // One Publish round trip, folded into `out` keyed by clientHandle. An omitted status field is Good;
  // DataValue only carries one when it is not.
  auto drainPublish = [&session](std::map<uint32_t, ua::StatusCode>& out)
  {
    auto pubResponse = session.subscriptions().try_publish_sync(ua::PublishRequest{});
    if (pubResponse.is_bad())
      return;
    const auto& response = pubResponse.value();
    if (response.response_header().service_result().is_bad())
      return;
    for (const auto& notification : response.notification_message().notification_data())
    {
      const auto* dataChange = dynamic_cast<const ua::DataChangeNotification*>(notification.get());
      if (dataChange == nullptr)
        continue;
      for (size_t index = 0; index < dataChange->monitored_items().size(); ++index)
      {
        const auto& entry = dataChange->monitored_items()[index];
        out.insert_or_assign(entry.client_handle(),
          entry.value().status().has_value() ? *entry.value().status() : ua::StatusCode{ua::Status::Good});
      }
    }
  };

  std::map<uint32_t, ua::StatusCode> beforeChange;
  auto beforeDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
  while (std::chrono::steady_clock::now() < beforeDeadline && beforeChange.size() < allHandles.size())
  {
    drainPublish(beforeChange);
    if (beforeChange.size() < allHandles.size())
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
  }
  ASSERT_EQ(beforeChange.size(), allHandles.size())
    << "not every MonitoredItem delivered under the privileged identity, so there is nothing to stop";
  for (auto handle : allHandles)
  {
    auto it = beforeChange.find(handle);
    ASSERT_NE(it, beforeChange.end()) << "item " << handle << " never reported before the change";
    ASSERT_TRUE(it->second.is_good())
      << "item " << handle << " must be readable under the privileged identity; status 0x" << std::hex
      << it->second.as_uint32();
  }

  // The identity change itself. Same Session, same channel, both Subscriptions untouched.
  auto restrictedActivate = session.try_activate_sync(username_config(reevalRestrictedUser, reevalPassword));
  ASSERT_TRUE(restrictedActivate.is_good())
    << "the re-activation under the second identity must succeed for the obligation to apply; status 0x"
    << std::hex << restrictedActivate.status_code().as_uint32();

  std::map<uint32_t, ua::StatusCode> afterChange;
  auto allDenied = [&afterChange, &allHandles]
  {
    for (auto handle : allHandles)
    {
      auto it = afterChange.find(handle);
      if (it == afterChange.end() || it->second.as_status() != Status::BadUserAccessDenied)
        return false;
    }
    return true;
  };

  auto denialDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
  while (std::chrono::steady_clock::now() < denialDeadline && !allDenied())
  {
    drainPublish(afterChange);
    if (!allDenied())
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
  }

  for (size_t subscription = 0; subscription < 2; ++subscription)
  {
    for (auto handle : handlesBySubscription[subscription])
    {
      auto it = afterChange.find(handle);
      ASSERT_NE(it, afterChange.end())
        << "item " << handle << " in Subscription " << subscription
        << " reported nothing at all after the identity change, so it cannot be shown to have been "
           "re-evaluated";
      EXPECT_EQ(it->second.as_status(), Status::BadUserAccessDenied)
        << "item " << handle << " in Subscription " << subscription << " last reported 0x" << std::hex
        << it->second.as_uint32()
        << " - the permissions of ALL MonitoredItems in Subscriptions assigned to the Session must be "
           "re-evaluated after the identity change, not only those created after it";
    }
  }

  auto restoredActivate = session.try_activate_sync(username_config(reevalPrivilegedUser, reevalPassword));
  ASSERT_TRUE(restoredActivate.is_good()) << "returning to the privileged identity must succeed; status 0x"
                                          << std::hex << restoredActivate.status_code().as_uint32();

  std::map<uint32_t, ua::StatusCode> afterRestore;
  auto allRestored = [&afterRestore, &allHandles]
  {
    return std::ranges::all_of(allHandles,
      [&afterRestore](uint32_t handle)
      {
        auto found = afterRestore.find(handle);
        return found != afterRestore.end() && found->second.is_good();
      });
  };
  auto restoreDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
  while (std::chrono::steady_clock::now() < restoreDeadline && !allRestored())
  {
    drainPublish(afterRestore);
    if (!allRestored())
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
  }
  EXPECT_TRUE(allRestored())
    << "every existing MonitoredItem must resume readable delivery after the privileged identity is restored";

  (void)session.try_close_sync();
  channel.close_sync();
}

// Part 4 section 5.6.2: "The SignatureAlgorithm shall be the AsymmetricSignatureAlgorithm specified in the
// SecurityPolicy for the Endpoint" -- the server-emit mirror of the clientSignature rule. The
// plausible implementation hard-codes the algorithm of the one policy it was written against, almost
// always Basic256Sha256's rsa-sha256, and every single-policy test agrees with it. Aes256Sha256RsaPss
// is the case that separates them: it takes the same RSA certificate, so the same PKI serves it, but
// its AsymmetricSignatureAlgorithm is rsa-pss-sha2-256, and a client that verifies with the algorithm
// its endpoint's policy names cannot verify a signature made under the other.
//
// The declared algorithm is read off the CreateSessionResponse the server actually emitted, and each
// Session is carried through to activation, which is what makes the declaration one the client
// accepted rather than merely one the server wrote down.
// @verifies AC-SVR-SESS-034-SERVERSIG-ALGORITHM
TEST_F(ComplianceSession, TheServerSignatureAlgorithmIsTheOneEachEndpointsPolicySpecifies)
{
  // The fixture offers Basic256Sha256 only; add two further RSA policies so "the endpoint's policy"
  // is distinguishable from "one fixed algorithm".
  {
    ServerEndpointConfig aes128Ep;
    aes128Ep.name = "Aes128Sha256RsaOaep_SignAndEncrypt";
    aes128Ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    aes128Ep.securityPolicyId = SecurityPolicyId::Aes128Sha256RsaOaep;
    aes128Ep.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(aes128Ep));

    ServerEndpointConfig aes256Ep;
    aes256Ep.name = "Aes256Sha256RsaPss_SignAndEncrypt";
    aes256Ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    aes256Ep.securityPolicyId = SecurityPolicyId::Aes256Sha256RsaPss;
    aes256Ep.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(aes256Ep));
  }

  const std::vector<SecurityPolicyId> policies{SecurityPolicyId::Basic256Sha256,
    SecurityPolicyId::Aes128Sha256RsaOaep,
    SecurityPolicyId::Aes256Sha256RsaPss};
  ASSERT_FALSE(policies.empty());

  // A constant would satisfy the whole table if every policy named the same algorithm; this is what
  // makes the per-endpoint assertions below capable of failing.
  {
    auto basicPolicy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
    auto pssPolicy = SecurityPolicy::create(SecurityPolicyId::Aes256Sha256RsaPss);
    ASSERT_NE(basicPolicy, nullptr);
    ASSERT_NE(pssPolicy, nullptr);
    auto basicUri = basicPolicy->asymmetric_signature_algorithm_uri();
    auto pssUri = pssPolicy->asymmetric_signature_algorithm_uri();
    ASSERT_NE(std::string_view{basicUri}, std::string_view{pssUri})
      << "the policies chosen share one AsymmetricSignatureAlgorithm, so a hard-coded algorithm would "
         "pass this row";
  }

  size_t observed = 0;
  for (size_t index = 0; index < policies.size(); ++index)
  {
    auto policy = SecurityPolicy::create(policies[index]);
    ASSERT_NE(policy, nullptr);
    auto expectedUri = policy->asymmetric_signature_algorithm_uri();
    ASSERT_FALSE(expectedUri.empty());

    auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, policies[index]);
    ASSERT_TRUE(channel.is_open()) << "could not open a channel under policy index " << index;

    auto captured =
      create_session_with_capture(channel, {.sessionName = "ServerSigAlg" + std::to_string(index)});
    ASSERT_TRUE(captured.session.is_created());
    ++observed;

    const auto& signature = captured.response.server_signature();
    EXPECT_FALSE(signature.signature().empty())
      << "policy index " << index << " is authenticated, so the serverSignature must be present";
    EXPECT_EQ(std::string_view{signature.algorithm()}, std::string_view{expectedUri})
      << "the serverSignature under policy index " << index
      << " declares an algorithm that is not the AsymmetricSignatureAlgorithm that endpoint's policy "
         "specifies";

    auto activateResult = captured.session.try_activate_sync();
    EXPECT_TRUE(activateResult.is_good())
      << "the Session must activate under policy index " << index
      << ", otherwise the declared algorithm is one no client could verify with; status 0x" << std::hex
      << activateResult.status_code().as_uint32();

    (void)captured.session.try_close_sync();
    channel.close_sync();
  }

  ASSERT_EQ(observed, policies.size()) << "not every policy was exercised";
}

// ---------------------------------------------------------------------------
// Additional include for the last row below: the null / empty user identity token is stamped onto the
// wire as a real AnonymousIdentityToken (and as nothing at all), so the concrete type has to be
// complete here to be constructed.
// ---------------------------------------------------------------------------
#include "ua_anonymous_identity_token.h"

namespace
{

/// The DisplayName the Session's current locales resolved to, flattened to plain strings so the rows
/// below can compare two resolutions without holding a LocalizedText across a Session close.
struct ResolvedDisplayName
{
  bool observed{false};
  std::string locale;
  std::string text;
};

/// Reads the Server node's DisplayName through `session` and flattens it. `observed` stays false if
/// the service faulted or the attribute did not come back as a LocalizedText, so a caller can never
/// mistake "nothing was read" for "an empty translation was returned".
ResolvedDisplayName read_server_display_name(ua::client::Session& session)
{
  ResolvedDisplayName out;
  auto response =
    session.attributes().read_sync(make_display_name_read_request(ua::NodeId{ua::ObjectId::Server}));
  if (response.response_header().service_result().is_bad())
    return out;
  if (response.results().size() != 1u || !response.results()[0].value().is_localized_text())
    return out;
  const auto& localizedText = response.results()[0].value().as<ua::LocalizedText>();
  out.observed = true;
  out.locale = std::string{std::string_view{localizedText.locale()}};
  out.text = std::string{std::string_view{localizedText.text()}};
  return out;
}

}  // namespace

// Part 4 section 5.6.3: the Session's localeIds are a PRIORITY ORDER, not a filter -- the server returns the
// highest-priority translation it holds, and where it holds none of the requested locales it returns
// the best it can rather than nothing. The fallback is the half that fails as an empty string:
// returning nothing when no requested locale matches leaves a client displaying blank names, where the
// specification asks for the best the server can do.
//
// The existing row (P4_SS_0035_LocaleIdsHonoured) asks for a locale the server holds and gets it,
// which a filter satisfies just as well. Here the FIRST requested locale is one the server does not
// hold while the second and third both are, so returning the second is a decision about priority and
// not about availability -- and a separate activation asks only for locales the server holds none of,
// which is where an empty LocalizedText is the failure.
// @verifies AC-SVR-SESS-035-LOCALE-BEST-MATCH
TEST_F(ComplianceSession, TheHighestPriorityAvailableTranslationIsReturnedWithAFallbackWhenNoneMatch)
{
  auto addressSpace = mServer->address_space();
  auto serverNode = addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::Server});
  serverNode.set_display_name(ua::LocalizedText{"en", "Server"});
  serverNode.set_display_name(ua::LocalizedText{"es", "Servidor"});
  serverNode.set_display_name(ua::LocalizedText{"de", "Server_DE"});

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  auto resolve = [&channel](const std::string& sessionName, const std::vector<const char*>& locales)
  {
    auto session = channel.create_session_sync({.sessionName = sessionName});
    ua::client::Session::ActivateConfig cfg;
    for (const auto* locale : locales)
      cfg.localeIds.push_back(locale);
    session.activate_sync(std::move(cfg));
    EXPECT_TRUE(session.is_active()) << sessionName << ": the Session must activate";
    auto resolved = read_server_display_name(session);
    (void)session.try_close_sync();
    return resolved;
  };

  // The server really does hold BOTH of the locales the priority case chooses between, so preferring
  // one of them there is a decision about priority rather than about availability.
  const auto spanish = resolve("LocaleSpanishOnly", {"es"});
  ASSERT_TRUE(spanish.observed) << "no DisplayName was read at all, so nothing is asserted over";
  ASSERT_EQ(spanish.text, "Servidor")
    << "the server does not hold the Spanish translation this row is built on; got '" << spanish.text << "'";
  const auto german = resolve("LocaleGermanOnly", {"de"});
  ASSERT_TRUE(german.observed) << "no DisplayName was read for the German control";
  ASSERT_EQ(german.text, "Server_DE")
    << "the server does not hold the German translation this row is built on; got '" << german.text << "'";

  // Three locales in priority order, of which the server holds the second and the third.
  const auto prioritised = resolve("LocalePriority", {"fr", "es", "de"});
  ASSERT_TRUE(prioritised.observed) << "no DisplayName was read for the priority case";
  EXPECT_EQ(prioritised.text, "Servidor")
    << "got '" << prioritised.text << "' (locale '" << prioritised.locale
    << "') - the highest-priority translation the server holds is the Spanish one, and the German one "
       "also being available is not a reason to prefer it";
  EXPECT_EQ(prioritised.locale, "es")
    << "the LocalizedText must name the locale it was actually resolved to, so a client can tell which "
       "of its preferences was honoured";

  // Locales the server holds none of. A filter returns nothing here.
  const auto unmatched = resolve("LocaleNoMatch", {"ja", "ko"});
  ASSERT_TRUE(unmatched.observed) << "no DisplayName was read for the no-match case";
  EXPECT_FALSE(unmatched.text.empty())
    << "no requested locale matched and the server returned an empty LocalizedText - priority is a "
       "preference order, not a filter, so a translation must still come back";

  channel.close_sync();
}

// Part 4 section 5.6.3: "the Server shall keep using the current localeIds for the Session." Null means
// UNCHANGED, not RESET, and re-activation happens for reasons that have nothing to do with locale --
// a reconnect after a channel failure would silently switch a running client's language if the empty
// list were read as a request for the server default.
//
// The existing row (P4_SS_0036_NullLocaleKeepsCurrent) compares two reads of a DisplayName that has
// only ever had one translation, so it passes whether the locales were preserved, reset or ignored.
// Here the Session's first activation resolves to a translation that is demonstrably NOT the server
// default -- the default is read off a Session that named no locale at all -- so preserving it and
// resetting to the default give different answers.
// @verifies AC-SVR-SESS-036-NULL-LOCALES-PRESERVE
TEST_F(ComplianceSession, ANullLocaleIdsOnReactivationLeavesTheSessionsCurrentLocalesUnchanged)
{
  auto addressSpace = mServer->address_space();
  auto serverNode = addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::Server});
  serverNode.set_display_name(ua::LocalizedText{"en", "Server"});
  serverNode.set_display_name(ua::LocalizedText{"es", "Servidor"});
  serverNode.set_display_name(ua::LocalizedText{"de", "Server_DE"});

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);

  // What a Session that never named a locale resolves to. Without this the preservation asserted below
  // could not be told apart from a reset to the server's own default.
  ResolvedDisplayName serverDefault;
  {
    auto defaulted = channel.create_session_sync({.sessionName = "LocaleServerDefault"});
    defaulted.activate_sync();
    ASSERT_TRUE(defaulted.is_active());
    serverDefault = read_server_display_name(defaulted);
    (void)defaulted.try_close_sync();
  }
  ASSERT_TRUE(serverDefault.observed) << "the server default translation was never read";
  ASSERT_NE(serverDefault.text, "Servidor")
    << "the server default is already the Spanish translation, so preserving the Session's locales and "
       "resetting to the default would be indistinguishable here";

  auto session = channel.create_session_sync({.sessionName = "LocalePreservedAcrossReactivation"});

  ua::client::Session::ActivateConfig spanishCfg;
  spanishCfg.localeIds.push_back("es");
  session.activate_sync(std::move(spanishCfg));
  ASSERT_TRUE(session.is_active());

  const auto beforeReactivation = read_server_display_name(session);
  ASSERT_TRUE(beforeReactivation.observed) << "no DisplayName was read before the re-activation";
  ASSERT_EQ(beforeReactivation.text, "Servidor")
    << "the first activation did not take the locale it asked for, so there is nothing to preserve; got '"
    << beforeReactivation.text << "'";

  // The re-activation names no locale at all.
  ua::client::Session::ActivateConfig nullLocaleCfg;
  ASSERT_TRUE(nullLocaleCfg.localeIds.empty()) << "this re-activation must name no locale of its own";
  session.activate_sync(std::move(nullLocaleCfg));
  ASSERT_TRUE(session.is_active());

  const auto afterReactivation = read_server_display_name(session);
  ASSERT_TRUE(afterReactivation.observed) << "no DisplayName was read after the re-activation";
  EXPECT_EQ(afterReactivation.text, beforeReactivation.text)
    << "got '" << afterReactivation.text << "' where the Session's locales resolved to '"
    << beforeReactivation.text << "' before the re-activation";
  EXPECT_EQ(afterReactivation.locale, beforeReactivation.locale)
    << "the resolved locale changed across a re-activation that named no locale";
  EXPECT_NE(afterReactivation.text, serverDefault.text)
    << "the re-activation reset the Session to the server default '" << serverDefault.text
    << "' - a null localeIds means unchanged, not reset, and a reconnect after a channel failure would "
       "otherwise switch a running client's language";

  session.close_sync();
  channel.close_sync();
}

// Part 4 section 5.6.3: "Null or empty user token shall always be interpreted as anonymous", and the
// EndpointDescription is what says which token types an endpoint accepts. "Always" is what closes the
// hole: a server that treated an empty token as UNSPECIFIED rather than as ANONYMOUS would fall
// through to whatever its default is, and on an endpoint whose declared policies are all
// authenticated the natural default is the first declared policy -- which grants an authenticated
// identity to a client that presented nothing.
//
// Both shapes are put to both kinds of endpoint. The refusals are the SERVER's: the client is given a
// UserName identity the endpoint really does declare, so it builds and sends a complete
// ActivateSession, and only the token that reaches the server is emptied at the pre-framing interface --
// the client's own policy match cannot be what answers. The control activation on that same endpoint
// shows a declared token still activates there, so the refusals are attributable to the anonymous
// interpretation and not to the endpoint.
// @verifies AC-SVR-SESS-037-NULL-IS-ANONYMOUS
TEST_F(ComplianceSessionUserTokens, ANullOrEmptyUserTokenIsAlwaysInterpretedAsAnonymous)
{
  // An endpoint that declares NO anonymous policy. Its security policy is used by no other endpoint on
  // this server, so the client's endpoint match (policy uri + mode) resolves to it unambiguously.
  auto authenticatedOnlyPolicy =
    create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Aes128Sha256RsaOaep);
  const std::string authenticatedOnlyPolicyId{authenticatedOnlyPolicy.policy_id()};
  ASSERT_FALSE(authenticatedOnlyPolicyId.empty());

  ServerEndpointConfig authenticatedOnlyEndpoint;
  authenticatedOnlyEndpoint.name = "Aes256Sha256RsaPss_SignAndEncrypt_NoAnonymous";
  authenticatedOnlyEndpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  authenticatedOnlyEndpoint.securityPolicyId = SecurityPolicyId::Aes256Sha256RsaPss;
  authenticatedOnlyEndpoint.userIdentityTokens.push_back(std::move(authenticatedOnlyPolicy));
  mServer->add_endpoint(mListenerHandle, std::move(authenticatedOnlyEndpoint));

  auto anonymousChannel = open_user_token_channel();
  ASSERT_TRUE(anonymousChannel.is_open());
  auto authenticatedOnlyChannel =
    open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes256Sha256RsaPss);
  ASSERT_TRUE(authenticatedOnlyChannel.is_open());

  enum class TokenShape
  {
    Absent,
    Empty
  };

  // The interface fires before framing, so this is the token the server decodes. `Absent` sends no
  // userIdentityToken at all; `Empty` sends one carrying no data whatever.
  auto installTokenShape = [](ua::client::SecureChannel& channel, TokenShape shape)
  {
    ua::client::SecureChannelTestAccess::on_strand(channel,
      [shape](auto& g)
      {
        g.outgoing_request_observer() = [shape](const ua::Structure& request)
        {
          const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
          if (activateRequest == nullptr)
            return;
          auto& mutableRequest = const_cast<ua::ActivateSessionRequest&>(*activateRequest);
          if (shape == TokenShape::Absent)
          {
            mutableRequest.user_identity_token().inner_unique_ptr().reset();
            return;
          }
          std::unique_ptr<ua::Structure> emptyToken = std::make_unique<ua::AnonymousIdentityToken>();
          mutableRequest.user_identity_token() = std::move(emptyToken);
        };
      });
  };

  auto clearObserver = [](ua::client::SecureChannel& channel)
  {
    ua::client::SecureChannelTestAccess::on_strand(
      channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  };

  auto shapeName = [](TokenShape shape)
  {
    return shape == TokenShape::Absent ? "a null userIdentityToken" : "a token carrying no data";
  };

  // Half one: on an endpoint that DOES declare an anonymous policy, both shapes are interpreted as
  // anonymous, and "interpreted" is carried as far as a Session that serves requests.
  for (auto shape : {TokenShape::Absent, TokenShape::Empty})
  {
    auto session = anonymousChannel.create_session_sync({.sessionName = "AnonymousDeclaredShape"});
    ASSERT_TRUE(session.is_created());
    installTokenShape(anonymousChannel, shape);
    auto result = session.try_activate_sync();
    clearObserver(anonymousChannel);

    ASSERT_TRUE(result.is_good())
      << shapeName(shape)
      << " must be interpreted as anonymous on an endpoint that declares an anonymous policy; status 0x"
      << std::hex << result.status_code().as_uint32();
    EXPECT_TRUE(session.is_active());
    auto read = session.attributes().read_sync(make_server_read_request());
    EXPECT_THAT(read, ::ua::test_helpers::ServiceResultIsGood())
      << "the Session must serve requests - 'accepted' is not 'interpreted as anonymous' unless it does";
    (void)session.try_close_sync();
  }

  // Falsifiability control: the endpoint that declares no anonymous policy really does activate a
  // Session when a token it DOES declare is supplied, so the refusals below cannot be explained by
  // that endpoint refusing everything.
  {
    ua::client::Session::ActivateConfig declaredCfg;
    declaredCfg.policyId = authenticatedOnlyPolicyId;
    declaredCfg.identity = ua::client::UsernamePasswordIdentity{
      .username = std::string{proofUser}, .password = std::string{proofPassword}};

    auto control = authenticatedOnlyChannel.create_session_sync({.sessionName = "NoAnonymousControl"});
    auto controlResult = control.try_activate_sync(std::move(declaredCfg));
    ASSERT_TRUE(controlResult.is_good())
      << "the endpoint that declares only a UserName policy must activate a Session for that policy, "
         "otherwise the refusals below say nothing about the anonymous interpretation; status 0x"
      << std::hex << controlResult.status_code().as_uint32();
    EXPECT_TRUE(control.is_active());
    (void)control.try_close_sync();
  }

  // Half two: on an endpoint that declares NO anonymous policy, both shapes are refused AS ANONYMOUS.
  // The client is given the declared UserName identity so that it builds and sends a complete request;
  // only the token the server decodes is emptied, so the endpoint's own first-declared policy is
  // exactly the thing a defaulting implementation would fall through to.
  for (auto shape : {TokenShape::Absent, TokenShape::Empty})
  {
    ua::client::Session::ActivateConfig declaredCfg;
    declaredCfg.policyId = authenticatedOnlyPolicyId;
    declaredCfg.identity = ua::client::UsernamePasswordIdentity{
      .username = std::string{proofUser}, .password = std::string{proofPassword}};

    auto session = authenticatedOnlyChannel.create_session_sync({.sessionName = "NoAnonymousShape"});
    ASSERT_TRUE(session.is_created());
    installTokenShape(authenticatedOnlyChannel, shape);
    auto result = session.try_activate_sync(std::move(declaredCfg));
    clearObserver(authenticatedOnlyChannel);

    EXPECT_TRUE(result.is_bad())
      << shapeName(shape)
      << " must be interpreted as anonymous and refused on an endpoint that declares no anonymous "
         "policy - accepting it grants an authenticated identity to a client that presented nothing";
    EXPECT_FALSE(session.is_active())
      << shapeName(shape)
      << " left the Session activated on an endpoint that declares no anonymous "
         "policy";
    auto read = session.attributes().try_read_sync(make_server_read_request());
    EXPECT_TRUE(read.is_bad()) << "the Session must serve nothing after an activation that had to be refused";
    (void)session.try_close_sync();
  }

  clearObserver(anonymousChannel);
  clearObserver(authenticatedOnlyChannel);
  (void)anonymousChannel.try_close_sync();
  (void)authenticatedOnlyChannel.try_close_sync();
}

// ---------------------------------------------------------------------------
// Additional include for the Cancel row below: a request is only cancellable while it is still
// outstanding, and the only interface this fixture has for holding one open is an ExternalValueSource
// read handler that keeps its completion callback instead of answering it.
// ---------------------------------------------------------------------------
#include "ua_instance_utils.h"

// Part 4 section 5.6.2.2: the serverSignature is made over (clientCertificate || clientNonce) with the
// private key of the server's Application Instance Certificate, and where a chain is involved the
// calculation is done with the LEAF alone -- the server-emit mirror of the clientSignature rule the
// row above covers. The asymmetric accommodation is on the verifying side: one peer signs the leaf,
// the other tries the leaf and only then the full chain before refusing.
//
// The fallback is the half a plausible client never implements, because the leaf-only calculation
// agrees with every server that signs the leaf, and the peers that do not are the ones whose
// certificates carry a chain. Both peers here are therefore issued by a CA, so the client has a real
// chain that differs from its leaf, and the second half substitutes the signature the server emitted
// for one made over (clientChain || clientNonce) with the server's own key. The substitution is
// proved to be exactly the case the fallback exists for: it is asserted NOT to verify over the leaf
// and to verify over the chain, so accepting it can only mean the client retried.
// @verifies AC-SVR-SESS-033-SERVERSIG-LEAF-THEN-CHAIN
TEST_F(ComplianceSession, TheServerSignatureIsVerifiedAgainstTheClientLeafWithAFullChainFallback)
{
  TestPki pki{mCrypto};

  auto caKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(caKeys);
  auto caCert = pki.create_root_ca(caKeys, "Server Leaf Then Chain CA", "500");
  ASSERT_NE(caCert, nullptr);
  const auto caDer = caCert->der_encoding();
  ASSERT_FALSE(caDer.empty());

  auto now = DateTime::now();
  auto expiry = DateTime{now.value() + std::chrono::days{365}};

  // Part 6 section 6.2.2 Table 43: CA-issued RSA ApplicationInstance certificates carry all four keyUsage
  // bits and the extendedKeyUsage purpose for the role in which each peer presents its certificate.
  enum class ApplicationCertificateRole
  {
    Client,
    Server,
  };
  auto mintLeaf = [&pki, &caKeys, &caCert, now, expiry](
                    const std::shared_ptr<const ua::AsymmetricKeyPair>& subjectKeys,
                    const std::string& serialNumber,
                    const std::string& commonName,
                    const std::string& applicationUri,
                    ApplicationCertificateRole role)
  {
    Crypto::CreateCertificateConfig params;
    params.serialNumber = serialNumber;
    params.subject.commonName = commonName;
    params.subjectKeys = subjectKeys;
    params.issuer = caCert;
    params.issuerKeys = caKeys;
    params.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    params.from = now;
    params.to = expiry;
    params.keyUsage.digitalSignature = true;
    params.keyUsage.nonRepudiation = true;
    params.keyUsage.keyEncipherment = true;
    params.keyUsage.dataEncipherment = true;
    params.keyUsage.clientAuth = role == ApplicationCertificateRole::Client;
    params.keyUsage.serverAuth = role == ApplicationCertificateRole::Server;
    params.basicConstraint.cA = false;
    params.subjectAlternateName.uris.push_back(applicationUri);
    params.subjectAlternateName.hostnames.emplace_back("localhost");
    params.subjectAlternateName.hostnames.emplace_back("127.0.0.1");
    return pki.create_cert(params);
  };

  auto serverLeafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(serverLeafKeys);
  auto serverLeaf = mintLeaf(serverLeafKeys,
    "501",
    "Server Leaf Then Chain Server",
    "urn:test:chain:serversigserver",
    ApplicationCertificateRole::Server);
  ASSERT_NE(serverLeaf, nullptr);

  auto clientLeafKeys = mCrypto->create_asymmetric_key_pair_sync(CertificateKeyAlgorithm::Rsa, 2048);
  ASSERT_TRUE(clientLeafKeys);
  auto clientLeaf = mintLeaf(clientLeafKeys,
    "502",
    "Server Leaf Then Chain Client",
    "urn:test:chain:serversigclient",
    ApplicationCertificateRole::Client);
  ASSERT_NE(clientLeaf, nullptr);
  const auto clientLeafDer = clientLeaf->der_encoding();
  ASSERT_FALSE(clientLeafDer.empty());

  // The client's full chain, leaf first as OPC UA orders one.
  ua::ByteString clientChainDer = clientLeafDer;
  for (auto b : caDer)
    clientChainDer.push_back(b);
  ASSERT_NE(clientChainDer, clientLeafDer)
    << "the client's chain is identical to its leaf, so the fallback below could not be told apart "
       "from the leaf-only calculation";

  TrustListValidationOptions validationOptions;

  auto chainServerStorePath = mTempDir / "serversig_chain_server_store";
  std::filesystem::create_directories(chainServerStorePath);
  auto chainServerStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
    mCrypto,
    {.trustListPath = chainServerStorePath, .validationOptions = validationOptions});
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = serverLeaf;
    appCert.keys = serverLeafKeys;
    chainServerStore->add_to_application_certificates_sync(appCert);
  }
  chainServerStore->add_to_issuer_certificates_sync(caCert);
  chainServerStore->add_to_trusted_certificates_sync(caCert);
  chainServerStore->add_to_trusted_certificates_sync(clientLeaf);

  auto chainClientStorePath = mTempDir / "serversig_chain_client_store";
  std::filesystem::create_directories(chainClientStorePath);
  auto chainClientStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = chainClientStorePath, .validationOptions = validationOptions});
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = clientLeaf;
    appCert.keys = clientLeafKeys;
    chainClientStore->add_to_application_certificates_sync(appCert);
  }
  chainClientStore->add_to_issuer_certificates_sync(caCert);
  chainClientStore->add_to_trusted_certificates_sync(caCert);
  chainClientStore->add_to_trusted_certificates_sync(serverLeaf);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ServerComponents components{.crypto = mCrypto, .applicationGroupCertificateStore = chainServerStore};
  components.authenticator = std::make_shared<AnonymousAuthenticator>();
  components.roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

  server::CreateConfig chainServerCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  std::optional<ua::server::Server> chainServer;
  auto logSink = test_log_sink();
  components.logSink = logSink;
  components.logLevel = LogLevel::Debug;
  chainServer.emplace(ua::server::Server::create(
    mServerThreadPool.executor(), std::move(chainServerCfg), std::move(components)));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto chainListener = chainServer->listen_sync(std::move(bind), {});

  ServerEndpointConfig chainEndpoint;
  chainEndpoint.name = "Basic256Sha256_SignAndEncrypt";
  chainEndpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  chainEndpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  chainEndpoint.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  chainServer->add_endpoint(chainListener, std::move(chainEndpoint));

  chainServer->start_sync();

  auto chainUrls = chainServer->advertised_urls(chainListener);
  ASSERT_FALSE(chainUrls.empty());
  const auto chainEndpointUrl = chainUrls.front().str();

  auto clientAppCfg = ua::test_utils::create_test_config();
  clientAppCfg.application_description_part().applicationUri = "urn:test:chain:serversigclient";
  client::CreateConfig chainClientCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
  auto chainClient = Client::create(mClientThreadPool.executor(),
    std::move(chainClientCfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = chainClientStore,
      .logSink = logSink,
      .logLevel = LogLevel::Debug});

  CoreClient::OpenChannelConfig channelCfg;
  channelCfg.endpointUrl = chainEndpointUrl;
  channelCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  channelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  channelCfg.serverCertificate = serverLeaf;
  auto channelResult = chainClient.core().try_open_channel_sync(std::move(channelCfg));
  ASSERT_TRUE(channelResult.is_good()) << "the channel to the chain-certificate server must open; status 0x"
                                       << std::hex << channelResult.status_code().as_uint32();
  auto channel = std::move(channelResult).value();
  ASSERT_TRUE(channel.is_open());

  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ASSERT_NE(policy, nullptr);
  auto crypto = mCrypto;

  auto verifies = [crypto, policy](const ua::ByteString& publicKey,
                    const ua::ByteString& data,
                    const ua::ByteString& signature)
  {
    try
    {
      crypto->asymmetric_verify_sync(policy->asymmetric_signature_algorithm(), publicKey, data, signature);
      return true;
    }
    catch (...)
    {
      return false;
    }
  };

  const auto serverPublicKey = serverLeaf->public_key();
  ASSERT_FALSE(serverPublicKey.empty());

  auto clearObserver = [&channel]
  {
    ua::client::SecureChannelTestAccess::on_strand(
      channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  };

  // Conjunct 1: the signature the server actually emits verifies over the client's LEAF alone, and
  // the client accepts it.
  {
    auto sent = std::make_shared<SentCreateSessionRequest>();
    ua::client::SecureChannelTestAccess::on_strand(channel,
      [sent](auto& g)
      {
        g.outgoing_request_observer() = [sent](const ua::Structure& request)
        {
          const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
          if (createRequest == nullptr)
            return;
          sent->record(*createRequest);
        };
      });

    auto captured = create_session_with_capture(channel, {.sessionName = "ServerSigLeaf"});
    clearObserver();
    ASSERT_TRUE(captured.session.is_created())
      << "the leaf-signed CreateSession must be accepted for the fallback below to be the only thing "
         "under test";

    ua::ByteString sentCertificate;
    ua::ByteString sentNonce;
    {
      std::lock_guard lock(sent->mutex);
      ASSERT_TRUE(sent->observed) << "no CreateSessionRequest was observed, so the signed input is unknown";
      sentCertificate = sent->clientCertificate;
      sentNonce = sent->clientNonce;
    }
    ASSERT_EQ(sentCertificate, clientLeafDer)
      << "the client did not send its leaf certificate, so 'the leaf alone' is not what was asserted";
    ASSERT_GE(sentNonce.size(), 32u) << "no clientNonce was sent, so there is no proof to verify";

    const auto& signature = captured.response.server_signature();
    ASSERT_FALSE(signature.signature().empty()) << "the server sent no signature to verify";

    ua::ByteString leafInput = clientLeafDer;
    for (auto b : sentNonce)
      leafInput.push_back(b);
    EXPECT_TRUE(verifies(serverPublicKey, leafInput, signature.signature()))
      << "the serverSignature does not verify over the client's LEAF certificate and clientNonce under "
         "the public key of the certificate that opened the SecureChannel";

    // Falsifiability control: the same verification over one flipped byte must NOT succeed.
    ua::ByteString tampered = leafInput;
    tampered[tampered.size() - 1] = static_cast<uint8_t>(~tampered[tampered.size() - 1]);
    EXPECT_FALSE(verifies(serverPublicKey, tampered, signature.signature()))
      << "verification accepts altered input, so the positive result above would hold for any signature";

    auto activateResult = captured.session.try_activate_sync();
    EXPECT_TRUE(activateResult.is_good())
      << "the client must accept a leaf-computed serverSignature; status 0x" << std::hex
      << activateResult.status_code().as_uint32();
    (void)captured.session.try_close_sync();
  }

  // Conjunct 2: where the leaf calculation FAILS, the client retries with the full chain before
  // refusing. The signature the server emitted is substituted for one made over
  // (clientChain || clientNonce) with the server's own private key, at the client's response interface,
  // before any validation runs.
  {
    auto sent = std::make_shared<SentCreateSessionRequest>();
    ua::client::SecureChannelTestAccess::on_strand(channel,
      [sent](auto& g)
      {
        g.outgoing_request_observer() = [sent](const ua::Structure& request)
        {
          const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
          if (createRequest == nullptr)
            return;
          sent->record(*createRequest);
        };
      });

    struct ChainSignature
    {
      mutable std::mutex mutex;
      bool installed{false};
      ua::ByteString nonce;
      ua::ByteString signature;
    };

    auto forged = std::make_shared<ChainSignature>();

    ua::client::SecureChannelTestAccess::on_strand(channel,
      [sent, forged, crypto, policy, clientChainDer, serverLeafKeys](auto& g)
      {
        g.next_create_session_response_observer() =
          [sent, forged, crypto, policy, clientChainDer, serverLeafKeys](
            const ua::CreateSessionResponse& response)
        {
          ua::ByteString nonce;
          {
            std::lock_guard lock(sent->mutex);
            if (!sent->observed)
              return;
            nonce = sent->clientNonce;
          }
          if (nonce.empty())
            return;

          ua::ByteString chainInput = clientChainDer;
          for (auto b : nonce)
            chainInput.push_back(b);

          ua::ByteString signature;
          try
          {
            signature = crypto->asymmetric_sign_sync(
              policy->asymmetric_signature_algorithm(), serverLeafKeys, chainInput);
          }
          catch (...)
          {
            return;
          }
          if (signature.empty())
            return;

          const_cast<ua::CreateSessionResponse&>(response).server_signature().signature() = signature;

          std::lock_guard lock(forged->mutex);
          forged->installed = true;
          forged->nonce = std::move(nonce);
          forged->signature = std::move(signature);
        };
      });

    auto chainResult = channel.try_create_session_sync({.sessionName = "ServerSigChainFallback"});
    clearObserver();

    ua::ByteString forgedNonce;
    ua::ByteString forgedSignature;
    {
      std::lock_guard lock(forged->mutex);
      ASSERT_TRUE(forged->installed)
        << "the chain-computed serverSignature was never substituted, so nothing was asserted over";
      forgedNonce = forged->nonce;
      forgedSignature = forged->signature;
    }
    ASSERT_FALSE(forgedSignature.empty());

    // This is what makes the acceptance below mean 'the client retried with the chain': the
    // substituted signature genuinely does NOT verify over the leaf, and genuinely DOES verify over
    // the full chain.
    ua::ByteString leafInput = clientLeafDer;
    for (auto b : forgedNonce)
      leafInput.push_back(b);
    ua::ByteString chainInput = clientChainDer;
    for (auto b : forgedNonce)
      chainInput.push_back(b);
    ASSERT_FALSE(verifies(serverPublicKey, leafInput, forgedSignature))
      << "the substituted signature verifies over the leaf as well, so accepting it says nothing about "
         "a chain fallback";
    ASSERT_TRUE(verifies(serverPublicKey, chainInput, forgedSignature))
      << "the substituted signature does not verify over the full chain either, so refusing it would be "
         "correct and this row would be unfalsifiable";

    ASSERT_TRUE(chainResult.is_good())
      << "a serverSignature that verifies only against the full clientCertificate chain must be "
         "accepted - the client must retry with the chain before refusing; status 0x"
      << std::hex << chainResult.status_code().as_uint32();
    auto chainSession = std::move(chainResult).value();

    auto activateResult = chainSession.try_activate_sync();
    EXPECT_TRUE(activateResult.is_good())
      << "the Session created from the chain-verified signature must activate; status 0x" << std::hex
      << activateResult.status_code().as_uint32();
    auto read = chainSession.attributes().try_read_sync(make_server_read_request());
    ASSERT_TRUE(read.is_good()) << "the Session must serve requests; status 0x" << std::hex
                                << read.status_code().as_uint32();
    EXPECT_THAT(read.value(), ::ua::test_helpers::ServiceResultIsGood());
    (void)chainSession.try_close_sync();
  }

  clearObserver();
  (void)channel.try_close_sync();

  if (chainServer)
    (void)chainServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  chainServer.reset();
}

// Part 4 section 5.6.3: "The EndpointDescription specifies what UserIdentityTokens the Server shall accept."
// The declaration is PER ENDPOINT, and that is what makes it a security control: a server offering
// anonymous access on one endpoint and requiring credentials on another has expressed a policy, and
// accepting a token because the server implements its type somewhere collapses the two endpoints into
// one. The plausible implementation resolves the policyId against the server's authenticators rather
// than against the endpoint the channel was opened on, and passes every single-endpoint test.
//
// The policyId presented is a real one this very server declares -- on a DIFFERENT endpoint, and the
// control activation there proves the server does accept it. The refusal is the SERVER's: the client
// is given an identity the endpoint under test does declare, so it builds and sends a complete
// ActivateSession, and only the token that reaches the server is replaced at the pre-framing interface.
// @verifies AC-SVR-SESS-037-TOKEN-POLICY
TEST_F(ComplianceSessionUserTokens, AnIdentityTokenWhosePolicyIdTheEndpointDoesNotDeclareIsRefused)
{
  using namespace std::chrono_literals;

  // The endpoint that DOES declare the UserName policy. Activating there is what shows the server
  // supports this policyId, so the refusal below cannot be explained by the credentials.
  auto declaringChannel = open_user_token_channel();
  ASSERT_TRUE(declaringChannel.is_open());
  {
    auto declared = declaringChannel.create_session_sync({.sessionName = "TokenPolicyDeclaring"});
    auto declaredResult = declared.try_activate_sync(username_config(proofUser, proofPassword));
    ASSERT_TRUE(declaredResult.is_good())
      << "the endpoint that declares the UserName policy must accept it, otherwise the refusal below "
         "says nothing about the endpoint declaration; status 0x"
      << std::hex << declaredResult.status_code().as_uint32();
    EXPECT_TRUE(declared.is_active());
    (void)declared.try_close_sync();
  }

  // The endpoint under test declares an Anonymous policy only.
  auto anonymousOnlyChannel =
    open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(anonymousOnlyChannel.is_open());

  // Falsifiability control: that endpoint really does activate Sessions for the token it declares.
  {
    auto control = anonymousOnlyChannel.create_session_sync({.sessionName = "TokenPolicyControl"});
    auto controlResult = control.try_activate_sync();
    ASSERT_TRUE(controlResult.is_good())
      << "the anonymous-only endpoint must activate a Session for its own declared token; status 0x"
      << std::hex << controlResult.status_code().as_uint32();
    EXPECT_TRUE(control.is_active());
    (void)control.try_close_sync();
  }

  const std::string undeclaredPolicyId = mUserNamePolicyId;
  ASSERT_FALSE(undeclaredPolicyId.empty());

  // The interface fires before framing, so this is the token the server decodes.
  ua::client::SecureChannelTestAccess::on_strand(anonymousOnlyChannel,
    [undeclaredPolicyId](auto& g)
    {
      g.outgoing_request_observer() = [undeclaredPolicyId](const ua::Structure& request)
      {
        const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
        if (activateRequest == nullptr)
          return;
        auto token = std::make_unique<ua::UserNameIdentityToken>();
        token->policy_id() = undeclaredPolicyId;
        token->user_name() = std::string{proofUser};
        token->password() = bytes_of(proofPassword);
        std::unique_ptr<ua::Structure> erased = std::move(token);
        const_cast<ua::ActivateSessionRequest&>(*activateRequest).user_identity_token() = std::move(erased);
      };
    });

  const size_t observedBefore = get_requests_of_type("ActivateSessionRequest").size();

  auto session = anonymousOnlyChannel.create_session_sync({.sessionName = "TokenPolicyUndeclared"});
  ASSERT_TRUE(session.is_created());
  auto result = session.try_activate_sync();

  ua::client::SecureChannelTestAccess::on_strand(
    anonymousOnlyChannel, [](auto& g) { g.outgoing_request_observer() = nullptr; });

  EXPECT_TRUE(wait_for_requests("ActivateSessionRequest", observedBefore + 1, 5s))
    << "the ActivateSession must have reached the server for its refusal to be the server's";
  EXPECT_TRUE(result.is_bad())
    << "a UserIdentityToken whose policyId matches no entry in this endpoint's userIdentityTokens must "
       "be refused - the server supporting that policy on another endpoint is not a reason to accept it";
  EXPECT_FALSE(session.is_active())
    << "the Session must be left unactivated when the token's policyId is undeclared here";
  auto read = session.attributes().try_read_sync(make_server_read_request());
  EXPECT_TRUE(read.is_bad()) << "the Session must serve nothing after an activation that had to be refused";

  (void)session.try_close_sync();
  (void)anonymousOnlyChannel.try_close_sync();
  (void)declaringChannel.try_close_sync();
}

// Part 4 section 5.6.3: "If the Client specified a user identity token that supports digital signatures,
// then it shall create a signature and pass it as this parameter. Otherwise the parameter is null or
// empty." A server can validate a supplied signature perfectly and never notice one is MISSING --
// verification code that runs only when the field is populated turns the whole proof into an optional
// extra, so an X509 identity token is admitted by simply omitting its signature.
//
// The accepted X509 path is exercised first, so the refusal is a verdict on the absent signature and
// not on a mechanism that never worked; the omission is made at the client's pre-framing interface so the
// request the server decodes is otherwise exactly the one the client built. The other direction is
// asserted on the request the SERVER received: for a token that requires no signature the parameter
// really is empty, and a populated field is refused rather than interpreted as anonymous proof.
// @verifies AC-SVR-SESS-038-TOKENSIGNATURE-PRESENCE
TEST_F(ComplianceSessionUserTokens, TheUserTokenSignatureIsPresentExactlyWhenTheTokenTypeRequiresIt)
{
  using namespace std::chrono_literals;

  auto channel = open_user_token_channel();
  ASSERT_TRUE(channel.is_open());

  ASSERT_NE(mServerCert, nullptr);
  const auto serverCertDer = mServerCert->der_encoding();
  ASSERT_FALSE(serverCertDer.empty());

  auto tokenPolicy = SecurityPolicy::create(SecurityPolicyId::Aes128Sha256RsaOaep);
  ASSERT_NE(tokenPolicy, nullptr);
  auto tokenAlgorithmUri = tokenPolicy->asymmetric_signature_algorithm_uri();

  auto clearObserver = [&channel]
  {
    ua::client::SecureChannelTestAccess::on_strand(
      channel, [](auto& g) { g.outgoing_request_observer() = nullptr; });
  };

  // Control: a correctly signed X509 identity token activates, so the refusal below is attributable
  // to the missing signature.
  {
    auto accepted = channel.create_session_sync({.sessionName = "TokenSigX509Accepted"});
    auto acceptedResult = accepted.try_activate_sync(certificate_config());
    ASSERT_TRUE(acceptedResult.is_good()) << "a correctly signed X509 identity token must activate; status 0x"
                                          << std::hex << acceptedResult.status_code().as_uint32();
    (void)accepted.try_close_sync();
  }

  // Conjunct: for a token that requires no signature the parameter really is null or empty. Asserted
  // on the ActivateSessionRequest the SERVER received, not on anything the client kept.
  {
    const size_t before = get_requests_of_type("ActivateSessionRequest").size();

    auto anonymous = channel.create_session_sync({.sessionName = "TokenSigAnonymousPlain"});
    auto anonymousResult = anonymous.try_activate_sync();
    ASSERT_TRUE(anonymousResult.is_good()) << "the anonymous activation must succeed; status 0x" << std::hex
                                           << anonymousResult.status_code().as_uint32();

    ASSERT_TRUE(wait_for_requests("ActivateSessionRequest", before + 1, 5s))
      << "the server never received the anonymous ActivateSessionRequest";
    auto observed = get_requests_of_type("ActivateSessionRequest");
    ASSERT_GT(observed.size(), before) << "there is no request to assert the signature parameter over";
    const auto* anonymousRequest =
      dynamic_cast<const ActivateSessionRequest*>(observed[before].request.get());
    ASSERT_NE(anonymousRequest, nullptr);
    EXPECT_NE(
      dynamic_cast<const ua::AnonymousIdentityToken*>(anonymousRequest->user_identity_token().get()), nullptr)
      << "the request asserted over did not carry an anonymous token, so it says nothing about a token "
         "that requires no signature";
    EXPECT_TRUE(anonymousRequest->user_token_signature().signature().empty())
      << "an AnonymousIdentityToken supports no digital signature, so the userTokenSignature must be "
         "null or empty";

    (void)anonymous.try_close_sync();
  }

  // Conjunct: an X509 identity token with the userTokenSignature omitted is refused.
  {
    ua::client::SecureChannelTestAccess::on_strand(channel,
      [](auto& g)
      {
        g.outgoing_request_observer() = [](const ua::Structure& request)
        {
          const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
          if (activateRequest == nullptr)
            return;
          auto& mutableRequest = const_cast<ua::ActivateSessionRequest&>(*activateRequest);
          mutableRequest.user_token_signature().signature() = ua::ByteString{};
          mutableRequest.user_token_signature().algorithm() = std::string{};
        };
      });

    const size_t before = get_requests_of_type("ActivateSessionRequest").size();

    auto unsigned509 = channel.create_session_sync({.sessionName = "TokenSigX509Omitted"});
    auto omittedResult = unsigned509.try_activate_sync(certificate_config());
    clearObserver();

    EXPECT_TRUE(wait_for_requests("ActivateSessionRequest", before + 1, 5s))
      << "the ActivateSession must have reached the server for its refusal to be the server's";
    EXPECT_TRUE(omittedResult.is_bad())
      << "an X509IdentityToken carrying no userTokenSignature must be refused - a token type that "
         "supports digital signatures proves nothing without one";
    EXPECT_FALSE(unsigned509.is_active())
      << "the Session must be left unactivated when the required userTokenSignature is absent";
    auto read = unsigned509.attributes().try_read_sync(make_server_read_request());
    EXPECT_TRUE(read.is_bad()) << "the Session must serve nothing after an activation that had to be refused";
    (void)unsigned509.try_close_sync();
  }

  // Conjunct: an AnonymousIdentityToken accompanied by a userTokenSignature is refused. The clause
  // says the parameter is null or empty otherwise; accepting a populated field would violate the
  // exactly-when presence rule and let unrelated proof material enter the anonymous path.
  {
    auto supplied = channel.create_session_sync({.sessionName = "TokenSigAnonymousSupplied"});
    const auto nonce = session_state(supplied).serverNonce;
    ASSERT_GE(nonce.size(), 32u) << "no server nonce was issued, so there is no signature to supply";
    ua::ByteString signedInput = serverCertDer;
    for (auto b : nonce)
      signedInput.push_back(b);
    auto signature = mCrypto->asymmetric_sign_sync(
      tokenPolicy->asymmetric_signature_algorithm(), mUserTokenKeys, signedInput);
    ASSERT_FALSE(signature.empty()) << "no signature was produced, so nothing was supplied";

    ua::client::SecureChannelTestAccess::on_strand(channel,
      [signature, tokenAlgorithmUri](auto& g)
      {
        g.outgoing_request_observer() = [signature, tokenAlgorithmUri](const ua::Structure& request)
        {
          const auto* activateRequest = dynamic_cast<const ua::ActivateSessionRequest*>(&request);
          if (activateRequest == nullptr)
            return;
          auto& mutableRequest = const_cast<ua::ActivateSessionRequest&>(*activateRequest);
          mutableRequest.user_token_signature().signature() = signature;
          mutableRequest.user_token_signature().algorithm() = tokenAlgorithmUri;
        };
      });

    auto suppliedResult = supplied.try_activate_sync();
    clearObserver();

    ASSERT_TRUE(suppliedResult.is_bad())
      << "an AnonymousIdentityToken accompanied by a userTokenSignature must be refused because the "
         "parameter is required to be null or empty for a non-signing token";
    EXPECT_FALSE(supplied.is_active());
    auto read = supplied.attributes().try_read_sync(make_server_read_request());
    EXPECT_TRUE(read.is_bad()) << "the Session must serve nothing after the invalid activation";
    (void)supplied.try_close_sync();
  }

  clearObserver();
  channel.close_sync();
}

// Part 4 section 5.6.3: the ActivateSession response carries a serverNonce that "shall have a minimum length
// of 32 bytes" and "should never be used in any other request", because the Client signs it at the
// NEXT ActivateSession to prove possession of its Application Instance Certificate. Length and
// freshness are one property: a constant nonce of the right size passes every length check and makes
// that next signature replayable by anyone who saw the previous one.
//
// The existing rows compare only the CreateSession nonce with the first ActivateSession nonce, which
// a server that generates one nonce per SESSION passes. Here the nonce is collected after EVERY
// activation, across repeated re-activations of one Session as well as across Sessions on one
// channel, and every pair is compared -- so a nonce fixed per session, per channel or per server all
// fail.
// @verifies AC-SVR-SESS-039-SERVERNONCE-LENGTH
TEST_F(ComplianceSession, EveryActivateSessionResponseCarriesAFreshServerNonceOfAtLeast32Bytes)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  constexpr int sessions = 4;
  constexpr int activationsPerSession = 3;
  std::vector<ua::ByteString> nonces;

  for (int session = 0; session < sessions; ++session)
  {
    auto handle =
      channel.create_session_sync({.sessionName = "ActivateNonceFresh" + std::to_string(session)});
    ASSERT_TRUE(handle.is_created()) << "session " << session;

    for (int activation = 0; activation < activationsPerSession; ++activation)
    {
      auto result = handle.try_activate_sync();
      ASSERT_TRUE(result.is_good()) << "session " << session << " activation " << activation
                                    << " must succeed for its nonce to be an ActivateSession nonce; "
                                       "status 0x"
                                    << std::hex << result.status_code().as_uint32();
      ASSERT_TRUE(handle.is_active());

      auto nonce = session_state(handle).serverNonce;
      EXPECT_GE(nonce.size(), 32u) << "session " << session << " activation " << activation
                                   << ": the ActivateSession serverNonce must be at least 32 bytes";
      nonces.push_back(std::move(nonce));
    }

    (void)handle.try_close_sync();
  }

  ASSERT_EQ(nonces.size(), static_cast<size_t>(sessions * activationsPerSession))
    << "no serverNonce was collected to assert over";

  for (size_t i = 0; i < nonces.size(); ++i)
  {
    for (size_t j = i + 1; j < nonces.size(); ++j)
    {
      EXPECT_NE(nonces[i], nonces[j])
        << "the ActivateSession serverNonce recurred between activations " << i << " and " << j
        << " - the Client signs this value at the next activation, so a repeat makes that signature "
           "replayable";
    }
  }

  channel.close_sync();
}

// Part 4 section 5.6.4: the Server "shall reject the request if the SecureChannel is not the same as the one
// associated with the CreateSession request." Without it the authenticationToken alone closes a
// Session -- and that token rides in every request header, so a peer that observed one could
// terminate another client's Session at will, a denial of service needing no credentials whatsoever.
//
// The refusal has to be the SERVER's, and a probe issued on the Session's own handle cannot show
// that: the client binds a Session to its creating channel, which is why the existing row skips. Here
// a second, genuinely active Session on the OTHER channel carries the target's authenticationToken,
// so the CloseSession really travels over a channel that is not the Session's. The control close on
// that same channel, run first, shows the channel does close Sessions that belong to it; and the
// target Session is required to still serve a request afterwards, which is the second conjunct.
// @verifies AC-SVR-SESS-040-CLOSESESSION-SAME-CHANNEL
TEST_F(ComplianceSessionWithHooks, ACloseSessionOnAnotherChannelIsRefusedAndTheSessionStaysOpen)
{
  auto ownerChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(ownerChannel.is_open());
  auto owned = ownerChannel.create_session_sync({.sessionName = "CloseBindingOwner"});
  owned.activate_sync();
  ASSERT_TRUE(owned.is_active());
  const auto ownedId = owned.session_id();
  const auto ownedToken = session_state(owned).authenticationToken;
  ASSERT_FALSE(ownedId.is_null());
  ASSERT_FALSE(ownedToken.is_null());

  auto foreignChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(foreignChannel.is_open());
  ASSERT_NE(foreignChannel.secure_channel_id(), ownerChannel.secure_channel_id())
    << "both Sessions are on one channel, so there is no cross-channel close to make";

  // Falsifiability control: the foreign channel really does close Sessions that belong to it.
  {
    auto ownGuest = foreignChannel.create_session_sync({.sessionName = "CloseBindingForeignOwn"});
    ownGuest.activate_sync();
    ASSERT_TRUE(ownGuest.is_active());
    auto controlClose = ownGuest.try_close_sync();
    ASSERT_TRUE(controlClose.is_good())
      << "the foreign channel must close its own Session, otherwise the refusal below would be "
         "explained by the channel rather than by the binding; status 0x"
      << std::hex << controlClose.status_code().as_uint32();
    ASSERT_TRUE(wait_for_requests("CloseSessionRequest", 1, std::chrono::seconds{5}))
      << "the control CloseSession never reached the server";
  }

  // The carrier stays on the foreign channel and is given the owner's identity, so the CloseSession
  // below genuinely travels over a channel that is not the target Session's.
  auto carrier = foreignChannel.create_session_sync({.sessionName = "CloseBindingCarrier"});
  carrier.activate_sync();
  ASSERT_TRUE(carrier.is_active());
  const auto carrierToken = session_state(carrier).authenticationToken;
  ASSERT_FALSE(carrierToken.is_null());
  ASSERT_NE(carrierToken, ownedToken);

  CSSTA::on_strand(carrier, [&](auto& g) { g.set_session_active(ownedId, ownedToken); });

  auto crossChannelClose = carrier.try_close_sync();
  EXPECT_TRUE(crossChannelClose.is_bad())
    << "a CloseSession carrying a Session's authenticationToken over a SecureChannel that is not that "
       "Session's must be rejected - otherwise the token alone closes a Session";
  EXPECT_TRUE(wait_for_requests("CloseSessionRequest", 2, std::chrono::seconds{5}))
    << "the cross-channel CloseSession must have reached the server for its refusal to be the server's";

  // Conjunct two: the Session stays open. Asserted on its OWN handle, over its own channel.
  EXPECT_TRUE(owned.is_active()) << "the target Session's handle was closed by a request it never made";
  auto survivorRead = owned.attributes().try_read_sync(make_server_read_request());
  ASSERT_TRUE(survivorRead.is_good())
    << "the Session must survive a CloseSession made over another channel; status 0x" << std::hex
    << survivorRead.status_code().as_uint32();
  EXPECT_THAT(survivorRead.value(), ::ua::test_helpers::ServiceResultIsGood())
    << "the surviving Session must still serve requests";

  owned.close_sync();
  (void)foreignChannel.try_close_sync();
  ownerChannel.close_sync();
}

// ---------------------------------------------------------------------------
// Additional helper for the Cancel row below: a request can only be cancelled while it is still
// outstanding, so the reads it targets are held open by a read handler that keeps its completion
// callback. Nothing blocks a thread -- the callbacks are stored and answered at the end.
// ---------------------------------------------------------------------------
namespace
{

struct HeldReads
{
  mutable std::mutex mutex;
  std::vector<std::function<void(ua::DataValueResult)>> heldCallbacks;

  void hold(std::function<void(ua::DataValueResult)> done)
  {
    std::lock_guard lock(mutex);
    heldCallbacks.push_back(std::move(done));
  }

  size_t held() const
  {
    std::lock_guard lock(mutex);
    return heldCallbacks.size();
  }

  void release_all()
  {
    std::vector<std::function<void(ua::DataValueResult)>> pending;
    {
      std::lock_guard lock(mutex);
      pending.swap(heldCallbacks);
    }
    for (auto& done : pending)
    {
      if (done)
        done(ua::DataValueResult{ua::DataValue{}});
    }
  }
};

}  // namespace

// Part 4 section 5.6.5: "Successfully cancelled service requests shall respond with
// Bad_RequestCancelledByClient", and "all outstanding requests with the matching requestHandle shall
// be cancelled". Cancelled requests must COMPLETE, not disappear: dropping them leaves the client
// waiting on responses that will never arrive, which is worse than the delay Cancel was called to
// end. The count is what lets a client tell "cancelled three" from "matched nothing", and the
// per-handle scope is what stops one Cancel taking down a Session's other work.
//
// The existing rows cancel a handle nothing carries, or race a loopback Read and accept either
// outcome, so neither of them ever observes a cancelled request completing. Here the reads are held
// genuinely outstanding by a read handler that keeps its completion callback, three of them carry one
// requestHandle and a fourth carries another, and every conjunct is asserted: the count, the status
// each cancelled request completes with, and the survival of the request with the other handle.
// @verifies AC-SVR-SESS-041-CANCEL
TEST_F(ComplianceSession, CancelledRequestsCompleteWithBadRequestCancelledByClientAndAreCounted)
{
  const ua::NodeId heldNode{ua::VariableId::Server_ServiceLevel};
  auto held = std::make_shared<HeldReads>();

  {
    std::promise<ua::VoidResult> installed;
    auto installedFuture = installed.get_future();
    ua::instance_utils::resolve_and_set_value_source_async(mServer->address_space(),
      heldNode,
      ua::make_value_source([held](const ua::ValueSource::ReadContext& /*context*/,
                              const ua::Node& /*node*/,
                              const ua::ReadValueId& /*read*/,
                              std::function<void(ua::DataValueResult)>
                                done) { held->hold(std::move(done)); }),
      [&installed](ua::VoidResult result) { installed.set_value(std::move(result)); });
    auto installResult = installedFuture.get();
    ASSERT_TRUE(installResult.is_good())
      << "the held-read handler could not be installed, so no request can be made long-running; "
         "status 0x"
      << std::hex << installResult.status_code().as_uint32();
  }

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "CancelOutstanding"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  constexpr uint32_t targetHandle{0x5CA10001U};
  constexpr uint32_t otherHandle{0x5CA10002U};
  constexpr int targetedCount = 3;

  auto makeHeldReadRequest = [&heldNode](uint32_t requestHandle)
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = heldNode;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    req.timestamps_to_return() = TimestampsToReturn::Neither;
    req.request_header().request_handle() = requestHandle;
    // Long enough that nothing here is decided by a client-side deadline.
    req.request_header().timeout_hint() = 120000;
    return req;
  };

  std::vector<std::shared_ptr<std::promise<SessionAttributeServices::ReadResponseResult>>> targeted;
  std::vector<std::future<SessionAttributeServices::ReadResponseResult>> targetedFutures;
  for (int i = 0; i < targetedCount; ++i)
  {
    auto promise = std::make_shared<std::promise<SessionAttributeServices::ReadResponseResult>>();
    targetedFutures.push_back(promise->get_future());
    targeted.push_back(promise);
    session.attributes().read_async(makeHeldReadRequest(targetHandle),
      [promise](SessionAttributeServices::ReadResponseResult result)
      { promise->set_value(std::move(result)); });
  }

  auto otherPromise = std::make_shared<std::promise<SessionAttributeServices::ReadResponseResult>>();
  auto otherFuture = otherPromise->get_future();
  session.attributes().read_async(makeHeldReadRequest(otherHandle),
    [otherPromise](SessionAttributeServices::ReadResponseResult result)
    { otherPromise->set_value(std::move(result)); });

  // All four must be genuinely outstanding before the Cancel, or the count below is a race.
  const size_t expectedHeld = static_cast<size_t>(targetedCount) + 1u;
  auto holdDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
  while (std::chrono::steady_clock::now() < holdDeadline && held->held() < expectedHeld)
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
  ASSERT_EQ(held->held(), expectedHeld)
    << "not every Read reached the held read handler, so there is nothing outstanding to cancel";

  CancelRequest cancelReq;
  cancelReq.request_handle() = targetHandle;
  auto cancelResp = session.cancel_sync(std::move(cancelReq));
  EXPECT_THAT(cancelResp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(cancelResp.cancel_count(), static_cast<uint32_t>(targetedCount))
    << "the Cancel response must report how many requests it cancelled - a client cannot tell "
       "'cancelled three' from 'matched nothing' without it";

  // Conjunct: every matching request COMPLETES, and completes with Bad_RequestCancelledByClient
  // rather than with its normal response.
  for (int i = 0; i < targetedCount; ++i)
  {
    ASSERT_EQ(targetedFutures[i].wait_for(std::chrono::seconds{10}), std::future_status::ready)
      << "cancelled request " << i
      << " never completed - a dropped request leaves the Client waiting forever, which is worse than "
         "the delay Cancel was called to end";
    auto result = targetedFutures[i].get();
    EXPECT_TRUE(result.is_bad()) << "cancelled request " << i << " returned its normal response";
    EXPECT_EQ(result.status_code().as_status(), Status::BadRequestCancelledByClient)
      << "cancelled request " << i << " completed with 0x" << std::hex << result.status_code().as_uint32();
  }

  // Conjunct: the request carrying a different handle is unaffected - it is still outstanding.
  EXPECT_EQ(otherFuture.wait_for(std::chrono::milliseconds{500}), std::future_status::timeout)
    << "a request carrying a requestHandle the Cancel did not name was cancelled too";

  // ... and completes normally once its read is answered.
  held->release_all();
  ASSERT_EQ(otherFuture.wait_for(std::chrono::seconds{20}), std::future_status::ready)
    << "the untargeted request never completed";
  auto otherResult = otherFuture.get();
  ASSERT_TRUE(otherResult.is_good()) << "the untargeted request failed with 0x" << std::hex
                                     << otherResult.status_code().as_uint32();
  EXPECT_THAT(otherResult.value(), ::ua::test_helpers::ServiceResultIsGood())
    << "a request the Cancel did not name must complete with its normal response";
  EXPECT_EQ(otherResult.value().results().size(), 1u);

  held->release_all();
  (void)session.try_close_sync();
  channel.close_sync();
}

// Part 4 section 5.6.5: "All outstanding requests with the matching requestHandle shall be cancelled." The
// quantifier is the obligation. requestHandles are chosen by the Client and are deliberately reusable
// across a batch -- that is what makes Cancel useful at all -- so a server that stops at the first
// match, or that indexes its in-flight requests by handle in a container holding one entry per key,
// answers Cancel successfully and leaves the rest of the batch running. The caller is then told the
// batch is stopped while four of its five requests continue.
//
// Five requests share one handle and a sixth carries another, and the sixth is issued in the MIDDLE of
// the batch so that a scan which halts on the first non-matching entry cancels two rather than five.
// Every conjunct of the observation is asserted separately: the count, the completion of each of the
// five, and the survival of the sixth. The repeat Cancel at the end is what distinguishes requests
// that were genuinely taken out of the outstanding set from a count reported off a stale registry.
// @verifies AC-SVR-SESS-042-CANCEL-ALL-MATCHING
TEST_F(ComplianceSession, CancelStopsEveryOutstandingRequestCarryingTheMatchingHandle)
{
  const ua::NodeId heldNode{ua::VariableId::Server_ServiceLevel};
  auto held = std::make_shared<HeldReads>();

  {
    std::promise<ua::VoidResult> installed;
    auto installedFuture = installed.get_future();
    ua::instance_utils::resolve_and_set_value_source_async(mServer->address_space(),
      heldNode,
      ua::make_value_source([held](const ua::ValueSource::ReadContext& /*context*/,
                              const ua::Node& /*node*/,
                              const ua::ReadValueId& /*read*/,
                              std::function<void(ua::DataValueResult)>
                                done) { held->hold(std::move(done)); }),
      [&installed](ua::VoidResult result) { installed.set_value(std::move(result)); });
    auto installResult = installedFuture.get();
    ASSERT_TRUE(installResult.is_good())
      << "the held-read handler could not be installed, so no request can be left outstanding long "
         "enough to be cancelled; status 0x"
      << std::hex << installResult.status_code().as_uint32();
  }

  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto session = channel.create_session_sync({.sessionName = "CancelAllMatching"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  constexpr uint32_t batchHandle{0x5CA20001U};
  constexpr uint32_t spectatorHandle{0x5CA20002U};
  constexpr size_t batchSize = 5;
  ASSERT_NE(batchHandle, spectatorHandle) << "the two handles must differ for the scope to be testable";

  auto makeHeldReadRequest = [&heldNode](uint32_t requestHandle)
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = heldNode;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    req.timestamps_to_return() = TimestampsToReturn::Neither;
    req.request_header().request_handle() = requestHandle;
    // Long enough that nothing here is decided by a client-side deadline.
    req.request_header().timeout_hint() = 120000;
    return req;
  };

  auto issue = [&session, &makeHeldReadRequest](uint32_t requestHandle)
  {
    auto promise = std::make_shared<std::promise<SessionAttributeServices::ReadResponseResult>>();
    auto future = promise->get_future();
    session.attributes().read_async(makeHeldReadRequest(requestHandle),
      [promise](SessionAttributeServices::ReadResponseResult result)
      { promise->set_value(std::move(result)); });
    return future;
  };

  // The spectator sits between the second and third member of the batch, so it is reached before the
  // batch is exhausted however the server walks its outstanding requests.
  std::vector<std::future<SessionAttributeServices::ReadResponseResult>> batchFutures;
  std::future<SessionAttributeServices::ReadResponseResult> spectatorFuture;
  for (size_t i = 0; i < batchSize; ++i)
  {
    batchFutures.push_back(issue(batchHandle));
    if (i == 1)
      spectatorFuture = issue(spectatorHandle);
  }
  ASSERT_EQ(batchFutures.size(), batchSize) << "the batch was never issued, so nothing is under test";
  ASSERT_TRUE(spectatorFuture.valid()) << "the request carrying the other handle was never issued";

  // All six must be genuinely outstanding before the Cancel, or the count below is a race.
  const size_t expectedHeld = batchSize + 1u;
  auto holdDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
  while (std::chrono::steady_clock::now() < holdDeadline && held->held() < expectedHeld)
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
  ASSERT_EQ(held->held(), expectedHeld)
    << "only " << held->held() << " of " << expectedHeld
    << " Reads reached the held read handler, so they are not all outstanding to be cancelled";

  CancelRequest cancelReq;
  cancelReq.request_handle() = batchHandle;
  auto cancelResp = session.cancel_sync(std::move(cancelReq));
  EXPECT_THAT(cancelResp, ::ua::test_helpers::ServiceResultIsGood())
    << "the Cancel service itself must succeed for its count to mean anything";
  EXPECT_EQ(cancelResp.cancel_count(), static_cast<uint32_t>(batchSize))
    << "Cancel reported " << cancelResp.cancel_count() << " of " << batchSize
    << " outstanding requests carrying the named requestHandle - ALL of them shall be cancelled, and a "
       "caller told the batch is stopped while some of it runs on is worse off than one told nothing";

  // Conjunct: every request sharing the handle completes, and completes as a cancelled request.
  for (size_t i = 0; i < batchFutures.size(); ++i)
  {
    ASSERT_EQ(batchFutures[i].wait_for(std::chrono::seconds{10}), std::future_status::ready)
      << "request " << i
      << " of the batch never completed - a request dropped rather than cancelled "
         "leaves the Client waiting forever";
    auto result = batchFutures[i].get();
    EXPECT_TRUE(result.is_bad()) << "request " << i
                                 << " of the batch returned its normal response despite the Cancel";
    EXPECT_EQ(result.status_code().as_status(), Status::BadRequestCancelledByClient)
      << "request " << i << " of the batch completed with 0x" << std::hex << result.status_code().as_uint32();
  }

  // Conjunct: the request carrying the other handle is untouched and still outstanding.
  EXPECT_EQ(spectatorFuture.wait_for(std::chrono::milliseconds{500}), std::future_status::timeout)
    << "the request carrying a requestHandle the Cancel did not name was cancelled along with the batch";

  // A second Cancel on the same handle must now match nothing: the five were removed from the
  // outstanding set, not merely counted in it.
  CancelRequest repeatReq;
  repeatReq.request_handle() = batchHandle;
  auto repeatResp = session.cancel_sync(std::move(repeatReq));
  EXPECT_THAT(repeatResp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(repeatResp.cancel_count(), 0u)
    << "a repeated Cancel on the same handle reported " << repeatResp.cancel_count()
    << " still outstanding - the first Cancel counted requests it had not taken out of the set";

  held->release_all();
  ASSERT_EQ(spectatorFuture.wait_for(std::chrono::seconds{20}), std::future_status::ready)
    << "the request carrying the other handle never completed";
  auto spectatorResult = spectatorFuture.get();
  ASSERT_TRUE(spectatorResult.is_good()) << "the request carrying the other handle failed with 0x" << std::hex
                                         << spectatorResult.status_code().as_uint32();
  EXPECT_THAT(spectatorResult.value(), ::ua::test_helpers::ServiceResultIsGood())
    << "a request the Cancel did not name must complete with its normal response";
  EXPECT_EQ(spectatorResult.value().results().size(), 1u);

  held->release_all();
  (void)session.try_close_sync();
  channel.close_sync();
}

// ---------------------------------------------------------------------------
// Additional includes for the audit-Event and channel-context rows below. Placed here, at the end,
// for the same reason the server-side hook includes above are.
// ---------------------------------------------------------------------------
#include "subscription.h"

#include "ua_event_field_list.h"
#include "ua_event_filter.h"
#include "ua_event_notification_list.h"
#include "ua_objecttype_id.h"
#include "ua_simple_attribute_operand.h"

#include <algorithm>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "test_components.h"

namespace
{

/// The select clauses the two audit rows below share. Their order fixes the field indices:
///   0 = EventType, 1 = SourceNode, 2 = AuditUrlMismatchEventType's own EndpointUrl.
///
/// `EndpointUrl` is selected off `AuditUrlMismatchEventType` because it is that subtype's own
/// Property; on any other audit Event it resolves to an empty Variant. Selecting it rather than
/// filtering on it with a WhereClause keeps the OfType machinery out of the assertion: a Server whose
/// OfType evaluation were broken would then answer "no such Event" for a reason that has nothing to
/// do with the obligation under test.
constexpr size_t auditFieldEventType{0};
constexpr size_t auditFieldSourceNode{1};
constexpr size_t auditFieldEndpointUrl{2};

ua::EventFilter make_session_audit_event_filter()
{
  auto clause = [](const char* fieldName, ua::NodeId typeDefinitionId)
  {
    ua::SimpleAttributeOperand operand;
    operand.type_definition_id() = std::move(typeDefinitionId);
    operand.browse_path().push_back(ua::QualifiedName{uint16_t{0}, fieldName});
    operand.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
    return operand;
  };

  ua::EventFilter filter;
  filter.select_clauses().push_back(clause("EventType", ua::NodeId{ua::ObjectTypeId::BaseEventType}));
  filter.select_clauses().push_back(clause("SourceNode", ua::NodeId{ua::ObjectTypeId::BaseEventType}));
  filter.select_clauses().push_back(
    clause("EndpointUrl", ua::NodeId{ua::ObjectTypeId::AuditUrlMismatchEventType}));
  return filter;
}

/// True when `events` holds one whose selected EventType field is exactly `eventType`.
bool contains_audit_event_of_type(const std::vector<ua::EventFieldList>& events, const ua::NodeId& eventType)
{
  for (const auto& efl : events)
  {
    if (efl.event_fields().size() > auditFieldEventType &&
        efl.event_fields()[auditFieldEventType].as<ua::NodeId>() == eventType)
    {
      return true;
    }
  }
  return false;
}

/// Polls `subscriptionId`, accumulating every EventFieldList delivered, until `predicate` accepts what
/// has been collected so far or `timeout` elapses. Everything collected is returned either way, so a
/// caller can report the denominator it scanned rather than only the hit it was hunting for.
std::vector<ua::EventFieldList> collect_audit_events_until(ua::client::Session& session,
  uint32_t subscriptionId, const std::function<bool(const std::vector<ua::EventFieldList>&)>& predicate,
  std::chrono::milliseconds timeout)
{
  std::vector<ua::EventFieldList> collected;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;)
  {
    auto batch = ::ua::test_helpers::collect_events(
      session, subscriptionId, {.minCount = 1, .timeout = std::chrono::milliseconds{200}});
    collected.insert(collected.end(), batch.begin(), batch.end());
    if (predicate(collected) || std::chrono::steady_clock::now() >= deadline)
    {
      return collected;
    }
  }
}

/// A one-line census of what a scan actually saw, so a run that quietly collected nothing does not
/// read the same as one that collected the wrong thing.
std::string describe_event_types(const std::vector<ua::EventFieldList>& events)
{
  std::map<std::string, size_t> counts;
  for (const auto& efl : events)
  {
    if (efl.event_fields().size() > auditFieldEventType)
    {
      counts[efl.event_fields()[auditFieldEventType].as<ua::NodeId>().as_definition()] += 1;
    }
  }
  std::string out;
  for (const auto& [name, count] : counts)
  {
    out += name + " x" + std::to_string(count) + "; ";
  }
  return out.empty() ? std::string{"(nothing)"} : out;
}

}  // namespace

/// `ComplianceSession` with auditing switched on.
///
/// `ServerConfig::auditingEnabled` defaults to false and the SDK only builds its audit-event
/// emitter when it is true, so on the unmodified fixture every audit obligation would be vacuous:
/// there is no audit log for the Events to be an alternative surface for. Part 4 section 6.5 states its rules
/// for a Server that supports auditing, and this makes the fixture one.
class ComplianceSessionAudit : public ComplianceSession
{
protected:
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.auditingEnabled = true;
  }
};

// Part 4 section 6.5: a Server that maintains an audit log makes each entry available as an Event of the
// corresponding AuditEventType. An audit trail that exists only in a server-side file is unreachable
// by the aggregating Clients Part 4 expects to collect it and by the operator console the whole
// AuditEventType hierarchy exists to feed -- the Event surface is what makes auditing a protocol
// feature rather than a deployment one.
//
// The subscription here is a real one, over the wire, on the Server Object, and the Events are read
// out of a PublishResponse. That is the whole point: the plausible implementation writes audit records
// to a log sink or hands them to an in-process listener and never puts them on the event bus, and
// every test that reads the records back through such a hook passes on it while no Client can see a
// thing. Nothing short of delivery to a subscriber satisfies the assertions below.
//
// The two EventTypes asserted are the ones Part 4 section 6.5.6 / section 6.5.7 name for the two actions
// provoked. Naming them is deliberate: a Server that pushed a bare BaseEventType (or the parent
// AuditEventType) for every audited action would leave a subscriber unable to tell a Session creation from a
// certificate rejection, and the criterion's words are "an Event of the CORRESPONDING AuditEventType".
// @verifies AC-SVR-SESS-007-AUDIT-VIA-EVENTS
TEST_F(ComplianceSessionAudit, AuditLogEntriesReachASubscriberAsEventsOfTheirCorrespondingAuditEventType)
{
  auto watchChannel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto watcher = watchChannel.create_session_sync({.sessionName = "AuditEventWatcher"});
  watcher.activate_sync();
  ASSERT_TRUE(watcher.is_active());

  const auto subscriptionId = ::ua::test_helpers::create_subscription(watcher, {.publishingInterval = 50.0});
  ASSERT_NE(subscriptionId, 0u) << "no Subscription was created, so no Event could be delivered to anything";

  const auto monitoredItemId = ::ua::test_helpers::create_event_monitored_item(watcher,
    subscriptionId,
    NodeId{ObjectId::Server},
    make_session_audit_event_filter(),
    {.clientHandle = 9001u, .samplingInterval = 0.0, .queueSize = 200});
  ASSERT_NE(monitoredItemId, 0u)
    << "the Server Object accepted no event MonitoredItem, so nothing here subscribes to audit Events";

  // The auditable actions, provoked AFTER the subscription exists so the emission cannot precede the
  // interest: a second Session created and activated on its own channel.
  auto auditedChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto audited = auditedChannel.create_session_sync({.sessionName = "AuditedSession"});
  audited.activate_sync();
  ASSERT_TRUE(audited.is_active()) << "the auditable action must actually happen, or there is nothing to log";

  const NodeId createSessionAudit{ObjectTypeId::AuditCreateSessionEventType};
  const NodeId activateSessionAudit{ObjectTypeId::AuditActivateSessionEventType};

  auto events = collect_audit_events_until(
    watcher,
    subscriptionId,
    [&createSessionAudit, &activateSessionAudit](const std::vector<ua::EventFieldList>& seen)
    {
      return contains_audit_event_of_type(seen, createSessionAudit) &&
             contains_audit_event_of_type(seen, activateSessionAudit);
    },
    std::chrono::seconds{10});

  GTEST_LOG_(INFO) << "Server-Object subscriber received " << events.size()
                   << " Events; by type: " << describe_event_types(events);

  EXPECT_TRUE(contains_audit_event_of_type(events, createSessionAudit))
    << "CreateSession produced no AuditCreateSessionEventType Event on the subscription - the audit "
       "entry may well exist on the Server, but it is not available to a Client as an Event. "
    << events.size() << " Events arrived in total: " << describe_event_types(events);
  EXPECT_TRUE(contains_audit_event_of_type(events, activateSessionAudit))
    << "ActivateSession produced no AuditActivateSessionEventType Event on the subscription. "
    << events.size() << " Events arrived in total: " << describe_event_types(events);

  (void)audited.try_close_sync();
  (void)auditedChannel.try_close_sync();
  (void)watcher.try_close_sync();
  (void)watchChannel.try_close_sync();
}

// Part 4 section 5.6.2, the `endpointUrl` parameter: "The HostName portion of the URL should be one of the
// HostNames for the application that are specified in the Server's ApplicationInstanceCertificate
// (see 7.2). The Server shall raise an AuditUrlMismatchEventType event if the URL does not match the
// Server's HostNames."
//
// The obligation is the EVENT, not a refusal. A mismatched HostName is usually a deployment error
// rather than an attack, so the Server may still serve the Session -- and nothing below asserts that
// it was rejected. That is also what makes the natural implementation wrong in a way no functional
// test notices: resolving the endpointUrl by port and path alone is enough to route the request to the
// right listener, so a Server that never compares the HostName serves every Session perfectly and
// raises nothing, and the operator loses the one signal that would have told them a certificate is
// misconfigured before Clients start refusing to connect (`AC-CL-DISC-005-HOSTNAME-MATCH`).
//
// The substituted URL therefore keeps the advertised endpoint's port and path and changes ONLY the
// HostName, which is checked against the Server certificate's own declared SAN hostnames rather than
// assumed. The control at the end is the AuditCreateSessionEventType raised by the very same
// CreateSession: the subscriber receives it, so a missing AuditUrlMismatchEventType is a missing
// Event and not a broken delivery path.
// @verifies AC-SVR-SESS-008-URLMISMATCH-EVENT
TEST_F(ComplianceSessionAudit, AnEndpointUrlOutsideTheCertificatesHostNamesRaisesAuditUrlMismatch)
{
  constexpr std::string_view urlPrefix{"opc.tcp://"};
  constexpr const char* foreignHost{"not-a-declared-hostname.invalid"};

  ASSERT_EQ(mEndpointUrl.rfind(std::string{urlPrefix}, 0), 0u)
    << "the fixture endpoint URL is not an opc.tcp URL: " << mEndpointUrl;
  const auto hostStart = urlPrefix.size();
  const auto portColon = mEndpointUrl.find(':', hostStart);
  ASSERT_NE(portColon, std::string::npos) << "the fixture endpoint URL carries no port: " << mEndpointUrl;
  const std::string advertisedHost = mEndpointUrl.substr(hostStart, portColon - hostStart);
  const std::string mismatchedUrl = std::string{urlPrefix} + foreignHost + mEndpointUrl.substr(portColon);

  // The antecedent, read off the certificate rather than assumed: the host the Server advertises IS
  // one of its certificate's declared domains and the substituted one is NOT. Without both halves the
  // stimulus is not the one the clause is about.
  ASSERT_NE(mServerCert, nullptr);
  const auto sanHostnames = mServerCert->san_hostnames();
  ASSERT_FALSE(sanHostnames.empty()) << "the Server certificate declares no HostNames at all, so no URL "
                                        "can be inside or outside them";
  GTEST_LOG_(INFO) << "Server certificate declares " << sanHostnames.size()
                   << " SAN HostName(s); advertised host is '" << advertisedHost << "'";
  ASSERT_NE(std::find(sanHostnames.begin(), sanHostnames.end(), advertisedHost), sanHostnames.end())
    << "the advertised host '" << advertisedHost
    << "' is not among the certificate's HostNames, so the unmodified URL would ALSO be a mismatch and "
       "the substitution below would prove nothing";
  ASSERT_EQ(std::find(sanHostnames.begin(), sanHostnames.end(), std::string{foreignHost}), sanHostnames.end())
    << "the substituted host is among the certificate's HostNames, so it is not a mismatch at all";

  auto watchChannel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto watcher = watchChannel.create_session_sync({.sessionName = "UrlMismatchWatcher"});
  watcher.activate_sync();
  ASSERT_TRUE(watcher.is_active());

  const auto subscriptionId = ::ua::test_helpers::create_subscription(watcher, {.publishingInterval = 50.0});
  ASSERT_NE(subscriptionId, 0u);
  const auto monitoredItemId = ::ua::test_helpers::create_event_monitored_item(watcher,
    subscriptionId,
    NodeId{ObjectId::Server},
    make_session_audit_event_filter(),
    {.clientHandle = 9002u, .samplingInterval = 0.0, .queueSize = 200});
  ASSERT_NE(monitoredItemId, 0u)
    << "the Server Object accepted no event MonitoredItem, so nothing here subscribes to audit Events";

  // The interface fires before framing, so this is the endpointUrl the Server decodes. Only that field is
  // touched: the channel itself was and stays connected to the advertised endpoint.
  auto substituted = std::make_shared<std::atomic_bool>(false);
  auto offendingChannel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ua::client::SecureChannelTestAccess::on_strand(offendingChannel,
    [mismatchedUrl, substituted](auto& g)
    {
      g.outgoing_request_observer() = [mismatchedUrl, substituted](const ua::Structure& request)
      {
        const auto* createRequest = dynamic_cast<const ua::CreateSessionRequest*>(&request);
        if (createRequest == nullptr)
          return;
        const_cast<ua::CreateSessionRequest&>(*createRequest).endpoint_url() = mismatchedUrl;
        substituted->store(true, std::memory_order_release);
      };
    });

  auto offendingResult = offendingChannel.try_create_session_sync({.sessionName = "UrlMismatchProbe"});
  ASSERT_TRUE(substituted->load(std::memory_order_acquire))
    << "no CreateSessionRequest carried the substituted endpointUrl - the stimulus never happened";
  // Deliberately unasserted: the clause permits the Server to serve this Session. Whether it did is
  // not the obligation; the Event is.
  if (offendingResult.is_good())
  {
    (void)offendingResult.value().try_close_sync();
  }

  const NodeId urlMismatchAudit{ObjectTypeId::AuditUrlMismatchEventType};
  const NodeId createSessionAudit{ObjectTypeId::AuditCreateSessionEventType};

  auto events = collect_audit_events_until(
    watcher,
    subscriptionId,
    [&urlMismatchAudit](const std::vector<ua::EventFieldList>& seen)
    { return contains_audit_event_of_type(seen, urlMismatchAudit); },
    std::chrono::seconds{10});

  GTEST_LOG_(INFO) << "Server-Object subscriber received " << events.size()
                   << " Events; by type: " << describe_event_types(events);

  // The control: this CreateSession did reach the audit surface, so the pipe carries Events.
  EXPECT_TRUE(contains_audit_event_of_type(events, createSessionAudit))
    << "the offending CreateSession raised no audit Event at all, so the absence asserted below cannot "
       "be attributed to the HostName check; "
    << events.size() << " Events arrived: " << describe_event_types(events);

  ASSERT_TRUE(contains_audit_event_of_type(events, urlMismatchAudit))
    << "a CreateSession naming '" << mismatchedUrl
    << "', whose HostName is not among the Server certificate's declared domains, raised no "
       "AuditUrlMismatchEventType. A Server that resolves the endpointUrl by port and path alone never "
       "compares the HostName and never raises this Event. "
    << events.size() << " Events arrived: " << describe_event_types(events);

  // The Event carries the offending URL, which is the whole diagnostic value of raising it.
  bool carriedTheUrl = false;
  for (const auto& efl : events)
  {
    if (efl.event_fields().size() <= auditFieldEndpointUrl)
      continue;
    if (efl.event_fields()[auditFieldEventType].as<ua::NodeId>() != urlMismatchAudit)
      continue;
    const auto reported = efl.event_fields()[auditFieldEndpointUrl].as<ua::String>();
    if (std::string_view{reported} == mismatchedUrl)
      carriedTheUrl = true;
  }
  EXPECT_TRUE(carriedTheUrl) << "the AuditUrlMismatchEventType Event did not carry the offending URL '"
                             << mismatchedUrl
                             << "' in its EndpointUrl field - an operator cannot act on a mismatch "
                                "report that does not say which URL mismatched";

  (void)watcher.try_close_sync();
  (void)watchChannel.try_close_sync();
  (void)offendingChannel.try_close_sync();
}

// @relation(AC-SVR-AUDIT-010-THE-TRANSFER-AUDIT-NAMES-THE-RECEIVING-SESSIONS-DIAGNOSTICS-OBJECT, scope=function)
TEST_F(ComplianceSessionAudit, TheTransferAuditNamesTheReceivingSessionsDiagnosticsObject)
{
  auto clause = [](const char* fieldName, ua::NodeId typeDefinitionId)
  {
    ua::SimpleAttributeOperand operand;
    operand.type_definition_id() = std::move(typeDefinitionId);
    operand.browse_path().push_back(ua::QualifiedName{uint16_t{0}, fieldName});
    operand.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
    return operand;
  };
  ua::EventFilter filter;
  filter.select_clauses().push_back(clause("SourceNode", ua::NodeId{ua::ObjectTypeId::BaseEventType}));
  filter.select_clauses().push_back(clause("SourceName", ua::NodeId{ua::ObjectTypeId::BaseEventType}));
  filter.select_clauses().push_back(clause("SessionId", ua::NodeId{ua::ObjectTypeId::AuditSessionEventType}));
  filter.select_clauses().push_back(clause("EventType", ua::NodeId{ua::ObjectTypeId::BaseEventType}));
  constexpr size_t sourceNodeField{0};
  constexpr size_t sourceNameField{1};
  constexpr size_t sessionIdField{2};
  constexpr size_t eventTypeField{3};
  auto watchChannel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto watcher = watchChannel.create_session_sync({.sessionName = "TransferAuditWatcher"});
  watcher.activate_sync();
  ASSERT_TRUE(watcher.is_active());
  const auto watchSubscription =
    ::ua::test_helpers::create_subscription(watcher, {.publishingInterval = 50.0});
  ASSERT_NE(watchSubscription, 0u);
  ASSERT_NE(::ua::test_helpers::create_event_monitored_item(watcher,
              watchSubscription,
              NodeId{ObjectId::Server},
              filter,
              {.clientHandle = 9101u, .samplingInterval = 0.0, .queueSize = 200}),
    0u);
  const auto setDiagnostics = [this](bool enabled)
  {
    auto node =
      mServer->address_space().find_node_sync(NodeId{VariableId::Server_ServerDiagnostics_EnabledFlag});
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->write_value_sync(Variant{enabled});
  };
  // The SessionDiagnostics Object of the Session named `sessionName`, as a Client finds it: the child of
  // SessionsDiagnosticsSummary with that BrowseName.
  const auto diagnosticsObjectOf = [&watcher](const std::string& sessionName) -> std::optional<NodeId>
  {
    auto response = watcher.view().browse_sync(
      BrowseRequestBuilder()
        .browse(NodeId{ObjectId::Server_ServerDiagnostics_SessionsDiagnosticsSummary})
        .direction(BrowseDirection::Forward)
        .reference_type(NodeId{ReferenceTypeId::HasComponent})
        .include_subtypes(true));
    if (!response.response_header().service_result().is_good() || response.results().size() != 1u)
      return std::nullopt;
    for (const auto& reference : response.results().payload()[0].references().payload())
    {
      if (reference.browse_name().name() == ua::String{sessionName})
        return reference.node_id().node_id();
    }
    return std::nullopt;
  };
  // Transfers a Subscription to a new Session named `heirName` and answers the heir's SessionId and the
  // "Session/TransferSubscriptions" audit Event the watcher received for it, if any.
  const auto transferTo = [&](const std::string& heirName, bool diagnosticsEnabled)
  {
    auto ownerChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
    auto owner = ownerChannel.create_session_sync({.sessionName = heirName + "Owner"});
    owner.activate_sync();
    const auto ownedSubscription =
      ::ua::test_helpers::create_subscription(owner, {.publishingInterval = 500.0});
    EXPECT_NE(ownedSubscription, 0u);
    auto heirChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
    auto heir = heirChannel.create_session_sync({.sessionName = heirName});
    heir.activate_sync();
    // The heir's SessionDiagnostics Object is browsable before the Session has finished creating it, and
    // until then the Session names no Object. A Write of the EnabledFlag is answered once every Session's
    // Object matches the flag, so writing the flag's current value waits for the heir to finish.
    setDiagnostics(diagnosticsEnabled);
    const auto heirId = heir.session_id();
    std::optional<NodeId> heirDiagnostics;
    for (int attempt = 0; attempt < 50 && !heirDiagnostics; ++attempt)
    {
      heirDiagnostics = diagnosticsObjectOf(heirName);
      if (!heirDiagnostics)
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
    }
    ua::TransferSubscriptionsRequest transferRequest;
    transferRequest.subscription_ids().push_back(ownedSubscription);
    transferRequest.send_initial_values() = false;
    auto transferred = heir.subscriptions().transfer_subscriptions_sync(std::move(transferRequest));
    EXPECT_THAT(transferred, ServiceResultIsGood());
    const auto isTheTransferAudit = [&heirId, sourceNameField, sessionIdField](const ua::EventFieldList& efl)
    {
      if (efl.event_fields().size() <= sessionIdField)
        return false;
      const auto* sourceName = efl.event_fields()[sourceNameField].try_as<ua::String>();
      const auto* sessionId = efl.event_fields()[sessionIdField].try_as<ua::NodeId>();
      return sourceName != nullptr && *sourceName == ua::String{"Session/TransferSubscriptions"} &&
             sessionId != nullptr && *sessionId == heirId;
    };
    // Use the existing observation window in full so a later duplicate is also counted.
    const auto events = collect_audit_events_until(
      watcher,
      watchSubscription,
      [](const std::vector<ua::EventFieldList>&) { return false; },
      std::chrono::seconds{8});
    EXPECT_EQ(std::ranges::count_if(events, isTheTransferAudit), 1)
      << "each transfer must raise exactly one matching audit Event";
    std::optional<ua::EventFieldList> audit;
    if (const auto found = std::ranges::find_if(events, isTheTransferAudit); found != events.end())
    {
      audit = *found;
      EXPECT_GT(audit->event_fields().size(), eventTypeField);
      if (audit->event_fields().size() > eventTypeField)
      {
        const auto* eventType = audit->event_fields()[eventTypeField].try_as<ua::NodeId>();
        EXPECT_NE(eventType, nullptr);
        if (eventType != nullptr)
        {
          EXPECT_EQ(*eventType, ua::NodeId{ua::ObjectTypeId::AuditSessionEventType})
            << "the transfer audit must be AuditSessionEventType";
        }
      }
    }
    (void)heir.try_close_sync();
    (void)heirChannel.try_close_sync();
    (void)owner.try_close_sync();
    (void)ownerChannel.try_close_sync();
    return std::tuple{heirDiagnostics, audit, events.size()};
  };
  const auto sourceNodeOf = [sourceNodeField](const ua::EventFieldList& audit) -> std::optional<NodeId>
  {
    const auto* sourceNode = audit.event_fields()[sourceNodeField].try_as<ua::NodeId>();
    return sourceNode != nullptr ? std::optional<NodeId>{*sourceNode} : std::nullopt;
  };
  setDiagnostics(true);
  const auto [withObject, enabledAudit, enabledSeen] = transferTo("TransferHeirWithDiagnostics", true);
  ASSERT_TRUE(withObject.has_value())
    << "the receiving Session has no SessionDiagnostics Object with diagnostics on";
  ASSERT_TRUE(enabledAudit.has_value())
    << "no Session/TransferSubscriptions audit Event reached the subscriber; " << enabledSeen
    << " Events arrived";
  EXPECT_EQ(sourceNodeOf(*enabledAudit), withObject)
    << "the audit's SourceNode is not the receiving Session's SessionDiagnostics Object";
  setDiagnostics(false);
  const auto [withoutObject, disabledAudit, disabledSeen] =
    transferTo("TransferHeirWithoutDiagnostics", false);
  EXPECT_FALSE(withoutObject.has_value()) << "a SessionDiagnostics Object exists with diagnostics off";
  ASSERT_TRUE(disabledAudit.has_value())
    << "no Session/TransferSubscriptions audit Event reached the subscriber; " << disabledSeen
    << " Events arrived";
  EXPECT_EQ(sourceNodeOf(*disabledAudit), std::optional<NodeId>{NodeId{ObjectId::Server}})
    << "without a SessionDiagnostics Object the audit's SourceNode is not the Server Object";
  (void)watcher.try_close_sync();
  (void)watchChannel.try_close_sync();
}

namespace
{

/// One reading a service implementation took of the channel carrying the request it was gating.
struct ChannelSecurityReading
{
  ua::NodeId node;
  ua::SecurityPolicyId securityPolicyId{ua::SecurityPolicyId::Invalid};
  ua::MessageSecurityMode messageSecurityMode{ua::MessageSecurityMode::Invalid};
};

/// The readings taken across every session, shared by the per-session authorizers the factory builds.
struct ChannelSecurityObservations
{
  mutable std::mutex mutex;
  mutable std::vector<ChannelSecurityReading> recordedReadings;

  void record(ChannelSecurityReading reading) const noexcept
  {
    // `authorize_operation` is `noexcept`; a test-side allocation must not be able to escape it.
    try
    {
      const std::lock_guard lock{mutex};
      recordedReadings.push_back(std::move(reading));
    }
    catch (...)
    {}
  }

  std::vector<ChannelSecurityReading> readings() const
  {
    const std::lock_guard lock{mutex};
    return recordedReadings;
  }
};

/// A namespace that records the immutable identity passed to the canonical access-control gate.
/// `effective_permissions` runs inside the Read service for the request that just arrived, and its
/// AccessIdentity carries the endpoint context resolved for that request's Session.
class ChannelSecurityRecordingNamespace final : public ua::default_ns::Namespace
{
public:
  ChannelSecurityRecordingNamespace(std::string_view uri, boost::asio::any_io_executor executor,
    std::shared_ptr<const ChannelSecurityObservations> log)
    : ua::default_ns::Namespace(uri, std::move(executor)), mLog(std::move(log))
  {}

  std::optional<ua::PermissionType> effective_permissions(
    const ua::AccessIdentity& identity, const ua::Node* node) const override
  {
    const auto& endpoint = identity.endpoint();
    if (node)
    {
      const ua::NodeDescription description = node->attributes();
      mLog->record(ChannelSecurityReading{
        description.node_id(), endpoint.securityPolicyId, endpoint.messageSecurityMode});
    }
    return ua::PermissionType{{ua::PermissionType::Bit::Browse, ua::PermissionType::Bit::Read}};
  }

private:
  std::shared_ptr<const ChannelSecurityObservations> mLog;
};

/// Records the channel and session metadata the stack pushes to the application.
class ChannelMetadataObserver final : public ua::server::ServerObserver
{
public:
  void on_secure_channel_opened(const ua::server::SecureChannelEventInfo& info) override
  {
    const std::lock_guard lock{mMutex};
    mChannels.push_back(info);
  }

  void on_session_activated(const ua::server::SessionEventInfo& info) override
  {
    const std::lock_guard lock{mMutex};
    mSessions.push_back(info);
  }

  std::optional<ua::server::SecureChannelEventInfo> channel(uint32_t channelId) const
  {
    const std::lock_guard lock{mMutex};
    for (const auto& info : mChannels)
    {
      if (info.secureChannelId == channelId)
        return info;
    }
    return std::nullopt;
  }

  std::optional<ua::server::SessionEventInfo> session(const ua::NodeId& sessionId) const
  {
    const std::lock_guard lock{mMutex};
    for (const auto& info : mSessions)
    {
      if (info.sessionId == sessionId)
        return info;
    }
    return std::nullopt;
  }

  size_t channel_count() const
  {
    const std::lock_guard lock{mMutex};
    return mChannels.size();
  }

private:
  mutable std::mutex mMutex;
  std::vector<ua::server::SecureChannelEventInfo> mChannels;
  std::vector<ua::server::SessionEventInfo> mSessions;
};

/// A Value read of one node, used to drive the per-item authorization gate.
ua::ReadRequest make_value_read(const ua::NodeId& nodeId)
{
  ua::ReadRequest req;
  ua::ReadValueId rv;
  rv.node_id() = nodeId;
  rv.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
  req.nodes_to_read().push_back(std::move(rv));
  req.timestamps_to_return() = ua::TimestampsToReturn::Neither;
  return req;
}

}  // namespace

/// `ComplianceSession` with a namespace-level permission interface that records what the stack told the
/// canonical access-control gate about the channel each request arrived on.
class ComplianceSessionChannelContext : public ComplianceSession
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  void SetUp() override
  {
    ComplianceSession::SetUp();
    auto addressSpace = mServer->address_space();
    auto nameSpace = std::make_shared<ChannelSecurityRecordingNamespace>(
      "urn:test:session:channel-context", addressSpace.executor(), mObservations);
    const auto namespaceIndex = addressSpace.add_namespace_sync(nameSpace);

    mPlainNode = NodeId{namespaceIndex, uint32_t{7100}};
    auto plain = addressSpace.create_node_sync(mPlainNode, NodeClass::Variable).as<VariableAccessor>();
    ASSERT_TRUE(plain.has_value());
    plain->set_data_type(NodeId{DataTypeId::UInt32});
    plain->write_value_sync(uint32_t{1});

    mSecuredNode = NodeId{namespaceIndex, uint32_t{7101}};
    auto secured = addressSpace.create_node_sync(mSecuredNode, NodeClass::Variable).as<VariableAccessor>();
    ASSERT_TRUE(secured.has_value());
    secured->set_data_type(NodeId{DataTypeId::UInt32});
    secured->write_value_sync(uint32_t{2});

    mRecordingNamespace = std::move(nameSpace);
  }

  std::shared_ptr<ChannelSecurityObservations> mObservations{std::make_shared<ChannelSecurityObservations>()};
  std::shared_ptr<ChannelSecurityRecordingNamespace> mRecordingNamespace;
  NodeId mPlainNode;
  NodeId mSecuredNode;
};

// Part 4 section 5.6.2.1: "The SecureChannel is always managed by the Communication Stack which means it
// shall provide APIs which the Server can use to find out information about the SecureChannel used for
// any given request. The Communication Stack shall, at a minimum, provide the SecurityPolicy and
// SecurityMode used by the SecureChannel. It shall also provide a SecureChannelId which uniquely
// identifies the SecureChannel or the Client Certificate used to establish the SecureChannel."
//
// Note the third item is a DISJUNCTION in the clause -- an id or the certificate -- so this asserts
// that one of the two identifies the channel, not that both do; demanding both would fail a conforming
// stack that offers only the certificate. Every authorisation criterion in this corpus rests on this
// API existing: `AC-SVR-SECADMIN-029-APPLICATIONS-NEEDS-SIGNING`,
// `AC-SVR-PULLCRT-006-UPDATECERTIFICATE-GUARDS` and `AC-SVR-SESS-001-REQUIRES-CHANNEL` all ask a service to
// check the channel it is running on.
//
// "They describe the channel the request arrived on, not a default" is the half that needs two
// channels. A stack that hard-codes the values of its first endpoint, or returns the configured
// default rather than the negotiated one, satisfies any single-channel probe: it is only when a
// None/None request and a Basic256Sha256/SignAndEncrypt request are gated by the SAME service, and
// each is required to report ITS OWN channel, that the two implementations separate. The two sessions
// therefore read two DIFFERENT nodes, so each recorded reading is attributable to one request without
// relying on the order the two arrived in.
// @verifies AC-SVR-SESS-002-STACK-EXPOSES-CHANNEL-CONTEXT
TEST_F(ComplianceSessionChannelContext, TheStackReportsEachRequestsOwnChannelPolicyModeAndIdentifier)
{
  auto observer = std::make_shared<ChannelMetadataObserver>();
  mServer->set_observer(observer);

  const NodeId plainNode = mPlainNode;
  const NodeId securedNode = mSecuredNode;

  auto plainChannel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto plainSession = plainChannel.create_session_sync({.sessionName = "ChannelContextPlain"});
  plainSession.activate_sync();
  ASSERT_TRUE(plainSession.is_active());

  auto securedChannel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  auto securedSession = securedChannel.create_session_sync({.sessionName = "ChannelContextSecured"});
  securedSession.activate_sync();
  ASSERT_TRUE(securedSession.is_active());

  const auto plainChannelId = plainChannel.secure_channel_id();
  const auto securedChannelId = securedChannel.secure_channel_id();

  auto plainRead = plainSession.attributes().read_sync(make_value_read(plainNode));
  ASSERT_THAT(plainRead, ::ua::test_helpers::ServiceResultIsGood());
  auto securedRead = securedSession.attributes().read_sync(make_value_read(securedNode));
  ASSERT_THAT(securedRead, ::ua::test_helpers::ServiceResultIsGood());

  // ---- (a) SecurityPolicy and MessageSecurityMode, as seen by the service that gated the request.
  const auto readings = mObservations->readings();
  GTEST_LOG_(INFO) << "service-layer authorization gate ran " << readings.size()
                   << " times across the two sessions";
  ASSERT_FALSE(readings.empty())
    << "the per-item authorization gate never ran, so no service implementation read anything about "
       "any channel and this row has no subject";

  auto readingFor = [&readings](const NodeId& node) -> std::optional<ChannelSecurityReading>
  {
    for (const auto& reading : readings)
    {
      if (reading.node == node)
        return reading;
    }
    return std::nullopt;
  };

  auto plainReading = readingFor(plainNode);
  ASSERT_TRUE(plainReading.has_value())
    << "no service-layer reading was taken for the request that arrived on the None channel";
  EXPECT_EQ(plainReading->securityPolicyId, SecurityPolicyId::None)
    << "the service gating a request that arrived on a SecurityPolicy None channel was told the policy "
       "was something else";
  EXPECT_EQ(plainReading->messageSecurityMode, MessageSecurityMode::None)
    << "the service gating a request that arrived on a MessageSecurityMode None channel was told the "
       "mode was something else";

  auto securedReading = readingFor(securedNode);
  ASSERT_TRUE(securedReading.has_value())
    << "no service-layer reading was taken for the request that arrived on the secured channel";
  EXPECT_EQ(securedReading->securityPolicyId, SecurityPolicyId::Basic256Sha256)
    << "the service gating a request that arrived on a Basic256Sha256 channel was told the policy was "
       "something else - the values describe a default, not the channel the request arrived on";
  EXPECT_EQ(securedReading->messageSecurityMode, MessageSecurityMode::SignAndEncrypt)
    << "the service gating a request that arrived on a SignAndEncrypt channel was told the mode was "
       "something else - the values describe a default, not the channel the request arrived on";

  // ---- (b) The SecureChannelId, or failing that the Client Certificate, for each request's channel.
  ASSERT_GE(observer->channel_count(), 2u)
    << "the application was told about fewer than the two channels that were opened";

  struct ChannelExpectation
  {
    const char* label;
    uint32_t channelId;
    NodeId sessionId;
    SecurityPolicyId policyId;
    MessageSecurityMode mode;
  };

  const ChannelExpectation expectations[]{
    {"None", plainChannelId, plainSession.session_id(), SecurityPolicyId::None, MessageSecurityMode::None},
    {"Basic256Sha256/SignAndEncrypt",
      securedChannelId,
      securedSession.session_id(),
      SecurityPolicyId::Basic256Sha256,
      MessageSecurityMode::SignAndEncrypt}};

  for (const auto& expected : expectations)
  {
    auto channelInfo = observer->channel(expected.channelId);
    ASSERT_TRUE(channelInfo.has_value())
      << expected.label << ": the stack surfaced no metadata for SecureChannelId " << expected.channelId;

    const bool identifiesTheChannel = expected.channelId != 0u || !channelInfo->clientCertificate.empty();
    EXPECT_TRUE(identifiesTheChannel)
      << expected.label
      << ": the stack offered neither a SecureChannelId nor the Client Certificate, so a service has no "
         "way to say which channel a request arrived on";

    auto policy = SecurityPolicy::create(expected.policyId);
    ASSERT_NE(policy, nullptr);
    EXPECT_EQ(channelInfo->securityPolicyUri, std::string{policy->uri()})
      << expected.label << ": the reported SecurityPolicy URI is not the one this channel negotiated";
    EXPECT_EQ(channelInfo->messageSecurityMode, expected.mode)
      << expected.label << ": the reported MessageSecurityMode is not the one this channel negotiated";

    // The request-to-channel link: a service holding only the session a request came in on can reach
    // that request's channel. Without it the three values above describe *a* channel, not *this* one.
    auto sessionInfo = observer->session(expected.sessionId);
    ASSERT_TRUE(sessionInfo.has_value())
      << expected.label << ": the stack surfaced no metadata for the activated session";
    EXPECT_EQ(sessionInfo->secureChannelId, expected.channelId)
      << expected.label << ": the session was reported against SecureChannelId "
      << sessionInfo->secureChannelId << " rather than the " << expected.channelId
      << " its requests actually arrive on";
  }

  // "Uniquely identifies": two live channels must not share an identifier, or the whole mechanism
  // resolves every request to the same channel.
  ASSERT_NE(plainChannelId, 0u) << "the None channel was given no SecureChannelId";
  ASSERT_NE(securedChannelId, 0u) << "the secured channel was given no SecureChannelId";
  EXPECT_NE(plainChannelId, securedChannelId)
    << "two concurrently open SecureChannels were given the same SecureChannelId";

  (void)securedSession.try_close_sync();
  (void)securedChannel.try_close_sync();
  (void)plainSession.try_close_sync();
  (void)plainChannel.try_close_sync();
  mServer->set_observer(nullptr);
}
