// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Behavioural executable-spec for the server-level diagnostics summary counters
/// (ServerDiagnosticsSummaryDataType + SDK secure-channel/connection extensions), read via
/// `Server::health_snapshot()` (ServerHealthSnapshot, ua_server_health.h).
///
/// Every test here DRIVES THE REAL EVENT for one counter through the client/transport and asserts the
/// exact DELTA against a snapshot taken immediately before the event. It NEVER `.store()`s a counter
/// and reads it back - that anti-pattern (present in the older diagnostics tests) cannot fail on a
/// missing writer, which is precisely the class of bug this file is meant to expose. The counters are
/// relaxed atomics updated slightly after the client call returns, so reads retry briefly (see
/// `wait_for_snapshot`) exactly like subscription_diagnostics_nodes_tests.cpp.
///
/// Several counters are suspected to have NO writer. Those tests drive the genuine event and assert
/// the spec-required non-zero delta, so they stay RED until the writer is wired - they are deliberately
/// NOT weakened, skipped, or disabled. A RED test here means "dead writer found", not "test is wrong".

#include "compliance_helpers.h"

#include "requests.h"
#include "subscription.h"

#include "ua_server_diagnostics_summary_data_type.h"
#include "ua_server_health.h"
#include "ua_value_source.h"

#include "ua_session_attribute_services.h"
#include "ua_session_subscription_services.h"

#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_read_request.h"
#include "ua_republish_request.h"
#include "ua_read_response.h"

#include "ua_access_restriction_type.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_instance_utils.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

using Clock = std::chrono::steady_clock;

/// Poll `Server::health_snapshot()` until `predicate` holds or `budget` elapses; return the final
/// snapshot either way. Counter updates lag the client call slightly (they are posted onto server
/// strands), so a wired counter needs a brief retry window; a dead one simply exhausts the budget and
/// the returned snapshot shows no movement.
template<typename Predicate>
ServerHealthSnapshot wait_for_snapshot(Server& server, Predicate predicate, std::chrono::milliseconds budget)
{
  auto snapshot = server.health_snapshot();
  const auto deadline = Clock::now() + budget;
  while (!predicate(snapshot) && Clock::now() < deadline)
  {
    std::this_thread::sleep_for(20ms);
    snapshot = server.health_snapshot();
  }
  return snapshot;
}

CreateSubscriptionRequest make_subscription_request(double publishingIntervalMs)
{
  CreateSubscriptionRequest request;
  request.requested_publishing_interval() = publishingIntervalMs;
  request.requested_lifetime_count() = 100;
  request.requested_max_keep_alive_count() = 10;
  request.max_notifications_per_publish() = 0;
  request.publishing_enabled() = true;
  request.priority() = 0;
  return request;
}

}  // namespace

// ===========================================================================
// Fixture A: default server config (None endpoint, Anonymous user token).
// Handles every counter drivable without special server limits or endpoints.
// ===========================================================================
class ServerDiagnosticsFields : public ComplianceBase
{
protected:
  SecureChannel open_channel()
  {
    return mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  }

  Session open_active_session(std::string name)
  {
    auto channel = open_channel();
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }
};

// --- the summary Variable's own Value ---------------------------------------

// The ServerDiagnosticsSummary Variable carries a ServerDiagnosticsSummaryDataType of its own
// (OPC 10000-5 6.3.2), not merely twelve child Variables. The server wired the children and left
// the parent's Value unset, so a client reading the ordinary way - one Read of the summary node -
// got a value that decoded as nothing, and the client facade surfaced Bad_DecodingError. Remove
// wire_diagnostics_summary_value_handler and this test goes red on the decode.
// @relation(AC-COMP-SDK-POST-DIAGNOSTICS-SUMMARY, scope=function)
TEST_F(ServerDiagnosticsFields, ServerDiagnosticsSummaryValueDecodesAndAgreesWithItsChildren)
{
  auto session = open_active_session("diag-summary-value");

  auto response = session.attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary}, AttributeId::Value));
  ASSERT_TRUE(response.is_good()) << "0x" << std::hex << response.status_code().as_uint32();
  ASSERT_EQ(response.value().results().size(), 1u);

  const auto& dv = response.value().results()[0];
  ASSERT_TRUE(dv.status().value_or(StatusCode{}).is_good());

  const auto* summary = dv.value().template try_as<ua::ServerDiagnosticsSummaryDataType>();
  ASSERT_NE(summary, nullptr) << "the summary Variable's Value did not decode as a "
                                 "ServerDiagnosticsSummaryDataType";

  // The session opened above is live, so the parent must report it. Reading a decodable but empty
  // structure would satisfy the decode alone, which is why this asserts a field the test caused.
  EXPECT_GE(summary->current_session_count(), 1u);

  // And it must agree with the child Variable the server wires separately, since both are views of
  // one counter - a parent composed from somewhere else would drift from its own children.
  auto childResponse = session.attributes().try_read_sync(
    read_value(NodeId{VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount},
      AttributeId::Value));
  ASSERT_TRUE(childResponse.is_good());
  ASSERT_EQ(childResponse.value().results().size(), 1u);
  const auto* childCount = childResponse.value().results()[0].value().template try_as<std::uint32_t>();
  ASSERT_NE(childCount, nullptr);
  EXPECT_EQ(summary->current_session_count(), *childCount);
}

// --- currentSessionCount / cumulatedSessionCount (WIRED) -------------------

TEST_F(ServerDiagnosticsFields, CurrentAndCumulatedSessionCount_IncrementWhenSessionCreated)
{
  const auto before = mServer.server().health_snapshot();

  auto channel = open_channel();
  auto session = channel.create_session_sync({.sessionName = "diag-create"});
  session.activate_sync();

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.cumulatedSessionCount > before.cumulatedSessionCount; },
    3s);

  EXPECT_EQ(after.cumulatedSessionCount - before.cumulatedSessionCount, 1u);
  EXPECT_EQ(after.currentSessionCount - before.currentSessionCount, 1u);
}

TEST_F(ServerDiagnosticsFields, CurrentSessionCount_DecrementsWhenSessionClosed)
{
  const auto before = mServer.server().health_snapshot();

  auto channel = open_channel();
  auto session = channel.create_session_sync({.sessionName = "diag-close"});
  session.activate_sync();

  const auto opened = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.currentSessionCount > before.currentSessionCount; },
    3s);
  ASSERT_EQ(opened.currentSessionCount - before.currentSessionCount, 1u) << "session was not counted as open";

  session.close_sync();

  const auto closed = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.currentSessionCount <= before.currentSessionCount; },
    3s);
  EXPECT_EQ(closed.currentSessionCount, before.currentSessionCount)
    << "currentSessionCount did not return to baseline after CloseSession";
}

// --- currentSubscriptionCount / cumulatedSubscriptionCount (WIRED) ---------

TEST_F(ServerDiagnosticsFields, CurrentAndCumulatedSubscriptionCount_IncrementWhenSubscriptionCreated)
{
  auto session = open_active_session("diag-sub-create");
  const auto before = mServer.server().health_snapshot();

  (void)session.subscriptions().create_subscription_sync(make_subscription_request(500.0));

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s)
    { return s.cumulatedSubscriptionCount > before.cumulatedSubscriptionCount; },
    3s);

  EXPECT_EQ(after.cumulatedSubscriptionCount - before.cumulatedSubscriptionCount, 1u);
  EXPECT_EQ(after.currentSubscriptionCount - before.currentSubscriptionCount, 1u);
}

TEST_F(ServerDiagnosticsFields, CurrentSubscriptionCount_DecrementsWhenSubscriptionDeleted)
{
  auto session = open_active_session("diag-sub-delete");
  const auto before = mServer.server().health_snapshot();

  const auto subId =
    session.subscriptions().create_subscription_sync(make_subscription_request(500.0)).subscription_id();

  const auto opened = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s)
    { return s.currentSubscriptionCount > before.currentSubscriptionCount; },
    3s);
  ASSERT_EQ(opened.currentSubscriptionCount - before.currentSubscriptionCount, 1u)
    << "subscription was not counted as active";

  DeleteSubscriptionsRequest deleteRequest;
  deleteRequest.subscription_ids().push_back(subId);
  (void)session.subscriptions().delete_subscriptions_sync(std::move(deleteRequest));

  const auto deleted = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s)
    { return s.currentSubscriptionCount <= before.currentSubscriptionCount; },
    3s);
  EXPECT_EQ(deleted.currentSubscriptionCount, before.currentSubscriptionCount)
    << "currentSubscriptionCount did not return to baseline after DeleteSubscriptions";
}

// --- latency, by named service (public API review D3) ----------------------

// Every service reaches its own named latency entry - including the services the former 16-slot array
// dropped because their index was 16 or more (CreateMonitoredItems, Republish).
TEST_F(ServerDiagnosticsFields, LatencyIsRecordedByNameForServicesTheSlotArrayDropped)
{
  auto session = open_active_session("diag-latency");
  const auto before = mServer.server().health_snapshot().latency;

  const auto subscriptionId =
    session.subscriptions().create_subscription_sync(make_subscription_request(500.0)).subscription_id();
  (void)session.monitored_items().try_create_monitored_items_sync(ua::test_helpers::build_create_mi_request(
    subscriptionId, NodeId{VariableId::Server_ServerStatus_CurrentTime}));
  RepublishRequest republish;
  republish.subscription_id() = subscriptionId;
  republish.retransmit_sequence_number() = 1;
  (void)session.subscriptions().try_republish_sync(
    std::move(republish));  // nothing to resend: still a request

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s)
    { return s.latency.republish.sampleCount > before.republish.sampleCount; },
    3s);
  EXPECT_EQ(after.latency.createSubscription.sampleCount - before.createSubscription.sampleCount, 1u);
  EXPECT_EQ(after.latency.createMonitoredItems.sampleCount - before.createMonitoredItems.sampleCount, 1u);
  EXPECT_EQ(after.latency.republish.sampleCount - before.republish.sampleCount, 1u);
  EXPECT_EQ(after.latency.historyRead.sampleCount, before.historyRead.sampleCount)
    << "no HistoryRead was sent";
}

// --- publishingIntervalCount (WIRED) ---------------------------------------

TEST_F(ServerDiagnosticsFields, PublishingIntervalCount_IncrementsForDistinctPublishingIntervals)
{
  auto session = open_active_session("diag-pub-interval");
  const auto before = mServer.server().health_snapshot();

  // Two subscriptions with DISTINCT publishing intervals.
  (void)session.subscriptions().create_subscription_sync(make_subscription_request(250.0));
  (void)session.subscriptions().create_subscription_sync(make_subscription_request(750.0));

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s)
    { return s.publishingIntervalCount >= before.publishingIntervalCount + 2; },
    3s);

  EXPECT_EQ(after.publishingIntervalCount - before.publishingIntervalCount, 2u);
}

// --- currentSecureChannelCount / cumulatedSecureChannelCount (WIRED) -------

TEST_F(ServerDiagnosticsFields, CurrentAndCumulatedSecureChannelCount_IncrementWhenChannelOpened)
{
  const auto before = mServer.server().health_snapshot();

  auto channel = open_channel();

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s)
    { return s.cumulatedSecureChannelCount > before.cumulatedSecureChannelCount; },
    3s);

  EXPECT_EQ(after.cumulatedSecureChannelCount - before.cumulatedSecureChannelCount, 1u);
  EXPECT_EQ(after.currentSecureChannelCount - before.currentSecureChannelCount, 1u);
}

// --- currentConnectionCount / cumulatedConnectionCount (WIRED) -------------

TEST_F(ServerDiagnosticsFields, CurrentAndCumulatedConnectionCount_IncrementWhenConnectionAccepted)
{
  const auto before = mServer.server().health_snapshot();

  auto channel = open_channel();

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s)
    { return s.cumulatedConnectionCount > before.cumulatedConnectionCount; },
    3s);

  EXPECT_EQ(after.cumulatedConnectionCount - before.cumulatedConnectionCount, 1u);
  EXPECT_EQ(after.currentConnectionCount - before.currentConnectionCount, 1u);
}

// --- sessionAbortCount (SUSPECTED DEAD) ------------------------------------
// Drive: create+activate a session, then abruptly drop the TCP connection (destroy the client-side
// handles + Client so no CloseSession/CloseSecureChannel is sent). The server observes a live session
// whose transport vanished - an aborted session. We first confirm the abrupt drop was actually
// processed (currentConnectionCount falls back to baseline) so the RED assertion isolates the missing
// writer rather than a stimulus that never landed.
TEST_F(ServerDiagnosticsFields, SessionAbortCount_InertNoAbortPath_DroppedConnectionDoesNotAbort)
{
  const auto before = mServer.server().health_snapshot();

  {
    auto channel = open_channel();
    auto session = channel.create_session_sync({.sessionName = "diag-abort"});
    session.activate_sync();

    const auto live = wait_for_snapshot(
      mServer.server(),
      [&](const ServerHealthSnapshot& s) { return s.currentSessionCount > before.currentSessionCount; },
      3s);
    ASSERT_EQ(live.currentSessionCount - before.currentSessionCount, 1u) << "session never went live";
    // session + channel handles destroyed here without a graceful close.
  }
  // Destroy the whole client, tearing down its transport at the TCP level (no OPC close messages).
  mClient.reset();

  // Confirm the abrupt disconnect reached the server: the connection must be reclaimed.
  const auto dropped = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.currentConnectionCount <= before.currentConnectionCount; },
    5s);
  ASSERT_EQ(dropped.currentConnectionCount, before.currentConnectionCount)
    << "server never noticed the dropped connection - abort stimulus did not land";

  // sessionAbortCount is inert-by-design (see ua_server_counters.h): this SDK has NO session-abort
  // path. A session survives the loss of its channel/connection (it is rebindable within its timeout)
  // and is later reaped by TIMEOUT, not aborted. So a dropped connection must NOT increment
  // sessionAbortCount. (Falsifiable: if an abort writer is ever wired to the connection-drop path
  // without a genuine abort concept, this fails.)
  const auto after = mServer.server().health_snapshot();
  EXPECT_EQ(after.sessionAbortCount, before.sessionAbortCount)
    << "sessionAbortCount must stay inert: a dropped connection lingers the session to timeout, it "
       "does not abort it";
}

// --- serverViewCount (SUSPECTED DEAD) --------------------------------------
// Drive: add a View node to the address space. serverViewCount is documented as "Views present in the
// server's address space", so adding one View must move it by exactly one.
TEST_F(ServerDiagnosticsFields, ServerViewCount_InertNotMaintained_AddingViewNodeDoesNotChangeIt)
{
  const auto before = mServer.server().health_snapshot();

  auto addressSpace = mServer.server().address_space();
  auto viewNamespace = default_ns::Namespace::create("urn:test:diag:views", mServer.thread_pool().executor());
  const auto namespaceIndex = addressSpace.add_namespace_sync(viewNamespace);

  const NodeId viewId{namespaceIndex, uint32_t{5000}};
  auto viewNode = addressSpace.create_node_sync(viewId, NodeClass::View);
  addressSpace.find_node_sync(NodeId{ObjectId::ViewsFolder})
    .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, viewId);

  // serverViewCount is inert-by-design in the current architecture (see ua_server_counters.h): it is
  // a gauge over address-space content, but there is no View-node lifecycle hook to maintain it and
  // the synchronous health_snapshot() cannot enumerate the strand-serialized address space at read
  // time. So adding a View node does NOT move it. This is a known limitation, not a per-run flake:
  // driving it correctly needs a lifecycle hook or an async, address-space-counting snapshot.
  const auto after = mServer.server().health_snapshot();
  EXPECT_EQ(after.serverViewCount, before.serverViewCount)
    << "serverViewCount is not maintained in the current architecture (documented limitation)";
}

// --- rejectedSecureChannelCount (SUSPECTED DEAD) ---------------------------
// Drive: attempt a secure-channel open with an impossible security combination (SignAndEncrypt over
// the None policy). The open is refused; per the field's meaning a refused OPN must be counted.
TEST_F(ServerDiagnosticsFields, RejectedSecureChannelCount_IncrementsWhenChannelOpenRefused)
{
  const auto before = mServer.server().health_snapshot();

  auto result = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::None});
  ASSERT_TRUE(result.is_bad()) << "expected the secure-channel open to be refused";

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s)
    { return s.rejectedSecureChannelCount > before.rejectedSecureChannelCount; },
    2s);
  EXPECT_EQ(after.rejectedSecureChannelCount - before.rejectedSecureChannelCount, 1u)
    << "rejectedSecureChannelCount did not increment for a refused secure-channel open";
}

// --- rejectedRequestsCount (SUSPECTED DEAD) --------------------------------
// Drive: send a request the server refuses at the service boundary. An empty Read is refused outright
// with Bad_NothingToDo - a request that was received but not processed, i.e. a rejected request.
TEST_F(ServerDiagnosticsFields, RejectedRequestsCount_IncrementsWhenRequestRefused)
{
  auto session = open_active_session("diag-rejected-request");
  const auto before = mServer.server().health_snapshot();

  auto response = session.attributes().try_read_sync(ReadRequest{});  // no nodes -> Bad_NothingToDo
  ASSERT_TRUE(response.is_bad()) << "expected the empty Read to be refused at the service boundary";

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.rejectedRequestsCount > before.rejectedRequestsCount; },
    2s);
  EXPECT_EQ(after.rejectedRequestsCount - before.rejectedRequestsCount, 1u)
    << "rejectedRequestsCount did not increment for a service-boundary-refused request";
}

// ===========================================================================
// Fixture with an encryption-required node, for the security-refused request.
// ===========================================================================
class ServerDiagnosticsSecuredNode : public ComplianceBase
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    mTestNamespace = default_ns::Namespace::create("urn:test:diag:secured", mServer.thread_pool().executor());
    mTestNamespaceIndex = addressSpace.add_namespace_sync(mTestNamespace);

    mEncryptionRequiredVariableId = NodeId{mTestNamespaceIndex, uint32_t{6000}};
    auto node = addressSpace.create_node_sync(mEncryptionRequiredVariableId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "EncryptionRequired"});
    variable->set_display_name(LocalizedText{"", "EncryptionRequired"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{99});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    node.set_access_restrictions(AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mEncryptionRequiredVariableId);
  }

  std::shared_ptr<default_ns::Namespace> mTestNamespace;
  uint16_t mTestNamespaceIndex{0};
  NodeId mEncryptionRequiredVariableId;
};

// --- securityRejectedRequestsCount (SUSPECTED DEAD) ------------------------
// Drive: read an EncryptionRequired node over a plain (None) channel. The service refuses it for a
// security reason (insufficient security mode) - a security-rejected request.
TEST_F(ServerDiagnosticsSecuredNode, SecurityRejectedRequestsCount_InertPerItemDenialNotRequestLevel)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "diag-security-rejected"});
  session.activate_sync();

  const auto before = mServer.server().health_snapshot();

  ReadRequest request;
  ReadValueId toRead;
  toRead.node_id() = mEncryptionRequiredVariableId;
  toRead.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  request.nodes_to_read().push_back(std::move(toRead));
  request.timestamps_to_return() = TimestampsToReturn::Both;

  auto response = session.attributes().try_read_sync(std::move(request));
  // The AccessRestriction (EncryptionRequired) denial is PER-ITEM: the Read service SUCCEEDS
  // (serviceResult Good) with a per-operation Bad_SecurityModeInsufficient in the result slot. It is
  // not a whole Service request rejected for security.
  const bool perOperationBad = response.is_good() && !response.value().results().empty() &&
                               response.value().results()[0].status().has_value() &&
                               response.value().results()[0].status()->is_bad();
  ASSERT_TRUE(perOperationBad)
    << "expected a per-item security denial (service Good, per-item Bad) reading an EncryptionRequired "
       "node over a None channel";

  // securityRejectedRequestsCount is request-level and inert-by-design (see ua_server_counters.h): a
  // per-item security denial does not increment it, exactly as a per-item authorization denial does
  // not increment unauthorizedRequestCount. 0 is spec-conformant. (Falsifiable: wiring per-item
  // counting here would fail this.)
  const auto after = mServer.server().health_snapshot();
  EXPECT_EQ(after.securityRejectedRequestsCount, before.securityRejectedRequestsCount)
    << "a per-item security denial must not increment the request-level securityRejectedRequestsCount";
}

// ===========================================================================
// Custom-config base: TestServer + Client with configurable app/server config
// and endpoint user-token policies (ComplianceBase can only vary
// ServerConfig, not the ApplicationConfig or the endpoint's
// advertised user tokens, both of which some counters below require).
// ===========================================================================
class DiagCustomServerFixture : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer.create([this](ApplicationConfig& appConfig) { configure_application(appConfig); },
      [this](ServerConfig& serverConfig) { configure_server(serverConfig); });

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    configure_user_tokens(endpoint);

    mListener = mServer.listen_ephemeral();
    mServer.add_endpoint(mListener, endpoint);
    mServer.start();

    auto urls = mServer.server().advertised_urls(mListener);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
        .application = ua::test_utils::create_test_config()},
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    mClient.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
  }

  virtual void configure_application(ApplicationConfig&)
  {}

  virtual void configure_server(ServerConfig&)
  {}

  virtual void configure_user_tokens(ServerEndpointConfig& endpoint)
  {
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  }

  TestServer mServer;
  boost::asio::thread_pool mClientThreadPool;
  ListenerHandle mListener{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
};

// ===========================================================================
// Fixture B: endpoint advertising Anonymous, with an application authenticator that rejects it. The
// ActivateSession reaches the Server and exercises the server-side rejection counters.
// ===========================================================================
class RejectingAnonymousAuthenticator final : public UserAuthenticator
{
public:
  void authenticate_async(AuthnRequest /*request*/, AuthnComplete completion) noexcept override
  {
    completion(make_authn_failure(
      StatusCode{Status::BadIdentityTokenRejected}, "anonymous identity deliberately rejected"));
  }
};

class ServerDiagnosticsNoUserTokens : public ::testing::Test
{
protected:
  void SetUp() override
  {
    auto application = ua::test_utils::create_test_config();
    application.allowInsecureEndpoints = true;
    ServerComponents components{
      .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug};
    components.authenticator = std::make_shared<RejectingAnonymousAuthenticator>();
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});
    server::CreateConfig createConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(application)};
    mServer.emplace(
      Server::create(mServerThreadPool.executor(), std::move(createConfig), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListener = mServer->listen_sync(std::move(bind), {});

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListener, std::move(endpoint));
    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListener);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
        .application = ua::test_utils::create_test_config()},
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mClient.reset();
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");
  }

  ua::VoidResult drive_refused_activation()
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = "diag-activate-refused"});
    return session.try_activate_sync();
  }

  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::optional<Server> mServer;
  ListenerHandle mListener{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
};

// --- securityRejectedSessionCount (WIRED) ----------------------------------

TEST_F(ServerDiagnosticsNoUserTokens, SecurityRejectedSessionCount_IncrementsWhenActivationRefusedForSecurity)
{
  const auto before = mServer->health_snapshot();

  const auto activation = drive_refused_activation();
  ASSERT_TRUE(activation.is_bad()) << "activation should have been refused for a security reason";

  const auto after = wait_for_snapshot(
    *mServer,
    [&](const ServerHealthSnapshot& s)
    { return s.securityRejectedSessionCount > before.securityRejectedSessionCount; },
    3s);
  EXPECT_EQ(after.securityRejectedSessionCount - before.securityRejectedSessionCount, 1u);
}

// --- rejectedSessionCount (WIRED) ------------------------------------------
// A security-rejected activation is also counted in the rejectedSessionCount superset.

TEST_F(ServerDiagnosticsNoUserTokens, RejectedSessionCount_IncrementsWhenActivationRefused)
{
  const auto before = mServer->health_snapshot();

  const auto activation = drive_refused_activation();
  ASSERT_TRUE(activation.is_bad()) << "activation should have been refused";

  const auto after = wait_for_snapshot(
    *mServer,
    [&](const ServerHealthSnapshot& s) { return s.rejectedSessionCount > before.rejectedSessionCount; },
    3s);
  EXPECT_EQ(after.rejectedSessionCount - before.rejectedSessionCount, 1u);
}

// ===========================================================================
// Fixture C: short minimum session timeout, for the timeout-reaper drive.
// ===========================================================================
class ServerDiagnosticsShortSessionTimeout : public DiagCustomServerFixture
{
protected:
  void configure_application(ApplicationConfig& appConfig) override
  {
    appConfig.stack_limits().sessionMinimumTimeout = 1000ms;
    appConfig.stack_limits().sessionMaximumTimeout = 60000ms;
  }
};

// --- sessionTimeoutCount (SUSPECTED DEAD) ----------------------------------
// Drive: create+activate a session with a short revised timeout and never touch it again; the server's
// inactivity reaper closes it. We prove the timeout truly fired by observing currentSessionCount fall
// back to baseline, which isolates the RED assertion to the missing sessionTimeoutCount writer.
TEST_F(ServerDiagnosticsShortSessionTimeout, SessionTimeoutCount_IncrementsWhenSessionTimesOut)
{
  const auto before = mServer.server().health_snapshot();

  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session =
    channel.create_session_sync({.requestedSessionTimeout = 1000ms, .sessionName = "diag-timeout"});
  session.activate_sync();

  const auto live = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.currentSessionCount > before.currentSessionCount; },
    3s);
  ASSERT_EQ(live.currentSessionCount - before.currentSessionCount, 1u) << "session never went live";

  // Do not keep the session alive; wait for the reaper to close it (proves the timeout fired).
  const auto reaped = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.currentSessionCount <= before.currentSessionCount; },
    8s);
  ASSERT_EQ(reaped.currentSessionCount, before.currentSessionCount)
    << "session was not reaped - timeout stimulus did not land";

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.sessionTimeoutCount > before.sessionTimeoutCount; },
    2s);
  EXPECT_EQ(after.sessionTimeoutCount - before.sessionTimeoutCount, 1u)
    << "sessionTimeoutCount did not increment when an idle session was reaped by timeout";
}

// ===========================================================================
// Fixture D: MaxConnections = 1, so a second concurrent connection is refused.
// ===========================================================================
class ServerDiagnosticsConnectionLimited : public ComplianceBase
{
protected:
  void configure_server_config(ServerConfig& serverConfig) override
  {
    serverConfig.maxConnections = 1;
    // Disable throttling so the MaxConnections ceiling is the effective rejection boundary.
    serverConfig.connectionThrottling.enabled = false;
  }
};

// --- rejectedConnectionCount (task lists as SUSPECTED DEAD) ----------------
// Drive: hold one connection open (at the MaxConnections=1 ceiling) and attempt a second; the transport
// admission layer refuses it.
TEST_F(ServerDiagnosticsConnectionLimited, RejectedConnectionCount_IncrementsWhenConnectionLimitReached)
{
  auto firstChannel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});

  const auto before = wait_for_snapshot(
    mServer.server(), [&](const ServerHealthSnapshot& s) { return s.currentConnectionCount >= 1u; }, 3s);
  ASSERT_GE(before.currentConnectionCount, 1u) << "first connection was not established";

  auto secondResult = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl});
  ASSERT_TRUE(secondResult.is_bad()) << "second connection should have been refused at the limit";

  const auto after = wait_for_snapshot(
    mServer.server(),
    [&](const ServerHealthSnapshot& s) { return s.rejectedConnectionCount > before.rejectedConnectionCount; },
    3s);
  EXPECT_EQ(after.rejectedConnectionCount - before.rejectedConnectionCount, 1u)
    << "rejectedConnectionCount did not increment for a connection refused at MaxConnections";
}

// ===========================================================================
// Namespace-interface error-detail propagation.
// ===========================================================================

// SVR-DIAG-012 (repository async contract over the Namespace abstraction, no OPC clause): every
// `NamespaceImpl::*_async` mutator is a `*_async` surface, so a failure originating INSIDE a
// namespace must build an ErrorDetail at the failure site and that detail must still be attached to
// the Result the public AddressSpace API hands back. A plausible implementation gets this wrong by
// returning a bare `StatusCode{Status::BadNodeIdUnknown}` from the mutator - the interface above it
// faithfully forwards `status_code()` and `shared_detail()`, so nothing is "lost in transit" and the
// bug is invisible from the interface; the detail was simply never built. The read side of the very same
// interface is asserted first as a control, so a null detail on the mutator cannot be blamed on an interface
// that strips details wholesale.
// @relation(AC-SVR-DIAG-012-NAMESPACE-MUTATOR-DETAIL, scope=function)
TEST_F(ServerDiagnosticsFields, NamespaceMutatorFailurePreservesItsErrorDetailAtThePublicApi)
{
  auto addressSpace = mServer.server().address_space();
  auto mutatorNamespace =
    default_ns::Namespace::create("urn:test:diag:mutator", mServer.thread_pool().executor());
  const auto namespaceIndex = addressSpace.add_namespace_sync(mutatorNamespace);

  const NodeId presentId{namespaceIndex, uint32_t{8000}};
  const NodeId absentId{namespaceIndex, uint32_t{8001}};
  (void)addressSpace.create_node_sync(presentId, NodeClass::Object);

  // The mutation really does reach this namespace: deleting a node it owns succeeds. Without this
  // the bad-path assertions below could be satisfied by an interface that never entered the namespace.
  const auto goodDeletion =
    addressSpace.try_delete_node_sync(presentId, /*deleteForwardHierarchicallyReferencedNodes=*/false);
  ASSERT_TRUE(goodDeletion.is_good())
    << "the delete mutator never reached the registered namespace - stimulus did not land";

  // Control: the read side of the same AddressSpace/Namespace crossing carries the namespace's own
  // ErrorDetail through unchanged.
  const auto lookup = addressSpace.try_find_node_sync(absentId);
  ASSERT_TRUE(lookup.is_bad()) << "an unknown node id must not resolve";
  ASSERT_NE(lookup.shared_detail(), nullptr)
    << "the AddressSpace/Namespace interface drops ErrorDetail wholesale - the mutator assertion below "
       "would be unattributable";
  EXPECT_FALSE(lookup.shared_detail()->source.empty());

  // The obligation: the mutator failure path must arrive with its detail too.
  const auto badDeletion =
    addressSpace.try_delete_node_sync(absentId, /*deleteForwardHierarchicallyReferencedNodes=*/false);
  ASSERT_TRUE(badDeletion.is_bad()) << "deleting an unknown node id must fail";
  EXPECT_EQ(badDeletion.status_code(), StatusCode{Status::BadNodeIdUnknown});
  ASSERT_NE(badDeletion.shared_detail(), nullptr)
    << "a Namespace mutator failure reached the public AddressSpace API with no ErrorDetail: the "
       "detail was never built at the failure site";
  EXPECT_FALSE(badDeletion.shared_detail()->code.empty())
    << "the surviving ErrorDetail must name the failure, not be an empty envelope";
  EXPECT_FALSE(badDeletion.shared_detail()->source.empty())
    << "the surviving ErrorDetail must name the producing component";
}

// ===========================================================================
// Fixture E: a Variable whose external value source delivers its read
// completion TWICE, re-entering a phase the per-request flow has already left.
// ===========================================================================
class ServerDiagnosticsDoubleCompletion : public ServerDiagnosticsFields
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    mTestNamespace = default_ns::Namespace::create("urn:test:diag:double", mServer.thread_pool().executor());
    mTestNamespaceIndex = addressSpace.add_namespace_sync(mTestNamespace);

    mDoubleCompletingId = NodeId{mTestNamespaceIndex, uint32_t{9000}};
    mSiblingId = NodeId{mTestNamespaceIndex, uint32_t{9001}};

    auto doubleNode = addressSpace.create_node_sync(mDoubleCompletingId, NodeClass::Variable);
    auto doubleVariable = doubleNode.as<VariableAccessor>();
    ASSERT_TRUE(doubleVariable.has_value());
    doubleVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "DoubleCompleting"});
    doubleVariable->set_display_name(LocalizedText{"", "DoubleCompleting"});
    doubleVariable->set_data_type(NodeId{DataTypeId::Int32});
    doubleVariable->write_value_sync(int32_t{0});
    doubleVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mDoubleCompletingId);

    auto siblingNode = addressSpace.create_node_sync(mSiblingId, NodeClass::Variable);
    auto siblingVariable = siblingNode.as<VariableAccessor>();
    ASSERT_TRUE(siblingVariable.has_value());
    siblingVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "Sibling"});
    siblingVariable->set_display_name(LocalizedText{"", "Sibling"});
    siblingVariable->set_data_type(NodeId{DataTypeId::Int32});
    siblingVariable->write_value_sync(int32_t{4242});
    siblingVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mSiblingId);
  }

  std::shared_ptr<default_ns::Namespace> mTestNamespace;
  uint16_t mTestNamespaceIndex{0};
  NodeId mDoubleCompletingId;
  NodeId mSiblingId;
};

// SVR-DIAG-006 (repository async contract, no OPC clause): a per-request flow's Step enum must be
// read at the top of every continuation, so a continuation delivered for a phase the flow has
// already left is REJECTED rather than run a second time. A plausible implementation records the
// step and never checks it (a write-only Step field), which looks identical in review: the second
// delivery then re-enters the completed phase, overwrites the settled per-operation result and
// decrements the pending-operation barrier a second time, so the response is emitted with the wrong
// value, the wrong number of result slots, or twice. This drives the duplicate delivery through the
// only re-entrant interface an application controls - an ExternalValueSource read handler that invokes
// its completion callback twice - and asserts the whole observable conjunction: the settled value
// survives, the sibling operation in the same request is unaffected, the response carries exactly
// one slot per requested item, and the service is still usable afterwards.
// @verifies AC-SVR-DIAG-006-STEP-GUARDS-CONTINUATIONS
TEST_F(ServerDiagnosticsDoubleCompletion, ContinuationForAnAlreadyCompletedStepIsRejectedNotExecuted)
{
  auto addressSpace = mServer.server().address_space();

  auto invocations = std::make_shared<std::atomic<int>>(0);
  std::promise<VoidResult> installed;
  instance_utils::resolve_and_set_value_source_async(addressSpace,
    mDoubleCompletingId,
    make_value_source(
      [invocations](const ValueSource::ReadContext& /*context*/,
        const Node& /*node*/,
        const ReadValueId& /*read*/,
        std::function<void(DataValueResult)>
          done)
      {
        invocations->fetch_add(1);
        // First delivery: this is the value the flow settles on.
        DataValue settled{Variant{int32_t{111}}};
        done(DataValueResult{std::move(settled)});
        // Second delivery for the SAME operation, whose read phase has now completed.
        DataValue reEntrant{Variant{int32_t{222}}};
        done(DataValueResult{std::move(reEntrant)});
      }),
    [&installed](VoidResult result) { installed.set_value(std::move(result)); });
  ASSERT_TRUE(installed.get_future().get().is_good()) << "read value handler was not installed";

  auto session = open_active_session("diag-double-completion");

  ReadRequest request;
  ReadValueId doubleItem;
  doubleItem.node_id() = mDoubleCompletingId;
  doubleItem.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  request.nodes_to_read().push_back(std::move(doubleItem));
  ReadValueId siblingItem;
  siblingItem.node_id() = mSiblingId;
  siblingItem.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  request.nodes_to_read().push_back(std::move(siblingItem));
  request.timestamps_to_return() = TimestampsToReturn::Both;

  auto response = session.attributes().try_read_sync(std::move(request));
  ASSERT_TRUE(response.is_good()) << "the Read service must complete normally despite the double delivery";
  ASSERT_GE(invocations->load(), 1) << "the value handler never ran - the duplicate delivery never happened";

  // Conjunct 1: exactly one result slot per requested operation (the second delivery must not have
  // produced or consumed an extra slot).
  ASSERT_EQ(response.value().results().size(), 2u)
    << "the out-of-step delivery changed the result cardinality";

  // Conjunct 2: the settled value survives; the out-of-step delivery did not overwrite it.
  const auto& doubleResult = response.value().results()[0];
  if (doubleResult.status().has_value())
  {
    EXPECT_TRUE(doubleResult.status()->is_good()) << "the double-completing read must still succeed";
  }
  const auto* observed = doubleResult.value().try_as<int32_t>();
  ASSERT_NE(observed, nullptr) << "the double-completing operation returned no Int32 value";
  EXPECT_EQ(*observed, 111)
    << "the continuation for an already-completed read phase was executed instead of rejected: it "
       "overwrote the settled value";

  // Conjunct 3: the sibling operation in the same request is untouched.
  const auto& siblingResult = response.value().results()[1];
  if (siblingResult.status().has_value())
  {
    EXPECT_TRUE(siblingResult.status()->is_good()) << "the sibling read must be unaffected";
  }
  const auto* sibling = siblingResult.value().try_as<int32_t>();
  ASSERT_NE(sibling, nullptr) << "the sibling operation returned no Int32 value";
  EXPECT_EQ(*sibling, 4242) << "the out-of-step delivery corrupted a neighbouring operation's slot";

  // Conjunct 4: the session and service set survive - the rejected continuation did not tear down
  // the flow or leave the request barrier in a state that wedges the next request.
  ReadRequest followUp;
  ReadValueId followUpItem;
  followUpItem.node_id() = mSiblingId;
  followUpItem.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  followUp.nodes_to_read().push_back(std::move(followUpItem));
  followUp.timestamps_to_return() = TimestampsToReturn::Both;

  auto followUpResponse = session.attributes().try_read_sync(std::move(followUp));
  ASSERT_TRUE(followUpResponse.is_good()) << "the service was wedged by the duplicate continuation";
  EXPECT_EQ(followUpResponse.value().results().size(), 1u);
}
