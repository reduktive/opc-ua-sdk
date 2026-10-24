// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::build_connect_plan (section 7.3 / section 8.2A) - the PURE translation
// of a user-facing ua::client::ConnectionConfig into the tier-0/tier-1 sub-configs the managed connect path
// drives. No server, no async, no clock: a pure function of its input.
//
// Falsifiability: each test asserts a specific field of the produced plan (a preserved security field, a
// threaded policy, a rejected endpoint-selection status + source tag), so a translation that dropped a
// field, downgraded security on the reopen config, or mis-gated reconnect fails a concrete assertion.

#include "ua_connect_plan.h"

#include "ua_client_observers.h"
#include "ua_connection_config.h"
#include "ua_crypto_types.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_message_security_mode.h"
#include "ua_node_id.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_user_token_policy.h"
#include "ua_user_token_type.h"
#include "ua_utilities.h"

#include "stub_x509_certificate.h"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

namespace
{
using ua::client::ConnectionConfig;
using ua::client::EndpointSelection;
using ua::client::detail::build_connect_plan;
using ua::client::detail::ConnectPlan;
using namespace std::chrono_literals;

constexpr std::string_view url = "opc.tcp://server.example:4840";

// Minimal observer subclasses (all interface methods default-empty) for slot-mapping assertions.
struct DummyConnectionObserver : ua::client::ConnectionObserver
{};

struct DummyAlarmObserver : ua::client::AlarmObserver
{};

ConnectionConfig minimal_config()
{
  ConnectionConfig config;
  config.endpointUrl = std::string{url};
  return config;
}

/// An ECC_nistP256_AesGcm SignAndEncrypt ExactUrl config, as easy_connect pins it.
ConnectionConfig pinned_ecc_config()
{
  ConnectionConfig config = minimal_config();
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = ua::SecurityPolicyId::EccNistP256AesGcm;
  return config;
}

/// One discovered endpoint with @p policy and @p mode, offering a token policy of each of @p tokenTypes.
ua::EndpointDescription discovered_endpoint(
  ua::SecurityPolicyId policy, ua::MessageSecurityMode mode, std::vector<ua::UserTokenType> tokenTypes)
{
  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = std::string{url};
  endpoint.security_mode() = mode;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(policy);
  for (const auto type : tokenTypes)
  {
    ua::UserTokenPolicy token;
    token.policy_id() = ua::to_string(type);
    token.token_type() = type;
    endpoint.user_identity_tokens().push_back(std::move(token));
  }
  return endpoint;
}

std::uint32_t status_value(ua::Status status)
{
  return ua::StatusCode{status}.value();
}

// --- Happy-path translation -------------------------------------------------------------------------------

TEST(ConnectPlan, MinimalExactUrlAnonymousProducesValidPlan)
{
  const ConnectPlan plan = build_connect_plan(minimal_config());

  ASSERT_TRUE(plan.valid);
  EXPECT_TRUE(plan.error.is_good());
  EXPECT_EQ(plan.channelOpen.endpointUrl, std::string{url});
  EXPECT_EQ(plan.channelOpen.securityMode, ua::MessageSecurityMode::None);
  EXPECT_EQ(plan.channelOpen.securityPolicyId, ua::SecurityPolicyId::None);
  EXPECT_EQ(plan.channelOpen.connectMode, ua::client::ConnectMode::Normal);
  // Default config has reconnect = ReconnectPolicy{} (ON), so the plan is auto-reconnecting.
  EXPECT_TRUE(plan.autoReconnect);
  EXPECT_TRUE(std::holds_alternative<ua::client::AnonymousIdentity>(plan.activate.identity));
}

// AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY: easy_connect pins an endpoint of its discovery
// result and connects ExactUrl with that result. When the discovered endpoints with the plan's policy and
// mode offer no UserName or IssuedToken policy, the plan asks for no EphemeralKey. Falsifiable: the former
// plan always asked. The discovered RSA endpoint offering UserName is not the pinned one and must not count.
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST(ConnectPlan, APinnedEndpointOfferingNoSecretTokenPolicyIsAskedForNoEphemeralKey)
{
  const ConnectPlan plan = build_connect_plan(pinned_ecc_config(),
    {discovered_endpoint(ua::SecurityPolicyId::EccNistP256AesGcm,
       ua::MessageSecurityMode::SignAndEncrypt,
       {ua::UserTokenType::Anonymous, ua::UserTokenType::Certificate}),
      discovered_endpoint(ua::SecurityPolicyId::Basic256Sha256,
        ua::MessageSecurityMode::SignAndEncrypt,
        {ua::UserTokenType::UserName})});
  ASSERT_TRUE(plan.valid);
  EXPECT_FALSE(plan.createSession.requestEphemeralKey);
}

// control: the pinned endpoint also offers a UserName policy, so a later reactivate can use the key.
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST(ConnectPlan, APinnedEndpointOfferingAUserNamePolicyIsAskedForAnEphemeralKey)
{
  const ConnectPlan plan = build_connect_plan(pinned_ecc_config(),
    {discovered_endpoint(ua::SecurityPolicyId::EccNistP256AesGcm,
      ua::MessageSecurityMode::SignAndEncrypt,
      {ua::UserTokenType::Anonymous, ua::UserTokenType::UserName})});
  ASSERT_TRUE(plan.valid);
  EXPECT_TRUE(plan.createSession.requestEphemeralKey);
}

// control: without a discovery result, or with none of its endpoints matching the plan's policy and mode, the
// plan knows nothing of the server's token policies and keeps asking (CL-ECC-003 NOTES).
// @relation(AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY, scope=function)
TEST(ConnectPlan, APlanWithoutAMatchingDiscoveredEndpointAsksForAnEphemeralKey)
{
  EXPECT_TRUE(build_connect_plan(pinned_ecc_config()).createSession.requestEphemeralKey);
  const ConnectPlan otherMode = build_connect_plan(pinned_ecc_config(),
    {discovered_endpoint(ua::SecurityPolicyId::EccNistP256AesGcm,
      ua::MessageSecurityMode::Sign,
      {ua::UserTokenType::Anonymous})});
  ASSERT_TRUE(otherMode.valid);
  EXPECT_TRUE(otherMode.createSession.requestEphemeralKey);
}

TEST(ConnectPlan, SecurityPreservedInChannelOpenForReopen)
{
  // The channelOpen is reused verbatim as the reconnect reopen config; a downgrade here would silently
  // reconnect at lower security (a trust downgrade). Assert the FULL secured config is carried.
  ConnectionConfig config = minimal_config();
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  const auto serverCert = ua::testing::make_stub_certificate();
  config.serverCertificate = serverCert;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  EXPECT_EQ(plan.channelOpen.securityMode, ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_EQ(plan.channelOpen.securityPolicyId, ua::SecurityPolicyId::Basic256Sha256);
  EXPECT_EQ(plan.channelOpen.serverCertificate, serverCert)
    << "server cert must survive into the reopen config";
}

TEST(ConnectPlan, ChannelLifetimeAndTimeoutPassThrough)
{
  ConnectionConfig config = minimal_config();
  config.channelLifetime = 45s;
  config.connectTimeout = 12s;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  ASSERT_TRUE(plan.channelOpen.requestedLifetime.has_value());
  EXPECT_EQ(*plan.channelOpen.requestedLifetime, 45s);
  ASSERT_TRUE(plan.channelOpen.timeout.has_value());
  EXPECT_EQ(*plan.channelOpen.timeout, 12s);
  // connectTimeout is ALSO carried as the overall connect deadline connect_async arms (not only
  // channel-open).
  ASSERT_TRUE(plan.connectTimeout.has_value());
  EXPECT_EQ(*plan.connectTimeout, 12s);
}

TEST(ConnectPlan, ReconnectNulloptYieldsSingleShot)
{
  ConnectionConfig config = minimal_config();
  config.reconnect = std::nullopt;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  EXPECT_FALSE(plan.autoReconnect);
}

// The client redundancy surface is withdrawn from the public API for the initial release
// (client_design.md section 8.11.10): `ConnectionConfig` no longer carries `enableRedundancy`, so no
// application can turn the manager on. This test replaces the former
// `EnableRedundancyThreadsThroughWhenAutoReconnect`, which pinned exactly the public opt-in path that
// has gone, and pins the withdrawal instead.
//
// **The engine being inert, not merely hidden, is the whole claim of the withdrawal** - the design
// says no Connection pays any wire or scheduling cost, and that holds only because
// `ConnectionImpl::create` gates `wire_redundancy` on this plan field
// (ua_connection_impl.cpp, `if (reconnect->enableRedundancy)`). A future change that defaulted the
// field on, or re-threaded it from somewhere else, would silently re-arm a subsystem whose failover
// path cannot be tested end to end while this SDK's own server publishes RedundancySupport = None.
// The internal `detail::ConnectionConfig` keeps the flag so `ConnectionImplTestAccess` can still
// drive the full wiring, which is why the engine's own 109 tests are unaffected.
TEST(ConnectPlan, NoPublicConfigCanArmTheRedundancyEngine)
{
  const ConnectPlan autoReconnect = build_connect_plan(minimal_config());
  ASSERT_TRUE(autoReconnect.valid);
  ASSERT_TRUE(autoReconnect.autoReconnect);
  EXPECT_FALSE(autoReconnect.enableRedundancy)
    << "a reconnect-wired plan built from the public ConnectionConfig armed the redundancy engine; "
       "the public opt-in was withdrawn, so nothing an application can set may reach this field";

  ConnectionConfig singleShot = minimal_config();
  singleShot.reconnect = std::nullopt;
  const ConnectPlan planSingle = build_connect_plan(singleShot);
  EXPECT_FALSE(planSingle.enableRedundancy) << "a single-shot plan armed the redundancy engine";
}

TEST(ConnectPlan, ReconnectPresentThreadsPolicyAndKeepAlive)
{
  ConnectionConfig config = minimal_config();
  ua::client::ReconnectPolicy policy;
  policy.maxAttempts = 7;
  config.reconnect = policy;
  config.keepAlive.interval = 2500ms;
  config.keepAlive.missedBeforeReconnect = 5;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  ASSERT_TRUE(plan.autoReconnect);
  ASSERT_TRUE(plan.reconnectPolicy.maxAttempts.has_value());
  EXPECT_EQ(*plan.reconnectPolicy.maxAttempts, 7u);
  EXPECT_EQ(plan.keepAlive.interval, 2500ms);
  EXPECT_EQ(plan.keepAlive.missedBeforeReconnect, 5u);
}

TEST(ConnectPlan, IdentityAndTokenPolicyThreadedToActivate)
{
  ConnectionConfig config = minimal_config();
  config.identity = ua::client::UsernamePasswordIdentity{"operator", "secret"};
  config.userTokenPolicyId = "username_policy";
  config.localeIds = {ua::String{"en-US"}, ua::String{"de-DE"}};

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  ASSERT_TRUE(std::holds_alternative<ua::client::UsernamePasswordIdentity>(plan.activate.identity));
  EXPECT_EQ(std::get<ua::client::UsernamePasswordIdentity>(plan.activate.identity).username, "operator");
  EXPECT_EQ(plan.activate.policyId, "username_policy");
  ASSERT_EQ(plan.activate.localeIds.size(), 2u);
  EXPECT_EQ(plan.activate.localeIds[0], ua::String{"en-US"});
}

TEST(ConnectPlan, SessionNameDefaultsWhenAbsentAndUsedWhenPresent)
{
  const ConnectPlan defaulted = build_connect_plan(minimal_config());
  ASSERT_TRUE(defaulted.valid);
  EXPECT_FALSE(defaulted.createSession.sessionName.empty()) << "a default session name must be supplied";
  // Pinned deliberately: this string is sent to every server and lands in its logs, session diagnostics and
  // audit events, so it must identify this SDK rather than reverting to a generic vendor-neutral label.
  EXPECT_EQ(defaulted.createSession.sessionName, "reduktive OPC UA Client");

  ConnectionConfig named = minimal_config();
  named.sessionName = "MyNamedSession";
  const ConnectPlan plan = build_connect_plan(named);
  ASSERT_TRUE(plan.valid);
  EXPECT_EQ(plan.createSession.sessionName, "MyNamedSession");
}

TEST(ConnectPlan, SessionTimeoutPassThrough)
{
  ConnectionConfig config = minimal_config();
  config.sessionTimeout = 120s;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  ASSERT_TRUE(plan.createSession.requestedSessionTimeout.has_value());
  EXPECT_EQ(*plan.createSession.requestedSessionTimeout, 120s);
}

// @verifies CL-DIAG-011
// @relation(CL-DIAG-011, scope=function)
TEST(ConnectPlan, ReturnDiagnosticsOverrideReachesCreateSessionAndConnection)
{
  ConnectionConfig config = minimal_config();
  config.diagnostics.requestedDiagnosticsMask = 0xFFFFu;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  EXPECT_EQ(plan.createSession.returnDiagnosticsOverride, std::optional<uint32_t>{0xFFFFu});
  EXPECT_EQ(plan.implConfig.diagnostics.requestedDiagnosticsMask, std::optional<uint32_t>{0xFFFFu});
}

// @verifies AC-CL-DISC-004-VERIFY-AGAINST-SECURED
// @relation(AC-CL-DISC-004-VERIFY-AGAINST-SECURED, scope=function)
TEST(ConnectPlan, EasyConnectDiscoveryEvidenceReachesCreateSessionVerification)
{
  ua::EndpointDescription unsecured;
  unsecured.endpoint_url() = ua::String{std::string{url}};
  unsecured.security_mode() = ua::MessageSecurityMode::None;
  unsecured.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None);

  ua::EndpointDescription secured;
  secured.endpoint_url() = ua::String{std::string{url}};
  secured.security_mode() = ua::MessageSecurityMode::SignAndEncrypt;
  secured.security_policy_uri() = ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256);

  const ConnectPlan plan = build_connect_plan(minimal_config(), {unsecured, secured});

  ASSERT_TRUE(plan.valid);
  ASSERT_EQ(plan.createSession.discoveryEndpoints.size(), 2u);
  EXPECT_EQ(plan.createSession.discoveryEndpoints[0].security_mode(), ua::MessageSecurityMode::None);
  EXPECT_EQ(
    plan.createSession.discoveryEndpoints[1].security_mode(), ua::MessageSecurityMode::SignAndEncrypt);
}

// @verifies CL-AUDIT-001
// @relation(CL-AUDIT-001, scope=function)
TEST(ConnectPlan, AuditEntryIdProviderThreadsToCreatedSession)
{
  ConnectionConfig config = minimal_config();
  config.auditEntryIdProvider = []
  {
    return ua::String{"audit-plan"};
  };
  const ConnectPlan plan = build_connect_plan(config);
  ASSERT_TRUE(static_cast<bool>(plan.createSession.auditEntryIdProvider));
  EXPECT_EQ(plan.createSession.auditEntryIdProvider(), ua::String{"audit-plan"});
}

// @verifies CL-DISC-005
// @relation(CL-DISC-005, scope=function)
TEST(ConnectPlan, RelaxHostnamePolicyThreadsToCreateSession)
{
  ConnectionConfig config = minimal_config();
  config.relaxHostNameCheck = true;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  EXPECT_TRUE(plan.createSession.relaxHostNameCheck);
}

TEST(ConnectPlan, ObserverSlotsMappedToImplConfig)
{
  ConnectionConfig config = minimal_config();
  auto connObs = std::make_shared<DummyConnectionObserver>();
  auto alarmObs = std::make_shared<DummyAlarmObserver>();
  config.connectionObserver = connObs;
  config.alarmObserver = alarmObs;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  EXPECT_EQ(plan.implConfig.observers.connection, connObs);
  EXPECT_EQ(plan.implConfig.observers.alarm, alarmObs);
  EXPECT_EQ(plan.implConfig.observers.subscription, nullptr);
  EXPECT_EQ(plan.implConfig.observers.redundancy, nullptr);
}

TEST(ConnectPlan, QueueKnobsThreadedToImplConfig)
{
  ConnectionConfig config = minimal_config();
  config.queueOnReconnect = false;
  config.pendingQueueLimit = std::nullopt;
  config.maxQueueAge = 5s;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  EXPECT_FALSE(plan.implConfig.queueOnReconnect);
  EXPECT_FALSE(plan.implConfig.pendingQueueLimit.has_value());
  EXPECT_EQ(plan.implConfig.maxQueueAge, std::chrono::steady_clock::duration{5s});
}

// Every policy field on the public ConnectionConfig must survive the translation into the impl config, at a
// NON-DEFAULT value: a policy that is dropped here reaches the Connection as the default, and the consumer's
// own tests (which build the internal detail::ConnectionConfig directly) never traverse this hop.
TEST(ConnectPlan, PolicyFieldsThreadedToImplConfig)
{
  ConnectionConfig config = minimal_config();
  config.subscriptionFallback.mode = ua::client::SubscriptionFallbackPolicy::Mode::Auto;  // default Disabled
  config.typeResolution.mode = ua::client::TypeResolutionMode::EagerThenLazy;  // default Lazy
  config.typeResolution.eagerTypes = {ua::NodeId{3, 4242}};
  config.typeResolution.tier2WaitForResolution = false;  // default true
  config.addressSpaceCache.enabled = true;  // default false

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  EXPECT_EQ(plan.implConfig.subscriptionFallback.mode, ua::client::SubscriptionFallbackPolicy::Mode::Auto)
    << "the polled-Read fallback policy must survive the public -> impl translation";
  EXPECT_EQ(plan.implConfig.typeResolution.mode, ua::client::TypeResolutionMode::EagerThenLazy);
  ASSERT_EQ(plan.implConfig.typeResolution.eagerTypes.size(), 1U)
    << "the eager interest set is the substance of Eager mode; dropping it makes the mode inert";
  EXPECT_EQ(plan.implConfig.typeResolution.eagerTypes[0], ua::NodeId(3, 4242));
  EXPECT_FALSE(plan.implConfig.typeResolution.tier2WaitForResolution);
  EXPECT_TRUE(plan.implConfig.addressSpaceCache.enabled);
}

TEST(ConnectPlan, EndpointDescriptionSynthesizedFromUrlAndSecurity)
{
  ConnectionConfig config = minimal_config();
  config.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  config.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;

  const ConnectPlan plan = build_connect_plan(config);

  ASSERT_TRUE(plan.valid);
  EXPECT_EQ(plan.implConfig.endpoint.endpoint_url(), ua::String{std::string{url}});
  EXPECT_EQ(plan.implConfig.endpoint.security_mode(), ua::MessageSecurityMode::SignAndEncrypt);
  EXPECT_EQ(plan.implConfig.endpoint.security_policy_uri(),
    ua::utils::get_security_policy_uri(ua::SecurityPolicyId::Basic256Sha256));
}

TEST(ConnectPlan, AutoBestEndpointSelectionProducesDiscoveryPlan)
{
  ConnectionConfig config = minimal_config();
  config.endpointSelection = EndpointSelection::AutoBest;

  const ConnectPlan plan = build_connect_plan(config);

  EXPECT_TRUE(plan.valid);
  EXPECT_EQ(plan.endpointSelection, EndpointSelection::AutoBest);
}

TEST(ConnectPlan, FirstMatchingEndpointSelectionProducesDiscoveryPlan)
{
  ConnectionConfig config = minimal_config();
  config.endpointSelection = EndpointSelection::FirstMatching;

  const ConnectPlan plan = build_connect_plan(config);

  EXPECT_TRUE(plan.valid);
  EXPECT_EQ(plan.endpointSelection, EndpointSelection::FirstMatching);
}

// --- Rejections -------------------------------------------------------------------------------------------

TEST(ConnectPlan, EmptyEndpointUrlRejected)
{
  ConnectionConfig config;  // endpointUrl left empty

  const ConnectPlan plan = build_connect_plan(config);

  EXPECT_FALSE(plan.valid);
  EXPECT_EQ(plan.error.value(), status_value(ua::Status::BadInvalidArgument));
}
}  // namespace
