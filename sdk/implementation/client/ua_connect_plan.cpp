// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_connect_plan.h"

#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_utilities.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ua::client::detail
{
namespace
{
// Default session name when the caller supplies none. This string is sent to every server we connect to and
// surfaces in its logs, session diagnostics and audit events, so it names *this SDK* rather than being a
// generic "client" label. A fixed string (not a generated per-connection unique name) keeps this translation
// pure; per-connection uniqueness is a follow-up on the establisher.
constexpr std::string_view defaultSessionName = "reduktive OPC UA Client";
constexpr std::string_view emptyUrlSource = "client.tier1.connect.endpoint_url.empty";

ua::EndpointDescription synthesize_endpoint(const ua::client::ConnectionConfig& config)
{
  // C1 has no GetEndpoints round-trip (ExactUrl), so the EndpointDescription that backs the tier-2
  // redundancy host's identity reads is synthesised from the explicit connect parameters.
  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = ua::String{config.endpointUrl};
  endpoint.security_mode() = config.securityMode;
  endpoint.security_policy_uri() = ua::utils::get_security_policy_uri(config.securityPolicyId);
  return endpoint;
}
}  // namespace

ConnectPlan build_connect_plan(
  const ua::client::ConnectionConfig& config, std::vector<ua::EndpointDescription> discoveryEndpoints)
{
  ConnectPlan plan;

  if (config.endpointUrl.empty())
  {
    plan.valid = false;
    plan.error = ua::StatusCode{ua::Status::BadInvalidArgument,
      ua::make_error_detail("EndpointUrlEmpty",
        "ConnectionConfig::endpointUrl must be a non-empty opc.tcp:// URL.",
        std::string{emptyUrlSource})};
    return plan;
  }

  // Channel open  -  reused VERBATIM for the initial open AND every reconnect reopen, so the full secured
  // config is preserved (a reconnect cannot silently downgrade to a URL-only reopen). mOnChannelError is
  // left empty on purpose: the managed Connection owns drop handling (keep-alive + dispatch-gated
  // notify_transport_drop), not this raw tier-0 hook.
  plan.channelOpen.endpointUrl = config.endpointUrl;
  plan.channelOpen.relaxHostNameCheck = config.relaxHostNameCheck;
  plan.channelOpen.securityMode = config.securityMode;
  plan.channelOpen.securityPolicyId = config.securityPolicyId;
  plan.channelOpen.serverCertificate = config.serverCertificate;
  plan.channelOpen.trustStoreOverride = config.trustStoreOverride;
  plan.channelOpen.requestedLifetime = config.channelLifetime;
  plan.channelOpen.auditEntryIdProvider = config.auditEntryIdProvider;
  plan.channelOpen.timeout = config.connectTimeout;
  plan.channelOpen.connectMode = ua::client::ConnectMode::Normal;
  plan.endpointSelection = config.endpointSelection;
  plan.allowUnsecuredEndpoint = config.allowUnsecuredEndpoint;

  plan.createSession.requestedSessionTimeout = config.sessionTimeout;
  plan.createSession.sessionName = config.sessionName.value_or(std::string{defaultSessionName});
  plan.createSession.relaxHostNameCheck = config.relaxHostNameCheck;
  plan.createSession.auditEntryIdProvider = config.auditEntryIdProvider;
  plan.createSession.returnDiagnosticsOverride = config.diagnostics.requestedDiagnosticsMask;
  plan.createSession.discoveryEndpoints = std::move(discoveryEndpoints);
  // A plan pinned from a discovery result (easy_connect resolves an endpoint, then connects ExactUrl) asks
  // for an EphemeralKey only when an endpoint of that result with the plan's policy and mode offers a token
  // policy that can use one, as the discovery-driven selection decides for the endpoint it selects. The URL
  // is not compared: EasyConnectConfig::customize may move it.
  {
    const ua::String policyUri = ua::utils::get_security_policy_uri(config.securityPolicyId);
    bool pinned = false;
    bool secretTokenOffered = false;
    for (const auto& endpoint : plan.createSession.discoveryEndpoints)
    {
      if (endpoint.security_mode() != config.securityMode || endpoint.security_policy_uri() != policyUri)
        continue;
      pinned = true;
      secretTokenOffered = secretTokenOffered || offers_secret_token_policy(endpoint);
    }
    plan.createSession.requestEphemeralKey = !pinned || secretTokenOffered;
  }
  // mOnSessionError left empty: the managed layer owns session-error handling.

  plan.activate.policyId = config.userTokenPolicyId;
  plan.activate.identity = config.identity;
  plan.activate.localeIds = config.localeIds;

  plan.implConfig.queueOnReconnect = config.queueOnReconnect;
  plan.implConfig.pendingQueueLimit = config.pendingQueueLimit;
  plan.implConfig.maxQueueAge = config.maxQueueAge;
  plan.implConfig.observers.connection = config.connectionObserver;
  plan.implConfig.observers.subscription = config.subscriptionObserver;
  // observers.security intentionally not set from ConnectionConfig: the slot was removed (D21) because
  // SecurityObserver events are client-wide. The client-level observer still populates this sink.
  plan.implConfig.observers.type = config.typeObserver;
  plan.implConfig.observers.addressSpace = config.addressSpaceObserver;
  plan.implConfig.observers.serverState = config.serverStateObserver;
  plan.implConfig.observers.alarm = config.alarmObserver;
  plan.implConfig.addressSpaceCache = config.addressSpaceCache;
  plan.implConfig.diagnostics = config.diagnostics;
  plan.implConfig.subscriptionFallback = config.subscriptionFallback;
  plan.implConfig.typeResolution = config.typeResolution;
  plan.implConfig.endpoint = synthesize_endpoint(config);

  // Auto-reconnect is opt-out: a present reconnect policy engages the FSM + keep-alive; nullopt is
  // single-shot (no FSM, no keep-alive).
  if (config.reconnect.has_value())
  {
    plan.autoReconnect = true;
    plan.reconnectPolicy = *config.reconnect;
    plan.keepAlive = config.keepAlive;
    // Redundancy failover is driven through the reconnect FSM, so it engages only with auto-reconnect
    // (CL-REDUN). A single-shot connect (reconnect == nullopt) never activates the redundancy manager.
  }

  // Overall connect deadline (channel-open + CreateSession + ActivateSession + bootstrap). connect_async arms
  // one soft timer for the whole chain; the per-phase tier-0 configs carry no request deadline of their own.
  plan.connectTimeout = config.connectTimeout;

  plan.valid = true;
  return plan;
}

bool offers_secret_token_policy(const ua::EndpointDescription& endpoint)
{
  for (const auto& policy : endpoint.user_identity_tokens().payload())
  {
    if (policy.token_type() == ua::UserTokenType::UserName ||
        policy.token_type() == ua::UserTokenType::IssuedToken)
      return true;
  }
  return false;
}

}  // namespace ua::client::detail
