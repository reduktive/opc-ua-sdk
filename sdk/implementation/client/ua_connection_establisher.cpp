// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_cert_validator.h"
#include "ua_connection_establisher.h"

#include "ua_client_answer_status.h"
#include "ua_client_security_policy_gate.h"
#include "ua_connection_impl.h"
#include "ua_easy_connect_policy.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_security_policy.h"
#include "ua_url_parser.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"

#include <atomic>
#include <algorithm>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace ua::client::detail
{
namespace
{
std::optional<ua::SecurityPolicyId> supported_policy_id(const ua::String& policyUri) noexcept
{
  try
  {
    return ua::utils::get_security_policy_id(policyUri);
  }
  catch (...)
  {
    return std::nullopt;
  }
}

ua::UserTokenType planned_token_type(const ua::client::UserIdentity& identity)
{
  return std::visit(
    [](const auto& concrete)
    {
      using Identity = std::decay_t<decltype(concrete)>;
      if constexpr (std::is_same_v<Identity, ua::client::AnonymousIdentity>)
        return ua::UserTokenType::Anonymous;
      else if constexpr (std::is_same_v<Identity, ua::client::UsernamePasswordIdentity>)
        return ua::UserTokenType::UserName;
      else if constexpr (std::is_same_v<Identity, ua::client::X509Identity>)
        return ua::UserTokenType::Certificate;
      else
        return ua::UserTokenType::IssuedToken;
    },
    identity);
}

/// Names the UserTokenPolicy on @p endpoint that @p identity activates under, if it advertises one.
///
/// A non-anonymous identity may not be sent without a policy id: Part 4 section 7.42 requires the token to
/// carry a policyId the endpoint advertised, and the tier-0 token builder refuses to invent one because it
/// holds no discovery result. A discovery-driven selection HAS just chosen the endpoint and therefore holds
/// its advertised list, so it is the only place on this path that can name one - the same obligation
/// `easy_connect`'s resolver discharges for its own path.
///
/// Two cases deliberately return empty: an anonymous identity, whose ANONYMOUS policy tier-0 selects at
/// activation, and an endpoint advertising no policy of the required kind, where the refusal must come from
/// the token builder with its own diagnosis rather than from a policy id the Server never offered.
std::string selected_user_token_policy_id(
  const ua::EndpointDescription& endpoint, const ua::client::UserIdentity& identity)
{
  const ua::UserTokenType wanted = planned_token_type(identity);
  if (wanted == ua::UserTokenType::Anonymous)
  {
    return {};
  }
  // Advertised order must not decide whether the secret travels in the clear. A UserTokenPolicy naming the
  // None SecurityPolicy presents the password as plaintext, which the token builder refuses outright unless
  // the application set `allowUnencryptedPassword` - so naming one because the Server listed it first would
  // hand the caller a policy that cannot be used. An EMPTY URI is not plaintext: Part 4 section 7.42 says it
  // inherits the channel's SecurityPolicy. Fall back to the first match so that when a plaintext policy is
  // the ONLY one of its kind the refusal still comes from the token builder, with its own diagnosis, rather
  // than from an empty id.
  const ua::UserTokenPolicy* fallback = nullptr;
  for (const auto& policy : endpoint.user_identity_tokens().payload())
  {
    if (policy.token_type() != wanted)
    {
      continue;
    }
    const auto tokenPolicyUri = policy.security_policy_uri();
    if (!tokenPolicyUri.empty() &&
        tokenPolicyUri == ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None))
    {
      if (!fallback)
      {
        fallback = &policy;
      }
      continue;
    }
    return std::string{policy.policy_id()};
  }
  return fallback ? std::string{fallback->policy_id()} : std::string{};
}

std::string planned_ecdh_policy_uri(
  const ua::EndpointDescription& endpoint, const ua::client::Session::ActivateConfig& activate)
{
  const ua::UserTokenType tokenType = planned_token_type(activate.identity);
  for (const auto& policy : endpoint.user_identity_tokens().payload())
  {
    if (policy.token_type() != tokenType ||
        (!activate.policyId.empty() && std::string_view{policy.policy_id()} != activate.policyId))
      continue;
    if (policy.security_policy_uri().empty())
      return std::string{endpoint.security_policy_uri()};
    try
    {
      if (ua::SecurityPolicy::create(policy.security_policy_uri())->ephemeral_key_algorithm() !=
          ua::EphemeralKeyAlgorithm::Invalid)
        return std::string{policy.security_policy_uri()};
    }
    catch (...)
    {
      return {};
    }
    // A token without key agreement needs no ephemeral key. Retain the channel policy as the
    // first-activation fallback so the Server can still return the next ephemeral key without rejecting
    // ECDHPolicyUri=None.
    return std::string{endpoint.security_policy_uri()};
  }
  return {};
}

// Per-call state for the open -> CreateSession -> ActivateSession -> construct chain. Held in a shared_ptr
// captured into each async step so the state survives across the tier-0 hops (mirrors the OpenChannelFlow
// pattern the tier-0 open path uses).
struct EstablishFlow
{
  ConnectPlan plan;
  ObserverSlots defaults;
  std::function<void(ua::Result<std::shared_ptr<ConnectionImpl>>)> callback;
  boost::asio::any_io_executor executor;
  ua::Logger logger;
  bool allowDeprecatedSecurityPolicies = false;
  RealConnectionEstablisher::OpenChannelOpsFactory openOpsFactory;
  RealConnectionEstablisher::ServerCertValidatorFactory serverCertValidatorFactory;
  RealConnectionEstablisher::ServerCertificateDecoder serverCertificateDecoder;
  ReopenChannelOps openOps;  // built once from the plan; reused verbatim for the reconnect reopen wiring
  // Server-cert re-validation interface for THIS connection's endpoint (empty when the establisher was built
  // without a factory  -  single-shot / test paths); consulted once in build_and_finish.
  ServerCertValidator serverCertValidator;
  std::shared_ptr<ChannelOps> channel;
  std::shared_ptr<SessionOps> session;
  /// Single-shot plans only: the Connection a lost channel is reported to, filled once it exists (BR-19).
  std::shared_ptr<std::atomic<std::weak_ptr<ConnectionImpl>>> lostChannelTarget;
};

/// A single-shot Connection learns that its SecureChannel was lost through the channel's error hook: it has
/// no keep-alive, and without a Subscription no Publish would ever notice (owner decision 2026-10-03, BR-19).
/// Errors before the Connection exists belong to the connect flow and are not forwarded.
void wire_lost_channel_hook(const std::shared_ptr<EstablishFlow>& flow)
{
  if (flow->plan.autoReconnect || flow->lostChannelTarget)
    return;
  flow->lostChannelTarget = std::make_shared<std::atomic<std::weak_ptr<ConnectionImpl>>>();
  flow->plan.channelOpen.onChannelError = [target = flow->lostChannelTarget](ua::VoidResult lost)
  {
    if (auto connection = target->load().lock())
      connection->on_channel_lost_async(lost.status_code(), lost.shared_detail());
  };
}

void finish_bad(const std::shared_ptr<EstablishFlow>& flow, ua::StatusCode status)
{
  flow->callback(ua::Result<std::shared_ptr<ConnectionImpl>>{status});
}

void build_and_finish(const std::shared_ptr<EstablishFlow>& flow)
{
  // Reconnect wiring (auto-reconnect plans only): reuse the SAME open interface for reopens, so a reconnect
  // re-opens with the identical secured config (no downgrade). Redundancy is empty in C1 (opt-in / later
  // slices); create_from_ops leaves the FSM absent when reconnect is nullopt.
  std::optional<ReconnectWiringOps> reconnectOps;
  if (flow->plan.autoReconnect)
  {
    reconnectOps = ReconnectWiringOps{flow->openOps,
      flow->plan.activate,
      flow->plan.reconnectPolicy,
      flow->plan.keepAlive,
      flow->plan.enableRedundancy,  // CL-REDUN: opt-in from ConnectionConfig::enableRedundancy
      /*redundancyPolicy=*/{},
      // OPEN-REDUN-discovery: an empty provider makes non-None FindServers cleanly return Bad_NotImplemented;
      // None/Transparent skip never calls it. A Client-backed cross-server provider is a follow-up.
      /*redundancyDiscovery=*/{},
      // Server-cert re-validation: re-validates this endpoint's server cert against the Client store on a
      // trust-list/cert change (CL-SECADMIN-004 immediate revalidation / CL-PULLCRT-006), routing a
      // now-untrusted cert to a CertRotated reconnect. Empty for single-shot / test establishers.
      std::move(flow->serverCertValidator)};
  }
  // A reconnect that creates a new Session asks the key agreement this one did (CL-ECC-003).
  flow->plan.implConfig.ecdhPolicyUri = flow->plan.createSession.ecdhPolicyUri;
  flow->plan.implConfig.requestEphemeralKey = flow->plan.createSession.requestEphemeralKey;
  auto connection = ConnectionImpl::create_from_ops(flow->executor,
    flow->session,
    std::move(flow->plan.implConfig),
    flow->logger,
    std::move(reconnectOps),
    std::move(flow->defaults));
  if (flow->lostChannelTarget)
    flow->lostChannelTarget->store(connection);
  flow->callback(ua::Result<std::shared_ptr<ConnectionImpl>>{std::move(connection)});
}

void activate_step(const std::shared_ptr<EstablishFlow>& flow)
{
  flow->session->activate_on_bound_channel_async(flow->plan.activate,
    [flow](ua::VoidResult result)
    {
      // The Connection acts on the activated Session, so an Uncertain ActivateSession answer is refused as a
      // Bad one is; a Good subcode is consumed.
      if (!result.is_good())
      {
        // Partial-failure cleanup: the server holds a Created (un-activated) session; CloseSession it so it
        // does not linger to the server session-timeout (resource-leak / DoS). Report the ORIGINAL activate
        // failure to the user, not the (best-effort) close outcome. `flow` keeps the session alive across the
        // close.
        const ua::StatusCode activateStatus =
          answer_refused(result.status_code(), "ServiceAnswerUncertain", "client.tier1.connect.activate");
        flow->session->close_async(
          [flow, activateStatus](ua::VoidResult /*closeResult*/) { finish_bad(flow, activateStatus); });
        return;
      }
      build_and_finish(flow);
    });
}

void create_session_step(const std::shared_ptr<EstablishFlow>& flow)
{
  flow->channel->create_session_async(flow->plan.createSession,
    [flow](ua::Result<std::shared_ptr<SessionOps>> result)
    {
      if (!result.has_value())
      {
        // CreateSession failed; drop the channel (its transport is closed on destruction  -  ChannelOps
        // exposes no explicit close) and report. An Uncertain answer without a Session is refused too.
        flow->channel.reset();
        finish_bad(flow,
          answer_refused(
            result.status_code(), "ServiceAnswerUncertain", "client.tier1.connect.create_session"));
        return;
      }
      const ua::StatusCode createStatus = result.status_code();
      flow->session = std::move(result).value();  // Created, not yet activated
      if (createStatus.is_uncertain())
      {
        // The Connection acts on the Session it creates, so an Uncertain CreateSession answer is refused:
        // the Session the server created is closed and the channel dropped.
        const ua::StatusCode refused = uncertain_answer_refused(
          createStatus, "ServiceAnswerUncertain", "client.tier1.connect.create_session");
        flow->session->close_async(
          [flow, refused](ua::VoidResult /*closeResult*/)
          {
            flow->channel.reset();
            finish_bad(flow, refused);
          });
        return;
      }
      flow->session->set_return_diagnostics_override(
        flow->plan.implConfig.diagnostics.requestedDiagnosticsMask);
      activate_step(flow);
    });
}

void open_step(const std::shared_ptr<EstablishFlow>& flow)
{
  flow->openOps(
    [flow](ua::Result<std::shared_ptr<ChannelOps>> result)
    {
      // The Connection acts on the channel it opens, so an Uncertain OpenSecureChannel answer is refused (a
      // channel it holds closes on destruction).
      if (!result.is_good())
      {
        finish_bad(flow,
          answer_refused(
            result.status_code(), "ServiceAnswerUncertain", "client.tier1.connect.open_channel"));
        return;
      }
      flow->channel = std::move(result).value();
      create_session_step(flow);
    });
}

void fail_discovery(const std::shared_ptr<EstablishFlow>& flow, ua::StatusCode status, std::string name,
  std::string message, std::shared_ptr<const ua::ErrorDetail> cause = {})
{
  finish_bad(flow,
    ua::StatusCode{status.value(),
      ua::ErrorDetail::build(std::move(name), "Discovery operation failed", "client.tier1.connect.discovery")
        .context(ua::ContextKeys::endpointUrl, flow->plan.channelOpen.endpointUrl)
        .context(ua::ContextKeys::errorMessage, message)
        .cause(std::move(cause))});
}

void fail_unsupported_discovery_policy(
  const std::shared_ptr<EstablishFlow>& flow, const ua::String& policyUri)
{
  finish_bad(flow,
    ua::StatusCode{ua::Status::BadSecurityPolicyRejected,
      ua::ErrorDetail::build("UnsupportedDiscoverySecurityPolicy",
        "GetEndpoints returned only endpoints with unrecognized SecurityPolicies",
        "client.tier1.connect.discovery")
        .context(ua::ContextKeys::endpointUrl, flow->plan.channelOpen.endpointUrl)
        .context(ua::ContextKeys::securityPolicy, std::string{policyUri})});
}

/// CL-DISC-019: an unsecured endpoint has no certificate to bind the host it names, so one on a host other
/// than the dialled one is a redirect the client cannot verify. Refused rather than rewritten (E-D2).
bool unsecured_endpoint_is_on_dialled_host(const std::string& dialledUrl, const std::string& advertisedUrl)
{
  const auto dialled = ua::transport::parse_opc_tcp_url(dialledUrl, "client.tier1.connect.discovery");
  const auto advertised = ua::transport::parse_opc_tcp_url(advertisedUrl, "client.tier1.connect.discovery");
  return dialled.is_good() && advertised.is_good() &&
         ua::transport::matches_host(dialled.value(), advertised.value());
}

bool is_unsecured_endpoint(const ua::EndpointDescription& endpoint)
{
  return endpoint.security_mode() == ua::MessageSecurityMode::None ||
         supported_policy_id(endpoint.security_policy_uri()) == ua::SecurityPolicyId::None;
}

void fail_unsecured_endpoint_refused(const std::shared_ptr<EstablishFlow>& flow)
{
  finish_bad(flow,
    ua::StatusCode{ua::Status::BadSecurityModeRejected,
      ua::ErrorDetail::build("AutoBestUnsecuredEndpointRefused",
        "GetEndpoints offered no secured endpoint this client's ranking admits; an unsecured endpoint is "
        "selected only when ConnectionConfig::allowUnsecuredEndpoint is set for this connection, because the "
        "endpoint list is unauthenticated and a list without secured endpoints may have been stripped in "
        "transit",
        "client.tier1.connect.discovery")
        .context(ua::ContextKeys::endpointUrl, flow->plan.channelOpen.endpointUrl)});
}

void fail_unsecured_endpoint_requires_anonymous(
  const std::shared_ptr<EstablishFlow>& flow, const ua::EndpointDescription& endpoint)
{
  finish_bad(flow,
    ua::StatusCode{ua::Status::BadSecurityModeRejected,
      ua::ErrorDetail::build("AutoBestUnsecuredRequiresAnonymous",
        "ConnectionConfig::allowUnsecuredEndpoint admits an unsecured endpoint for an anonymous identity "
        "only; "
        "a user token over an unsecured channel would travel in clear",
        "client.tier1.connect.discovery")
        .context(ua::ContextKeys::endpointUrl, std::string{endpoint.endpoint_url()})});
}

void fail_unsecured_endpoint_host_changed(
  const std::shared_ptr<EstablishFlow>& flow, const ua::EndpointDescription& endpoint)
{
  finish_bad(flow,
    ua::StatusCode{ua::Status::BadSecurityChecksFailed,
      ua::ErrorDetail::build("UnsecuredEndpointHostChanged",
        "the selected unsecured endpoint names a host other than the one dialled; without a server "
        "certificate "
        "nothing binds the advertised host, so the redirect is refused",
        "client.tier1.connect.discovery")
        .context(ua::ContextKeys::endpointUrl, std::string{endpoint.endpoint_url()})
        .context(ua::ContextKeys::errorMessage, "dialled " + flow->plan.channelOpen.endpointUrl)});
}

void fail_discovery_application_uri_mismatch(
  const std::shared_ptr<EstablishFlow>& flow, std::string_view applicationUri)
{
  finish_bad(flow,
    ua::StatusCode{ua::Status::BadCertificateUriInvalid,
      ua::ErrorDetail::build("DiscoveryApplicationUriMismatch",
        "The EndpointDescription ApplicationUri is absent from its server certificate",
        "client.tier1.connect.discovery")
        .context(ua::ContextKeys::endpointUrl, flow->plan.channelOpen.endpointUrl)
        .context(ua::ContextKeys::applicationUri, std::string{applicationUri})});
}

void select_endpoint_and_open(const std::shared_ptr<EstablishFlow>& flow, ua::GetEndpointsResponse response)
{
  const ua::StatusCode serviceStatus = response.response_header().service_result();
  // The endpoint is selected from this answer, so an Uncertain one is refused as a Bad one is.
  if (!serviceStatus.is_good())
  {
    const ua::StatusCode refused =
      answer_refused(serviceStatus, "ServiceAnswerUncertain", "client.tier1.connect.discovery");
    fail_discovery(flow,
      refused,
      "GetEndpointsServiceFault",
      "GetEndpoints returned a service error",
      refused.shared_detail());
    return;
  }

  std::vector<ua::EndpointDescription> endpoints(response.endpoints().begin(), response.endpoints().end());
  const auto supported = [](const ua::EndpointDescription& endpoint)
  {
    return supported_policy_id(endpoint.security_policy_uri()).has_value();
  };

  auto selected = endpoints.end();
  bool sawUnsecured = false;
  auto unsecuredElsewhere = endpoints.end();
  if (flow->plan.endpointSelection == ua::client::EndpointSelection::FirstMatching)
  {
    const ua::String requestedPolicy =
      ua::utils::get_security_policy_uri(flow->plan.channelOpen.securityPolicyId);
    selected = std::ranges::find_if(endpoints,
      [&flow, &requestedPolicy, &supported](const ua::EndpointDescription& endpoint)
      {
        return supported(endpoint) && endpoint.security_mode() == flow->plan.channelOpen.securityMode &&
               endpoint.security_policy_uri() == requestedPolicy;
      });
  }
  else
  {
    // CL-DISC-019: the client's own ordering decides (the table easy_connect applies, client design section
    // 7.3A); the advertised securityLevel travelled over an unauthenticated channel and only breaks ties. A
    // deprecated policy is a candidate only when the application allows it (the Discovery facade filters the
    // list easy_connect ranks the same way); an unsecured endpoint only when this connection opted in, and
    // then only on the dialled host, so a multi-homed server's other-host copies never shadow the usable one.
    int selectedScore = 0;
    for (auto candidate = endpoints.begin(); candidate != endpoints.end(); ++candidate)
    {
      if (!supported(*candidate))
      {
        continue;
      }
      if (!flow->allowDeprecatedSecurityPolicies &&
          is_deprecated_client_security_policy_uri(std::string_view{candidate->security_policy_uri()}))
      {
        continue;
      }
      if (is_unsecured_endpoint(*candidate))
      {
        if (!flow->plan.allowUnsecuredEndpoint)
        {
          sawUnsecured = true;
          continue;
        }
        if (!unsecured_endpoint_is_on_dialled_host(
              flow->plan.channelOpen.endpointUrl, std::string{candidate->endpoint_url()}))
        {
          if (unsecuredElsewhere == endpoints.end())
          {
            unsecuredElsewhere = candidate;
          }
          continue;
        }
      }
      const int score = ua::client::default_easy_connect_ranker(*candidate);
      if (score <= 0)
      {
        continue;
      }
      const bool outranks = selected == endpoints.end() || score > selectedScore ||
                            (score == selectedScore &&
                              (candidate->security_level() > selected->security_level() ||
                                (candidate->security_level() == selected->security_level() &&
                                  std::tuple{candidate->security_policy_uri(), candidate->security_mode()} <
                                    std::tuple{selected->security_policy_uri(), selected->security_mode()})));
      if (outranks)
      {
        selected = candidate;
        selectedScore = score;
      }
    }
  }

  if (selected == endpoints.end())
  {
    if (!endpoints.empty() &&
        std::ranges::all_of(endpoints, [&supported](const auto& endpoint) { return !supported(endpoint); }))
    {
      fail_unsupported_discovery_policy(flow, endpoints.front().security_policy_uri());
      return;
    }
    if (sawUnsecured)
    {
      fail_unsecured_endpoint_refused(flow);
      return;
    }
    if (unsecuredElsewhere != endpoints.end())
    {
      fail_unsecured_endpoint_host_changed(flow, *unsecuredElsewhere);
      return;
    }
    fail_discovery(flow,
      ua::StatusCode{ua::Status::BadSecurityPolicyRejected},
      "NoSupportedDiscoveryEndpoint",
      "GetEndpoints returned no endpoint this client's ranking admits: a SecurityPolicy it does not "
      "implement or "
      "Basic128Rsa15 is never selected, and Basic256 only when ApplicationConfig::"
      "allowDeprecatedSecurityPolicies is set");
    return;
  }

  const auto selectedPolicyId = supported_policy_id(selected->security_policy_uri());
  if (!selectedPolicyId)
  {
    fail_discovery(flow,
      ua::StatusCode{ua::Status::BadSecurityPolicyRejected},
      "UnsupportedDiscoveryEndpoint",
      "the selected endpoint uses an unsupported SecurityPolicy");
    return;
  }
  const ua::SecurityPolicyId policyId = *selectedPolicyId;
  if (flow->plan.endpointSelection == ua::client::EndpointSelection::AutoBest &&
      is_unsecured_endpoint(*selected))
  {
    if (!unsecured_endpoint_is_on_dialled_host(
          flow->plan.channelOpen.endpointUrl, std::string{selected->endpoint_url()}))
    {
      fail_unsecured_endpoint_host_changed(flow, *selected);
      return;
    }
    if (!std::holds_alternative<ua::client::AnonymousIdentity>(flow->plan.activate.identity))
    {
      fail_unsecured_endpoint_requires_anonymous(flow, *selected);
      return;
    }
    flow->logger.warning(
      "AutoBest selected the unsecured endpoint {} (ConnectionConfig::allowUnsecuredEndpoint "
      "is set): the channel is neither signed nor encrypted and the server is not authenticated",
      std::string_view{selected->endpoint_url()});
  }
  std::shared_ptr<const ua::X509Certificate> certificate;
  if (policyId != ua::SecurityPolicyId::None)
  {
    if (selected->server_certificate().empty() || !flow->serverCertificateDecoder)
    {
      fail_discovery(flow,
        ua::StatusCode{ua::Status::BadCertificateInvalid},
        "DiscoveryServerCertificateMissing",
        "the selected secured endpoint has no decodable server certificate");
      return;
    }
    auto decoded = flow->serverCertificateDecoder(selected->server_certificate());
    if (!decoded.is_good())
    {
      fail_discovery(flow,
        decoded.status_code(),
        "DiscoveryServerCertificateDecodeFailed",
        "failed to decode the selected endpoint server certificate",
        decoded.shared_detail());
      return;
    }
    certificate = std::move(decoded).value();
    if (!certificate)
    {
      fail_discovery(flow,
        ua::StatusCode{ua::Status::BadCertificateInvalid},
        "DiscoveryServerCertificateDecodeFailed",
        "the selected endpoint server certificate decoder returned no certificate");
      return;
    }

    // CL-DISC-012: reject the unauthenticated endpoint before OPN when its claimed ApplicationUri is absent
    // from the advertised certificate. SessionImpl repeats this binding against CreateSession for
    // CL-DISC-004 after the channel is authenticated.
    const std::string applicationUri{selected->server().application_uri()};
    const auto certificateUris = certificate->san_uris();
    if (std::ranges::find(certificateUris, applicationUri) == certificateUris.end())
    {
      fail_discovery_application_uri_mismatch(flow, applicationUri);
      return;
    }
  }

  flow->plan.channelOpen.endpointUrl = std::string{selected->endpoint_url()};
  flow->plan.channelOpen.securityMode = selected->security_mode();
  flow->plan.channelOpen.securityPolicyId = policyId;
  // A server certificate the caller supplied wins (as userTokenPolicyId does): the discovered one fills the
  // field only when it was left empty. The OpenSecureChannel still validates whichever is used.
  if (!flow->plan.channelOpen.serverCertificate)
    flow->plan.channelOpen.serverCertificate = std::move(certificate);
  flow->plan.createSession.discoveryEndpoints = endpoints;
  if (flow->plan.activate.policyId.empty())
  {
    // An explicit caller choice wins: only fill the field in when the caller left it for us. Derived once,
    // then carried: a reconnect reopens the endpoint pinned here rather than re-running discovery (the
    // no-downgrade property the reopen interface exists for), so the id travels with the plan exactly as a
    // caller-supplied one always has.
    flow->plan.activate.policyId = selected_user_token_policy_id(*selected, flow->plan.activate.identity);
  }
  flow->plan.createSession.ecdhPolicyUri = planned_ecdh_policy_uri(*selected, flow->plan.activate);
  // An endpoint offering a UserName or IssuedToken policy is asked even for another identity, so that a later
  // reactivate with that identity finds its key (CL-ECC-003 NOTES); one offering neither is not asked.
  flow->plan.createSession.requestEphemeralKey = offers_secret_token_policy(*selected);
  flow->plan.implConfig.endpoint = *selected;
  // The channel records the request it validates the server with; the revalidation resubmits it.
  flow->plan.channelOpen.validatedServerRequest = std::make_shared<detail::ValidatedServerRequest>();
  wire_lost_channel_hook(flow);
  flow->openOps = flow->openOpsFactory(flow->plan.channelOpen);
  if (flow->serverCertValidatorFactory)
  {
    flow->serverCertValidator = flow->serverCertValidatorFactory(flow->plan.channelOpen);
  }
  open_step(flow);
}

void discovery_step(const std::shared_ptr<EstablishFlow>& flow)
{
  ua::client::CoreClient::OpenChannelConfig discoveryConfig = flow->plan.channelOpen;
  discoveryConfig.securityMode = ua::MessageSecurityMode::None;
  discoveryConfig.securityPolicyId = ua::SecurityPolicyId::None;
  discoveryConfig.serverCertificate.reset();
  discoveryConfig.trustStoreOverride.reset();

  auto discoveryOpen = flow->openOpsFactory(discoveryConfig);
  discoveryOpen(
    [flow](ua::Result<std::shared_ptr<ChannelOps>> channelResult)
    {
      if (!channelResult.is_good())
      {
        const ua::StatusCode refused = answer_refused(
          channelResult.status_code(), "ServiceAnswerUncertain", "client.tier1.connect.discovery");
        fail_discovery(flow,
          refused,
          "DiscoveryChannelOpenFailed",
          "failed to open the session-less discovery channel",
          refused.shared_detail());
        return;
      }
      auto channel = std::move(channelResult).value();
      ua::GetEndpointsRequest request;
      request.endpoint_url() = flow->plan.channelOpen.endpointUrl;
      channel->get_endpoints_async(std::move(request),
        [flow, channel = std::move(channel)](ua::Result<ua::GetEndpointsResponse> endpointsResult) mutable
        {
          auto* rawChannel = channel.get();
          rawChannel->close_async(
            [flow, channel = std::move(channel), endpointsResult = std::move(endpointsResult)](
              ua::VoidResult closeResult) mutable
            {
              channel.reset();
              if (closeResult.is_bad())
              {
                fail_discovery(flow,
                  closeResult.status_code(),
                  "DiscoveryChannelCloseFailed",
                  "failed to close the session-less discovery channel",
                  closeResult.shared_detail());
                return;
              }
              if (!endpointsResult.has_value())
              {
                const ua::StatusCode refused = answer_refused(
                  endpointsResult.status_code(), "ServiceAnswerUncertain", "client.tier1.connect.discovery");
                fail_discovery(flow,
                  refused,
                  "GetEndpointsFailed",
                  "the discovery GetEndpoints request failed",
                  refused.shared_detail());
                return;
              }
              select_endpoint_and_open(flow, std::move(endpointsResult).value());
            });
        });
    });
}
}  // namespace

RealConnectionEstablisher::RealConnectionEstablisher(boost::asio::any_io_executor executor, ua::Logger logger,
  OpenChannelOpsFactory openOpsFactory, ServerCertValidatorFactory serverCertValidatorFactory,
  ServerCertificateDecoder serverCertificateDecoder, bool allowDeprecatedSecurityPolicies)
  : mExecutor(std::move(executor)), mLogger(std::move(logger)), mOpenOpsFactory(std::move(openOpsFactory)),
    mServerCertValidatorFactory(std::move(serverCertValidatorFactory)),
    mServerCertificateDecoder(std::move(serverCertificateDecoder)),
    mAllowDeprecatedSecurityPolicies(allowDeprecatedSecurityPolicies)
{}

void RealConnectionEstablisher::establish_async(ConnectPlan plan, ObserverSlots clientObserverDefaults,
  std::function<void(ua::Result<std::shared_ptr<ConnectionImpl>>)> callback)
{
  auto flow = std::make_shared<EstablishFlow>();
  flow->executor = mExecutor;
  flow->logger = mLogger;
  flow->allowDeprecatedSecurityPolicies = mAllowDeprecatedSecurityPolicies;
  flow->openOpsFactory = mOpenOpsFactory;
  flow->serverCertValidatorFactory = mServerCertValidatorFactory;
  flow->serverCertificateDecoder = mServerCertificateDecoder;
  flow->plan = std::move(plan);
  flow->defaults = std::move(clientObserverDefaults);
  flow->callback = std::move(callback);

  if (flow->plan.endpointSelection == ua::client::EndpointSelection::ExactUrl)
  {
    // The channel records the request it validates the server with; the revalidation resubmits it.
    flow->plan.channelOpen.validatedServerRequest = std::make_shared<detail::ValidatedServerRequest>();
    wire_lost_channel_hook(flow);
    flow->openOps = flow->openOpsFactory(flow->plan.channelOpen);
    if (mServerCertValidatorFactory)
    {
      flow->serverCertValidator = mServerCertValidatorFactory(flow->plan.channelOpen);
    }
    open_step(flow);
    return;
  }

  discovery_step(flow);
}

}  // namespace ua::client::detail
