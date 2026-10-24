// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// ClientLdsRegistrar - client-backed adapter implementing the LdsRegistrar port.
//
// Each register_async call drives one full CONNECT-PER-CYCLE flow against a single
// discovery target: open a fresh session-less SecureChannel -> RegisterServer2 (or the
// memoised RegisterServer fallback) -> close. The Client is held strong (long-lived,
// owns cert/trust/executor); the per-cycle SecureChannel is held strong only for the
// duration of the cycle and is MOVED into the close continuation so it outlives the call.
//
// The flow is expressed as anonymous-namespace free functions so no LdsRegistrar `this`
// is captured across async boundaries: the only registrar state is the long-lived Client,
// and once the channel is open the cycle is fully described by the channel + payload.
//
// ErrorDetail tags (highest priority - never discarded):
//   app.discovery.registration.open_failed
//   app.discovery.registration.register_failed
//   app.discovery.registration.fallback_register_failed

#include "ua_certificate_validation_paths.h"
#include "ua_exceptions.h"
#include "ua_lds_registrar.h"
#include "ua_registration_endpoint_choice.h"

#include "ua_core_client.h"
#include "ua_crypto.h"
#include "ua_discovery_registration.h"
#include "ua_easy_connect_policy.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_register_server2_request.h"
#include "ua_register_server2_response.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_status.h"
#include "ua_to_result.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"

#include <memory>
#include <utility>
#include <vector>

namespace ua::app
{

namespace
{

constexpr auto sourceOpenFailed = "app.discovery.registration.open_failed";
constexpr auto sourceRegisterFailed = "app.discovery.registration.register_failed";
constexpr auto sourceFallbackRegisterFailed = "app.discovery.registration.fallback_register_failed";

using RegisterOutcome = LdsRegistrar::RegisterOutcome;
using RegisterResultCallback = LdsRegistrar::RegisterResultCallback;
using ChannelPtr = std::shared_ptr<ua::client::SecureChannel>;

/// Build a retry-class error Result carrying ErrorDetail. Connect failures and
/// registration failures collapse into the same Result error class for the driver's
/// retry logic; the ErrorDetail source distinguishes them for observability. Runtime
/// facts ride in structured context; the originating status threads as the cause.
ua::Result<RegisterOutcome> make_failure(ua::StatusCode status, std::string code, std::string summary,
  std::string source, std::vector<std::pair<ua::ContextKey, std::string>> context = {})
{
  auto builder =
    ua::ErrorDetail::build(std::move(code), "Discovery server registration cycle failed", std::move(source));
  builder.context(ua::ContextKeys::errorMessage, std::move(summary));
  for (auto& [key, value] : context)
    builder.context(key, std::move(value));
  builder.cause(status);
  auto detail = std::shared_ptr<const ua::ErrorDetail>(builder);
  return ua::Result<RegisterOutcome>{ua::StatusCode{status.value(), std::move(detail)}};
}

/// The status a cycle fails with when an answer the registrar acts on (an opened channel, the GetEndpoints
/// response) is not Good: a Bad answer's own code, or Bad_InternalError for an Uncertain one, which is not
/// used, with that code as the cause.
ua::StatusCode not_good_answer(const ua::StatusCode& answer)
{
  if (answer.is_bad())
    return answer;
  return ua::StatusCode{ua::Status::BadInternalError,
    ua::ErrorDetail::build(
      "RegistrationAnswerUncertain", "The SDK does not act on an answer that is uncertain", sourceOpenFailed)
      .cause(answer)};
}

/// The code of a service answer: the result's own code combined with the response's ServiceResult.
template<typename ResponseResult>
ua::StatusCode answered_code(const ResponseResult& result)
{
  ua::StatusCode code = result.status_code();
  if (result.has_value())
    code = ua::detail::combined_status(code, result.value().response_header().service_result());
  return code;
}

/// The outcome of a RegisterServer or RegisterServer2 answer whose code is not Bad. The registrar acts on
/// nothing in the answer: it closes the channel and reports, so the code is kept on the outcome (a Good
/// subcode or an Uncertain code) and the caller decides. An answer holding no response holds no outcome.
template<typename ResponseResult>
ua::Result<RegisterOutcome> reported_outcome(
  const ResponseResult& result, const ua::StatusCode& code, bool usedFallback)
{
  if (!result.has_value())
    return ua::Result<RegisterOutcome>{code};
  return ua::Result<RegisterOutcome>{RegisterOutcome{usedFallback}, code};
}

/// Fire-and-forget courtesy close of a channel the cycle does not use further.
void close_courtesy(ChannelPtr channel)
{
  auto* channelPtr = channel.get();
  channelPtr->close_async([channel = std::move(channel)](ua::VoidResult) mutable {});
}

/// MOVE the move-only channel handle into the close continuation so it outlives the call;
/// the cycle outcome is reported regardless of the close (courtesy) result.
void close_channel(
  ChannelPtr channel, ua::Result<RegisterOutcome> cycleResult, RegisterResultCallback callback)
{
  auto* channelPtr = channel.get();
  channelPtr->close_async(
    [channel = std::move(channel), cycleResult = std::move(cycleResult), callback = std::move(callback)](
      ua::VoidResult) mutable { callback(std::move(cycleResult)); });
}

/// RegisterServer v1 fallback (drops the mDNS discovery configuration).
void send_fallback(
  ChannelPtr channel, ua::RegisteredServer server, RegisterResultCallback callback, bool usedFallback)
{
  ua::RegisterServerRequest request;
  request.server() = std::move(server);

  auto* channelPtr = channel.get();
  channelPtr->register_server_async(std::move(request),
    [channel = std::move(channel), callback = std::move(callback), usedFallback](
      ua::client::SecureChannel::RegisterServerResponseResult result) mutable
    {
      const ua::StatusCode outcome = answered_code(result);

      ua::Result<RegisterOutcome> cycleResult =
        outcome.is_bad() ? make_failure(outcome,
                             "RegisterServerFailed",
                             "RegisterServer (fallback) rejected by discovery server",
                             sourceFallbackRegisterFailed)
                         : reported_outcome(result, outcome, usedFallback);

      close_channel(std::move(channel), std::move(cycleResult), std::move(callback));
    });
}

/// RegisterServer2 with RS2->RS fallback on Bad_ServiceUnsupported.
void send_registration(ChannelPtr channel, ua::RegisteredServer server,
  std::vector<std::shared_ptr<ua::Structure>> discoveryConfiguration, bool preferFallback,
  RegisterResultCallback callback)
{
  if (preferFallback)
  {
    send_fallback(std::move(channel), std::move(server), std::move(callback), /*usedFallback=*/true);
    return;
  }

  ua::RegisterServer2Request request;
  request.server() = server;
  for (const auto& configuration : discoveryConfiguration)
  {
    if (configuration)
      request.discovery_configuration().push_back(ua::RefStructure<ua::Structure>{configuration->clone()});
  }

  auto* channelPtr = channel.get();
  channelPtr->register_server2_async(std::move(request),
    [channel = std::move(channel), server = std::move(server), callback = std::move(callback)](
      ua::client::SecureChannel::RegisterServer2ResponseResult result) mutable
    {
      const ua::StatusCode outcome = answered_code(result);

      // RS2 unsupported -> fall back to RegisterServer v1 on the same channel.
      if (outcome.as_status() == ua::Status::BadServiceUnsupported)
      {
        send_fallback(std::move(channel), std::move(server), std::move(callback), /*usedFallback=*/true);
        return;
      }

      ua::Result<RegisterOutcome> cycleResult = outcome.is_bad()
                                                  ? make_failure(outcome,
                                                      "RegisterServer2Failed",
                                                      "RegisterServer2 rejected by discovery server",
                                                      sourceRegisterFailed)
                                                  : reported_outcome(result, outcome, /*usedFallback=*/false);

      close_channel(std::move(channel), std::move(cycleResult), std::move(callback));
    });
}

/// Open the registration channel (with the resolved server certificate for secured targets),
/// then drive RegisterServer2 / fallback.
void open_and_register(std::shared_ptr<ua::client::CoreClient> client, DiscoveryTarget target,
  std::shared_ptr<const ua::X509Certificate> serverCertificate, ua::RegisteredServer server,
  std::vector<std::shared_ptr<ua::Structure>> discoveryConfiguration, bool preferFallback,
  RegisterResultCallback callback)
{
  ua::client::CoreClient::OpenChannelConfig openConfig;
  openConfig.endpointUrl = target.discoveryUrl;
  openConfig.securityMode = target.messageSecurityMode;
  openConfig.securityPolicyId = target.securityPolicyId.value_or(ua::SecurityPolicyId::None);
  openConfig.serverCertificate = std::move(serverCertificate);

  client->open_channel_async(std::move(openConfig),
    [server = std::move(server),
      discoveryConfiguration = std::move(discoveryConfiguration),
      preferFallback,
      callback = std::move(callback)](ua::client::CoreClient::SecureChannelResult channelResult) mutable
    {
      if (!channelResult.is_good())
      {
        // Connect failure collapses into the same retry-class Result error. A channel opened Uncertain
        // is not used, and is closed.
        const ua::StatusCode opened = channelResult.status_code();
        if (channelResult.has_value())
          close_courtesy(std::make_shared<ua::client::SecureChannel>(std::move(channelResult).value()));
        callback(make_failure(not_good_answer(opened),
          "ChannelOpenFailed",
          "Failed to open channel to discovery server",
          sourceOpenFailed));
        return;
      }

      // The channel handle is move-only; keep it alive on the heap for the cycle so it can be
      // moved into the close continuation regardless of which register path completes.
      auto channel = std::make_shared<ua::client::SecureChannel>(std::move(channelResult).value());

      send_registration(std::move(channel),
        std::move(server),
        std::move(discoveryConfiguration),
        preferFallback,
        std::move(callback));
    });
}

/// The target's policy for a log or ErrorDetail: its URI, or a note that the strongest is wanted.
std::string requested_policy_text(const DiscoveryTarget& target)
{
  if (target.securityPolicyId)
  {
    return std::string{ua::utils::get_security_policy_uri(*target.securityPolicyId)};
  }
  return "the strongest offered";
}

/// Resolve the discovery server's certificate via a session-less GetEndpoints over a None channel,
/// then open the secured registration channel. Required because an authenticated OPN needs the peer
/// certificate, and a conforming LDS rejects None-mode registration channels (Part 4 5.4.5.1). The
/// certificate is re-discovered every cycle (cheap relative to the 60 s cadence); per-target caching
/// is a possible future optimisation.
void fetch_certificate_then_register(std::shared_ptr<ua::client::CoreClient> client, DiscoveryTarget target,
  ua::RegisteredServer server, std::vector<std::shared_ptr<ua::Structure>> discoveryConfiguration,
  bool preferFallback, RegisterResultCallback callback)
{
  ua::client::CoreClient::OpenChannelConfig discoveryConfig;
  discoveryConfig.endpointUrl = target.discoveryUrl;  // None mode + None policy by default

  client->open_channel_async(std::move(discoveryConfig),
    [client,
      target = std::move(target),
      server = std::move(server),
      discoveryConfiguration = std::move(discoveryConfiguration),
      preferFallback,
      callback = std::move(callback)](ua::client::CoreClient::SecureChannelResult channelResult) mutable
    {
      if (!channelResult.is_good())
      {
        // A channel opened Uncertain is not used, and is closed.
        const ua::StatusCode opened = channelResult.status_code();
        if (channelResult.has_value())
          close_courtesy(std::make_shared<ua::client::SecureChannel>(std::move(channelResult).value()));
        callback(make_failure(not_good_answer(opened),
          "DiscoveryChannelOpenFailed",
          "Failed to open discovery channel to fetch the LDS endpoints",
          sourceOpenFailed,
          {{ua::ContextKeys::endpointUrl, target.discoveryUrl}}));
        return;
      }

      auto discoveryChannel = std::make_shared<ua::client::SecureChannel>(std::move(channelResult).value());

      ua::GetEndpointsRequest request;
      request.endpoint_url() = ua::String{target.discoveryUrl};

      auto* channelPtr = discoveryChannel.get();
      channelPtr->get_endpoints_async(std::move(request),
        [client,
          target = std::move(target),
          server = std::move(server),
          discoveryConfiguration = std::move(discoveryConfiguration),
          preferFallback,
          callback = std::move(callback),
          discoveryChannel = std::move(discoveryChannel)](
          ua::client::SecureChannel::GetEndpointsResponseResult result) mutable
        {
          ChannelPtr channelToClose = std::move(discoveryChannel);

          // The endpoints are acted on, so only a Good answer is used.
          const ua::StatusCode status = answered_code(result);
          if (!status.is_good())
          {
            close_courtesy(std::move(channelToClose));
            callback(make_failure(not_good_answer(status),
              "GetEndpointsFailed",
              "GetEndpoints on the discovery server failed",
              sourceOpenFailed,
              {{ua::ContextKeys::endpointUrl, target.discoveryUrl}}));
            return;
          }

          // The endpoint to register over: the target's mode, and its policy when set; otherwise the
          // strongest non-deprecated policy offered for that mode, ranked as the client ranks endpoints.
          const ua::EndpointDescription* chosen =
            detail::choose_registration_endpoint(result.value().endpoints(), target);
          std::shared_ptr<const ua::X509Certificate> serverCertificate;
          if (chosen != nullptr)
          {
            target.securityPolicyId = ua::utils::get_security_policy_id(chosen->security_policy_uri());
            if (auto crypto = client->crypto())
            {
              // Answered, not thrown: this runs in the client's completion, which would swallow an
              // exception and leave the registration cycle without an answer.
              auto parsed = detail::registration_server_certificate(*crypto, *chosen);
              if (!parsed.is_good())
              {
                close_courtesy(std::move(channelToClose));
                callback(make_failure(parsed.status_code(),
                  "ServerCertificateUnparsable",
                  "The discovery server's endpoint carries a server certificate that does not parse",
                  sourceOpenFailed,
                  {{ua::ContextKeys::endpointUrl, target.discoveryUrl}}));
                return;
              }
              serverCertificate = std::move(parsed).value();
            }
          }

          close_courtesy(std::move(channelToClose));

          if (!serverCertificate)
          {
            callback(make_failure(ua::StatusCode{ua::Status::BadCertificateInvalid},
              "ServerCertificateUnavailable",
              "No matching secured endpoint with a server certificate on the discovery server",
              sourceOpenFailed,
              {{ua::ContextKeys::endpointUrl, target.discoveryUrl},
                {ua::ContextKeys::securityPolicy, requested_policy_text(target)},
                {ua::ContextKeys::securityMode, ua::to_string(target.messageSecurityMode)}}));
            return;
          }

          open_and_register(std::move(client),
            std::move(target),
            std::move(serverCertificate),
            std::move(server),
            std::move(discoveryConfiguration),
            preferFallback,
            std::move(callback));
        });
    });
}

}  // namespace

namespace detail
{

const ua::EndpointDescription* choose_registration_endpoint(
  const ua::Array<ua::EndpointDescription>& endpoints, const DiscoveryTarget& target)
{
  const ua::EndpointDescription* chosen = nullptr;
  int chosenScore = 0;
  for (const auto& endpoint : endpoints)
  {
    if (endpoint.security_mode() != target.messageSecurityMode)
    {
      continue;
    }
    const int score = ua::client::default_easy_connect_ranker(endpoint);
    if (score <= 0)
    {
      continue;  // a policy this SDK does not implement
    }
    const ua::SecurityPolicyId policyId = ua::utils::get_security_policy_id(endpoint.security_policy_uri());
    if (target.securityPolicyId)
    {
      if (policyId != *target.securityPolicyId)
      {
        continue;
      }
    }
    else if (ua::utils::is_deprecated_security_policy(policyId))
    {
      continue;
    }
    bool outranks = chosen == nullptr || score > chosenScore;
    if (!outranks && score == chosenScore)
    {
      outranks = endpoint.security_level() > chosen->security_level() ||
                 (endpoint.security_level() == chosen->security_level() &&
                   endpoint.security_policy_uri() < chosen->security_policy_uri());
    }
    if (outranks)
    {
      chosen = &endpoint;
      chosenScore = score;
    }
  }
  return chosen;
}

ua::Result<std::shared_ptr<const ua::X509Certificate>> registration_server_certificate(
  const ua::Crypto& crypto, const ua::EndpointDescription& chosen)
{
  const auto& der = chosen.server_certificate();
  if (der.empty())
    return ua::Result<std::shared_ptr<const ua::X509Certificate>>{
      std::shared_ptr<const ua::X509Certificate>{}};
  // The one chain parser: the field may carry the issuers after the leaf.
  auto parsed = ua::detail::parse_certificate_field(crypto, der);
  if (!parsed.is_good())
    return ua::Result<std::shared_ptr<const ua::X509Certificate>>{parsed.status_code()};
  return ua::Result<std::shared_ptr<const ua::X509Certificate>>{std::move(parsed).value().front()};
}

}  // namespace detail

ClientLdsRegistrar::ClientLdsRegistrar(std::shared_ptr<ua::client::CoreClient> client) noexcept
  : mClient(std::move(client))
{}

ClientLdsRegistrar::~ClientLdsRegistrar() = default;

void ClientLdsRegistrar::register_async(DiscoveryTarget target, ua::RegisteredServer server,
  std::vector<std::shared_ptr<ua::Structure>> discoveryConfiguration, bool preferFallback,
  RegisterResultCallback callback) noexcept
{
  // This facade is noexcept (the LdsRegistrar contract says it never throws), but the cycle setup
  // below can throw (e.g. bad_alloc when building requests/configs or the std::function wrappers).
  // Keep a surviving copy of the callback so that if any step throws before the work is queued the
  // error is reported synchronously rather than escaping the noexcept boundary or being silently
  // dropped (never discard an error at a boundary).
  RegisterResultCallback reportFailure = callback;
  try
  {
    if (!mClient)
    {
      callback(make_failure(ua::StatusCode{ua::Status::BadInvalidState},
        "ClientUnavailable",
        "LDS registrar has no client",
        sourceOpenFailed,
        {{ua::ContextKeys::endpointUrl, target.discoveryUrl}}));
      return;
    }

    // A mode and a policy that contradict each other are refused, never corrected: None with a secured
    // policy, or a secured mode with the None policy.
    const bool unsecuredMode = target.messageSecurityMode == ua::MessageSecurityMode::None;
    const bool nonePolicy = target.securityPolicyId == ua::SecurityPolicyId::None;
    if ((unsecuredMode && target.securityPolicyId && !nonePolicy) || (!unsecuredMode && nonePolicy))
    {
      callback(make_failure(ua::StatusCode{ua::Status::BadInvalidArgument},
        "DiscoveryTargetSecurityMismatch",
        "The discovery target's security mode and security policy contradict each other",
        sourceOpenFailed,
        {{ua::ContextKeys::endpointUrl, target.discoveryUrl},
          {ua::ContextKeys::securityPolicy, requested_policy_text(target)},
          {ua::ContextKeys::securityMode, ua::to_string(target.messageSecurityMode)}}));
      return;
    }

    // An unsecured (None) target needs no server certificate - open directly. A secured target
    // requires the LDS peer certificate to encrypt the asymmetric OPN, so first resolve it via a
    // session-less GetEndpoints over a None channel, then open the secured registration channel.
    if (target.messageSecurityMode == ua::MessageSecurityMode::None)
    {
      open_and_register(mClient,
        std::move(target),
        /*serverCertificate=*/nullptr,
        std::move(server),
        std::move(discoveryConfiguration),
        preferFallback,
        std::move(callback));
      return;
    }

    fetch_certificate_then_register(mClient,
      std::move(target),
      std::move(server),
      std::move(discoveryConfiguration),
      preferFallback,
      std::move(callback));
  }
  catch (...)
  {
    // Cycle setup threw before the async work was queued, so no continuation will ever fire. Report
    // synchronously via the surviving callback copy so the failure is never silently dropped.
    reportFailure(make_failure(ua::exception_to_status_code(std::current_exception()),
      "RegistrationSetupFailed",
      "Failed to start the discovery registration cycle",
      sourceOpenFailed));
  }
}

}  // namespace ua::app
