// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Policy for the discovery-driven managed-connect facade @ref ua::client::Client::easy_connect_async.
/// @ingroup client

#ifndef UA_EASY_CONNECT_POLICY_H
#define UA_EASY_CONNECT_POLICY_H

#include "ua_connection_config.h"
#include "ua_user_identity.h"

#include "ua_status_code.h"

#include <chrono>
#include <functional>
#include <optional>
#include <string>

namespace ua
{
class EndpointDescription;
class X509Certificate;
}  // namespace ua

namespace ua::client
{

/// @ingroup client
/// The application's answer to "the server's certificate is not trusted - now what?"
///
/// Returned by `EasyConnectConfig::trustPrompt`. This is a decision, not a notification, which is
/// why it lives on the policy struct and not on an observer: a fire-and-forget observer is the wrong
/// shape for a question whose answer gates the connect (client design section 7.3A).
enum class TrustDecision
{
  /// Abandon the connect. `easy_connect_async` fails with `Bad_SecurityChecksFailed` chained to the
  /// underlying validation cause, so the rejection reason survives in the `ErrorDetail` chain.
  Reject,
  /// Connect, trusting this certificate for THIS Connection only. Nothing is written to the
  /// certificate store, so the next process run asks again.
  AcceptForThisSession,
  /// Write the certificate to the store's trusted-certificates directory, re-validate, and connect.
  /// The decision persists: subsequent connects validate cleanly with no prompt.
  AcceptAndPersist,
};

/// Inputs to @ref Client::easy_connect_async - the discovery-driven connect path (client design
/// section 7.3A).
///
/// `connect_async` is the power-user entry: it takes a fully-built @ref ConnectionConfig and assumes
/// the caller has already done the discovery and trust-decision work. `EasyConnectConfig` is the
/// other end of that trade - name a URL, and the SDK performs GetEndpoints, ranks the endpoints by
/// security, validates the server certificate, asks you about it if it is not trusted, and connects.
///
/// The happy path for a trusted server is one line:
/// @code
/// auto connection = client.easy_connect_sync(EasyConnectConfig{.endpointUrl = url});
/// @endcode
///
/// @note Endpoint ranking here is the same ordering that @ref EndpointSelection::AutoBest applies
///       inside `connect_async` (the same score table, the advertised `securityLevel` as the tie-break,
///       then the `(policy URI, mode)` tuple; deprecated policies are filtered from the list unless the
///       application allows them, and an unsecured endpoint needs the respective opt-in); what this policy
///       adds on top is the discovery hand-off and the trust-prompt exchange.
/// @ingroup client
/// @see Client::easy_connect_async, TrustDecision, default_easy_connect_ranker
struct EasyConnectConfig
{
  /// Discovery URL to query and connect to (e.g. `opc.tcp://host:4840`). Required.
  std::string endpointUrl;

  /// User identity for the session. Defaults to anonymous.
  UserIdentity identity = AnonymousIdentity{};

  /// Invoked when the chosen endpoint's server certificate fails validation on a **trust** class
  /// (`Bad_CertificateUntrusted` / `Bad_CertificateChainIncomplete`) - never for any other failure,
  /// which fails straight through unprompted.
  ///
  /// Receives the decoded server certificate and the validation StatusCode that triggered the
  /// prompt, and returns the application's @ref TrustDecision. Invoked at most once per connect,
  /// from the easy-connect flow's executor; it must not block for long (a UI prompt should be
  /// marshalled, not run inline).
  ///
  /// **Null is the safe production default**: with no prompt configured an untrusted certificate is
  /// a hard failure (`client.tier1.easy_connect.trust_unconfigured`), never a silent accept.
  std::function<TrustDecision(
    const ua::X509Certificate& serverCertificate, ua::StatusCode validationFailureReason)>
    trustPrompt;

  /// Scores each endpoint returned by GetEndpoints; the highest score wins. Null uses
  /// @ref default_easy_connect_ranker. A custom ranker REPLACES the default entirely, so it owns
  /// the whole security-preference decision; ties are broken deterministically either way, by the higher
  /// advertised `securityLevel` and then the caller-visible `(policy URI, security mode)` ordering. An
  /// unsecured endpoint (mode None or policy None) still needs @ref allowAnonymousFirstConnect, whatever
  /// the ranker scores it.
  std::function<int(const ua::EndpointDescription&)> ranker;

  /// Permits an unsecured endpoint (MessageSecurityMode `None` or SecurityPolicy `None`) to win, for
  /// bootstrap-onboarding ("trust on first use") flows, and only with an @ref AnonymousIdentity.
  ///
  /// Default `false`: an unsecured winner is always refused - even when the server offers only
  /// unsecured endpoints - because the endpoint list is unauthenticated and a list without secured
  /// endpoints cannot be told from one that was stripped in transit (CL-DISC-019). When `true`, a
  /// non-anonymous identity over an unsecured winner is still refused (the secret would travel in
  /// clear), an unsecured winner on a host other than the dialled one is still refused, the gate is
  /// applied again after @ref customize ran, and every unsecured connect logs a warning. Creating the
  /// Session additionally requires the process-wide `ApplicationConfig::allowInsecureEndpoints`.
  bool allowAnonymousFirstConnect = false;

  /// Deadline applied SEPARATELY to the discovery call and to the connect - it is not one budget
  /// spanning the path. `nullopt` defers to the client default.
  ///
  /// It does NOT bound @ref trustPrompt. The prompt is invoked between those two operations, with
  /// no timer running, so a prompt that waits on a person waits indefinitely as far as the SDK is
  /// concerned. If your application must not hang on an unanswered question, impose your own
  /// deadline inside the prompt and return TrustDecision::Reject when it expires.
  std::optional<std::chrono::milliseconds> timeout;

  /// Applied to the assembled @ref ConnectionConfig immediately before connecting, after endpoint,
  /// identity and trust are resolved. The composability hook: tune reconnect / keep-alive / cache
  /// policy without abandoning the easy path for the manual
  /// GetEndpoints + rank + trust + `ConnectionConfig` route. Observers are set at Client level and
  /// are not duplicated here.
  std::function<void(ConnectionConfig&)> customize;

  /// A policy that auto-accepts an untrusted server certificate, for development against
  /// self-signed or TOFU servers.
  ///
  /// A **named factory, deliberately not a `bool` flag**: a boolean "insecure" toggle is a
  /// production footgun that reads as innocuous in a config file, whereas a call to a function with
  /// this name does not survive code review by accident. Emits one loud warning per process the
  /// first time its prompt fires.
  ///
  /// @param endpointUrl Discovery URL to connect to.
  /// @return A policy whose @ref trustPrompt returns @ref TrustDecision::AcceptForThisSession.
  /// @warning Never use in production. It auto-accepts any certificate this client has not been
  ///          told about, which is the whole of server authentication as far as IDENTITY is
  ///          concerned - you cannot know you reached the machine you meant. It does not turn off
  ///          the checks that catch a DEFECTIVE certificate: expiry, revocation, host name and
  ///          policy all still run and still fail, because the prompt is only reached on
  ///          Bad_CertificateUntrusted and Bad_CertificateChainIncomplete. It also sets
  ///          @ref allowAnonymousFirstConnect, so an unsecured endpoint may win - with the default
  ///          anonymous identity only; a user name over an unsecured winner is still refused.
  ///          The null-`trustPrompt` default hard-fails instead, which is what you want.
  [[nodiscard]] static EasyConnectConfig accept_all_for_development(std::string endpointUrl);
};

/// The default endpoint ranking used by @ref Client::easy_connect_async (client design section 7.3A).
///
/// Scores security strength so that the strongest endpoint the client supports wins:
/// - policy: 100 per tier of the SDK's security ordering, the one the server's `securityLevel` uses
///   (@ref compute_security_level "compute_security_level": every policy with SecureChannelEnhancements above
///   every policy without them, NIST curves one tier below Brainpool and RSA_DH, Bernstein curves one above);
///   of the tier-0 policies `Basic256` scores 10, `None` 1 and the rest 0
/// - mode:   `SignAndEncrypt` 20, `Sign` 10, `None` 1, so the policy always dominates the mode; a
///   mode outside the enumeration makes the score 0
/// - score = policy + mode, except that an unsecured endpoint (mode `None` or policy `None`) always scores
///   as `None`/`None` (2): it is neither signed nor encrypted whatever its other half says, so it never
///   outranks a secured endpoint, however an unauthenticated endpoint list labels it (CL-DISC-019).
///
/// Ties are broken by the caller on the higher advertised `securityLevel`, then lexicographically on
/// `(policy URI, security mode)`, so ranking is
/// deterministic across runs and across servers that return endpoints in arbitrary order.
///
/// @param endpoint The endpoint to score.
/// @return The endpoint's score; higher wins. Unsupported policies score 0.
/// @ingroup client
[[nodiscard]] int default_easy_connect_ranker(const ua::EndpointDescription& endpoint);

}  // namespace ua::client

#endif  // !UA_EASY_CONNECT_POLICY_H
