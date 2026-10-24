// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Resolves an EasyConnectConfig into a connectable ConnectionConfig (client design section 7.3A).
//
// Discovery -> rank -> decode -> validate -> (trust prompt) -> build config -> customize. The final
// connect stays with Client::easy_connect_async so every decision made here is observable in the
// resolved config (or the ErrorDetail), which is what makes the whole surface unit-testable.

#include "ua_easy_connect.h"

#include "ua_session_trust_store.h"
#include "ua_client_answer_status.h"

#include "ua_certificate_store.h"
#include "ua_endpoint_description.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_security_policy.h"
#include "ua_user_identity.h"
#include "ua_user_token_policy.h"
#include "ua_user_token_type.h"
#include "ua_url_parser.h"
#include "ua_utilities.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>

namespace ua::client
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

// The policy dominates the mode: a policy's points are 100 per tier of the SDK's one security ordering
// (decision D-7, shared with the server's securityLevel), and no mode adds 100.
int policy_points(ua::SecurityPolicyId id) noexcept
{
  if (const int tier = ua::security_policy_tier(id); tier > 0)
    return 100 * tier;
  // Tier 0 is "not recommended"; these two stay reachable below every ranked policy (a deprecated policy
  // only where the application allows it, None only with the per-connection opt-in).
  switch (id)
  {
  case ua::SecurityPolicyId::Basic256:
    return 10;
  case ua::SecurityPolicyId::None:
    return 1;
  default:
    return 0;
  }
}

int mode_points(ua::MessageSecurityMode mode) noexcept
{
  switch (mode)
  {
  case ua::MessageSecurityMode::SignAndEncrypt:
    return 20;
  case ua::MessageSecurityMode::Sign:
    return 10;
  case ua::MessageSecurityMode::None:
    return 1;
  default:
    return 0;
  }
}
}  // namespace

int default_easy_connect_ranker(const ua::EndpointDescription& endpoint)
{
  const auto id = supported_policy_id(endpoint.security_policy_uri());
  if (!id)
  {
    return 0;  // unsupported policy - never a winner
  }
  const int points = policy_points(*id);
  if (points == 0)
  {
    return 0;
  }
  // CL-DISC-019: an unsecured endpoint (mode None or policy None) is neither signed nor encrypted whatever
  // its other half says, so it scores as None/None and never outranks a secured endpoint. Without this an
  // unauthenticated list could name an ECC policy under mode None and outscore every RSA secured offer.
  if (*id == ua::SecurityPolicyId::None || endpoint.security_mode() == ua::MessageSecurityMode::None)
  {
    return policy_points(ua::SecurityPolicyId::None) + mode_points(ua::MessageSecurityMode::None);
  }
  // A mode outside the enumeration secures nothing the client can name, so it never wins on its policy.
  const int mode = mode_points(endpoint.security_mode());
  if (mode == 0)
  {
    return 0;
  }
  return points + mode;
}

EasyConnectConfig EasyConnectConfig::accept_all_for_development(std::string endpointUrl)
{
  EasyConnectConfig policy;
  policy.endpointUrl = std::move(endpointUrl);
  policy.allowAnonymousFirstConnect = true;
  policy.trustPrompt = [](const ua::X509Certificate&, ua::StatusCode) noexcept
  {
    // One loud warning per process: this factory disables server authentication, and a build that
    // reaches production with it must be noisy enough that somebody notices. Written to stderr
    // rather than the Logger deliberately - the warning must survive a process with no log sink
    // configured, which is exactly the throwaway-development setup this factory exists for.
    static std::once_flag warned;
    std::call_once(warned,
      []
      {
        std::fputs(
          "[SECURITY WARNING] ua::client::EasyConnectConfig::accept_all_for_development is in "
          "use: any server certificate this client has not been told about is accepted, so the "
          "server is NOT authenticated - you cannot know you reached the machine you meant. "
          "Defect checks (expiry, revocation, host name, policy) still run and still fail; it is "
          "the identity decision that is disabled. This must never ship to production.\n",
          stderr);
      });
    return TrustDecision::AcceptForThisSession;
  };
  return policy;
}

}  // namespace ua::client

namespace ua::client::detail
{
namespace
{
constexpr std::string_view discoverySource = "client.tier1.easy_connect.discovery";
constexpr std::string_view selectionSource = "client.tier1.easy_connect.selection";
constexpr std::string_view decodeSource = "client.tier1.easy_connect.certificate_decode";
constexpr std::string_view trustUnconfiguredSource = "client.tier1.easy_connect.trust_unconfigured";
constexpr std::string_view userRejectedSource = "client.tier1.easy_connect.user_rejected";
constexpr std::string_view persistSource = "client.tier1.easy_connect.trust_persist";
constexpr std::string_view validationSource = "client.tier1.easy_connect.certificate_validation";

using ResolutionResult = EasyConnectResolutionResult;

/// Per-call flow state. Heap-held so it survives the async hops; every continuation captures it
/// strongly because the flow - not a component - owns this work.
struct Flow
{
  EasyConnectDeps deps;
  ua::client::EasyConnectConfig policy;
  EasyConnectResolutionCallback callback;
  ua::EndpointDescription endpoint;
  std::vector<ua::EndpointDescription> discoveryEndpoints;
  std::shared_ptr<const ua::X509Certificate> certificate;
  /// The issuers the server presented with @ref certificate, validated with it (decision 24).
  std::vector<std::shared_ptr<const ua::X509Certificate>> presentedIssuers;
  bool prompted{false};
  /// Whether the ranked list held a supported secured endpoint (names the refusal when an unsecured
  /// configuration is caught after `customize`).
  bool securedWasOffered{false};

  void complete(ResolutionResult result)
  {
    if (auto cb = std::exchange(callback, nullptr))
    {
      cb(std::move(result));
    }
  }

  /// Completes the flow with a failure. @p cause is the status whose ErrorDetail becomes the
  /// inner link of the chain; it defaults to @p status, which is right whenever the reported
  /// status IS the root cause. Pass the underlying failure explicitly where the reported status
  /// is a summary of something more specific - a rejected trust prompt reports
  /// Bad_SecurityChecksFailed, but the reason the prompt was shown at all
  /// (Bad_CertificateUntrusted, Bad_CertificateChainIncomplete, ...) is what a caller needs to
  /// diagnose it, and dropping it leaves the caller a leaf status and nothing behind it.
  void fail(ua::StatusCode status, std::string code, std::string summary, std::string_view source,
    std::optional<ua::StatusCode> cause = std::nullopt)
  {
    complete(ResolutionResult{ua::StatusCode{status.as_status(),
      ua::ErrorDetail::build(std::move(code), "EasyConnect configuration failed", std::string{source})
        .context(ua::ContextKeys::errorMessage, summary)
        .cause(cause.value_or(status))}});
  }
};

/// The UserTokenType a client identity activates under.
///
/// Mirrors `build_user_token`'s own mapping. Anonymous is absent on purpose: tier-0 already selects the
/// endpoint's ANONYMOUS policy at activation, and naming it here would change nothing.
std::optional<ua::UserTokenType> token_type_for(const ua::client::UserIdentity& identity) noexcept
{
  if (std::holds_alternative<ua::client::UsernamePasswordIdentity>(identity))
  {
    return ua::UserTokenType::UserName;
  }
  if (std::holds_alternative<ua::client::X509Identity>(identity))
  {
    return ua::UserTokenType::Certificate;
  }
  if (std::holds_alternative<ua::client::IssuedTokenIdentity>(identity))
  {
    return ua::UserTokenType::IssuedToken;
  }
  return std::nullopt;
}

/// Names the UserTokenPolicy on @p endpoint that @p identity activates under, if it advertises one.
///
/// A non-anonymous identity cannot be sent without a policy id (Part 4 section 7.42: the token carries the
/// policyId the endpoint advertised, and the client may not invent one). This resolver has just chosen the
/// endpoint, so it is the only place on the managed path that holds the advertised list. When the endpoint
/// advertises no policy of the required kind the id is left empty, so the refusal comes from the token
/// builder with its own diagnosis rather than from a policy id the server never offered.
std::string select_user_token_policy_id(
  const ua::EndpointDescription& endpoint, const ua::client::UserIdentity& identity)
{
  const auto wanted = token_type_for(identity);
  if (!wanted)
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
  for (const auto& candidate : endpoint.user_identity_tokens())
  {
    if (candidate.token_type() != *wanted)
    {
      continue;
    }
    const auto tokenPolicyUri = candidate.security_policy_uri();
    if (!tokenPolicyUri.empty() &&
        tokenPolicyUri == ua::utils::get_security_policy_uri(ua::SecurityPolicyId::None))
    {
      if (!fallback)
      {
        fallback = &candidate;
      }
      continue;
    }
    return std::string{candidate.policy_id()};
  }
  return fallback ? std::string{fallback->policy_id()} : std::string{};
}

/// CL-DISC-019: mode None or policy None. Either alone leaves the channel unauthenticated. Takes the policy
/// id rather than a URI so that an id `customize` may have set to a value no policy implements (Invalid, the
/// PubSub ids) is compared, never converted: the conversion throws, and this runs inside a completion.
bool is_unsecured(ua::MessageSecurityMode mode, std::optional<ua::SecurityPolicyId> policy)
{
  return mode == ua::MessageSecurityMode::None || policy == ua::SecurityPolicyId::None;
}

/// An unsecured endpoint has no certificate to bind the host it names, so one on a host other than the
/// dialled one is a redirect the client cannot verify. Refused rather than rewritten (E-D2).
bool unsecured_endpoint_is_on_dialled_host(const std::string& dialledUrl, const std::string& advertisedUrl)
{
  const auto dialled = ua::transport::parse_opc_tcp_url(dialledUrl, std::string{selectionSource});
  const auto advertised = ua::transport::parse_opc_tcp_url(advertisedUrl, std::string{selectionSource});
  return dialled.is_good() && advertised.is_good() &&
         ua::transport::matches_host(dialled.value(), advertised.value());
}

/// The unsecured-winner gate, applied to the ranked winner and again to the assembled configuration
/// (after `customize`, which may change the mode, the policy, the identity or the URL). Returns true when
/// the flow may continue.
bool admit_unsecured(const std::shared_ptr<Flow>& flow, const std::string& endpointUrl,
  const ua::client::UserIdentity& identity, bool securedWasOffered)
{
  if (!flow->policy.allowAnonymousFirstConnect)
  {
    if (securedWasOffered)
    {
      // A secured endpoint was on offer but an unsecured one won: refuse rather than silently
      // downgrade. Opt in with allowAnonymousFirstConnect for genuine bootstrap flows.
      flow->fail(ua::StatusCode{ua::Status::BadSecurityModeRejected},
        "EasyConnectRefusedDowngrade",
        "the highest-ranked endpoint is unsecured while the server also offers a secured endpoint; "
        "set EasyConnectConfig::allowAnonymousFirstConnect to permit this",
        selectionSource);
      return false;
    }
    flow->fail(ua::StatusCode{ua::Status::BadSecurityModeRejected},
      "EasyConnectRefusedUnsecured",
      "the highest-ranked endpoint is unsecured and no secured endpoint this client supports was offered; "
      "the "
      "endpoint list is unauthenticated, so a list without secured endpoints may have been stripped in "
      "transit - "
      "set EasyConnectConfig::allowAnonymousFirstConnect only for a bootstrap connect",
      selectionSource);
    return false;
  }
  if (!std::holds_alternative<ua::client::AnonymousIdentity>(identity))
  {
    flow->fail(ua::StatusCode{ua::Status::BadSecurityModeRejected},
      "EasyConnectUnsecuredRequiresAnonymous",
      "allowAnonymousFirstConnect admits an unsecured endpoint for an anonymous identity only; a user "
      "token over an unsecured channel would travel in clear",
      selectionSource);
    return false;
  }
  if (!unsecured_endpoint_is_on_dialled_host(flow->policy.endpointUrl, endpointUrl))
  {
    flow->fail(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      "UnsecuredEndpointHostChanged",
      "the unsecured endpoint " + endpointUrl + " names a host other than the one dialled (" +
        flow->policy.endpointUrl + "); without a server certificate nothing binds the advertised host",
      selectionSource);
    return false;
  }
  return true;
}

/// Builds the ConnectionConfig from the resolved endpoint + certificate, applies `customize` LAST so
/// the caller's tuning wins, and completes.
void finish(const std::shared_ptr<Flow>& flow, std::shared_ptr<ua::CertificateStore> sessionOverride)
{
  ua::client::ConnectionConfig config;
  config.endpointUrl = std::string{flow->endpoint.endpoint_url()};
  config.endpointSelection = ua::client::EndpointSelection::ExactUrl;
  config.securityMode = flow->endpoint.security_mode();
  if (const auto id = supported_policy_id(flow->endpoint.security_policy_uri()))
  {
    config.securityPolicyId = *id;
  }
  config.serverCertificate = flow->certificate;
  config.identity = flow->policy.identity;
  config.userTokenPolicyId = select_user_token_policy_id(flow->endpoint, config.identity);
  config.connectTimeout = flow->policy.timeout;
  // AcceptForThisSession: the override lives only as long as this Connection, so the decision is
  // NOT persisted and the next process run asks again (client design section 7.3A step 4).
  config.trustStoreOverride = std::move(sessionOverride);

  if (flow->policy.customize)
  {
    flow->policy.customize(config);
  }
  // CL-DISC-019: the gate runs again on what will actually be connected, because `customize` may have
  // lowered the mode or the policy, swapped the identity or moved the URL after the winner was checked.
  if (is_unsecured(config.securityMode, config.securityPolicyId))
  {
    if (!admit_unsecured(flow, config.endpointUrl, config.identity, flow->securedWasOffered))
    {
      return;
    }
    flow->deps.logger.warning(
      "easy_connect is connecting to the unsecured endpoint {} "
      "(EasyConnectConfig::allowAnonymousFirstConnect is set): the channel is neither "
      "signed nor encrypted and the server is not authenticated",
      config.endpointUrl);
  }
  flow->complete(
    ResolutionResult{EasyConnectResolution{std::move(config), std::move(flow->discoveryEndpoints)}});
}

void run_trust_prompt(const std::shared_ptr<Flow>& flow, ua::StatusCode failure);

/// Validates the decoded certificate, escalating ONLY a trust-class failure to the prompt.
void validate_step(const std::shared_ptr<Flow>& flow)
{
  if (!flow->deps.validate)
  {
    finish(flow, nullptr);  // no validator wired (e.g. a None endpoint): nothing to check
    return;
  }
  flow->deps.validate(flow->certificate,
    flow->presentedIssuers,
    std::string{flow->endpoint.endpoint_url()},
    [flow](ua::VoidResult verdict)
    {
      if (verdict.is_good())
      {
        finish(flow, nullptr);
        return;
      }
      const auto status = verdict.status_code();
      if (!is_trust_class_failure(status))
      {
        // Malformed / expired / revoked: never promptable, so a permissive prompt cannot wave it past.
        flow->fail(status,
          "EasyConnectCertificateInvalid",
          "the server certificate failed validation for a reason that is not a trust decision",
          validationSource);
        return;
      }
      if (flow->prompted)
      {
        // Re-validation after AcceptAndPersist still says untrusted - do not loop.
        flow->fail(status,
          "EasyConnectPersistDidNotEstablishTrust",
          "the server certificate was persisted to the trusted store but still failed validation",
          persistSource);
        return;
      }
      run_trust_prompt(flow, status);
    });
}

void run_trust_prompt(const std::shared_ptr<Flow>& flow, ua::StatusCode failure)
{
  if (!flow->policy.trustPrompt)
  {
    // The safe production default: no prompt configured means an untrusted server is a hard failure,
    // never a silent accept.
    flow->fail(failure,
      "EasyConnectTrustUnconfigured",
      "the server certificate is not trusted and EasyConnectConfig::trustPrompt is not set",
      trustUnconfiguredSource);
    return;
  }

  flow->prompted = true;
  const auto decision = flow->policy.trustPrompt(*flow->certificate, failure);
  switch (decision)
  {
  case ua::client::TrustDecision::Reject:
    // Chain the validation failure that caused the prompt. Without it the caller reads
    // Bad_SecurityChecksFailed and cannot tell an untrusted certificate from an incomplete
    // chain from an expired one - which is exactly the question they are debugging.
    flow->fail(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      "EasyConnectUserRejected",
      "the application rejected the server certificate at the trust prompt",
      userRejectedSource,
      failure);
    return;

  case ua::client::TrustDecision::AcceptForThisSession:
  {
    // Trust this certificate for THIS Connection only. The override must be a store that ACCEPTS
    // the certificate - handing back the runtime store would hand back the very store that just
    // rejected it - so wrap it in a SessionTrustStore that validates this one thumbprint and
    // delegates everything else. Nothing is written to the runtime store.
    auto store = flow->deps.storeAccessor ? flow->deps.storeAccessor() : nullptr;
    if (!store)
    {
      flow->fail(ua::StatusCode{ua::Status::BadInvalidState},
        "EasyConnectNoCertificateStore",
        "AcceptForThisSession needs a certificate store to delegate to, but none is configured",
        validationSource);
      return;
    }
    finish(flow, std::make_shared<SessionTrustStore>(std::move(store), flow->certificate));
    return;
  }

  case ua::client::TrustDecision::AcceptAndPersist:
  {
    auto store = flow->deps.storeAccessor ? flow->deps.storeAccessor() : nullptr;
    if (!store)
    {
      flow->fail(ua::StatusCode{ua::Status::BadInvalidState},
        "EasyConnectNoCertificateStore",
        "AcceptAndPersist needs a certificate store, but none is configured",
        persistSource);
      return;
    }
    store->add_to_trusted_certificates_async(flow->certificate,
      [flow](ua::VoidResult written)
      {
        if (written.is_bad())
        {
          flow->fail(written.status_code(),
            "EasyConnectTrustPersistFailed",
            "the server certificate could not be written to the trusted-certificates store",
            persistSource);
          return;
        }
        validate_step(flow);  // re-validate; `prompted` guards against a prompt loop
      });
    return;
  }
  }
}

/// Ranks the discovered endpoints and pins the winner.
void select_step(const std::shared_ptr<Flow>& flow, std::vector<ua::EndpointDescription> endpoints)
{
  if (endpoints.empty())
  {
    flow->fail(ua::StatusCode{ua::Status::BadNotFound},
      "EasyConnectNoEndpoints",
      "GetEndpoints returned no endpoints for the requested URL",
      selectionSource);
    return;
  }

  const auto& ranker = flow->policy.ranker ? flow->policy.ranker : ua::client::default_easy_connect_ranker;

  const ua::EndpointDescription* best = nullptr;
  const ua::EndpointDescription* unsecuredElsewhere = nullptr;
  int bestScore = 0;
  bool anySecuredOffered = false;
  for (const auto& endpoint : endpoints)
  {
    const auto id = supported_policy_id(endpoint.security_policy_uri());
    if (id && *id != ua::SecurityPolicyId::None && endpoint.security_mode() != ua::MessageSecurityMode::None)
    {
      anySecuredOffered = true;
    }
    const int score = ranker(endpoint);
    if (score <= 0)
    {
      continue;  // unsupported / rejected by the ranker
    }
    // CL-DISC-019: an unsecured copy on another host is never the winner while a copy on the dialled host
    // (a multi-homed server lists one per host name) may be; the first such copy names the refusal when
    // nothing else is selectable.
    if (is_unsecured(endpoint.security_mode(), id) &&
        !unsecured_endpoint_is_on_dialled_host(
          flow->policy.endpointUrl, std::string{endpoint.endpoint_url()}))
    {
      if (unsecuredElsewhere == nullptr)
      {
        unsecuredElsewhere = &endpoint;
      }
      continue;
    }
    // Ties: the advertised securityLevel first (the same tie-break AutoBest applies), then the (policy URI,
    // mode) tuple, so both entry points open the same endpoint from the same list.
    if (best == nullptr || score > bestScore ||
        (score == bestScore && (endpoint.security_level() > best->security_level() ||
                                 (endpoint.security_level() == best->security_level() &&
                                   std::tuple{endpoint.security_policy_uri(), endpoint.security_mode()} <
                                     std::tuple{best->security_policy_uri(), best->security_mode()}))))
    {
      best = &endpoint;
      bestScore = score;
    }
  }

  if (best == nullptr && unsecuredElsewhere != nullptr && flow->policy.allowAnonymousFirstConnect)
  {
    flow->fail(ua::StatusCode{ua::Status::BadSecurityChecksFailed},
      "UnsecuredEndpointHostChanged",
      "the only selectable endpoints are unsecured and name a host other than the one dialled (" +
        flow->policy.endpointUrl + "); without a server certificate nothing binds the advertised host",
      selectionSource);
    return;
  }
  if (best == nullptr && unsecuredElsewhere != nullptr)
  {
    best =
      unsecuredElsewhere;  // refused below by the opt-in gate, which names the reason a caller can act on
  }
  if (best == nullptr)
  {
    flow->fail(ua::StatusCode{ua::Status::BadSecurityPolicyRejected},
      "EasyConnectNoSupportedEndpoint",
      "no endpoint returned by GetEndpoints uses a SecurityPolicy this client supports",
      selectionSource);
    return;
  }

  // CL-DISC-019: an unsecured winner is refused unless the caller opted in - whether or not a secured
  // endpoint was also listed, because the list is unauthenticated and "only None offered" is what a stripped
  // list looks like.
  if (is_unsecured(best->security_mode(), supported_policy_id(best->security_policy_uri())) &&
      !admit_unsecured(flow, std::string{best->endpoint_url()}, flow->policy.identity, anySecuredOffered))
  {
    return;
  }
  flow->securedWasOffered = anySecuredOffered;

  flow->endpoint = *best;
  flow->discoveryEndpoints = std::move(endpoints);

  if (flow->endpoint.server_certificate().empty())
  {
    // A None endpoint legitimately advertises no certificate: nothing to decode or validate.
    finish(flow, nullptr);
    return;
  }
  if (!flow->deps.decodeCertificate)
  {
    flow->fail(ua::StatusCode{ua::Status::BadInvalidState},
      "EasyConnectNoCertificateDecoder",
      "the easy-connect flow has no server-certificate decoder",
      decodeSource);
    return;
  }

  auto decoded = flow->deps.decodeCertificate(flow->endpoint.server_certificate());
  if (!decoded.is_good())
  {
    flow->fail(decoded.status_code(),
      "EasyConnectCertificateDecodeFailed",
      "the server certificate advertised by GetEndpoints could not be decoded",
      decodeSource);
    return;
  }
  auto chain = std::move(decoded).value();
  if (chain.empty() || !chain.front())
  {
    flow->fail(ua::StatusCode{ua::Status::BadCertificateInvalid},
      "EasyConnectCertificateDecodeFailed",
      "the server certificate advertised by GetEndpoints holds no certificate",
      decodeSource);
    return;
  }
  flow->certificate = chain.front();
  flow->presentedIssuers.assign(chain.begin() + 1, chain.end());
  validate_step(flow);
}
}  // namespace

bool is_trust_class_failure(ua::StatusCode status) noexcept
{
  const auto value = status.as_status();
  return value == ua::Status::BadCertificateUntrusted || value == ua::Status::BadCertificateChainIncomplete;
}

void resolve_easy_connect_async(
  EasyConnectDeps deps, ua::client::EasyConnectConfig policy, EasyConnectResolutionCallback callback) noexcept
{
  auto flow = std::make_shared<Flow>();
  flow->deps = std::move(deps);
  flow->policy = std::move(policy);
  flow->callback = std::move(callback);

  if (flow->policy.endpointUrl.empty())
  {
    flow->complete(ResolutionResult{ua::Status::BadInvalidArgument,
      ua::make_error_detail("EasyConnectEndpointUrlEmpty",
        "EasyConnectConfig::endpointUrl must be a non-empty opc.tcp:// URL",
        std::string{discoverySource})});
    return;
  }
  if (!flow->deps.getEndpoints)
  {
    flow->complete(ResolutionResult{ua::Status::BadInvalidState,
      ua::make_error_detail("EasyConnectNoDiscovery",
        "the easy-connect flow has no discovery collaborator",
        std::string{discoverySource})});
    return;
  }

  ua::client::GetEndpointsOptions options;
  options.timeout = flow->policy.timeout;
  const std::string url = flow->policy.endpointUrl;

  flow->deps.getEndpoints(url,
    std::move(options),
    [flow](Discovery::GetEndpointsResult result)
    {
      // The endpoint is selected from this answer, so an Uncertain one is refused as a Bad one is; a Good
      // subcode is consumed.
      if (!result.is_good())
      {
        flow->fail(answer_refused(result.status_code(), "ServiceAnswerUncertain", discoverySource),
          "EasyConnectDiscoveryFailed",
          "GetEndpoints failed, so no endpoint could be selected",
          discoverySource);
        return;
      }
      select_step(flow, std::move(result).value());
    });
}

}  // namespace ua::client::detail
