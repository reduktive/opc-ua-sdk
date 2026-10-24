// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Per-Connection configuration for the tier-1 managed connect entry (`Client::connect_async`).
/// @ingroup client

#ifndef UA_CONNECTION_CONFIG_H
#define UA_CONNECTION_CONFIG_H

#include "ua_address_space_cache_policy.h"
#include "ua_client_diagnostic_policy.h"
#include "ua_message_security_mode.h"
#include "ua_crypto_types.h"
#include "ua_reconnect_policy.h"
#include "ua_string.h"
#include "ua_subscription_fallback_policy.h"
#include "ua_type_resolution_policy.h"
#include "ua_user_identity.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua
{
class X509Certificate;
class CertificateStore;
}  // namespace ua

namespace ua::client
{

/// Produces the human-readable local audit-log identifier stamped into the next Service request header.
/// Invoked synchronously immediately before the request is handed to the Session send path (CL-AUDIT-001).
using AuditEntryIdProvider = std::function<ua::String()>;

// The eight role-cohesive observer interfaces (section 7.8). Forward-declared: the config holds `shared_ptr`
// slots, so the definitions (`ua_client_observers.h`) are pulled in only where the slots are consumed.
class ConnectionObserver;
class SubscriptionObserver;
class SecurityObserver;
class TypeObserver;
class AddressSpaceObserver;
class ServerStateObserver;
class AlarmObserver;

/// @ingroup client
/// How the endpoint named by `ConnectionConfig::endpointUrl` is selected (client design section 7.7).
enum class EndpointSelection
{
  /// Use `ConnectionConfig::endpointUrl` and the explicit security fields verbatim  -  no discovery
  /// round-trip. The default: `connect_async` is the power-user entry that takes a pre-built config, so the
  /// caller owns the discovery + trust decision (CTT "Discovery Client Configure Endpoint"). SECURITY: with
  /// this mode the SDK does NOT perform the GetEndpoints cross-check that guards against endpoint / security
  /// downgrade substitution  -  the caller is responsible for having validated that `securityMode` /
  /// `securityPolicyId` / `serverCertificate` match a real server endpoint. For discovery-driven selection
  /// WITH that cross-check, use @ref AutoBest (below), or
  /// @ref ua::client::Client::easy_connect_async when you also want the trust-prompt exchange
  /// (client design section 7.3A).
  ExactUrl,
  /// Pick the strongest endpoint whose SecurityPolicy is supported, using a session-less GetEndpoints call
  /// before the final SecureChannel is opened. "Strongest" is the client's own ordering of SecurityPolicy and
  /// MessageSecurityMode (@ref default_easy_connect_ranker, the ranking `easy_connect_async` applies); the
  /// advertised `securityLevel` only breaks ties, because the GetEndpoints result is unauthenticated. A
  /// deprecated `Basic256` is skipped unless the application set
  /// `ApplicationConfig::allowDeprecatedSecurityPolicies`, exactly as the Discovery facade filters
  /// the list `easy_connect_async` ranks, and `Basic128Rsa15` is never selected (the table scores it zero).
  /// An unsecured endpoint (mode None or policy None) is never selected unless @ref
  /// ConnectionConfig::allowUnsecuredEndpoint is set (CL-DISC-019).
  AutoBest,
  /// Pick the first returned endpoint matching @ref ConnectionConfig::securityMode and
  /// @ref ConnectionConfig::securityPolicyId.
  FirstMatching,
};

/// Per-Connection configuration for @ref Client::connect_async (client design section 7.7).
///
/// A POD with sensible defaults: an anonymous, auto-reconnecting connect needs only @ref endpointUrl (plus
/// the security fields for a secured endpoint). `connect_async` is the power-user entry  -  it takes this
/// pre-built config and assumes the caller has already done any discovery + trust-decision work. For the
/// discovery-driven alternative that resolves the endpoint and the trust decision for you, see
/// @ref ua::client::Client::easy_connect_async and @ref ua::client::EasyConnectConfig (client design
/// section 7.3A).
///
/// @note Every field on this struct reaches the Connection it configures - there is no field here that
///       silently does nothing. The event-subscriber policy described in the full section 7.7 design is the
///       one piece still absent, and it is absent from the struct rather than present-and-inert.
///       Reverse-connect via `connect_async` is deferred (use the reverse-connect listener API).
/// @ingroup client
struct ConnectionConfig
{
  // --- Endpoint + channel security ---

  /// OPC UA endpoint URL to connect to (e.g. `opc.tcp://host:4840`).
  std::string endpointUrl;

  /// How @ref endpointUrl is selected. Defaults to @ref EndpointSelection::ExactUrl (verbatim, no discovery).
  EndpointSelection endpointSelection = EndpointSelection::ExactUrl;

  /// Sign / SignAndEncrypt / None for the SecureChannel.
  ua::MessageSecurityMode securityMode{ua::MessageSecurityMode::None};

  /// Security policy governing the channel's crypto.
  ua::SecurityPolicyId securityPolicyId{ua::SecurityPolicyId::None};

  /// Server certificate (from a prior GetEndpoints call). Required for authenticated policies with
  /// @ref EndpointSelection::ExactUrl; ignored for @ref ua::SecurityPolicyId::None. May be null. With
  /// @ref EndpointSelection::AutoBest and @ref EndpointSelection::FirstMatching a value set here always wins:
  /// discovery fills the field in only when it was left empty. Either way the certificate is validated
  /// against the trust store when the SecureChannel opens.
  std::shared_ptr<const ua::X509Certificate> serverCertificate;

  /// Optional per-connect trust-store override  -  when set, OPN server-certificate validation uses THIS
  /// store instead of the client's runtime store (bootstrap trust, CL-PULLCRT-001). `nullptr` validates
  /// against the runtime store. The reconnect path re-supplies this override so a reconnected channel does
  /// not revert to the runtime store (a trust downgrade).
  std::shared_ptr<ua::CertificateStore> trustStoreOverride;

  /// When false (default), a CreateSession endpointUrl HostName that does not match the server certificate
  /// fails the connection and closes the SecureChannel. When true, the mismatch is reported as a warning and
  /// the connection may continue (OPC 10000-4 section 5.4.1 permits, but does not require, channel closure).
  bool relaxHostNameCheck = false;

  /// Permits discovery-driven selection (@ref EndpointSelection::AutoBest) to choose an unsecured endpoint
  /// (MessageSecurityMode None or SecurityPolicy None) for THIS connection.
  ///
  /// Default `false`: an unsecured endpoint is skipped, and a GetEndpoints result that offers nothing else
  /// fails `Bad_SecurityModeRejected` (`AutoBestUnsecuredEndpointRefused`) - the result is unauthenticated,
  /// so a list showing only unsecured endpoints cannot be told from one whose secured endpoints were removed
  /// in transit (CL-DISC-019). When `true`, an unsecured endpoint is still refused unless it is on the host
  /// that was dialled (`UnsecuredEndpointHostChanged`) and the @ref identity is an @ref AnonymousIdentity
  /// (`AutoBestUnsecuredRequiresAnonymous`: a user token over an unsecured channel would travel in clear),
  /// and selecting one logs a warning. When several unsecured copies of an endpoint are advertised (a
  /// multi-homed server lists one per host name), the copy on the dialled host is the candidate. Deprecated
  /// `Basic256` is skipped unless `mAllowDeprecatedSecurityPolicies` is set and `Basic128Rsa15` is never
  /// selected, so with this set a server offering only such policies beside an unsecured endpoint connects
  /// unsecured. Creating
  /// a Session over an unsecured channel additionally requires the process-wide
  /// `ApplicationConfig::allowInsecureEndpoints`, which this per-connection field does not replace.
  /// Ignored by @ref EndpointSelection::ExactUrl and @ref EndpointSelection::FirstMatching, where the caller
  /// names the security explicitly.
  bool allowUnsecuredEndpoint = false;

  /// Requested SecureChannel lifetime. `nullopt` uses the client's configured default.
  std::optional<std::chrono::milliseconds> channelLifetime;

  /// Overall timeout for the connect operation (channel open + CreateSession + ActivateSession + bootstrap).
  /// `nullopt` uses the configured default.
  std::optional<std::chrono::milliseconds> connectTimeout;

  // --- Identity + session ---

  /// User identity to authenticate the session with. Defaults to @ref AnonymousIdentity.
  UserIdentity identity = AnonymousIdentity{};

  /// Identifier of the server UserTokenPolicy to activate under.
  ///
  /// A non-anonymous identity may not be sent without one: Part 4 section 7.42 requires the token to carry
  /// a policyId the endpoint advertised, and the client may not invent one. Who fills it in depends on the
  /// entry point. @ref Client::easy_connect_async has just run GetEndpoints and chosen an endpoint, so it
  /// names the advertised policy matching @ref identity and leaves this empty only for an
  /// @ref AnonymousIdentity, whose policy is selected at activation. @ref Client::connect_async does the
  /// same whenever it runs discovery itself - @ref EndpointSelection::AutoBest and
  /// @ref EndpointSelection::FirstMatching. Only @ref EndpointSelection::ExactUrl, the power-user mode that
  /// performs no discovery round-trip, leaves the caller to name the policy here. A value set here always
  /// wins: discovery fills the field in only when it was left empty.
  std::string userTokenPolicyId;

  /// Human-readable session name reported to the server, where it appears in logs, the session diagnostics
  /// nodes and audit events. `nullopt` sends the SDK's own default (`"reduktive OPC UA Client"`); set it to
  /// something identifying *your* application when several clients share one server, since operators
  /// otherwise cannot tell your sessions apart from any other built on this SDK.
  std::optional<std::string> sessionName;

  /// Requested session timeout. `nullopt` uses the client's configured default.
  std::optional<std::chrono::milliseconds> sessionTimeout;

  /// Preferred locale identifiers, in priority order, for server-returned localised text. Empty leaves the
  /// server default in effect.
  std::vector<ua::String> localeIds;

  /// Optional per-request audit identifier provider. When configured, its return value populates an empty
  /// RequestHeader.auditEntryId immediately before dispatch. A request whose header already carries a
  /// per-call value keeps that override. Empty provider/return value is conformant "not used".
  AuditEntryIdProvider auditEntryIdProvider;

  // --- Lifecycle automation ---

  /// Automatic-reconnect policy. Present (the default) engages the managed auto-reconnect FSM + keep-alive;
  /// `nullopt` opts OUT  -  a single-shot Connection that transitions to `Failed` on the first drop.
  std::optional<ReconnectPolicy> reconnect = ReconnectPolicy{};

  /// Keep-alive poll policy (only meaningful when @ref reconnect is engaged  -  a miss drives the FSM).
  KeepAlivePolicy keepAlive;

  // --- Pending-request queue during reconnect (section 8.2A.5) ---

  /// When true, wire ops submitted while the Connection is Reconnecting are queued and flushed on
  /// recovery; when false they fail fast with `Bad_SessionNotActivated`.
  ///
  /// Distinguish three statuses that all mean "the queue refused it", because they need different
  /// responses: `Bad_SessionNotActivated` = queueing is off (a configuration choice);
  /// `Bad_ResourceUnavailable` = the queue was full and this entry was evicted (raise
  /// @ref pendingQueueLimit, or shed load); `Bad_Timeout` = it queued but aged past
  /// @ref maxQueueAge before the link came back. A handle that is already Closed or Failed
  /// short-circuits ahead of the queue entirely with `Bad_ConnectionClosed`.
  bool queueOnReconnect = true;

  /// Bound on the reconnect pending queue (oldest-evicted when exceeded). `nullopt` = explicit opt-in
  /// unbounded (advisory at ~50% fill).
  std::optional<std::size_t> pendingQueueLimit = 1024;

  /// Stale-request budget: a queued op older than this is completed `Bad_Timeout` rather than
  /// replayed on recovery. The age is only tested when the queue flushes - that is, AFTER the
  /// reconnect succeeds - so an operation is never failed for age while the link is still down.
  ///
  /// A queued request has never reached a Server, so no `timeoutHint` (OPC 10000-4 section 7.33) applies
  /// to it and no server-side deadline governs it. This budget is the only bound it has.
  std::chrono::milliseconds maxQueueAge{std::chrono::seconds{30}};

  // --- Optional client-side address-space cache (section 8.7) ---

  /// The optional per-Connection address-space cache policy (RegisterNodes alias substitution +
  /// static-attribute / Browse-result caching). Opt-in: the default is disabled (@ref
  /// ua::client::AddressSpaceCachePolicy::enabled is false), so a Connection that does not set this behaves
  /// exactly as before  -  the cache is a clean pass-through no-op and every operation goes wire-direct. Set
  /// `addressSpaceCache.enabled = true` to trade a bounded amount of client memory for fewer server
  /// round-trips (CL-VIEW-009/010/011).
  AddressSpaceCachePolicy addressSpaceCache;

  // --- Diagnostics policy (section 7.10.4) ---

  /// The per-Connection diagnostics policy: whether decoded server diagnostics fire the error-chain observer
  /// (@ref ClientDiagnosticPolicy::emitOnErrorChainObserver, default on) and the decoded-chain depth cap
  /// (@ref ClientDiagnosticPolicy::maxChainDepth). The defaults preserve the pre-policy behaviour exactly.
  ClientDiagnosticPolicy diagnostics;

  // --- Polled-Read Subscription fallback (section 8.4, CL-SUB-019) ---

  /// When a `CreateSubscription` fails and this policy permits, the Connection transparently replaces the
  /// would-be Subscription with a timer-driven bulk-`Read` polling driver that feeds the user's MonitoredItem
  /// callbacks  -  the user's @ref ua::client::Subscription / @ref ua::client::MonitoredItem handles stay
  /// valid and unaware. Opt-in: the default (@ref SubscriptionFallbackPolicy::Mode::Disabled) preserves
  /// today's behaviour exactly (a failed create surfaces its bad status; no polling driver starts).
  SubscriptionFallbackPolicy subscriptionFallback{};

  // --- Type resolution (section 8.6) ---

  /// The per-Connection type-resolution policy: how the Connection's `TypeResolver` populates its registry
  /// (@ref TypeResolutionMode - Lazy decode-and-defer by default, or Eager / EagerThenLazy pre-scanning the
  /// interest set named by @ref TypeResolutionPolicy::eagerTypes
  /// at connect time), the per-resolve timeout, whether a typed read WAITS for resolution or returns a
  /// placeholder (@ref TypeResolutionPolicy::tier2WaitForResolution), and the decode-and-defer budgets. The
  /// default is Lazy with no eager interest set, which costs no connect-time round-trip.
  TypeResolutionPolicy typeResolution;

  // --- Per-Connection observer slots (section 7.8) ---
  // Each is independently optional; a non-null slot OVERRIDES the Client-level default observer for that
  // family on this Connection (section 7.3 / section 7.7). The Client-level defaults
  // (`Client::set_*_observer`) apply when the corresponding slot here is null.

  /// The connection observer.
  std::shared_ptr<ConnectionObserver> connectionObserver;
  /// The subscription observer.
  std::shared_ptr<SubscriptionObserver> subscriptionObserver;
  // NOTE: there is deliberately no per-connection `securityObserver` slot. `SecurityObserver`'s two
  // callbacks (certificate rotation, pull-cert lifecycle) originate in the client-wide pull-certificate
  // manager, so no event is scoped to a single Connection and a per-connection slot could never fire.
  // Install one with `Client::set_security_observer` instead. Removed after a mutation test showed the
  // slot was inert (D21).
  /// The type observer.
  std::shared_ptr<TypeObserver> typeObserver;
  /// The address space observer.
  std::shared_ptr<AddressSpaceObserver> addressSpaceObserver;
  /// The server state observer.
  std::shared_ptr<ServerStateObserver> serverStateObserver;
  /// The alarm observer.
  std::shared_ptr<AlarmObserver> alarmObserver;
};

}  // namespace ua::client

#endif  // UA_CONNECTION_CONFIG_H
