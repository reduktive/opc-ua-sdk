// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_CONFIGURATION_H
#define UA_SERVER_CONFIGURATION_H

/// @file
/// @brief Server-only configuration: limits, throttling, capabilities, listeners, and roles.
/// @ingroup server

#include "ua_data_access_utils.h"
#include "ua_duration.h"
#include "ua_error_detail.h"
#include "ua_includes.h"
#include "ua_listen_options.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_service_operation_limits.h"
#include "ua_transport_address.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace ua::server
{

/// The server name of @ref ua::DataAccessOutOfRangePolicy, kept for existing callers.
///
/// @ingroup server
using DataAccessOutOfRangePolicy = ua::DataAccessOutOfRangePolicy;

/// @ingroup server
/// One of the nine OPC 10000-18 well-known Roles.
///
/// Stored as a dense `uint8_t` so a set of roles can be expressed as
/// `std::optional<std::vector<WellKnownRole>>` (nullopt = ship all nine).
///
/// `TrustedApplication` was added in OPC 10000 Release 1.05.04 (NodeId 18625);
/// it is granted to any Session authenticating with a trusted
/// ApplicationInstanceCertificate (see the `TrustedApplication` IdentityCriteria
/// in `ua_role_configuration.cpp`).
enum class WellKnownRole : uint8_t
{
  Anonymous,  ///< Granted to any Session, including unauthenticated ones.
  AuthenticatedUser,  ///< Granted to any Session authenticated with a non-anonymous identity.
  Observer,  ///< Read/browse access to the information model.
  Operator,  ///< Observer plus the ability to operate the running system.
  Engineer,  ///< Operator plus the ability to configure the system.
  Supervisor,  ///< Elevated operational oversight of the running system.
  ConfigureAdmin,  ///< Administrative configuration of the server's information model.
  SecurityAdmin,  ///< Administration of security settings (the default admin Role).
  TrustedApplication  ///< Granted to Sessions presenting a trusted ApplicationInstanceCertificate.
};

/// Server-only configuration: limits, throttling, capabilities, listeners, and roles.
///
/// A plain value type passed to the server at construction. Members are read
/// during startup; mutate them before `start()`, not after. Counts are absolute
/// concurrency caps, durations carry their `std::chrono` units, and `optional`
/// limits left as nullopt mean "unbounded / OS-limited" unless noted otherwise.
/// @ingroup server
struct ServerConfig
{

  /// Maximum number of concurrent transport connections, including those still in the
  /// HEL/ACK handshake.
  ///
  /// nullopt leaves connections limited only by OS/resources. The default is ABOVE
  /// `maxSecureChannels` on purpose; see that field.
  optional<uint32_t> maxConnections{200};

  /// Maximum number of concurrent secure channels across all transports.
  ///
  /// **Set `maxConnections` ABOVE this value.** The two limits are not interchangeable capacity
  /// numbers: they are consecutive admission gates with different behaviour. `maxConnections` is
  /// checked first and REJECTS the connection; this limit is checked second and EVICTS the oldest
  /// sessionless channel, which is what OPC 10000-4 section 5.5.2.1 requires of a server under a
  /// channel-exhaustion attack. Configure them equal and the reject fires before the eviction layer
  /// is ever reached, so the required behaviour is unreachable and a conformance test for it fails.
  /// The defaults are 200/100 for this reason; `Server::start_sync` logs a warning when a configuration
  /// sets the two so that the evicting gate cannot be reached (a refusal would break deployments
  /// that choose the connection limit as their refusal point on purpose).
  ///
  /// Outbound (reverse-connect) connections bypass `maxConnections` but are still gated by this
  /// limit. nullopt leaves it unbounded.
  optional<uint32_t> maxSecureChannels{100};

  /// Maximum number of concurrent in-flight requests per session.
  ///
  /// Excludes Publish requests, which are limited separately by
  /// `ServerCapabilities::maxPublishRequestsPerSession`. nullopt leaves it unbounded.
  optional<uint32_t> maxRequestsPerSession{100};

  /// Maximum number of concurrent in-flight requests across the whole server.
  ///
  /// A server-wide admission cap: once this many non-Publish service requests are simultaneously
  /// being processed (across all sessions/channels), further requests are rejected with
  /// `BadServerTooBusy` until one completes. Bounds aggregate work that the per-session cap cannot
  /// (N sessions each under `maxRequestsPerSession` can still overwhelm the server). Publish
  /// requests are excluded (they are parked flow-control, bounded by the publish-queue limits).
  /// nullopt (or 0) leaves it unbounded.
  optional<uint32_t> maxInFlightRequests{2000};

  /// Maximum number of concurrent in-flight requests per transport connection (secure channel).
  ///
  /// A per-connection admission cap measured across all sessions hosted on a channel; over-cap
  /// requests are rejected with `BadServerTooBusy`. Excludes Publish (see `maxInFlightRequests`).
  /// nullopt (or 0) leaves it unbounded.
  optional<uint32_t> maxInFlightRequestsPerConnection{50};

  /// Per-remote connection throttling configuration. A remote is an IPv4 address, the IPv4 carried by
  /// a v4-mapped IPv6 address, or an IPv6 address masked to `ipv6PrefixLength` bits.
  struct ConnectionThrottling
  {
    bool enabled{true};  ///< Whether connection throttling is applied.
    /// Maximum concurrent connections from one remote. A connection counts from its accept until it
    /// leaves the server: a failed handshake, a refusal, or the removal of the channel it became. So
    /// this bounds open channels per remote, not handshakes in flight.
    uint32_t maxConnectionsPerEndpoint{10};
    uint32_t maxConnectionAttemptsPerMinute{30};  ///< Connection-attempt rate limit per remote, per minute.
    /// Bits of an IPv6 address that identify a remote: 128 (the default) is per address, scope id
    /// included, which suits a LAN where every host of one /64 is its own client; 64 makes a whole
    /// /64 one remote, which suits an internet-facing server whose clients each hold a /64 and could
    /// otherwise claim 2^64 budgets. Below 128 the scope id is dropped from the key, except that a
    /// link-local address (fe80::/10) is always keyed whole, scope id included, whatever the prefix.
    /// Must be 1..128 (`ServerConfig::validate()`).
    uint32_t ipv6PrefixLength{128};
    /// Hard cap on the number of distinct remote-IP keys tracked. At the cap a new IP evicts the
    /// least-recently-seen entry (LRU), bounding memory against a spoofed-source-IP flood. Must be >= 1
    /// (`0` is rejected by `ServerConfig::validate()`).
    uint32_t maxTrackedEndpoints{10000};
  };

  ConnectionThrottling connectionThrottling;  ///< Active per-IP connection throttling settings.

  /// User identity token attack protection (OPC 10000-4, 5.6.3).
  struct IdentityThrottling
  {
    bool enabled{true};  ///< Whether identity-token throttling is applied.
    uint32_t maxFailedAttemptsBeforeLockout{5};  ///< Failed attempts that trigger a lockout.
    std::chrono::seconds lockoutDuration{60};  ///< Lockout period per client application (principal).
    /// The principal identifies the calling Client the way OPC 10000-4 5.6.3 requires: its
    /// ApplicationInstanceUri on a secured channel (taken from the client certificate), and its
    /// IP address on an unsecured one. Clients sharing an address therefore share a lockout
    /// bucket only when they connect without security.
    ///
    /// Hard cap on the number of distinct client applications (principals) tracked. At the cap a new key
    /// evicts the least-recently-failed entry (LRU); active lockouts have recent timestamps and so survive
    /// until the map is saturated with recent failures (itself a bounded state). Must be >= 1
    /// (`0` is rejected by `ServerConfig::validate()`).
    uint32_t maxTrackedIdentities{10000};
  };

  IdentityThrottling identityThrottling;  ///< Active identity-token attack-protection settings.

  /// Maximum number of distinct live access identities retained by the server.
  ///
  /// Sessions whose complete authorization identity is equal share one entry. Zero is invalid:
  /// this is the hard memory bound for a key partly controlled by an unauthenticated client URI.
  uint32_t maxAccessIdentities{10000};

  /// One-operation deadline for asynchronous namespace permission resolution.
  ///
  /// All namespaces needed by one authorization operation share this budget and are resolved in
  /// parallel. A namespace that has not answered by the deadline denies only its own items.
  std::chrono::milliseconds authzTimeout{1000};

  /// Deadline for one authentication check (the UserAuthenticator's answer to an ActivateSession)
  /// before it is abandoned and the activation refused.
  std::chrono::milliseconds authnTimeout{1000};

  /// Discovery service load protection (OPC 10000-4, 5.4.2.1, 5.4.4.1).
  struct DiscoveryThrottling
  {
    uint32_t concurrencyThreshold{10};  ///< Concurrent discovery requests above which the delay applies.
    std::chrono::milliseconds delayPerRequest{100};  ///< Delay added per request while above the threshold.
  };

  DiscoveryThrottling discoveryThrottling;  ///< Active discovery-service throttling settings.

  /// Enables the unsecured discovery-only endpoint used when no configured endpoint accepts
  /// SecurityPolicy None. Disable this for closed deployments whose clients are preconfigured.
  bool discoveryEndpointEnabled{true};

  /// Accepts non-zero padding bytes in encrypted UserIdentityToken secrets. The default remains strict;
  /// enable only as a temporary interoperability measure for a known non-conforming client.
  bool acceptInvalidPadding{false};

  /// Caps on server-internal queues and stores (memory fail-safes).
  ///
  /// These bound work-set growth under load or hostile input. None is an OPC-UA-advertised capability
  /// (there is no NodeSet representation for any of them - verified against Release 1.05); they are
  /// purely SDK admission/memory controls. Each is enforced as a hard cap with a drop-oldest,
  /// fail-closed, or read-pause policy at its point of use.
  ///
  /// A value of `0` is **invalid** - there is no "unlimited" setting for an admission/memory control
  /// (that would defeat its purpose). `ServerConfig::validate()` rejects any zero field with
  /// `BadConfigurationError`; every field must be >= 1.
  struct ResourceLimits
  {
    /// Value equality across all limits.
    /// @return true when every limit compares equal, otherwise false.
    bool operator==(const ResourceLimits&) const = default;

    /// Max queued-but-not-started EventBus dispatch tasks; drop-oldest on overflow.
    uint32_t eventDispatchQueueDepth{10000};
    /// Max retained ConditionBranches per condition instance; drop-oldest (Retain=False) on overflow.
    uint32_t conditionBranchesPerCondition{100};
    /// Max orphaned (session-detached, awaiting-transfer) subscriptions retained; drop-oldest.
    uint32_t orphanedSubscriptionStore{1000};
    /// Max service responses buffered per session while it has no attached channel; drop-oldest.
    uint32_t bufferedResponsesPerSession{1000};
    /// Buffers queued for transmission per connection at or beyond which a NEW message is refused
    /// (`BadTcpNotEnoughResources`). Applied at a message's first chunk only: a message once admitted
    /// is queued whole, so the true bound is this cap plus one maximum-size message.
    uint32_t writeQueueDepthPerConnection{4096};
    /// Bytes queued or in flight for transmission per connection at or beyond which a NEW message is
    /// refused the same way, applied at the message's first chunk like the depth cap (true bound: this
    /// budget plus one maximum-size message). The depth cap bounds the buffer COUNT; a peer that
    /// negotiates large chunks and stops reading would otherwise hold depth x chunk size. Default 16 MiB.
    uint32_t writeQueueBytesPerConnection{16u * 1024u * 1024u};
    /// Max incoming message chunks buffered per channel awaiting decode before the transport
    /// **read-pauses** (stops re-arming the socket read until the queue drains below half this depth).
    /// Graceful backpressure - no chunk is dropped, no error is raised; a smaller value simply throttles
    /// a peer that floods faster than the channel decodes. Bounds per-channel memory to roughly this
    /// many times the negotiated ReceiveBufferSize.
    uint32_t incomingChunkQueueDepth{64};
    /// Most FileType handles (OPC 10000-20 section 4.2) one Session may hold open at once, across every
    /// file in the address space; an Open beyond it is refused with Bad_TooManyOperations
    /// (`FileHandleLimitReached`). Each open handle holds an operating-system file descriptor until it is
    /// closed or its Session ends, so one Session must not be able to take them all. The default leaves
    /// room for the eight transfers `TemporaryFileTransferConfig::maxActiveTransfersPerSession` allows by
    /// default, each of which holds one handle, and for ordinary files beside them.
    uint32_t openFileHandlesPerSession{16};
    /// Most FileType handles all Sessions, and the SDK's own callers, may hold open at once; an Open
    /// beyond it is refused the same way. Bounds the file descriptors files can take from the process,
    /// which the server also needs for its connections: keep it, plus `maxConnections`, under the
    /// process's open-file limit.
    uint32_t openFileHandles{256};
  };

  ResourceLimits resourceLimits;  ///< Active server-internal queue/store caps.

  /// Period on which each active MonitoredItem's read/receive-events authorization is re-evaluated,
  /// honoring access-rights changes after CreateMonitoredItems (OPC 10000-4 sec. 5.12.2.1: a revoked
  /// Node permission makes the item deliver Bad_UserAccessDenied and stop streaming; a regained
  /// permission resumes data). This interval is the propagation bound the spec permits (OPC 10000-18
  /// sec. 4.2.3 "some lag may occur"). Must be strictly positive: disabling re-evaluation would turn
  /// finite propagation lag into a permanent authorization grant.
  /// SDK-internal operational policy - NOT an advertised ServerCapabilitiesType Property, so it lives on
  /// ServerConfig (like resourceLimits / the throttling structs), not in the ServerCapabilities
  /// mirror of the spec-mandated Object (OPC 10000-5 6.3.2).
  std::chrono::seconds monitoredItemAccessRecheckInterval{60};

  /// Subscription and Publish-flow tuning knobs (SDK-internal operational policy).
  ///
  /// None of these is an advertised `ServerCapabilitiesType` Property (OPC 10000-5 6.3.2) - they are
  /// the server's subscription/publish admission and revision policy, so they live on
  /// ServerConfig (like `resourceLimits` / the throttling structs), not in the
  /// `ServerCapabilities` mirror of the spec-mandated Object. `optional` fields left as nullopt are
  /// treated as unbounded / use the built-in default; durations carry their `std::chrono` units.
  struct SubscriptionLimits
  {
    /// Value equality across all limits.
    /// @return true when every limit compares equal, otherwise false.
    bool operator==(const SubscriptionLimits&) const = default;

    optional<std::chrono::milliseconds> minPublishingInterval{
      std::chrono::milliseconds{100}};  ///< Smallest publishing interval the server grants.
    optional<std::chrono::milliseconds> maxPublishingInterval{
      std::chrono::milliseconds{3600000}};  ///< Largest publishing interval the server grants (1 hour).
    optional<uint32_t> maxKeepAliveCount{300};  ///< Maximum keep-alive count a subscription may request.
    /// Largest lifetime count a subscription may request. A subscription whose owning session is gone
    /// lives for `lifetimeCount` publishing intervals; without a cap a client can park a subscription,
    /// and every MonitoredItem slot it holds, for the life of the process. Revised down to this value
    /// (never below three keep-alive counts, Part 4 section 5.13.2).
    optional<uint32_t> maxLifetimeCount{10000};
    optional<uint32_t> maxNotificationsPerPublish{
      10000};  ///< Maximum notifications returned in a single Publish response.
    /// Maximum queued Publish requests per session; the retransmission queue holds twice this many
    /// messages. nullopt derives it from MaxSubscriptionsPerSession; `0` is rejected by
    /// `ServerConfig::validate()`.
    optional<uint32_t> maxPublishRequestsPerSession{100};
    optional<uint32_t> defaultEventQueueSize{50};  ///< Default queue size for event MonitoredItems.

    /// Maximum queued, not-yet-delivered StatusChangeNotifications per session.
    ///
    /// StatusChangeNotifications (subscription lifetime `Bad_Timeout`, `Good_SubscriptionTransferred`)
    /// are parked until the client sends a Publish request to carry them. A client that creates
    /// subscriptions and never publishes would otherwise grow this backlog without bound - each expiry
    /// parks one notification AND frees its subscription slot, so `maxSubscriptionsPerSession` never
    /// trips. At the cap the oldest parked notification is dropped (the subscription it referred to is
    /// already gone), mirroring the evict-oldest policy of the Publish and retransmission queues.
    /// nullopt leaves it unbounded.
    optional<uint32_t> maxPendingStatusChanges{100};

    /// Whether SetSubscriptionDurable (OPC 10000-4 5.13.9) is supported.
    ///
    /// When false the Method is refused with `Bad_ServiceUnsupported` and per-MonitoredItem queues
    /// stay at the non-durable `ServerCapabilities::maxMonitoredItemsQueueSize` ceiling - the
    /// memory-bounding gate for constrained deployments (a durable subscription buffers offline,
    /// lifting that ceiling). On by default; the Embedded profile turns it off.
    bool durableSubscriptionsEnabled{true};

    /// Maximum durable-subscription lifetime, in hours.
    ///
    /// SetSubscriptionDurable revises a larger request down to this - OPC 10000-4 5.13.9 leaves the
    /// upper bound to the server (the CTT only warns when revised != requested).
    uint32_t maxDurableSubscriptionLifetimeHours{24};

    /// Ceiling a durable subscription's MonitoredItem queue is lifted to.
    ///
    /// A durable subscription's per-MonitoredItem queue cap becomes
    /// `max(ServerCapabilities::maxMonitoredItemsQueueSize, maxDurableMonitoredItemQueueSize)`,
    /// bounding the offline buffer a durable client can demand. Replaces the former hard-coded
    /// 100'000 entry ceiling.
    uint32_t maxDurableMonitoredItemQueueSize{10000};

    /// Total byte budget for string literal operands across an event MonitoredItem's where clause.
    ///
    /// The `Like` operator is O(text x pattern) per event and `And`/`Or` do not short-circuit, so a
    /// long pattern literal - bounded only by `ServerCapabilities::maxStringLength` (up to 1 MB) -
    /// repeated across where-clause elements multiplies per-event CPU on the subscription strand (an
    /// authenticated slow-burn DoS the operand-COUNT cap does not bound). The where clause is rejected
    /// at compile (`Bad_MonitoredItemFilterInvalid`) when the summed byte size of its string literal
    /// operands exceeds this, before any per-event evaluation. SDK-internal complexity cap (not an
    /// advertised Property); threaded into the MonitoredItem create flow alongside `defaultEventQueueSize`.
    /// nullopt disables the budget.
    optional<uint32_t> maxWhereClauseOperandBytes{65536};
  };

  SubscriptionLimits subscriptionLimits;  ///< Active subscription/publish-flow tuning knobs.

  /// Lifetime of an idle Browse continuation point.
  ///
  /// SDK-internal operational policy, not an advertised `ServerCapabilitiesType` Property - lives on
  /// ServerConfig. nullopt leaves continuation points without a timeout.
  optional<std::chrono::milliseconds> browseContinuationPointTimeout{std::chrono::milliseconds{30000}};

  /// Lifetime of an idle HistoryRead continuation point.
  ///
  /// SDK-internal operational policy, not an advertised `ServerCapabilitiesType` Property - lives on
  /// ServerConfig. nullopt leaves continuation points without a timeout.
  optional<std::chrono::milliseconds> historyContinuationPointTimeout{std::chrono::milliseconds{30000}};

  /// Fraction of a request's `timeoutHint` after which Browse, BrowseNext and HistoryRead stop waiting
  /// and answer with what they have.
  ///
  /// At that point every finished operation returns its results and every unfinished one returns no
  /// results and a continuation point that takes over the running work: the next BrowseNext or
  /// HistoryRead with it returns that work's results, or no results and a new continuation point if it
  /// is still running (OPC 10000-4 sections 5.8.2 and 5.10.3.1, OPC 10000-11 section 6.3). A request
  /// with `timeoutHint` 0 asked for no timeout and has no such point. Read, Write and Call are not
  /// affected: they run to the full `timeoutHint`. Must be greater than 0 and less than 1.
  double partialResultDeadlineFraction{0.8};

  /// Server ceiling on the number of references returned per node in a single Browse page.
  ///
  /// The Browse `requestedMaxReferencesPerNode` of `0` means "no Client-side limit" (OPC 10000-4
  /// 5.8.2). Left unclamped, a node's entire reference list is returned as one page with no
  /// continuation point, so the `MaxBrowseContinuationPoints` throttle never engages and a node with a
  /// very large reference set yields an unbounded outbound array. This ceiling is the server's default
  /// page size: a request of `0` uses it, and an explicit request larger than it is clamped down to it,
  /// so the continuation-point path always engages. SDK-internal operational policy, not an advertised
  /// `ServerCapabilitiesType` Property. nullopt disables the ceiling (legacy: `0` returns everything).
  optional<uint32_t> maxReferencesPerNode{10000};

  /// Budget on the number of references one Browse request may return across all of its operations.
  ///
  /// `maxReferencesPerNode` bounds one operation; a request that names the same high-fan-in node
  /// `MaxNodesPerBrowse` times still returned `MaxNodesPerBrowse x MaxReferencesPerNode` references in
  /// one response. Operations run concurrently, so the budget is split deterministically: each
  /// operation's page size is min(the per-node cap, budget / operations), and the ordinary
  /// continuation-point path pages the rest. `validate()` requires a `MaxNodesPerBrowse` limit and a
  /// budget of at least that, so every operation keeps a page of at least one reference and the
  /// response never exceeds the budget. A budget below `operations x fan-out` creates one continuation point
  /// per operation, which `MaxBrowseContinuationPoints` then bounds: size the two together. SDK-internal
  /// operational policy, not an advertised `ServerCapabilitiesType` Property. nullopt disables the
  /// budget and is preserved by the configuration file (written as null).
  optional<uint32_t> maxReferencesPerBrowseRequest{1000000};

  /// Per-operation budget on the number of references examined during a single TranslateBrowsePaths walk.
  ///
  /// `MaxNodesPerTranslateBrowsePathsToNodeIds` bounds only the path count; the walk itself fetches
  /// every reference of every reachable target and rotates per relative-path element, so cost grows as
  /// `paths x depth x edges` with no intrinsic bound - an authenticated CPU-amplification DoS on the
  /// service strand. When the references examined for one operation exceed this budget the operation is
  /// terminated with `Bad_QueryTooComplex`. Because every emitted BrowsePathTarget required examining at
  /// least the reference that produced it, this also transitively bounds the outbound target array
  /// (further bounded by `MaxResponseMessageSize`). SDK-internal operational policy, not an advertised
  /// Property. nullopt disables the budget.
  optional<uint32_t> maxBrowsePathWalkReferences{100000};

  /// Whether the server emits audit events and advertises auditing support.
  ///
  /// When true the server generates audit events for security-sensitive and state-modifying
  /// operations (OPC 10000-4, 6.5) and sets the `Server.Auditing` property to true. When false
  /// (default) no audit infrastructure is created - zero runtime cost.
  bool auditingEnabled = false;

  /// What the Write service does with a client's Value write to a Variable of a Data Access type (OPC 10000-8
  /// 5.3) that the type's Properties bound.
  ///
  /// When set, an AnalogItem's value (a BaseAnalogType or ArrayItemType Variable) outside its
  /// InstrumentRange, or its EURange when it has no InstrumentRange, is refused with Bad_OutOfRange
  /// (`Reject`) or clamped into it and answered Good_Clamped (`Clamp`); a MultiStateDiscrete or
  /// MultiStateValueDiscrete value that is not one of the Variable's EnumStrings indexes or EnumValues is
  /// refused with Bad_OutOfRange. OPC 10000-8 5.3.2.2 leaves the outcome to the server and is silent on
  /// InstrumentRange: bounding by InstrumentRange first is this SDK's choice. When nullopt (default) no write
  /// is checked and the Write service makes no call for it. The rule then belongs to the owner of the data,
  /// such as a `ValueSource` using `data_access_utils`.
  std::optional<DataAccessOutOfRangePolicy> dataAccessWritePolicy;

  /// Whether the OPC 10000-18 RoleType Method handlers permit runtime Role mutation.
  ///
  /// When true the RoleType Methods (AddIdentity / RemoveIdentity / AddApplication /
  /// RemoveApplication / AddEndpoint / RemoveEndpoint) are wired and runtime mutation of the
  /// RoleConfiguration is permitted. When false (default) the Methods remain browseable but
  /// Calls return Bad_NotExecutable.
  bool roleManagementEnabled{false};

  /// Whether an authenticator's published Role claim is mapped to the SecurityAdmin Role.
  ///
  /// When enabled and SecurityAdmin is materialised, the SDK installs one byte-exact `Role`
  /// identity rule whose criteria is the well-known Role name and publishes
  /// `CustomConfiguration = TRUE` on that Role Object. Disabled by default because applications
  /// forwarding unfiltered third-party claims must not gain administrative access accidentally.
  bool enableClaimToRoleMapping{false};

  /// Subset of well-known Roles to materialise in the address space.
  ///
  /// nullopt (default) ships all nine; an explicit list restricts the surface for constrained
  /// deployments. `Anonymous` and `AuthenticatedUser` receive default IdentityMappingRules
  /// (anyone matches Anonymous; non-Anonymous identities match AuthenticatedUser); the other
  /// roles are added with empty rule lists and require explicit configuration to match callers.
  std::optional<std::vector<WellKnownRole>> wellKnownRoles;

  /// Default grace period, in seconds, for shutdown while clients are connected.
  ///
  /// During this period `SecondsTillShutdown` counts down so clients can disconnect in an orderly
  /// fashion.
  uint32_t defaultShutdownGracePeriodSeconds{5};

  /// Whether the server offers Part 12 push certificate management.
  ///
  /// When true (default) the `ServerConfiguration` Object of the address space is wired: its TrustLists
  /// accept changes (Open for write, CloseAndUpdate, AddCertificate, RemoveCertificate) and its Methods
  /// (UpdateCertificate, CreateSigningRequest, ApplyChanges, CancelChanges, GetRejectedList,
  /// GetCertificates, ResetToServerDefaults) are callable by the SecurityAdmin Role (OPC 10000-12, 7.10).
  /// When false the `ServerConfiguration` Object and everything under it are removed from the address
  /// space, so nothing can change the server's certificates or trust lists through the server. A server
  /// whose certificates and trust lists are provisioned by pull management (a `PullCertificateManager`
  /// writing the server's certificate store) sets it to false, so the store has a single writer.
  bool pushCertificateManagementEnabled{true};

  /// A reverse-connect target - a Client endpoint the Server maintains persistent outbound
  /// connections to.
  struct ReverseConnectTarget
  {
    /// Stable identifier for this target, unique within the server configuration.
    std::string name;

    /// The ApplicationUri of the Client to reverse-connect to.
    std::string clientApplicationUri;

    /// TCP address of the Client's reverse-connect listener.
    std::string clientEndpointUrl;

    /// The Server EndpointUrl advertised in the ReverseHello message.
    std::string serverEndpointUrl;

    /// Endpoint configurations available on this reverse-connect target.
    std::vector<ServerEndpointConfig> endpoints;

    /// Interval between periodic new connection attempts (spec S5).
    std::chrono::seconds periodicConnectInterval{30};

    /// Maximum simultaneous pending sockets to this Client (spec P2); 0 = no limit.
    uint32_t maxPendingSockets{5};
  };

  /// A network listener: a bind address plus the endpoints offered on it.
  struct ListenerConfig
  {
    /// Stable identifier for this listener, unique within the server configuration.
    std::string name;

    ua::transport::BindAddress bind{};  ///< Local address and port the listener binds to.
    ListenOptions listenOptions{};  ///< Socket-level options applied to the listener.

    /// Optional external URL override.
    ///
    /// Only needed when the server is behind NAT or a load balancer and the externally reachable
    /// port/path differs from the bind address. When empty (the common case), the port is derived
    /// from the bind address and the host is taken from the client's request URL.
    std::optional<ua::transport::EndpointUrl> externalUrl;

    std::vector<ServerEndpointConfig> endpoints;  ///< Endpoint configurations offered on this listener.
  };

  /// Per-service caps on the number of nodes/items accepted in a single service request.
  ///
  /// Advertised via the Server's OperationLimits object. nullopt leaves the corresponding limit
  /// unadvertised / unbounded. The type is the core library's @ref ua::ServiceOperationLimits, which the
  /// server also passes to its address space (@ref ua::AddressSpace::set_operation_limits).
  using OperationLimits = ::ua::ServiceOperationLimits;

  /// Server limits and capabilities advertised under Server.ServerCapabilities.
  ///
  /// `optional` fields left as nullopt are not advertised / treated as unbounded. Sizes are in
  /// bytes, durations carry their `std::chrono` units.
  struct ServerCapabilities
  {
    /// Value equality across all capabilities.
    /// @return true when every capability compares equal, otherwise false.
    bool operator==(const ServerCapabilities&) const = default;

    Duration minSupportedSampleRate{
      0};  ///< Smallest sampling interval, in milliseconds, the server supports.
    uint16_t maxBrowseContinuationPoints{
      100};  ///< Maximum concurrent Browse continuation points per session.
    uint16_t maxQueryContinuationPoints{100};  ///< Maximum concurrent Query continuation points per session.
    uint16_t maxHistoryContinuationPoints{
      100};  ///< Maximum concurrent HistoryRead continuation points per session.
    optional<uint32_t> maxArrayLength{65535};  ///< Maximum element count of an array value.
    optional<uint32_t> maxStringLength{1048576};  ///< Maximum length, in bytes, of a String value (1 MB).
    optional<uint32_t> maxByteStringLength{
      16777216};  ///< Maximum length, in bytes, of a ByteString value (16 MB).
    OperationLimits operationLimits;  ///< Per-service node/item count limits.
    optional<uint32_t> maxSessions{100};  ///< Maximum concurrent sessions.
    optional<uint32_t> maxSubscriptions{1000};  ///< Maximum concurrent subscriptions across all sessions.
    optional<uint32_t> maxMonitoredItems{
      10000};  ///< Maximum concurrent MonitoredItems across all subscriptions.
    optional<uint32_t> maxSubscriptionsPerSession{50};  ///< Maximum subscriptions per session.
    optional<uint32_t> maxMonitoredItemsPerSubscription{1000};  ///< Maximum MonitoredItems per subscription.
    optional<uint32_t> maxSelectClauseParameters{
      100};  ///< Maximum select-clause parameters in an event filter.
    optional<uint32_t> maxWhereClauseParameters{
      100};  ///< Maximum where-clause parameters in an event filter.
    optional<uint32_t> maxMonitoredItemsQueueSize{
      1000};  ///< Maximum queue size requestable for a MonitoredItem.

    /// Locales the server supports.
    ///
    /// Advertised via `Server.ServerCapabilities.LocaleIdArray` (mandatory property,
    /// OPC 10000-5 6.3.1). Default: English.
    std::vector<std::string> localeIds{"en"};

    /// Conformance profile URIs the server claims.
    ///
    /// Advertised via `Server.ServerCapabilities.ServerProfileArray` (mandatory property,
    /// OPC 10000-7). Empty advertises no profile claim; set per deployment / certification scope.
    std::vector<std::string> serverProfiles;
  };

  /// Policy controlling how much DiagnosticInfo the server returns in service responses.
  struct DiagnosticPolicy
  {
    /// Amount of diagnostic information emitted in a service response.
    enum class Level
    {
      None,  ///< No diagnostic information emitted.
      Summary,  ///< symbolicId, locale, and localizedText only.
      Full  ///< All DiagnosticInfo fields.
    };

    /// Ceiling applied to a caller carrying no diagnostics claim. It bounds what the client's
    /// own `returnDiagnostics` mask can obtain; it is not a floor. Part 4 7.33 makes a zero mask
    /// an explicit "return nothing", so a request that asks for no diagnostics receives none
    /// whatever this is set to.
    Level defaultLevel = Level::None;
    /// Upper bound on the level any caller can reach, including one whose claims would otherwise
    /// elevate them. `validate()` rejects a configuration whose DefaultLevel exceeds it.
    Level maxLevel = Level::Full;
  };

  /// Names a diagnostic level for error context.
  ///
  /// @param level The level to name.
  /// @return The level's name as it appears in error context - `None`, `Summary` or `Full` - and
  ///         `Unknown` for a value outside the enumeration.
  static constexpr std::string_view diagnostic_level_name(DiagnosticPolicy::Level level)
  {
    switch (level)
    {
    case DiagnosticPolicy::Level::None:
      return "None";
    case DiagnosticPolicy::Level::Summary:
      return "Summary";
    case DiagnosticPolicy::Level::Full:
      return "Full";
    }
    return "Unknown";
  }

  /// Configuration for HistoryServerCapabilitiesType (OPC 10000-11, 5.2).
  struct HistoryConfig
  {
    /// Value equality across all fields.
    /// @return true when every field compares equal, otherwise false.
    bool operator==(const HistoryConfig&) const = default;

    /// Maximum data values returned per node per HistoryRead (Part 11 5.7.2); 0 = no limit, an
    /// explicit choice the configuration file preserves. Default 10000 (DEF-6): the old default of 0
    /// let one request materialise a node's whole archive.
    uint32_t maxReturnDataValues{10000};
    /// Maximum events returned per node per HistoryRead; 0 = no limit. Default 10000 (DEF-6).
    /// A configuration file written before this default existed omitted the history section when it
    /// ran unlimited; such a file now reloads with these defaults, and must say 0 to stay unlimited.
    uint32_t maxReturnEventValues{10000};
  };

  DiagnosticPolicy diagnosticPolicy;  ///< Active DiagnosticInfo return policy.
  HistoryConfig historyConfiguration;  ///< Active history-access capability limits.

  /// Reverse-connect targets, activated by `start()` alongside listeners.
  std::vector<ReverseConnectTarget> reverseConnectTargets;

  /// Server-as-Local-Discovery-Server (LDS) configuration; gated OFF by default.
  ///
  /// When enabled the server accepts inbound RegisterServer / RegisterServer2 requests and
  /// aggregates registered servers into FindServers responses.
  struct LocalDiscoveryServer
  {
    /// Value equality across all fields.
    /// @return true when every field compares equal, otherwise false.
    bool operator==(const LocalDiscoveryServer&) const = default;
    bool enabled{false};  ///< Whether the LDS surface is active; gated OFF by default.
    std::chrono::seconds registrationExpiry{
      600};  ///< Time after which a registration expires (~10 min); isOnline=false evicts immediately.
    std::optional<uint32_t> maxRegistrations{1000};  ///< Maximum stored registrations; nullopt = unlimited.
    /// Directory the registrants' `semaphoreFilePath` values must lie in (Part 4 5.4.5.2). While set, a
    /// registration naming a semaphore file outside it is refused with Bad_SemaphoreFileMissing at
    /// RegisterServer, so a registrant cannot use the expiry sweep's existence check as a probe of
    /// arbitrary paths on the host. nullopt (the default) keeps the legacy behaviour: any path is
    /// honoured, and the residual is that a registrant with a trusted certificate can learn whether a
    /// path of its choosing exists by watching its own registration outlive the expiry.
    std::optional<std::string> semaphoreFileDirectory;
  };

  LocalDiscoveryServer localDiscoveryServer;  ///< Active Local-Discovery-Server settings.

  /// Returns the server capability limits (read-only view).
  /// @return Read-only reference to the advertised @ref ServerCapabilities.
  const ServerCapabilities& server_capabilities() const
  {
    return mServerCapabilities;
  }

  /// Returns the server capability limits for mutation before startup.
  /// @return Mutable reference to the advertised @ref ServerCapabilities.
  ServerCapabilities& server_capabilities()
  {
    return mServerCapabilities;
  }

  /// Returns the configured network listeners (read-only view).
  /// @return Read-only reference to the configured @ref ListenerConfig list.
  const std::vector<ListenerConfig>& listeners() const
  {
    return mListeners;
  }

  /// Returns the configured network listeners for mutation before startup.
  /// @return Mutable reference to the configured @ref ListenerConfig list.
  std::vector<ListenerConfig>& listeners()
  {
    return mListeners;
  }

  /// Validates the configuration, throwing on the first inconsistency found.
  ///
  /// Checks that connection/channel limits are non-zero and that listener and endpoint names are
  /// present, unique, and well-formed.
  ///
  /// @throws UaException with `Status::BadConfigurationError` if any constraint is violated.
  void validate() const
  {
    // OPC 10000-5 6.3.11: "Any operational limits Property that is provided shall have a non zero value".
    if (const auto zero = mServerCapabilities.operationLimits.first_zero_limit(); !zero.empty())
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidOperationLimit",
          "An operation limit that is set must be greater than zero (OPC 10000-5 6.3.11)",
          "ServerConfiguration")
          .context(ua::ContextKeys::fieldName, std::string{zero})
          .context(ua::ContextKeys::min, "1")};
    }
    if (maxReferencesPerBrowseRequest.has_value() && (*maxReferencesPerBrowseRequest == 0))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidEndpointConfig",
          "MaxReferencesPerBrowseRequest must be greater than zero",
          "ServerConfiguration")
          .context(ua::ContextKeys::actual, std::to_string(*maxReferencesPerBrowseRequest))
          .context(ua::ContextKeys::min, "1")};
    }
    if (maxReferencesPerBrowseRequest.has_value() && !mServerCapabilities.operationLimits.maxNodesPerBrowse)
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidEndpointConfig",
          "MaxReferencesPerBrowseRequest needs a MaxNodesPerBrowse limit: an unlimited operation count "
          "cannot be budgeted (set MaxReferencesPerBrowseRequest to nullopt to run without a budget)",
          "ServerConfiguration")};
    }
    if (maxReferencesPerBrowseRequest.has_value() && mServerCapabilities.operationLimits.maxNodesPerBrowse &&
        *maxReferencesPerBrowseRequest < *mServerCapabilities.operationLimits.maxNodesPerBrowse)
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidEndpointConfig",
          "MaxReferencesPerBrowseRequest must be at least MaxNodesPerBrowse so every Browse operation keeps "
          "a page",
          "ServerConfiguration")};
    }
    if (maxConnections.has_value() && (*maxConnections == 0))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build(
          "InvalidEndpointConfig", "MaxConnections must be greater than zero", "ServerConfiguration")
          .context(ua::ContextKeys::actual, std::to_string(*maxConnections))
          .context(ua::ContextKeys::min, "1")};
    }

    if (maxSecureChannels.has_value() && (*maxSecureChannels == 0))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build(
          "InvalidEndpointConfig", "MaxSecureChannels must be greater than zero", "ServerConfiguration")
          .context(ua::ContextKeys::actual, std::to_string(*maxSecureChannels))
          .context(ua::ContextKeys::min, "1")};
    }

    if (maxAccessIdentities == 0)
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidAccessIdentityLimit",
          "MaxAccessIdentities must be greater than zero",
          "ServerConfiguration")
          .context(ua::ContextKeys::actual, "0")
          .context(ua::ContextKeys::min, "1")};
    }

    if (authzTimeout <= std::chrono::milliseconds::zero())
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidAuthorizationTimeout",
          "AuthorizationTimeoutMs must be greater than zero",
          "ServerConfiguration")
          .context(ua::ContextKeys::actual, std::to_string(authzTimeout.count()))
          .context(ua::ContextKeys::min, "1")};
    }

    if (authnTimeout <= std::chrono::milliseconds::zero())
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidAuthenticationTimeout",
          "AuthenticationTimeoutMs must be greater than zero",
          "ServerConfiguration")
          .context(ua::ContextKeys::actual, std::to_string(authnTimeout.count()))
          .context(ua::ContextKeys::min, "1")};
    }

    if (monitoredItemAccessRecheckInterval <= std::chrono::seconds::zero())
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidMonitoredItemAccessRecheckInterval",
          "MonitoredItemAccessRecheckIntervalSeconds must be greater than zero",
          "ServerConfiguration")
          .context(ua::ContextKeys::actual, std::to_string(monitoredItemAccessRecheckInterval.count()))
          .context(ua::ContextKeys::min, "1")};
    }

    // Written as a positive test so that NaN, which compares false with everything, is rejected too.
    if (!(partialResultDeadlineFraction > 0.0 && partialResultDeadlineFraction < 1.0))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidPartialResultDeadlineFraction",
          "PartialResultDeadlineFraction must be greater than 0 and less than 1",
          "ServerConfiguration")
          .context(ua::ContextKeys::actual, std::to_string(partialResultDeadlineFraction))
          .context(ua::ContextKeys::min, "0 (exclusive)")
          .context(ua::ContextKeys::max, "1 (exclusive)")};
    }

    // A default above the ceiling is self-contradictory: the default is what a caller with no
    // diagnostics claim receives, so it would exceed the bound that the same struct declares.
    if (diagnosticPolicy.defaultLevel > diagnosticPolicy.maxLevel)
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidDiagnosticPolicy",
          "DiagnosticPolicy DefaultLevel must not exceed MaxLevel",
          "ServerConfiguration")
          .context(ua::ContextKeys::actual, std::string{diagnostic_level_name(diagnosticPolicy.defaultLevel)})
          .context(ua::ContextKeys::max, std::string{diagnostic_level_name(diagnosticPolicy.maxLevel)})};
    }

    std::unordered_set<std::string_view> listenerNames;
    for (const auto& l : mListeners)
    {
      if (l.name.empty())
      {
        throw UaException{Status::BadConfigurationError,
          make_error_detail(
            "MissingRequiredConfig", "Listener Name must not be empty", "ServerConfiguration")};
      }

      if (l.bind.address.empty())
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build(
            "MissingRequiredConfig", "Listener BindAddress must not be empty", "ServerConfiguration")
            .context(ua::ContextKeys::listenerName, std::string{l.name})};
      }

      if (!listenerNames.emplace(l.name).second)
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build("InvalidEndpointConfig", "Duplicate listener Name", "ServerConfiguration")
            .context(ua::ContextKeys::listenerName, std::string{l.name})};
      }

      std::unordered_set<std::string_view> endpointNames;
      for (const auto& ep : l.endpoints)
      {
        if (ep.name.empty())
        {
          throw UaException{Status::BadConfigurationError,
            ErrorDetail::build(
              "MissingRequiredConfig", "Listener endpoint Name must not be empty", "ServerConfiguration")
              .context(ua::ContextKeys::listenerName, std::string{l.name})};
        }

        if (!endpointNames.emplace(ep.name).second)
        {
          throw UaException{Status::BadConfigurationError,
            ErrorDetail::build(
              "InvalidEndpointConfig", "Listener contains duplicate endpoint Name", "ServerConfiguration")
              .context(ua::ContextKeys::listenerName, std::string{l.name})
              .context(ua::ContextKeys::endpointName, std::string{ep.name})};
        }
      }

      if (l.externalUrl && !l.externalUrl->has_basic_format())
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build(
            "InvalidEndpointConfig", "Listener has an invalid external URL", "ServerConfiguration")
            .context(ua::ContextKeys::listenerName, std::string{l.name})
            .context(ua::ContextKeys::endpointUrl, l.externalUrl->str())};
      }
    }

    if (connectionThrottling.ipv6PrefixLength == 0 || connectionThrottling.ipv6PrefixLength > 128)
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("InvalidResourceLimit",
          "ConnectionThrottling.Ipv6PrefixLength must be between 1 and 128 bits",
          "ServerConfiguration")
          .context(ua::ContextKeys::fieldName, std::string{"ConnectionThrottling.Ipv6PrefixLength"})
          .context(ua::ContextKeys::sizeActual, connectionThrottling.ipv6PrefixLength)
          .context(ua::ContextKeys::sizeMax, 128)};
    }

    // Internal admission/memory caps: 0 is invalid (there is no "unlimited" setting for a control whose
    // whole purpose is to bound growth). Reject any zero field rather than silently normalising it.
    const std::pair<std::string_view, uint32_t> internalCaps[]{
      {"ResourceLimits.EventDispatchQueueDepth", resourceLimits.eventDispatchQueueDepth},
      {"ResourceLimits.ConditionBranchesPerCondition", resourceLimits.conditionBranchesPerCondition},
      {"ResourceLimits.OrphanedSubscriptionStore", resourceLimits.orphanedSubscriptionStore},
      {"ResourceLimits.BufferedResponsesPerSession", resourceLimits.bufferedResponsesPerSession},
      {"ResourceLimits.WriteQueueDepthPerConnection", resourceLimits.writeQueueDepthPerConnection},
      {"ResourceLimits.WriteQueueBytesPerConnection", resourceLimits.writeQueueBytesPerConnection},
      {"ResourceLimits.IncomingChunkQueueDepth", resourceLimits.incomingChunkQueueDepth},
      {"ResourceLimits.OpenFileHandlesPerSession", resourceLimits.openFileHandlesPerSession},
      {"ResourceLimits.OpenFileHandles", resourceLimits.openFileHandles},
      {"ConnectionThrottling.MaxTrackedEndpoints", connectionThrottling.maxTrackedEndpoints},
      {"IdentityThrottling.MaxTrackedIdentities", identityThrottling.maxTrackedIdentities},
      {"SubscriptionLimits.MaxPublishRequestsPerSession",
        subscriptionLimits.maxPublishRequestsPerSession.value_or(1)},
    };
    for (const auto& [name, value] : internalCaps)
    {
      if (value == 0)
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build("InvalidResourceLimit",
            "Server-internal resource cap must be greater than zero (0 is not 'unlimited')",
            "ServerConfiguration")
            .context(ua::ContextKeys::fieldName, std::string{name})
            .context(ua::ContextKeys::actual, "0")
            .context(ua::ContextKeys::min, "1")};
      }
    }
  }

private:
  ServerCapabilities mServerCapabilities;
  std::vector<ListenerConfig> mListeners;
};

/// Applies the **Embedded Server Profile** preset to an existing `ServerConfig` in place.
///
/// The Embedded profile targets a low-MB-class device that still needs mandatory security: it tightens
/// every concurrency/size cap to a small, coherent set so the server's working set stays bounded and
/// hostile or accidental over-demand fails closed rather than growing memory. It is the runtime half of
/// the design - a lightweight preset applied to the one runtime surface (`ServerConfig`), not a
/// separate profile tier object.
///
/// What it sets (all overwritten, not merged): connection / secure-channel / per-session request caps;
/// session, subscription and MonitoredItem caps; MonitoredItem and event queue sizes; per-service
/// OperationLimits; continuation-point counts; EventFilter clause limits; the per-value encoding size
/// caps (array / String / ByteString); and it bounds the returned DiagnosticInfo to Summary.
///
/// What it deliberately leaves untouched, so it can be applied to a partly-built config: listeners and
/// their endpoints; application identity; role configuration and the role/management feature gates;
/// the advertised `ServerProfileArray` (a deployment/certification choice); and Local-Discovery-Server
/// settings. Auditing is already off by default and is left as-is.
///
/// Apply this first, then layer any deployment-specific overrides on top - e.g.
/// `apply_embedded_server_profile(config); config.server_capabilities().maxSessions = 8;`. The
/// resulting config still satisfies `ServerConfig::validate` (all caps stay non-zero).
///
/// @param config Configuration to tighten in place.
/// @see ServerConfig
void apply_embedded_server_profile(ServerConfig& config);

}  // namespace ua::server

#endif  // !UA_SERVER_CONFIGURATION_H
