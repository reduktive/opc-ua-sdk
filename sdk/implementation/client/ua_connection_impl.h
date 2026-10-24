// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_IMPL_H
#define UA_CONNECTION_IMPL_H

/// @file
/// @brief Tier-1 Connection orchestrator hub (client, section 8.2A) - bootstrap + gated read/write/browse +
/// close.
/// @ingroup client

#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_address_space_cache_policy.h"
#include "ua_client_diagnostic_policy.h"
#include "ua_subscription_fallback_policy.h"
#include "ua_type_resolution_policy.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_cancel_request.h"
#include "ua_cancel_response.h"
#include "ua_client_handle_allocator.h"
#include "ua_client_monitored_item.h"
#include "ua_client_subscription.h"  // ua::client::SetTriggeringResult (per-link SetTriggering results)
#include "ua_client_secure_channel.h"
#include "ua_await_callback.h"
#include "ua_client_session.h"
#include "ua_client_subscriptions_pipeline.h"
#include "ua_connection_dispatch.h"
#include "ua_connection_state.h"
#include "ua_data_change_monitored_item_owner.h"
#include "ua_data_value.h"
#include "ua_endpoint_description.h"
#include "ua_get_endpoints_response.h"  // CL-RECONN-005: refresh_endpoint_from_get_endpoints parameter
#include "ua_subscription_factory.h"  // detail::SubscriptionCreated + SubscriptionFactoryOps role
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_nodes_request.h"
#include "ua_event_filter.h"
#include "ua_event_backbone_ops.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_keep_alive_tracker.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_logger.h"
#include "ua_modify_subscription_response.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_namespace_table.h"
#include "ua_node_id.h"
#include "ua_observer_sink.h"
#include "ua_open_continuation_point_tracker.h"
#include "ua_query_first_request.h"
#include "ua_query_first_response.h"
#include "ua_query_next_request.h"
#include "ua_query_next_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_reconnect_policy.h"
#include "ua_redundancy_manager.h"  // ua::client::RedundancyManager + RedundancyPolicy (redundancy() + wiring)
#include "ua_redundancy_manager_connection_host.h"  // RedundancyManagerConnectionHost + RedundancyDiscoveryProvider
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_result.h"
#include "ua_session_ops.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_server_table.h"
#include "ua_status_code.h"
#include "ua_timer.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua
{
class ResponseHeader;  // CL-BASEDIAG-001: surface_response_diagnostics reads a received response header
}

namespace ua::client::detail
{

class ReconnectionFSM;
class SubscriptionIdCellRegistry;
class ConnectionReconnectHost;
class ConnectionOpsShim;
class WireOps;
class SupportOps;
class EventSubscriberImpl;
class EventRouter;
class AlarmConditionTrackerImpl;
class ConnectionEventBackboneOps;
class TypeResolver;
class SubscriptionFactoryOps;
class SemanticChangeCache;
class AddressSpaceCache;
class RedundancyManagerImpl;

// @ref SubscriptionCreated is homed in ua_subscription_factory.h (included above) so the narrow
// @ref SubscriptionFactoryOps interface and the tier-2 streaming accessor can name it without pulling in this
// heavy orchestrator header.

// The public lifecycle state (@ref ConnectionState) lives in ua_connection_state.h so the upward
// ConnectionOps interface (@ref SupportOps) and this orchestrator can both name it without an include cycle.

/// Slice-1 subset of the per-Connection configuration (section 7.7 / section 8.2A.5).
struct ConnectionConfig
{
  /// When true, wire ops submitted while not `Active` are queued; when false they fail fast.
  bool queueOnReconnect = true;
  /// Optional bound on the reconnect pending queue (oldest-evicted when exceeded).
  std::optional<std::size_t> pendingQueueLimit = 1024;
  /// Stale-request budget for queued ops.
  std::chrono::steady_clock::duration maxQueueAge = std::chrono::seconds{30};
  /// Per-Connection observer slots (section 7.7 / section 7.8). Each family is independently optional; a
  /// non-null slot overrides the Client-level default for that family (resolved into the sink at
  /// construction). The eight flat section 7.7 fields are grouped here as one @ref ObserverSlots for a single
  /// source of truth + a direct feed to `resolve_observer_slots`.
  ObserverSlots observers;
  /// The optional client-side address-space cache policy (section 8.7 / Slice V1). Opt-in (default disabled =
  /// a clean pass-through no-op). Decomposed into the immutable @ref ConnectionImpl::mAddressSpaceCachePolicy
  /// member at construction and injected into the lazily-constructed @ref detail::AddressSpaceCache.
  ua::client::AddressSpaceCachePolicy addressSpaceCache;
  /// The per-Connection diagnostics policy (section 7.10.4). Decomposed into the immutable
  /// @ref ConnectionImpl::mDiagnosticPolicy at construction. Defaults preserve the pre-policy behaviour.
  ua::client::ClientDiagnosticPolicy diagnostics;
  /// The polled-Read Subscription-fallback policy (section 8.4, CL-SUB-019). Its @ref
  /// ua::client::SubscriptionFallbackPolicy::Mode is decomposed into the immutable
  /// @ref ConnectionImpl::mSubscriptionFallbackMode at construction and handed to the
  /// @ref detail::SubscriptionsPipeline at wire time. Defaults to Disabled (== today's behaviour).
  ua::client::SubscriptionFallbackPolicy subscriptionFallback;
  /// The per-Connection type-resolution policy (section 8.6). Decomposed into the immutable
  /// @ref ConnectionImpl::mTypeResolutionPolicy at construction and handed to the lazily-constructed
  /// @ref detail::TypeResolver, which is the ONLY consumer. Defaults to Lazy with no eager interest set.
  ua::client::TypeResolutionPolicy typeResolution;
  /// The endpoint this Connection is bound to (section 7.7). Published to the Rule-4 cross-strand
  /// @ref ConnectionImpl::active_endpoint_snapshot at construction so the tier-2 redundancy manager's
  /// synchronous identity reads (`current_endpoint` / `current_application_uri`, section 8.11) serve off a
  /// lock-free atomic snapshot rather than the orchestrator's strand-owned state (F1/J45). Defaults to an
  /// empty description; the connect path fills it, and a reconnect-commit republish is a W9 concern.
  ua::EndpointDescription endpoint;
  /// The key agreement of the CreateSession that made this Connection's Session: the ECDHPolicyUri planned
  /// for the UserIdentityToken and whether an EphemeralKey is asked for at all (CL-ECC-003,
  /// AC-CL-ECC-003-NO-KEY-REQUEST-WITHOUT-A-SECRET-TOKEN-POLICY). A reconnect that creates a new Session asks
  /// the same. The defaults are a CreateSessionConfig's.
  std::string ecdhPolicyUri;
  bool requestEphemeralKey = true;
};

/// Reopens a fresh @ref ua::client::SecureChannel to the same endpoint (captures the Client +
/// OpenChannelConfig at the call site). Invoked by the reconnect open-channel step; the callback it is
/// handed fires on the executor with the new channel (or an @ref ua::ErrorDetail).
using ReopenChannel = std::function<void(std::function<void(ua::Result<ua::client::SecureChannel>)>)>;

/// Re-validates THIS Connection's CURRENT server certificate against the certificate store and delivers the
/// verdict (section 722/section 727, CL-SECADMIN-004). A `Good` @ref ua::VoidResult means "still trusted"; a
/// `Bad` one (BadCertificateUntrusted / TimeInvalid / Revoked / ...) means "no longer trusted / revoked" and
/// the Connection ACTS on it by triggering a `CertRotated` reconnect (CL-RECONN-006). An empty interface
/// means only that server-trust revalidation is unavailable; an explicit own-certificate change still forces
/// the Part 4 section 6.7 new-Session reconnect. Delivered off the connection strand (the store validate is
/// itself
/// async).
///
/// SEAM CONTRACT (the connect-path implementer MUST honour): invoke the supplied verdict callback EXACTLY
/// ONCE (never zero times, never more than once) and do NOT throw synchronously out of the interface
/// invocation. A interface that never fires its verdict leaks the owed completion and HANGS the
/// `CoreClientImpl::revalidate_connections` walk barrier forever; an interface that fires twice is
/// defensively de-duplicated by
/// @ref ConnectionImpl::revalidate_server_cert_async (a fire-once guard), but relying on that is a contract
/// violation. A synchronous throw is caught by the enclosing strand guard but still drops the owed
/// completion.
using ServerCertValidator = std::function<void(std::function<void(ua::VoidResult)>)>;

/// Keep-alive poll policy  -  the canonical type is the public @ref ua::client::KeepAlivePolicy
/// (ua_reconnect_policy.h), aliased here so the tier-1 interfaces (@ref ReconnectWiring, @ref
/// create_with_ops) and the tier-0 detail code can name it without the `ua::client::` qualifier. Single
/// source of truth.
using KeepAlivePolicy = ua::client::KeepAlivePolicy;

/// Optional automatic-reconnect wiring for @ref ConnectionImpl::create (section 8.3). When present the
/// orchestrator owns a @ref ReconnectionFSM and rebinds the session onto a fresh channel on a drop;
/// when absent the Connection is single-shot (current bootstrap-only behaviour).
struct ReconnectWiring
{
  /// Interface that opens a fresh SecureChannel to the same endpoint (the reconnect open-channel step).
  ReopenChannel reopenChannel;
  /// Activation parameters used when rebinding the existing session onto the fresh channel.
  ua::client::Session::ActivateConfig activateConfig;
  /// Backoff / attempt / recovery policy for the reconnect FSM.
  ua::client::ReconnectPolicy policy;
  /// Keep-alive poll policy. Keep-alive is a reconnect-adjacent concern (a miss drives the FSM), so it
  /// lives here - a single-shot Connection with no reconnect wiring has nothing to do on a miss.
  KeepAlivePolicy keepAlive;
  /// Non-transparent redundancy / failover OPT-IN (section 8.11 / J49). Default OFF: redundancy monitoring
  /// reads the server's `RedundancySupport` + `ServerUriArray` and installs a `ServiceLevel` MonitoredItem on
  /// every reach-Active, which is real per-connection overhead a non-redundant deployment should not pay  -
  /// so the engine is constructed ONLY when the application asks for failover. When false, @ref
  /// ConnectionImpl leaves `mRedundancyManager` null and `Connection::redundancy()` hands back the null-safe
  /// handle.
  bool enableRedundancy = false;
  /// Per-Connection redundancy / failover knobs (section 8.11.1). Threaded into the eagerly-constructed
  /// @ref ua::client::detail::RedundancyManagerImpl (only when @ref enableRedundancy, F3/J44); const after
  /// ctor.
  ua::client::RedundancyPolicy redundancyPolicy{};
  /// The FindServers translation interface the redundancy host uses (section 8.11, F2/J46). Empty on the
  /// current bootstrap-only path  -  the connect path lights it up in a later slice; absent, the host's
  /// `find_servers_async` completes a source-tagged `Bad_NotImplemented` (never silent).
  RedundancyDiscoveryProvider redundancyDiscovery{};
  /// Server-certificate re-validation interface (section 722/section 727, CL-SECADMIN-004 / CL-RECONN-006).
  /// Drives
  /// @ref ConnectionImpl::revalidate_server_cert_async, which the Client-level walk
  /// (`CoreClientImpl::revalidate_connections_async`) fans out to after a renewed cert / new trust list is
  /// committed (W6 PullCert). Empty on the current bootstrap-only path  -  no active secured channel is
  /// retained yet, so the revalidate is a Good no-op; the connect path fills it (W5 leaves it empty).
  ServerCertValidator serverCertValidator{};
};

/// Interface-level analogue of @ref ReconnectWiring: identical, except the reopen step is the already-adapted
/// @ref ReopenChannelOps (yields a @ref ChannelOps) rather than the caller-facing @ref ReopenChannel (yields
/// a @ref ua::client::SecureChannel). This is what @ref create_from_ops consumes  -  the production connect
/// path (which drives the tier-0 interfaces directly) and unit tests build a @ref ReopenChannelOps without a
/// concrete @ref ua::client::Client, so they pass this variant; @ref create adapts a @ref ReconnectWiring
/// into it via @ref make_real_reopen. When absent (nullopt), the Connection is single-shot.
struct ReconnectWiringOps
{
  /// Interface that opens a fresh channel to the same endpoint and yields it as a @ref ChannelOps.
  ReopenChannelOps reopenChannel;
  /// Activation parameters used when rebinding the session onto the fresh channel (identity preserved).
  ua::client::Session::ActivateConfig activateConfig;
  /// Backoff / attempt / recovery policy for the reconnect FSM.
  ua::client::ReconnectPolicy policy;
  /// Keep-alive poll policy (a miss drives the FSM).
  KeepAlivePolicy keepAlive;
  /// Non-transparent redundancy / failover OPT-IN (section 8.11 / J49); default OFF.
  bool enableRedundancy = false;
  /// Per-Connection redundancy knobs (consumed only when @ref enableRedundancy).
  ua::client::RedundancyPolicy redundancyPolicy{};
  /// FindServers translation interface for the redundancy host (empty  to  source-tagged
  /// `Bad_NotImplemented`).
  RedundancyDiscoveryProvider redundancyDiscovery{};
  /// Server-certificate re-validation interface (empty  to  `revalidate_server_cert_async` is a Good no-op).
  ServerCertValidator serverCertValidator{};
};

/// Classifies a bad wire @p status as "the current channel or session is gone" - a real transport drop
/// that warrants an automatic reconnect (section 8.3, CL-RECONN-001). Two families qualify: channel-fatal
/// (the SecureChannel / TCP connection died - the tier-0 completes in-flight requests with
/// BadSecureChannelClosed on a drop; the others cover explicit disconnect / transport errors) and
/// session-fatal (the channel may be fine but the Session is gone, e.g. the server restarted; the
/// reconnect re-activates, falling back to CreateSession per CL-RECONN-003 when ActivateSession is
/// rejected). Deliberately EXCLUDES ambiguous / transient results: BadTimeout (a slow server is not a
/// drop), BadTooManyPublishRequests (flow control), and BadNoSubscription (a lifecycle result). The
/// automatic drop path (@ref ConnectionImpl::notify_transport_drop_async) is gated on this predicate.
[[nodiscard]] bool is_channel_fatal(ua::StatusCode status) noexcept;

/// The server's per-call OperationLimits (OPC 10000-5 section 6.3.11, CL-BASE-003), read once at bootstrap
/// from `Server.ServerCapabilities.OperationLimits.*` and refreshed on every reconnect re-read. Each field
/// caps the number of items the client packs into a single batched service call before splitting the request
/// into chunks; a field of `0` means "no server-published limit" (absent / bad / non-UInt32 all map to 0),
/// which the SDK treats as no client-imposed limit (unlimited). Strand-owned on @ref ConnectionImpl.
struct OperationLimits
{
  std::uint32_t maxNodesPerRead = 0;
  std::uint32_t maxNodesPerWrite = 0;
  std::uint32_t maxNodesPerMethodCall = 0;
  std::uint32_t maxNodesPerBrowse = 0;
  std::uint32_t maxNodesPerRegisterNodes = 0;
  std::uint32_t maxNodesPerTranslateBrowsePathsToNodeIds = 0;
  std::uint32_t maxNodesPerNodeManagement = 0;
  std::uint32_t maxMonitoredItemsPerCall = 0;
  std::uint32_t maxNodesPerHistoryReadData = 0;
  std::uint32_t maxNodesPerHistoryReadEvents = 0;
  std::uint32_t maxNodesPerHistoryUpdateData = 0;
  std::uint32_t maxNodesPerHistoryUpdateEvents = 0;
};

/// Per-Session continuation-point ceilings published by ServerCapabilities (OPC 10000-5 section 6.3.2,
/// CL-BASE-004). Zero means the Server imposes no advertised client-side cap.
struct ContinuationPointLimits
{
  std::uint16_t maxBrowse = 0;
  std::uint16_t maxQuery = 0;
  std::uint16_t maxHistory = 0;
};

/// Cross-strand snapshot of the Connection (Rule 4; atomic-loaded by @ref ConnectionImpl::info).
///
/// Immutable and value-typed: republished wholesale on every visible state change, never mutated in
/// place. A holder of a `std::shared_ptr<const ConnectionInfo>` may read it from any thread.
struct ConnectionInfo
{
  /// The public lifecycle state.
  ConnectionState state = ConnectionState::Connecting;
  /// The server-assigned session identifier (null before the session is created on the server).
  ua::NodeId sessionId;
  /// The number of namespaces in the current NamespaceArray snapshot (0 before bootstrap completes).
  std::size_t namespaceCount = 0;
  /// The server's `Server.UrisVersion` change counter for the current snapshot (CL-BASE-001), or
  /// `std::nullopt` before bootstrap completes or when the server does not publish it.
  std::optional<std::uint32_t> urisVersion;
  /// The server's per-call OperationLimits (CL-BASE-003), read at bootstrap; all-zero (no client-imposed
  /// limit) before bootstrap completes or for any limit the server does not publish.
  OperationLimits operationLimits;
  /// The server's per-Session continuation-point ceilings (CL-BASE-004).
  ContinuationPointLimits continuationPointLimits;
};

/// The outcome of a successful single-item `CreateMonitoredItems` (section 8.4): the server-assigned
/// monitored-item id plus the server's REVISED sampling interval (CL-MI-002). Threaded out of
/// @ref ConnectionImpl::begin_create_monitored_item so the @ref monitor_data_change_async facade can snapshot
/// the revised interval onto the returned @ref ua::client::MonitoredItem handle (the id-only
/// @ref create_monitored_item_async caller ignores the interval).
struct CreatedMonitoredItem
{
  std::uint32_t monitoredItemId = 0;
  double revisedSamplingIntervalMs = 0.0;
  std::uint32_t revisedQueueSize =
    0;  ///< the server's REVISED queue size (CL-MI-019), seeded onto the handle
};

/// The tier-1 Connection orchestrator (section 8.2A): owns a tier-0 @ref ua::client::Session and the wire-op
/// submit gate (@ref ConnectionDispatch), and drives session bootstrap, tier-1 wire ops
/// (Read / Write / Browse via the generic @ref invoke_wire_op funnel), and graceful close on a private
/// strand.
///
/// Strand-serialized: every public method posts onto the private strand; all mutable state
/// (`mState`, `mSessionId`, `mNamespaceTable`) lives there and is read cross-thread only via the
/// @ref ConnectionInfo snapshot. User callbacks are always delivered on the executor, never on the
/// connection strand (section 8.2A.1 hard rule 3). This is slice 1 - the KeepAliveTimer, ReconnectionFSM,
/// SubscriptionsPipeline, and the full tier-1/2 surface layer on top in later slices.
/// Outcome of comparing a replacement NamespaceArray snapshot against the one it replaces.
struct NamespaceRemap
{
  bool contentsChanged{false};  ///< Any URI added, removed, or moved. The gate for notifying at all.
  bool sizeChanged{false};  ///< The number of namespaces differs.
  bool indexShifted{false};  ///< A URI present in both tables sits at a DIFFERENT index.
};

/// Compares two NamespaceArray snapshots (CL-ADDRSP-004).
///
/// `indexShifted` is the consequential one: a NodeId encodes a namespace INDEX, so a URI that moved
/// index invalidates every persisted NodeId that referenced it - and the NodeId still parses, still
/// resolves, and now names the wrong node. A first table (no previous) is not a remap.
///
/// Declared here so the comparison is directly testable: it is the part that did not exist, and the
/// firing site is a single call on the reconnect re-read path.
[[nodiscard]] NamespaceRemap compare_namespace_tables(
  const std::shared_ptr<const NamespaceTable>& previous, const std::shared_ptr<const NamespaceTable>& next);

class ConnectionImpl : public std::enable_shared_from_this<ConnectionImpl>
{
public:
  /// Registers a live `Subscription` handle's server-id cell so a recreate can carry it forward.
  ///
  /// @param cell The handle's id cell; held weakly and pruned once the handle is destroyed.
  void register_subscription_id_cell(std::weak_ptr<std::atomic<std::uint32_t>> cell);

  /// Points every live handle that still names @p oldId at @p newId, and prunes dead entries.
  ///
  /// @param oldId The create-time server subscription id the handles still carry.
  /// @param newId The id the recreate obtained for the replacement Subscription.
  void rekey_subscription_id_cells(std::uint32_t oldId, std::uint32_t newId);

  /// Creates a Connection orchestrator in the `Connecting` state around an already-activated session.
  ///
  /// @param executor  The io_context executor for the private strand and callbacks.
  /// @param session   The tier-0 session (already created + activated); moved in and owned.
  /// @param config    Slice-1 dispatch/queue configuration.
  /// @param logger    Logger for the exception-guarded async boundaries.
  /// @param reconnect Optional auto-reconnect wiring (section 8.3). When present the orchestrator owns a
  ///                  @ref ReconnectionFSM and rebinds the session onto a fresh channel on a drop;
  ///                  when absent (default) the Connection is single-shot.
  /// @param clientObserverDefaults The Client-level observer defaults resolved against this Connection's own
  ///                  @ref ConnectionConfig::observers (per-Connection non-null wins;
  ///                  section 7.3/section 7.7). Empty by default  -  the Client connect path threads its
  ///                  process-wide defaults here (see the W1 wiring note: the Client connect path that
  ///                  consumes this is a later slice).
  /// @return A shared orchestrator; call @ref start_async to run the bootstrap.
  [[nodiscard]] static std::shared_ptr<ConnectionImpl> create(boost::asio::any_io_executor executor,
    ua::client::Session session, ConnectionConfig config, ua::Logger logger,
    std::optional<ReconnectWiring> reconnect = std::nullopt, ObserverSlots clientObserverDefaults = {});

  /// Production factory over the tier-0 @ref SessionOps interface (section 8.2A). Identical to @ref create
  /// except it takes an already-activated session as a @ref SessionOps (not a concrete @ref
  /// ua::client::Session) and the reconnect wiring as the interface-level @ref ReconnectWiringOps (not @ref
  /// ReconnectWiring). This is the factory the production connect path (`RealConnectionEstablisher`) drives:
  /// it opens the channel, creates and activates the session through the interfaces, then hands the resulting
  /// @ref SessionOps here  -  so the same interface that unit tests inject (a fake) is the interface
  /// production uses (a @ref RealSessionOps), and the establisher's own sequencing / cleanup logic is
  /// unit-testable. @ref create and the test-only
  /// @ref create_with_ops both delegate here (single construction path). Reconnect is engaged iff @p
  /// reconnect is present (single-shot otherwise  -  no FSM, no keep-alive).
  ///
  /// @return A shared orchestrator in `Connecting`; call @ref start_async to run the bootstrap.
  [[nodiscard]] static std::shared_ptr<ConnectionImpl> create_from_ops(boost::asio::any_io_executor executor,
    std::shared_ptr<SessionOps> sessionOps, ConnectionConfig config, ua::Logger logger,
    std::optional<ReconnectWiringOps> reconnect = std::nullopt, ObserverSlots clientObserverDefaults = {});

  /// The SecureChannel of a single-shot Connection (no automatic reconnect) was lost (owner decision
  /// 2026-10-03, BR-19): with nothing to reconnect, the loss is terminal - the Connection goes Failed and
  /// reports `on_disconnected` once with @p status and @p detail, as a reconnect that gave up does. Ignored
  /// for a Connection with automatic reconnect (its keep-alive and Publish paths own drop handling) and for
  /// one already closing, closed or failed. Thread-safe; posts to the strand.
  void on_channel_lost_async(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> detail) noexcept;

  /// Installs a one-shot teardown hook invoked once from the destructor (before any member is destroyed).
  /// The Client connect path uses it to unregister this Connection from `CoreClientImpl`'s weak connection
  /// registry (section 8.1A / W5) exactly once on every destruction path (bootstrap-fail drop, graceful
  /// close, handle drop)  -  RAII cleanup without a `CoreClientImpl` back-reference (layering: tier-1
  /// orthogonal to root). The hook MUST NOT block or re-enter this Connection; it is a lightweight registry
  /// erase. Set-once; a second call replaces the prior hook (the prior one never fires).
  void set_teardown_hook(std::function<void()> hook);

  ConnectionImpl(const ConnectionImpl&) = delete;
  ConnectionImpl& operator=(const ConnectionImpl&) = delete;
  ConnectionImpl(ConnectionImpl&&) = delete;
  ConnectionImpl& operator=(ConnectionImpl&&) = delete;
  ~ConnectionImpl();

  /// Runs the session bootstrap: reads `Server.NamespaceArray`, builds the @ref NamespaceTable
  /// snapshot, and transitions `Connecting -> Active` (or `Failed`).
  ///
  /// @param callback Receives `Good` once Active, or a Result carrying an @ref ua::ErrorDetail chain
  ///                 when the bootstrap Read fails (delivered on the executor).
  void start_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// Re-activates the existing Session on its bound channel with @p newIdentity. Valid only while Active;
  /// preserves the Session, subscription pipeline, and reconnect state.
  void reactivate_async(
    ua::client::UserIdentity newIdentity, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Issues a tier-1 Read through the dispatch gate.
  ///
  /// When `Active` the Read dispatches to the tier-0 session immediately; when `Closed` it fails with
  /// `Bad_ConnectionClosed`. The callback runs on the executor.
  ///
  /// @param request  The Read request.
  /// @param callback Receives the @ref ua::ReadResponse on success, or a bad Result (on the executor).
  void read_async(
    ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) noexcept;

  /// Issues a tier-1 HistoryRead through the dispatch gate (same gating as @ref read_async): queued while
  /// Reconnecting, fast-failed `Bad_ConnectionClosed` when terminal, dispatched on the current session when
  /// Active. The request is funnelled opaquely; continuation-point / details handling is the caller's.
  ///
  /// @param request  The HistoryRead request.
  /// @param callback Receives the @ref ua::HistoryReadResponse on success, or a bad Result (on the executor).
  void history_read_async(ua::HistoryReadRequest request,
    std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) noexcept;

  /// Issues a tier-1 Write through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The Write request.
  /// @param callback Receives the @ref ua::WriteResponse on success, or a bad Result (on the executor).
  void write_async(
    ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) noexcept;

  /// Issues a tier-1 Browse through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The Browse request.
  /// @param callback Receives the @ref ua::BrowseResponse on success, or a bad Result (on the executor).
  void browse_async(
    ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) noexcept;

  /// Issues a tier-1 BrowseNext (continue a Browse continuation point) through the dispatch gate (same
  /// gating as @ref read_async).
  ///
  /// @param request  The BrowseNext request (carrying the continuation points).
  /// @param callback Receives the @ref ua::BrowseNextResponse on success, or a bad Result (on the executor).
  void browse_next_async(
    ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept;
  void browse_next_on_session_async(std::uint64_t expectedSessionGeneration, ua::BrowseNextRequest request,
    std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept;

  /// Issues a tier-1 TranslateBrowsePathsToNodeIds (resolve browse paths to NodeIds) through the dispatch
  /// gate (same gating as @ref read_async).
  ///
  /// @param request  The TranslateBrowsePathsToNodeIds request.
  /// @param callback Receives the response on success, or a bad Result (on the executor).
  void translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
    std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) noexcept;

  /// Issues a tier-1 Call (method invocation) through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The Call request.
  /// @param callback Receives the @ref ua::CallResponse on success, or a bad Result (on the executor).
  void call_async(
    ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) noexcept;

  /// Issues a tier-1 Cancel (cancel outstanding requests) through the dispatch gate (same gating as
  /// @ref read_async).
  ///
  /// @param request  The Cancel request.
  /// @param callback Receives the @ref ua::CancelResponse on success, or a bad Result (on the executor).
  void cancel_async(
    ua::CancelRequest request, std::function<void(ua::Result<ua::CancelResponse>)> callback) noexcept;

  /// Issues a tier-1 RegisterNodes through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The RegisterNodes request.
  /// @param callback Receives the @ref ua::RegisterNodesResponse on success, or a bad Result (on the
  /// executor).
  void register_nodes_async(ua::RegisterNodesRequest request,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) noexcept;

  /// Issues a tier-1 UnregisterNodes through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The UnregisterNodes request.
  /// @param callback Receives the @ref ua::UnregisterNodesResponse on success, or a bad Result (on the
  /// executor).
  void unregister_nodes_async(ua::UnregisterNodesRequest request,
    std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) noexcept;

  /// Issues a tier-1 AddNodes through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The AddNodes request.
  /// @param callback Receives the @ref ua::AddNodesResponse on success, or a bad Result (on the executor).
  void add_nodes_async(
    ua::AddNodesRequest request, std::function<void(ua::Result<ua::AddNodesResponse>)> callback) noexcept;

  /// Issues a tier-1 AddReferences through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The AddReferences request.
  /// @param callback Receives the @ref ua::AddReferencesResponse on success, or a bad Result (on the
  /// executor).
  void add_references_async(ua::AddReferencesRequest request,
    std::function<void(ua::Result<ua::AddReferencesResponse>)> callback) noexcept;

  /// Issues a tier-1 DeleteNodes through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The DeleteNodes request.
  /// @param callback Receives the @ref ua::DeleteNodesResponse on success, or a bad Result (on the executor).
  void delete_nodes_async(ua::DeleteNodesRequest request,
    std::function<void(ua::Result<ua::DeleteNodesResponse>)> callback) noexcept;

  /// Issues a tier-1 DeleteReferences through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The DeleteReferences request.
  /// @param callback Receives the @ref ua::DeleteReferencesResponse on success, or a bad Result (on the
  /// executor).
  void delete_references_async(ua::DeleteReferencesRequest request,
    std::function<void(ua::Result<ua::DeleteReferencesResponse>)> callback) noexcept;

  /// Issues a tier-1 HistoryUpdate through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The HistoryUpdate request.
  /// @param callback Receives the @ref ua::HistoryUpdateResponse on success, or a bad Result (on the
  /// executor).
  void history_update_async(ua::HistoryUpdateRequest request,
    std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) noexcept;

  /// Issues a tier-1 SetMonitoringMode through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The SetMonitoringMode request.
  /// @param callback Receives the @ref ua::SetMonitoringModeResponse on success, or a bad Result (on the
  /// executor).
  void set_monitoring_mode_async(ua::SetMonitoringModeRequest request,
    std::function<void(ua::Result<ua::SetMonitoringModeResponse>)> callback) noexcept;

  /// Issues a tier-1 ModifyMonitoredItems through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The ModifyMonitoredItems request.
  /// @param callback Receives the @ref ua::ModifyMonitoredItemsResponse on success, or a bad Result.
  void modify_monitored_items_async(ua::ModifyMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::ModifyMonitoredItemsResponse>)> callback) noexcept;

  /// Issues a tier-1 SetTriggering (configure triggering links) through the dispatch gate (same gating as
  /// @ref read_async).
  ///
  /// @param request  The SetTriggering request.
  /// @param callback Receives the @ref ua::SetTriggeringResponse on success, or a bad Result.
  void set_triggering_async(ua::SetTriggeringRequest request,
    std::function<void(ua::Result<ua::SetTriggeringResponse>)> callback) noexcept;

  /// Issues a tier-1 QueryFirst through the dispatch gate (same gating as @ref read_async).
  ///
  /// @param request  The QueryFirst request.
  /// @param callback Receives the @ref ua::QueryFirstResponse on success, or a bad Result (on the executor).
  void query_first_async(
    ua::QueryFirstRequest request, std::function<void(ua::Result<ua::QueryFirstResponse>)> callback) noexcept;

  /// Issues a tier-1 QueryNext (continue a QueryFirst continuation point) through the dispatch gate (same
  /// gating as @ref read_async).
  ///
  /// @param request  The QueryNext request.
  /// @param callback Receives the @ref ua::QueryNextResponse on success, or a bad Result (on the executor).
  void query_next_async(
    ua::QueryNextRequest request, std::function<void(ua::Result<ua::QueryNextResponse>)> callback) noexcept;

  /// Creates a Subscription on the server and registers it with the SubscriptionsPipeline (section 8.4).
  ///
  /// Gated like a wire op: fast-fails with `Bad_ConnectionClosed` when not `Active` (WITHOUT touching the
  /// tier-0 session). On `Active` it issues `CreateSubscription`, registers the returned subscription id
  /// with the pipeline, and starts the Publish pump. The callback runs on the executor.
  ///
  /// @param publishingInterval The requested publishing interval (milliseconds).
  /// @param callback           Receives the server-assigned subscription id on success, or a bad Result.
  void create_subscription_async(
    double publishingInterval, std::function<void(ua::Result<std::uint32_t>)> callback) noexcept;

  /// Creates a Subscription and returns the full @ref SubscriptionCreated details for a public
  /// @ref ua::client::Subscription handle (section 7.4). Like @ref create_subscription_async but honours the
  /// config's publishing-enabled flag and surfaces the server-revised publishing interval + enabled flag.
  ///
  /// @param publishingInterval The requested publishing interval (ms).
  /// @param publishingEnabled  Whether publishing starts enabled.
  /// @param callback           Receives the @ref SubscriptionCreated snapshot on success, or a bad Result.
  void create_subscription_managed_async(double publishingInterval, bool publishingEnabled,
    std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept;
  void create_subscription_managed_async(double publishingInterval, bool publishingEnabled,
    std::optional<std::uint32_t> maxNotificationsPerPublish,
    std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept;

  /// The CreateSubscription parameters a caller may tune (OPC 10000-4 5.13.2, Table 85), resolved to the
  /// values actually put on the wire. The defaults below are the conventional ones an internal caller with
  /// nothing to tune wants.
  ///
  /// Retaining them per Subscription is not an optimisation. ModifySubscription REPLACES the whole
  /// parameter set (OPC 10000-4 5.13.3.1), and a session-CHANGED reconnect rebuilds the Subscription from
  /// nothing, so both need the caller's parameters to rebuild from. `maxKeepAliveCount` and `lifetimeCount`
  /// together decide how fast a dead Subscription is detected, and `priority` decides which Subscription a
  /// loaded server publishes first.
  struct SubscriptionTuning
  {
    std::uint32_t lifetimeCount = 30;  ///< publishing intervals before the server drops an unpublished sub
    std::uint32_t maxKeepAliveCount = 10;  ///< publishing intervals of silence before a keep-alive
    std::uint32_t maxNotificationsPerPublish = 0;  ///< per-Publish notification cap; 0 == no limit
    std::uint8_t priority = 0;  ///< relative publishing priority; 0 == lowest
    bool publishingEnabled = true;  ///< whether the Subscription publishes at all
  };

  /// Creates a Subscription with the caller's full tuning, retained for the two paths that outlive the
  /// create (modify and the session-CHANGED recreate).
  ///
  /// @param publishingInterval The requested publishing interval (ms).
  /// @param tuning             The lifetime/keep-alive/priority/publishing-enabled the caller asked for.
  /// @param maxNotificationsPerPublish The per-Publish notification cap, or nullopt for the server default.
  /// @param callback           Receives the @ref SubscriptionCreated snapshot on success, or a bad Result.
  void create_subscription_managed_async(double publishingInterval, SubscriptionTuning tuning,
    std::optional<std::uint32_t> maxNotificationsPerPublish,
    std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept;

  /// Folds a caller's stated parameters over @p retained (the values the server currently holds), returning
  /// the set to put on the wire. Anything left unstated keeps its retained value, because
  /// ModifySubscription replaces the WHOLE parameter set (OPC 10000-4 5.13.3.1) - a parameter that is not
  /// re-sent is not left alone, it is reset. When only the keep-alive is stated the lifetime is raised to
  /// the Table 90 floor (>= 3 x keep-alive); a caller who states BOTH is sent verbatim, ratio or no ratio,
  /// because at least the server reports what it revised. Shared by the create, modify and recreate paths so
  /// the rule cannot be applied differently at one of them.
  [[nodiscard]] static SubscriptionTuning resolve_subscription_tuning(SubscriptionTuning retained,
    const std::optional<std::uint32_t>& lifetimeCount, const std::optional<std::uint32_t>& maxKeepAliveCount,
    const std::optional<std::uint8_t>& priority,
    const std::optional<std::uint32_t>& maxNotificationsPerPublish = std::nullopt);

  /// Records @p tuning as the parameter set the server currently holds for @p subscriptionId. Posts to the
  /// strand, so it is safe to call from a wire completion running on the executor.
  void retain_subscription_tuning(std::uint32_t subscriptionId, SubscriptionTuning tuning);

  /// Drops the retained tuning for a Subscription that is gone (deleted, or the server disowned it).
  void forget_subscription_tuning(std::uint32_t subscriptionId);

  /// Attaches a data-change monitor and returns the unified self-acting @ref ua::client::MonitoredItem
  /// handle (section 7.4). Allocates a Connection-unique `clientHandle`, registers @p onData with the
  /// pipeline, issues `CreateMonitoredItems`, records the item's routing with the data-change owner, and
  /// constructs a handle whose self-actions route back through that owner. Gated like a wire op; the callback
  /// runs on the executor.
  ///
  /// @param subscriptionId The owning Subscription id.
  /// @param request        The data-change monitor request (node + params; section 7.4).
  /// @param onData         Invoked (on the executor) with each @ref ua::client::DataChangeEvent.
  /// @param callback       Receives the @ref ua::client::MonitoredItem on success, or a bad Result.
  void monitor_data_change_async(std::uint32_t subscriptionId, ua::client::MonitorRequest request,
    ua::client::DataChangeCallback onData,
    std::function<void(ua::client::MonitoredItemResult)> callback) noexcept;

  /// Configures triggering links between monitored items identified by their `clientHandle`s (section 7.4,
  /// T18). Resolves each handle to its server monitored-item id via the data-change owner, builds a
  /// `SetTriggering` request, and surfaces the per-link add/remove StatusCode arrays in a @ref
  /// ua::client::SetTriggeringResult (CL-MI-029, Part 4 section 5.12.5.2 Table 78)  -  positionally paired
  /// with the input add/remove handle lists. A per-link Bad does NOT make the Result bad; the Result is bad
  /// only on a local precondition failure or a transport/service-level fault. Each handle is validated
  /// locally BEFORE any wire request is built (CL-MI-027): a handle with no live routing fails
  /// `Bad_MonitoredItemIdInvalid`, and a live handle owned by a DIFFERENT Subscription fails
  /// `Bad_InvalidArgument` (OPC UA Part 4 section 5.12.5.1 requires every item in one call to share a
  /// Subscription). Existence is checked before membership, so a non-live handle keeps its
  /// `Bad_MonitoredItemIdInvalid`.
  ///
  /// @param subscriptionId  The Subscription owning the items.
  /// @param triggerHandle   The triggering item's clientHandle.
  /// @param addHandles      Client handles of the links to add.
  /// @param removeHandles   Client handles of the links to remove.
  /// @param callback        Receives the @ref ua::client::SetTriggeringResult on success, or a bad Result
  ///                        (on the executor).
  void set_triggering_by_handles_async(std::uint32_t subscriptionId, std::uint32_t triggerHandle,
    std::vector<std::uint32_t> addHandles, std::vector<std::uint32_t> removeHandles,
    std::function<void(ua::Result<ua::client::SetTriggeringResult>)> callback) noexcept;

  /// The connection-lifetime data-change @ref detail::MonitoredItemOwner interface (section 7.4). A @ref
  /// MonitoredItem weak-references it; its lock failing == the Connection is gone.
  [[nodiscard]] std::shared_ptr<detail::MonitoredItemOwner> monitored_item_owner() const noexcept;

  /// Snapshots the live (reconnect-surviving) Subscriptions as @ref SubscriptionCreated descriptors, backing
  /// the public `Subscriptions::list_async()` (section 7.4). Delivers on the executor.
  void subscription_descriptors_async(
    std::function<void(std::vector<SubscriptionCreated>)> callback) noexcept;

  /// Creates a data-change MonitoredItem on an existing Subscription and registers its data callback
  /// (section 8.4).
  ///
  /// Gated like a wire op. On `Active` it registers @p onData with the pipeline under @p clientHandle
  /// FIRST (so a fast initial notification is not missed), then issues `CreateMonitoredItems` for the
  /// node's Value attribute. The result callback runs on the executor and receives the server-assigned
  /// monitored-item id (or a bad Result). Notifications for the item are delivered to @p onData on the
  /// executor.
  ///
  /// @param subscriptionId The Subscription to add the item to.
  /// @param node           The node to monitor (Value attribute).
  /// @param clientHandle   The Connection-unique client handle for the item.
  /// @param onData         Invoked (on the executor) with each data-change DataValue for the item.
  /// @param callback       Receives the server-assigned monitored-item id on success, or a bad Result.
  void create_monitored_item_async(std::uint32_t subscriptionId, ua::NodeId node, std::uint32_t clientHandle,
    std::function<void(ua::DataValue)> onData,
    std::function<void(ua::Result<std::uint32_t>)> callback) noexcept;

  /// Deletes a Subscription (DeleteSubscriptions) and, on service success, deregisters it from the
  /// pipeline so its sequence tracking + acks stop. Gated like a wire op.
  ///
  /// @param subscriptionId The server-assigned Subscription id to delete.
  /// @param callback       Receives the @ref ua::DeleteSubscriptionsResponse (or a bad Result, on the
  /// executor).
  void delete_subscription_async(std::uint32_t subscriptionId,
    std::function<void(ua::Result<ua::DeleteSubscriptionsResponse>)> callback) noexcept;

  /// Deletes a monitored item (DeleteMonitoredItems) and, on service success, deregisters its client
  /// handle from the pipeline so later notifications for it are dropped. Gated like a wire op.
  ///
  /// @param subscriptionId  The owning Subscription id.
  /// @param monitoredItemId The server-assigned monitored-item id to delete.
  /// @param clientHandle    The item's Connection-unique client handle (deregistered from the pipeline).
  /// @param callback        Receives the @ref ua::DeleteMonitoredItemsResponse (or a bad Result, on the
  /// executor).
  void delete_monitored_item_async(std::uint32_t subscriptionId, std::uint32_t monitoredItemId,
    std::uint32_t clientHandle,
    std::function<void(ua::Result<ua::DeleteMonitoredItemsResponse>)> callback) noexcept;

  /// Creates an event MonitoredItem on an existing Subscription carrying @p filter, backing the tier-2
  /// @ref ua::client::EventSubscriber backbone (section 8.13). The item is forced to `attributeId =
  /// EventNotifier`, `samplingInterval = 0`, `queueSize = @p queueSize` at the wire boundary (CL-MI-013/014).
  /// Gated like a wire op; the server-assigned monitored-item id is delivered on the executor. No data/event
  /// callback is registered here  -  the tier-2 subscriber owns the demux and receives the feed separately
  /// (deferred).
  void create_event_monitored_item_async(std::uint32_t subscriptionId, ua::NodeId notifier,
    std::uint32_t clientHandle, ua::EventFilter filter, std::uint32_t queueSize,
    std::function<void(ua::Result<EventBackboneCreated>)> callback) noexcept;

  /// The lazily-constructed, co-owned tier-2 @ref ua::client::detail::EventSubscriberImpl (section 8.13).
  /// Backs `Connection::events()` and `Connection::alarms()`; constructed on first call and kept alive for
  /// the Connection's lifetime. Thread-safe (guarded by @ref mEventSubscriberOnce).
  [[nodiscard]] std::shared_ptr<detail::EventSubscriberImpl> events_impl();

  /// The lazily-constructed, co-owned tier-2 @ref ua::client::detail::AlarmConditionTrackerImpl (section 8.8)
  /// - a no-own-strand sub-object of the @ref events_impl subscriber. Ensures the subscriber exists first,
  /// then constructs + starts the tracker on the subscriber's strand. Backs `Connection::alarms()`.
  [[nodiscard]] std::shared_ptr<detail::AlarmConditionTrackerImpl> alarms_impl();

  /// The lazily-constructed, co-owned per-Connection @ref ua::client::detail::TypeResolver (section 8.6).
  /// Backs the `SupportOps::type_resolver()` reach-through the tier-2 typed accessors use for structure
  /// resolution. Constructed on first call over this orchestrator's strand + upward interfaces (default
  /// resolution policy). Seeded with the NamespaceTable at first reach-Active (@ref on_first_session_active)
  /// and re-seeded on the reconnect NamespaceArray re-read (@ref apply_namespace_read), so a consumer always
  /// resolves against the current table. Thread-safe (guarded by @ref mTypeResolverOnce).
  [[nodiscard]] std::shared_ptr<detail::TypeResolver> type_resolver();

  /// A fresh @ref ua::client::detail::SubscriptionFactoryOps leaf (wiring section 2) that weak-references
  /// this orchestrator and forwards @ref create_subscription_managed_async / @ref monitor_data_change_async.
  /// Backs `SupportOps::subscription_factory()`; a stateless weak-ref leaf, so a new instance per call is
  /// cheap and forms no cycle (the caller holds it per op only).
  [[nodiscard]] std::shared_ptr<detail::SubscriptionFactoryOps> subscription_factory();

  /// The lazily-constructed, co-owned per-Connection @ref ua::client::detail::SemanticChangeCache
  /// (section 8.18.2 / Slice W2a). Backs `SupportOps::semantic_change_cache()`  -  a DataAccess typed handle
  /// registers its Property snapshot here at construction (CL-DA-010/011). The cache is constructed with THIS
  /// orchestrator's strand injected (it has no private strand); its OWN state mutations
  /// (register/invalidate/close) self-marshal onto that strand, so the cache handle can be reached from any
  /// thread  -  in particular from the off-strand DataAccess handle-build completion (which runs on the
  /// executor, NOT the connection strand) and from the subscription / event trigger paths alike.
  ///
  /// **Free-threaded accessor** (like @ref type_resolver / @ref events_impl): callable from any thread. The
  /// lazy construction is `mSemanticChangeCacheOnce`-guarded (`std::call_once` makes it race-free); it does
  /// NOT run on, or require, the connection strand. The observer-hook install is a W2a stub  -  the real
  /// `on_semantic_change` subscription that routes semantic changes into `invalidate_async` lands in W8.
  ///
  /// @return The @ref SemanticChangeCache. Once first called it stays non-null for the Connection's life;
  ///         the shim returns null only when the Connection itself is gone.
  [[nodiscard]] std::shared_ptr<detail::SemanticChangeCache> semantic_change_cache();

  /// The lazily-constructed, co-owned per-Connection @ref ua::client::detail::AddressSpaceCache (section 8.7
  /// / Slice W8a). The optional client-side address-space cache  -  alias substitution (RegisterNodes,
  /// CL-VIEW-009), the static-attribute pre-flight cache (CL-ATTR-009), the Browse-result cache, and the
  /// CL-EVT-003 model-change flush target. Constructed with THIS orchestrator's strand injected (it has no
  /// private strand) over the upward @ref WireOps interface (held WEAK  -  the cache only weak-refs the
  /// Connection, so no ownership cycle forms). Its OWN async mutations (eviction / invalidation / shutdown
  /// drain) self-marshal onto that strand; the synchronous caller-on-strand lookups run inline.
  ///
  /// **Free-threaded accessor** (like @ref semantic_change_cache / @ref type_resolver / @ref events_impl):
  /// callable from any thread. The lazy construction is `mAddressSpaceCacheOnce`-guarded (`std::call_once`
  /// makes it race-free); it does NOT run on, or require, the connection strand  -  the W8b model-change
  /// router reaches it off the executor.
  ///
  /// The cache is constructed with the immutable per-Connection @ref mAddressSpaceCachePolicy decomposed from
  /// the connect @ref ConnectionConfig (Slice V1)  -  opt-in (section 8.7): a disabled cache (the default) is
  /// a clean pass-through no-op, an enabled one goes live for the RegisterNodes alias substitution / eviction
  /// / session-scope wiring (CL-VIEW-009/010/011). The W8b EventSubscriber router still gets a reachable,
  /// non-null instance to route the CL-EVT-003 model-change flush into (a no-op flush when disabled).
  ///
  /// @return The @ref AddressSpaceCache. Once first called it stays non-null for the Connection's life.
  [[nodiscard]] std::shared_ptr<detail::AddressSpaceCache> address_space_cache();

  /// Records a successfully observed AccessLevelEx value in the opt-in address-space cache. The merge and
  /// callback are serialized on the private connection strand; a disabled cache is a deterministic no-op.
  void observe_access_level_ex_async(
    ua::NodeId node, std::uint32_t accessLevelEx, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Records a successfully observed ValueRank in the opt-in address-space cache.
  void observe_value_rank_async(
    ua::NodeId node, std::int32_t valueRank, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Applies cached pre-flight policy for a ranged Value write. A known positive ValueRank requires every
  /// NumericRange dimension (CL-ATTR-009), and AccessLevelEx.WriteFullArrayOnly rejects any ranged write
  /// (CL-ATTR-024). A disabled cache or attribute miss returns Good so the server remains authoritative.
  void validate_index_range_write_async(
    ua::NodeId node, ua::String indexRange, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Modifies a Subscription (ModifySubscription). Gated like a wire op.
  ///
  /// ModifySubscription replaces the WHOLE parameter set (OPC 10000-4 5.13.3.1), so every parameter the
  /// caller leaves unstated is re-sent from the tuning retained at create - not from the SDK defaults. A
  /// parameter that is not re-sent is reset by the server, which reports success either way.
  ///
  /// @param subscriptionId    The Subscription to modify.
  /// @param publishingInterval The requested publishing interval (ms).
  /// @param callback          Receives the @ref ua::ModifySubscriptionResponse (or a bad Result, on the
  /// executor).
  void modify_subscription_async(std::uint32_t subscriptionId, double publishingInterval,
    std::function<void(ua::Result<ua::ModifySubscriptionResponse>)> callback) noexcept;

  /// @param lifetimeCount     The requested lifetime count, or nullopt to keep the retained value.
  /// @param maxKeepAliveCount The requested keep-alive count, or nullopt to keep the retained value.
  /// @param priority          The requested priority, or nullopt to keep the retained value.
  /// @param maxNotificationsPerPublish The requested per-Publish cap, or nullopt to keep the retained value.
  void modify_subscription_async(std::uint32_t subscriptionId, double publishingInterval,
    std::optional<std::uint32_t> lifetimeCount, std::optional<std::uint32_t> maxKeepAliveCount,
    std::optional<std::uint8_t> priority, std::optional<std::uint32_t> maxNotificationsPerPublish,
    std::function<void(ua::Result<ua::ModifySubscriptionResponse>)> callback) noexcept;

  /// Enables or disables publishing for a Subscription (SetPublishingMode). Gated like a wire op.
  ///
  /// @param subscriptionId    The Subscription to set the publishing mode on.
  /// @param publishingEnabled Whether publishing is enabled.
  /// @param callback          Receives the @ref ua::SetPublishingModeResponse (or a bad Result, on the
  /// executor).
  void set_publishing_mode_async(std::uint32_t subscriptionId, bool publishingEnabled,
    std::function<void(ua::Result<ua::SetPublishingModeResponse>)> callback) noexcept;

  /// Gracefully closes the Connection: drains the dispatch gate, closes the tier-0 session, and
  /// transitions to `Closed`.
  ///
  /// @param callback Receives `Good` once closed (on the executor).
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// Returns the cross-strand state snapshot (atomic-load; any thread).
  ///
  /// @return The latest published @ref ConnectionInfo.
  [[nodiscard]] std::shared_ptr<const ConnectionInfo> info() const noexcept;

  /// Returns the current immutable NamespaceTable snapshot (atomic-load; any thread), or null before the
  /// bootstrap NamespaceArray Read completes. Republished on every visible state change alongside
  /// @ref info. Backs the upward @ref SupportOps::namespace_table interface (section 8.2A.13) and the
  /// eventual public `Connection::namespace_table()` (section 8.5).
  [[nodiscard]] std::shared_ptr<const NamespaceTable> namespace_table_snapshot() const noexcept;

  [[nodiscard]] const ua::client::ClientDiagnosticPolicy& diagnostic_policy() const noexcept
  {
    return mDiagnosticPolicy;
  }

  /// Returns the separately synchronized Session-generation token used by Session-bound tier-2 cursors.
  [[nodiscard]] std::shared_ptr<const std::atomic<std::uint64_t>> session_generation_token() const noexcept
  {
    return mSessionGeneration;
  }

  /// Returns the current immutable ServerTable snapshot (atomic-load; any thread), or null before bootstrap.
  [[nodiscard]] std::shared_ptr<const ServerTable> server_table_snapshot() const noexcept;

  /// Returns the immutable endpoint snapshot this Connection is bound to (atomic-load; any thread), or null
  /// only if no snapshot has ever been published. Published from @ref ConnectionConfig::endpoint at
  /// construction (F1/J45); backs the tier-2 redundancy host's synchronous cross-strand identity reads
  /// (`current_endpoint` / `current_application_uri`, section 8.11) so they never touch the connection
  /// strand.
  [[nodiscard]] std::shared_ptr<const ua::EndpointDescription> active_endpoint_snapshot() const noexcept;

  /// Returns the server's `MaxNodesPerRead` operation limit (default 100 until the server-published value
  /// is fetched, which is tier-2). Backs the @ref WireOps::max_nodes_per_read interface that pages the
  /// polled-Read fallback (section 8.4, CL-SUB-019..022). Safe from any thread (atomic-load).
  [[nodiscard]] std::uint32_t max_nodes_per_read() const noexcept;

  /// Snapshots the ids of every currently-registered (reconnect-surviving) Subscription and delivers them
  /// on the executor. Backs the public `Subscriptions::list_async()` accessor (section 7.4). Reads the
  /// pipeline's callback-free recovery-descriptor snapshot on the pipeline strand, maps it to the ids, then
  /// hands the result to the executor (the design specification - user-facing callback never fires on a
  /// component strand). Delivers an empty vector when the Connection has no pipeline.
  ///
  /// @param callback Receives the registered Subscription ids (on the executor).
  void subscription_ids_async(std::function<void(std::vector<std::uint32_t>)> callback) noexcept;

  /// Requests a reconnect (manual drive point, section 8.3). Posts to the strand and triggers the FSM with
  /// @ref ua::client::TransportDropped. A no-op when the Connection was created without reconnect
  /// wiring. Used by tests to exercise the reconnect sequence without a real transport drop.
  void trigger_reconnect_async() noexcept;

  /// Re-validates this Connection's CURRENT server certificate against the store and ACTS on the verdict
  /// (section 722/section 727, CL-SECADMIN-004 / CL-RECONN-006). Backs
  /// `CoreClientImpl::revalidate_connections_async`, which the W6 PullCert manager fans out to after
  /// committing a renewed cert / new trust list. @p ownCertificateChanged categorically triggers
  /// `CertRotated` because Part 4 section 6.7 forbids carrying the changed client certificate on the existing
  /// Session; independently, every open Connection re-checks its server cert and triggers the same reconnect
  /// if it is now untrusted.
  ///
  /// Posts to the strand. Terminal/closing  to  completes @p callback `Good` (nothing to do). When
  /// @p ownCertificateChanged is true, starts the reconnect before consulting the optional validator. No
  /// validator interface wired then completes `Good` after that mandatory action (or is a no-op for
  /// trust-only). Otherwise invokes the @ref ServerCertValidator interface; on the verdict it re-hops to the
  /// strand: `Good` (still trusted)  to  completes `Good`; `Bad` (untrusted/revoked)  to  triggers a
  /// `CertRotated` reconnect (fire-and-forget) THEN completes `Good`. The completion is ACKNOWLEDGED-`Good`
  /// on BOTH the still-trusted and acted-on-untrusted paths  -  the Connection owns its reconnect and the
  /// walk aggregate is advisory (J53). On every LIVE path @p callback is delivered on the executor, never on
  /// the connection strand. On the rare Connection-destroyed-mid-flight path the owed completion is still
  /// delivered `Good` (best-effort, possibly inline on the interface's verdict thread) so the walk barrier
  /// can never hang  -  the aggregate consumer (the barrier) is thread-agnostic; a DIRECT caller that needs
  /// strict executor affinity must not assume it on that path.
  void revalidate_server_cert_async(bool ownCertificateChanged, bool revalidateServerCertificate,
    std::function<void(ua::VoidResult)> callback) noexcept;

  /// Hands out the upward-interface @ref WireOps role handle (a subobject of the one @ref ConnectionOpsShim,
  /// which weak-refs this orchestrator - so this strong handle forms no cycle). Tier-2 facades that own a
  /// wire-driven cursor / cache (e.g. @ref ua::client::BrowseCursor) hold it WEAK and lock-then-bail, so a
  /// dropped Connection completes their in-flight op with a boundary failure rather than dereferencing a
  /// gone orchestrator (section 8.2A.13 / section 8.7 / section 7.5).
  ///
  /// @return The @ref WireOps interface handle (never null once the Connection is constructed).
  [[nodiscard]] std::shared_ptr<WireOps> wire_ops() const noexcept;

  /// Hands out the upward-interface @ref SupportOps role handle (a subobject of the one @ref
  /// ConnectionOpsShim, aliasing its control block). Tier-2 facades that need the cross-cutting support
  /// surface
  /// (`namespace_table()` / `post_to_executor()` / `state()`) hold it WEAK and lock-then-bail, exactly as
  /// they hold @ref wire_ops (section 8.2A.13). A Phase-2 fake need only implement the two roles.
  ///
  /// @return The @ref SupportOps interface handle (never null once the Connection is constructed).
  [[nodiscard]] std::shared_ptr<SupportOps> support_ops() const noexcept;

  /// @return The executor the private strand and every user callback run on (section 8.2A.1). Backs the
  /// executor
  ///         a tier-2 cursor / cache posts buffered yields and boundary failures on.
  [[nodiscard]] boost::asio::any_io_executor executor() const noexcept;

  /// @return THIS orchestrator's strand (immutable after construction; a copy shares the one serialization
  ///         domain). NOT a general "post to my strand" API  -  the strand stays a private detail of every
  ///         PUBLIC surface. This internal accessor exists solely so a wire-driven collaborator that must
  ///         serialize its @ref detail::AddressSpaceCache lookups/installs with the cache's own strand-run
  ///         invalidation path (which shares THIS strand) can be threaded that same strand  -  specifically
  ///         the
  ///         @ref ua::client::BrowseCursor read-surface cache hop (section 8.7). Mirrors the injected-strand
  ///         pattern the cache / event router / semantic cache are already constructed with.
  [[nodiscard]] boost::asio::strand<boost::asio::any_io_executor> strand() const noexcept;

  /// @return The Connection's logger (a value handle sharing the sink/level). Handed to tier-2 facades so
  ///         their best-effort wire-boundary outcomes (e.g. the HistoryReadCursor continuation-point release,
  ///         CL-HIST-009) are logged rather than silently discarded.
  [[nodiscard]] ua::Logger logger() const noexcept
  {
    return mLogger;
  }

  /// @return True iff the per-Connection address-space cache is enabled by policy. Reads the IMMUTABLE
  ///         @ref mAddressSpaceCachePolicy (const after ctor; safe from any thread) WITHOUT
  ///         force-constructing the cache  -  the EventRouter's J57 subscribe-gate must learn "cache is a
  ///         flush target" without `call_once`-materialising an inert cache merely to read `enabled()`
  ///         (CL-EVT-003), and a tier-2
  ///         @ref ua::client::BrowseCursor gates its read-surface cache hop on this so a disabled Connection
  ///         never constructs or consults the cache (strict pass-through no-op, section 8.7).
  [[nodiscard]] bool address_space_cache_enabled() const noexcept
  {
    return mAddressSpaceCachePolicy.enabled;
  }

  // ---- Observer registration (section 7.8 / wiring section 1) ----
  // Per-Connection observer setters. Each posts to the strand, replaces the per-Connection family slot, and
  // re-resolves the sink's immutable snapshot against the Client-level defaults (per-Connection non-null
  // wins). Passing `nullptr` clears the per-Connection slot (the Client-level default then applies again).

  void set_connection_observer_async(std::shared_ptr<ConnectionObserver> observer) noexcept;
  void set_subscription_observer_async(std::shared_ptr<SubscriptionObserver> observer) noexcept;
  void set_security_observer_async(std::shared_ptr<SecurityObserver> observer) noexcept;
  void set_type_observer_async(std::shared_ptr<TypeObserver> observer) noexcept;
  void set_address_space_observer_async(std::shared_ptr<AddressSpaceObserver> observer) noexcept;
  void set_server_state_observer_async(std::shared_ptr<ServerStateObserver> observer) noexcept;
  void set_alarm_observer_async(std::shared_ptr<AlarmObserver> observer) noexcept;
  void set_redundancy_observer_async(std::shared_ptr<RedundancyObserver> observer) noexcept;

  /// The per-Connection observer fan-out sink (section 7.8 / wiring section 1). Host shims (W3..W8) forward
  /// `fire_observer_*` -> `sink.fire_*`; the sink posts every hook to the executor. Never null once the
  /// Connection is constructed.
  [[nodiscard]] std::shared_ptr<ObserverSink> observer_sink() const noexcept;

  /// The tier-2 non-transparent redundancy / failover handle (section 8.11, F3/J44). Backs
  /// `Connection::redundancy()`. The engine is eagerly constructed (reconnect-wired only) and WRITE-ONCE
  /// before `self` is published, so this is a plain synchronous member read (no strand / atomic). A
  /// single-shot Connection has no manager, so this returns a null-wrapped handle whose facade is already
  /// null-safe (empty info / Bad_ConnectionClosed / Good-close).
  [[nodiscard]] ua::client::RedundancyManager redundancy();

private:
  // The reconnect host drives these tier-0 primitives + notify handlers on this orchestrator's strand.
  friend class ConnectionReconnectHost;
  // The upward-interface shim forwards the Publish / Republish send interface onto this orchestrator's strand
  // (SubscriptionOps) and reads the strand-published snapshots (SupportOps / WireOps).
  friend class ConnectionOpsShim;
  // The tier-2 redundancy host shim reaches the wire/subscription/reconnect interfaces below (weak-locked) to
  // serve the own-strand RedundancyManagerImpl; it holds this orchestrator only WEAK (no cycle).
  friend class RedundancyManagerConnectionHost;
  // Test-only access to strand-private state + the reconnect primitives (the design specification). Reaches
  // the private members / methods below; adds NO public members for testing.
  friend class ConnectionImplTestAccess;

  ConnectionImpl(boost::asio::any_io_executor executor, std::shared_ptr<SessionOps> sessionOps,
    ConnectionConfig config, ua::Logger logger);

  /// Test-only injecting factory (reachable only via @ref ConnectionImplTestAccess): mirrors @ref create
  /// but injects the tier-0 @ref SessionOps interface and the interface-level @ref ReopenChannelOps directly
  /// (fakes), instead of wrapping a concrete @ref ua::client::Session / a user reopen. Wires the pipeline and
  /// the reconnect FSM exactly as production does, so a unit test drives the orchestrator's own logic in
  /// isolation. Not part of the public API.
  [[nodiscard]] static std::shared_ptr<ConnectionImpl> create_with_ops(boost::asio::any_io_executor executor,
    std::shared_ptr<SessionOps> sessionOps, ConnectionConfig config, ua::Logger logger,
    ReopenChannelOps reopen, ua::client::Session::ActivateConfig activateConfig,
    ua::client::ReconnectPolicy policy, KeepAlivePolicy keepAlivePolicy = {},
    ObserverSlots clientObserverDefaults = {}, bool enableRedundancy = false,
    ua::client::RedundancyPolicy redundancyPolicy = {}, RedundancyDiscoveryProvider redundancyDiscovery = {},
    ServerCertValidator serverCertValidator = {});

  /// Constructs the upward-interface @ref ConnectionOpsShim @p self owns and wires the eagerly-created
  /// @ref SubscriptionsPipeline onto its three role subobject handles (section 8.2A.13). Called by both
  /// factory paths after @p self is a live `shared_ptr` (so `weak_from_this()` is valid). Strong
  /// `ConnectionImpl -> pipeline -> shim`; the shim weak-refs @p self, so no cycle.
  static void wire_pipeline_and_ops(const std::shared_ptr<ConnectionImpl>& self);

  /// Eagerly constructs the tier-2 redundancy host shim + own-strand @ref detail::RedundancyManagerImpl
  /// (section 8.11 / W4), write-once into @ref mRedundancyHost / @ref mRedundancyManager. Called from BOTH
  /// factory paths inside the reconnect-wired branch only, after @p self is a live `shared_ptr` (so the
  /// shim's weak back-ref is valid). Strong `ConnectionImpl -> manager -> host`; the host weak-refs @p self,
  /// so no cycle.
  static void wire_redundancy(const std::shared_ptr<ConnectionImpl>& self,
    ua::client::RedundancyPolicy policy, RedundancyDiscoveryProvider discovery);

  // Strand-only steps of the bootstrap / close chains.
  /// Re-activates the Session on its bound channel. One await, and the pre- and post-conditions the
  /// chain expressed through four nested lambdas.
  ua::async::Task<> run_reactivate(
    ua::client::UserIdentity newIdentity, std::function<void(ua::VoidResult)> completion);

  /// Delivers a reactivation outcome on the EXECUTOR, never on the connection strand
  /// (section 8.2A.1 rule 3). Moves the callback out, so a second call is a no-op.
  void deliver_reactivate_result(std::function<void(ua::VoidResult)>& completion, ua::VoidResult result);

  /// Awaits one collaborator call of this connection's own body, back on its strand.
  /// @see ua::async::await_callback
  template<typename T, typename Initiate>
  auto await_step(Initiate&& initiate)
  {
    return ua::async::await_callback<T>(mStrand,
      mLogger,
      weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate)](auto completion) mutable
      {
        initiate(ua::async::post_borrowing(this,
          mStrand,
          mLogger,
          [completion = std::move(completion)](ConnectionImpl&, auto&&... args) mutable
          { completion(std::forward<decltype(args)>(args)...); }));
      });
  }

  void begin_bootstrap(std::function<void(ua::VoidResult)> callback);
  void finish_bootstrap(
    ua::Result<ua::ReadResponse> readResult, std::function<void(ua::VoidResult)> callback);
  ua::VoidResult apply_bootstrap_read(const ua::Result<ua::ReadResponse>& readResult);
  ua::VoidResult apply_namespace_read(
    const ua::Result<ua::ReadResponse>& readResult, bool replaceServerTable);
  void begin_close(std::function<void(ua::VoidResult)> completion);
  void delete_owned_subscriptions_then_close(std::function<void(ua::VoidResult)> completion);
  void close_dispatch_then_session(std::function<void(ua::VoidResult)> completion);
  void close_session(std::function<void(ua::VoidResult)> completion);

  // --- Address-space alias cache wiring (Slice V1 / CL-VIEW-009/010/011). Every helper is a STRICT no-op
  //     when `mAddressSpaceCachePolicy.enabled` is false (or `useRegisterNodes` is false): it early-returns
  //     BEFORE touching the cache, so a disabled Connection (the default) is byte-for-byte unchanged. ------

  /// Substitutes the cached RegisterNodes alias for each NodeId in an outgoing request (CL-VIEW-009), at
  /// request build, on the connection strand. Overloaded per NodeId-carrying op (the request completion point
  /// is the tier-1 `*_async` body  -  there is no single funnel because each request's NodeIds live in a
  /// type-specific shape). A miss / stale-generation alias passes the NodeId through verbatim, so an
  /// unregistered node is always sent unaliased.
  void apply_alias_substitution(ua::ReadRequest& request);
  void apply_alias_substitution(ua::WriteRequest& request);
  void apply_alias_substitution(ua::CallRequest& request);
  void apply_alias_substitution(ua::HistoryReadRequest& request);

  /// Wraps a RegisterNodes completion so that, on a Good response, the (@p requestedNodes -> registered)
  /// pairs are installed into the alias cache ON THE STRAND before @p completion is delivered on the executor
  /// (CL-VIEW-010)  -  so a subsequent op the caller issues from its callback observes the alias. When the
  /// cache is disabled this returns @p completion unchanged (strict no-op). Bad / cache-gone paths deliver
  /// the result verbatim without installing.
  [[nodiscard]] std::function<void(ua::Result<ua::RegisterNodesResponse>)> install_aliases_on_register(
    std::vector<ua::NodeId> requestedNodes,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> completion);

  // --- Subscription wire ops (section 8.4). Each runs on the connection strand and gates on Active (a
  // service
  //     accessor on a closed session blocks, so a non-Active state fast-fails WITHOUT touching mSession).
  void begin_create_subscription(
    double publishingInterval, std::function<void(ua::Result<std::uint32_t>)> completion);
  void begin_create_monitored_item(std::uint32_t subscriptionId, ua::NodeId node, std::uint32_t clientHandle,
    std::function<void(ua::DataValue)> onData,
    std::function<void(ua::Result<CreatedMonitoredItem>)> completion,
    ua::AttributeId attribute = ua::AttributeId::Value, std::optional<std::string> indexRange = std::nullopt,
    double samplingIntervalMs = 0.0, std::uint32_t queueSize = 1,
    ua::MonitoringMode monitoringMode = ua::MonitoringMode::Reporting, bool discardOldest = true,
    std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter> filter = {});

  // --- SubscriptionsPipeline host paths (section 8.4). Called by ConnectionSubscriptionsHost from the
  // PIPELINE
  //     strand; each hops onto this orchestrator's strand and, only when Active, drives the tier-0 session
  //     (Active-gated so the pipeline's Publish pump never blocks on a closed session's service accessor).
  void pipeline_send_publish(std::vector<SubscriptionAcknowledgement> acknowledgements);
  void pipeline_republish(std::uint32_t subscriptionId, std::uint32_t sequenceNumber);
  void adjust_max_notifications_per_publish_async(std::uint32_t subscriptionId, double publishingInterval,
    std::uint32_t maxNotificationsPerPublish, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Subscription-event-loss signal (Finding 2 / CL-AC-003). The @ref SubscriptionsPipeline calls this  -  on
  /// its OWN strand  -  when a REACTIVE Republish drain for @p subscriptionId terminated with an unrecovered
  /// sequence gap (dropped messages, possibly a lost ConditionRefresh RefreshEnd) or hit its iteration cap.
  /// It is the production wiring of the pipeline's `onSubscriptionEventLoss` interface (installed in
  /// @ref wire_pipeline_and_ops). Hops onto THIS orchestrator's strand (weak-guarded  -  the pipeline may
  /// outlive a torn-down orchestrator), then, if an event subscriber exists, drives
  /// `EventSubscriberImpl::on_reconnect_recovered_async({subscriptionId}, EventLossDetected)` to reset the
  /// affected backbone's dead ConditionRefresh state and re-arm its resync. The subscriber posts to its OWN
  /// strand  -  this connection strand never reaches into subscriber/tracker state. Best-effort; noexcept
  /// target; nothing throws out of the posted handler.
  void on_subscription_event_loss(std::uint32_t subscriptionId);

  /// Automatic drop detection (section 8.3): a channel/session-fatal Publish result (see @ref
  /// is_channel_fatal) routes here. Posts to the strand and drives the reconnect FSM with @ref
  /// ua::client::TransportDropped carrying the real @p cause. A no-op when created without reconnect wiring
  /// or when already terminal; the FSM itself debounces a re-entrant trigger while a reconnect is in flight.
  /// Unlike the manual
  /// @ref trigger_reconnect_async this carries the observed cause status rather than a synthetic one.
  ///
  /// @p issuedEpoch is @ref mReconnectAttemptEpoch captured when the Publish was ISSUED. A drop is honoured
  /// only when the epoch is unchanged; a stale completion from a channel a later reconnect already
  /// superseded (its epoch has moved on) is dropped, so it cannot re-trigger an already-recovered, healthy
  /// connection (mirrors the epoch-guard on the reconnect-step completions).
  void notify_transport_drop_async(ua::StatusCode cause, std::uint64_t issuedEpoch) noexcept;

  // --- KeepAlive poll (section 8.2A.6, CL-RECONN-009 / CL-SESS-025). A strand-serialized periodic poll of
  //     `Server.ServerStatus.State` that detects a silently-dead link on a Connection that issues no
  //     Publishes (no active Subscription), so the Publish-fatal drop path cannot cover it. -----------

  /// Arms the keep-alive timer (strand-only). A no-op when the Connection has no reconnect wiring (nothing
  /// to do on a miss), when the interval is `<= 0` (disabled), or when not `Active`. Reconstructs the
  /// tracker (fresh miss count) and reschedules @ref mKeepAliveTimer on the connection strand. Called on
  /// reach-active (bootstrap and reconnect) so a poll runs for the whole Active lifetime.
  void arm_keep_alive_timer();

  /// Cancels the keep-alive timer and clears the poll-in-flight guard (strand-only). Called on
  /// close / entering Reconnecting / the terminal Failed path. Idempotent (the empty timer cancels a no-op).
  void disarm_keep_alive_timer();

  /// One keep-alive poll step (strand-only; invoked by the timer notifier on the connection strand). When
  /// `Active` and no poll is already in flight, issues one Read of `ServerStatus.State`, `ServiceLevel`,
  /// and optional `EstimatedReturnTime` on
  /// @ref mSessionOps (directly, like @ref pipeline_send_publish - NOT through the wire-op gate, so it
  /// probes even while ops queue), capturing @ref mReconnectAttemptEpoch at issue. Only ONE poll is in
  /// flight at a time (a slow read counts as its own interval; its own timeout makes a stall a miss).
  void keep_alive_poll_on_strand();

  /// Handles a keep-alive Read completion (strand-only; re-entered via a strand hop). Clears the in-flight
  /// guard, drops a poll whose @p issuedEpoch a later reconnect has superseded (epoch guard) or that raced
  /// into a non-Active state, then feeds the tracker: a transport/service-fatal read is a miss, an answered
  /// read is a success (carrying whether State/ServiceLevel reports shutdown/maintenance and any usable
  /// future EstimatedReturnTime). Maps the tracker's
  /// @ref KeepAliveAction onto @ref notify_keep_alive_missed_async / @ref notify_server_shutdown_async.
  void finish_keep_alive_poll(ua::Result<ua::ReadResponse> readResult, std::uint64_t issuedEpoch);

  /// Drives the FSM with a `KeepAliveMissed` reconnect (CL-RECONN-009) once the miss threshold is reached.
  /// Mirrors @ref notify_transport_drop_async exactly - posts to the strand, no-ops on a single-shot /
  /// terminal Connection, and epoch-guards @p issuedEpoch so a poll from a superseded attempt cannot
  /// re-trigger an already-recovered connection; the FSM itself debounces a re-entrant in-flight trigger.
  void notify_keep_alive_missed_async(std::uint64_t issuedEpoch) noexcept;

  /// Drives the FSM with a `ServerShutdown` reconnect (CL-SESS-025 / CL-BASE-005) when a poll reports
  /// shutdown or ServiceLevel=0. A future @p estimatedReturnTime defers the first attempt until that instant;
  /// absent/elapsed/invalid hints start immediately and use the FSM's shutdown slow-retry backoff.
  void notify_server_shutdown_async(
    std::uint64_t issuedEpoch, std::optional<ua::DateTime> estimatedReturnTime) noexcept;

  // --- Reconnect FSM notify handlers (section 8.3). Called by ConnectionReconnectHost from the FSM strand;
  //     each hops onto this orchestrator's strand to update mState + drive the dispatch gate, and fires the
  //     matching ConnectionObserver lifecycle transition off-strand via @ref mObserverSink (W3). Each carries
  //     the FSM's reconnect context so it is NOT dropped: the attempt+cause for `on_reconnecting`, the
  //     recovered @ref ReconnectOutcome (with its optional cause) for `on_reconnected`, and the terminal
  //     @ref ua::ErrorDetail chain for `on_disconnected` / `on_error_chain`. ---
  void reconnect_notify_reconnecting(std::size_t attempt, ReconnectCause cause);
  void reconnect_notify_active(ReconnectOutcome outcome);
  void reconnect_notify_failed(ua::StatusCode terminal, std::shared_ptr<const ua::ErrorDetail> chain);

  /// Kicks the reconnect FSM (section 8.3) with a redundancy failover @p cause (contrast @ref
  /// trigger_reconnect_async, which hardcodes `TransportDropped`). Backs the redundancy host's
  /// `trigger_reconnect_async` interface (F4). Posts to the strand: if the Connection is single-shot /
  /// terminal, completes @p callback `Bad_ConnectionClosed` on the executor (the manager returns to
  /// Monitoring); otherwise stashes @p callback in the strand-only @ref mRedundancyReconnectPending (firing
  /// any prior pending `Good` first) and triggers the FSM  -  the stashed completion is fired from the notify
  /// handlers (W3 outcome/chain drive the manager; P3). @p degradeStatus + @p chain are threaded into the FSM
  /// cause classification.
  void trigger_redundancy_reconnect_async(ua::client::ReconnectCause cause, ua::StatusCode degradeStatus,
    std::shared_ptr<const ua::ErrorDetail> chain, std::function<void(ua::VoidResult)> callback) noexcept;

  /// Strand-only: delivers the single in-flight redundancy-reconnect completion (@ref
  /// mRedundancyReconnectPending) its terminal @p result on the executor (never the strand), then clears it.
  /// A no-op when none is pending. Called from exactly one of the terminal paths (reconnect reached Active to
  /// Good; reconnect failed  to  Bad; begin_close  to  Bad) so the manager's `trigger_reconnect_async`
  /// completion is fired exactly once, never dropped (F4).
  void fire_redundancy_reconnect_pending(ua::VoidResult result);

  /// Strand-only: kicks the reconnect FSM with a `CertRotated` cause (CL-RECONN-006) because a server-cert
  /// re-validation found the current cert now-untrusted/revoked. Called from the (already-on-strand)
  /// @ref revalidate_server_cert_async verdict re-hop. Mirrors @ref trigger_reconnect_async's guard
  /// (single-shot / terminal Connection  to  no-op) but is FIRE-AND-FORGET: unlike the redundancy trigger it
  /// stashes no pending completion  -  the Connection owns its reconnect and the revalidate walk aggregate is
  /// advisory (J53). The FSM itself debounces a re-entrant trigger while a reconnect is in flight. @p status
  /// +
  /// @p chain carry the interface verdict's real rejection reason (BadCertificate{Untrusted,Revoked,...} +
  /// chain), threaded into the FSM so a reconnect exhaustion surfaces the actual reason (the design
  /// specification  - the ErrorDetail is never discarded; it is also logged at the revalidate decision
  /// boundary).
  void trigger_cert_rotated_reconnect(ua::StatusCode status, std::shared_ptr<const ua::ErrorDetail> chain);

  /// Strand-only: hops to the executor and delivers @p callback an ACKNOWLEDGED `Good` @ref ua::VoidResult
  /// for @ref revalidate_server_cert_async (never on the connection strand  -  section 8.2A.1 rule 3). The
  /// revalidate always acknowledges `Good`: a triggered `CertRotated` reconnect is the Connection's own
  /// concern and the walk aggregate is advisory (J53), so no failure is manufactured on this path.
  void deliver_revalidate_ack(std::function<void(ua::VoidResult)> callback);

  /// First-reach-Active hook (strand-only; W3). Called EXACTLY ONCE the first time the initial bootstrap
  /// reaches `Active` (from @ref finish_bootstrap on both the single-shot and reconnect-enabled paths,
  /// guarded by @ref mFirstActiveReached). Fires the initial `on_connected` + `on_session_activated`
  /// ConnectionObserver transitions off-strand via @ref mObserverSink, and is the attach point W4 will use to
  /// lazily construct + drive the RedundancyManager (it needs a live, activated Session before it can score /
  /// fail over).
  void on_first_session_active();

  /// Re-evaluates the EventRouter subscribe-gate after a late observer registration (strand-only; M1). Calls
  /// @ref EventRouter::start (idempotent, re-checks its consumer gate) when the router exists AND
  /// first-active has already been reached  -  so a consumer registered AFTER connect (the common
  /// connect-then-observe flow) still triggers the four backbone event Subscriptions the eager first-active
  /// start would otherwise have suppressed for a then-consumer-less connection.
  void start_event_routing_if_active();

  // --- Reconnect FSM tier-0 service primitives (section 8.3). Called by ConnectionReconnectHost from the FSM
  //     strand; each hops onto this orchestrator's strand, does its work over the real tier-0 session,
  //     and completes @p done exactly once (which re-enters the FSM strand). ---
  void reconnect_get_endpoints(std::function<void(ua::VoidResult)> done);
  void reconnect_open_secure_channel(std::function<void(ua::VoidResult)> done);
  void reconnect_activate_session(std::function<void(ua::VoidResult)> done);
  void reconnect_create_session(std::function<void(ua::VoidResult)> done);
  void reconnect_re_read_namespace_array(std::function<void(ua::VoidResult)> done);
  void reconnect_recover_subscriptions(
    ua::client::SubscriptionRecovery recovery, std::function<void(ua::VoidResult)> done);
  void reconnect_commit(std::function<void(ua::VoidResult)> done);

  /// CL-RECONN-005: refreshes the published endpoint snapshot (@ref mEndpointSnapshot) from a GetEndpoints
  /// response fetched on the security-failure recovery path. Strand-only. Selects the description for the
  /// bound endpoint (match on endpoint_url, then security_policy_uri + security_mode) so a rotated server
  /// certificate / changed security fields are picked up, and republishes via @ref publish_info. Never
  /// clobbers the current snapshot when no endpoint in the response matches the bound URL.
  void refresh_endpoint_from_get_endpoints(const ua::GetEndpointsResponse& response);

  /// Session-CHANGED subscription recovery (section 6.7 - #24). Runs on the connection strand from the
  /// recover step when the reconnect created a FRESH Session (@ref mSessionChangedThisAttempt), so the old
  /// server-side Subscription ids no longer exist. Snapshots the pipeline's callback-free @ref
  /// RecoveryDescriptor set, then drives a HETEROGENEOUS barrier against @ref mPendingSession:
  ///   - `TransferThenRecreate`: one `TransferSubscriptions` (sendInitialValues); each transferred sub is
  ///     kept as-is (id + sequence continue, gap drained reactively post-Active), each refused sub is
  ///     recreated (CreateSubscription + CreateMonitoredItems for its retained items);
  ///   - `RecreateOnly`: every sub is recreated directly (no transfer).
  /// Every wire completion is epoch-guarded (@ref mReconnectAttemptEpoch) so a response from a superseded
  /// attempt cannot stage a re-key. Re-keys are STAGED into @ref mStagedRekeys and applied ATOMICALLY at
  /// @ref reconnect_commit only on full success; on any failure nothing is applied and @p done carries the
  /// worst status so the FSM backs off and re-drives from the pipeline's pristine original ids (the
  /// stage-and-commit keystone that closes the stale-re-key window, NEW HAZARD 1). @p issuedEpoch is the
  /// attempt epoch captured when the recover step began.
  void recover_session_changed(ua::client::SubscriptionRecovery recovery,
    std::vector<RecoveryDescriptor> descriptors, std::uint64_t issuedEpoch,
    std::function<void(ua::VoidResult)> done);

  /// Transient per-attempt barrier for @ref recover_session_changed (strand-only). Held by `shared_ptr` so
  /// every in-flight transfer/create completion keeps it alive until the last Subscription reaches a
  /// terminal, at which point @ref recovery_settle_one fires @ref done exactly once.
  struct SessionChangedRecovery
  {
    std::size_t pending = 0;  ///< Subscriptions not yet transferred-or-recreated.
    bool anyFailed = false;  ///< A recreate failed: apply nothing, complete Bad (=> FSM backoff + retry).
    ua::StatusCode worstStatus{ua::Status::Good};  ///< The first bad terminal (carries its ErrorDetail).
    /// The code of the answers the restored Subscriptions were rebuilt from, folded by
    /// ua::detail::combined_status: a Good subcode or an Uncertain code the server answered is reported.
    ua::StatusCode answeredStatus{ua::Status::Good};
    std::vector<std::pair<std::uint32_t, std::uint32_t>> stagedRekeys;  ///< oldId -> newId (recreated subs).
    /// Owner-routing re-keys for the recreated items (CRITICAL 1): applied at commit alongside stagedRekeys
    /// so the owner map's clientHandle routing tracks the new {subscriptionId, monitoredItemId}.
    std::vector<DataChangeMonitoredItemOwner::ItemRekey> stagedOwnerRekeys;
    std::function<void(ua::VoidResult)> done;  ///< The FSM recover-step completion (fired once).
    std::uint64_t issuedEpoch = 0;  ///< The attempt epoch the recovery was issued under (H1 stale guard).
  };

  /// Recreates one Subscription on @ref mPendingSession (the refused-transfer / RecreateOnly path): issues
  /// CreateSubscription (fresh server id) then CreateMonitoredItems for every retained item, both
  /// epoch-guarded against @p barrier's issued epoch. On success (a Good answer, or an Uncertain one holding
  /// the response) stages the `{oldId, newId}` re-key into @p barrier (applied at commit) and settles the sub
  /// with the answers' code; on any failure, an Uncertain answer without a response refused
  /// (`ServiceAnswerUncertain`) included, settles it bad. Runs on the connection strand.
  void recovery_recreate_subscription(
    std::shared_ptr<SessionChangedRecovery> barrier, RecoveryDescriptor descriptor);

  /// Records one Subscription's terminal in @p barrier (strand only): decrements the pending count, folds a
  /// bad @p status into the worst outcome and any other into the answers' code, and - when the last sub
  /// settles - either applies the staged re-keys (moving them into @ref mStagedRekeys for
  /// @ref reconnect_commit) and fires `done(answeredStatus)`, or applies nothing and fires
  /// `done(worstStatus)`. Fires @ref SessionChangedRecovery::done exactly once.
  void recovery_settle_one(const std::shared_ptr<SessionChangedRecovery>& barrier, ua::StatusCode status);

  /// Validates the merged CreateMonitoredItems results of a recreated Subscription (strand only), stages the
  /// pipeline re-key `{oldId, newId}` + the per-item owner re-keys (pairing each preserved @p clientHandles
  /// entry with the response's server monitored-item id, in request order), and settles @p barrier. Shared by
  /// the single-CreateMonitoredItems path and the CL-BASE-003 MaxMonitoredItemsPerCall-chunked path (which
  /// concatenates the per-chunk results here). A per-item bad status fails the whole recovery (re-drive
  /// rather than a partial subscription); an item's Good subcode or Uncertain code is folded into
  /// @p answered, the code of the CreateSubscription and CreateMonitoredItems answers, which the Subscription
  /// settles with. The caller has already applied the epoch guard + transport/service checks.
  void recovery_settle_recreated_items(std::shared_ptr<SessionChangedRecovery> barrier, std::uint32_t oldId,
    std::uint32_t newId, std::size_t itemCount, std::vector<std::uint32_t> clientHandles,
    const ua::Array<ua::MonitoredItemCreateResult>& itemResults, ua::StatusCode answered);

  /// Creates a fresh session on @p channel and installs it as @ref mPendingSession (strand-only; runs from
  /// the reconnect_create_session body). The completion is epoch-gated (section 3.1 finding D): a create
  /// issued under a superseded attempt settles `Bad_ConnectionClosed` and installs nothing. @p settle
  /// completes exactly once (it re-enters the FSM strand).
  void create_session_on(const std::shared_ptr<ChannelOps>& channel, std::uint64_t epoch,
    std::function<void(ua::VoidResult)> settle);

  /// True when the Connection is `Closing`, `Closed`, or `Failed` - a terminal / draining state that new
  /// work (a bootstrap completion, a reconnect step, a trigger) must never resurrect. Strand-only.
  [[nodiscard]] bool is_terminal_state() const noexcept;

  /// Generic gated wire-op funnel (section 7.2 `invoke_wire_op`). Runs on the connection strand.
  ///
  /// Terminal states (`Closing`/`Closed`/`Failed`) fast-fail with `Bad_ConnectionClosed` on the executor,
  /// WITHOUT touching the tier-0 session (a service accessor on a closed session blocks, section 8.2A.3).
  /// Active and Reconnecting both submit a @ref PendingRequest through the gate: Active dispatches
  /// immediately, Reconnecting queues and flushes on recovery (CL-SESS-019/021). The session handle is
  /// grabbed at DISPATCH time (the dispatch closure hops back to the connection strand and issues on the
  /// CURRENT session), so a queued op binds to the rebound session after a reconnect. The `fail` path
  /// completes
  /// @p callback with a bad typed Result. Exactly-once either way.
  ///
  /// @tparam Response       The service response type (e.g. `ua::ReadResponse`).
  /// @tparam IssueOnSession Callable `(SessionOps&, std::shared_ptr<Owed>) -> void` that ISSUES the op
  ///                        against the given (current) session interface; its tier-0 completion delivers on
  ///                        the executor via the shared owed callback.
  /// @param operationTag    Short op label for diagnostics / the pending queue.
  /// @param issueOnSession  Issues the op on the current session at dispatch time.
  /// @param callback        The typed user callback (completed exactly once, on the executor).
  template<typename Response, typename IssueOnSession>
  void invoke_wire_op(std::string operationTag, IssueOnSession issueOnSession,
    std::function<void(ua::Result<Response>)> callback,
    std::optional<std::uint32_t> requestHandle = std::nullopt);

  template<typename Response, typename IssueOnSession, typename CountOpened>
  void invoke_initial_continuation_op(OpenContinuationPointTracker& tracker, std::string operationTag,
    IssueOnSession issueOnSession, CountOpened countOpened,
    std::function<void(ua::Result<Response>)> callback,
    std::optional<std::uint32_t> requestHandle = std::nullopt);

  template<typename Response, typename IssueOnSession, typename CountOpened>
  void invoke_continuation_op(OpenContinuationPointTracker& tracker, std::size_t consumedPoints,
    std::string operationTag, IssueOnSession issueOnSession, CountOpened countOpened,
    std::function<void(ua::Result<Response>)> callback,
    std::optional<std::uint32_t> requestHandle = std::nullopt);

  /// CL-BASEDIAG-001: decode a received server `serviceDiagnostics` (Part 4 section 7.34) and surface it to
  /// the observer fan-out  -  `on_error_chain` when @p header carries a bad `service_result`, else
  /// `on_advisory_diagnostic`. STRICT NO-OP when `serviceDiagnostics` is null (the default, since
  /// `defaultReturnDiagnostics == 0`), so the observer-free path is byte-for-byte unchanged. Best-effort +
  /// `noexcept`: a malformed server `DiagnosticInfo` must never throw out of the wire funnel (process-abort
  /// class). Called from the `invoke_wire_op` completion wrap on every transport-good response.
  void surface_response_diagnostics(
    const ua::ResponseHeader& header, std::string_view operationTag) const noexcept;

  void publish_info();  // rebuild + atomic-store the snapshot from strand state

  /// Re-resolves the per-Connection slots against the Client-level defaults and atomically installs the fresh
  /// snapshot on @ref mObserverSink (strand-only: reads @ref mPerConnectionObservers). Called from each
  /// observer setter after it mutates a per-Connection slot.
  void reresolve_observers_on_strand();

  /// The reactivation body. Lives on the connection, so it dies with it.
  ua::async::Task<> mReactivateTask;
  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  ua::Logger mLogger;
  // One-shot destructor hook (see set_teardown_hook): the connect path installs a registry-erase here so the
  // Connection self-unregisters from CoreClientImpl exactly once on destruction. Plain std::function (no
  // strand / CoreClientImpl dependency  -  layering-safe). Not touched by any strand-posted method, so no
  // synchronisation is needed beyond the single-threaded set-then-run lifecycle (set at connect, run at
  // destruction).
  std::function<void()> mTeardownHook;
  std::shared_ptr<SessionOps>
    mSessionOps;  // owned tier-0 session interface (injectable; the design specification)
  // Strand-only count of tier-1 service operations currently issued on the Session, grouped by the
  // caller-supplied RequestHeader.requestHandle. Cancel uses this advisory snapshot for CL-SESS-024; it
  // never changes cancellation semantics or retries a divergent server count.
  std::unordered_map<std::uint32_t, std::size_t> mOutstandingRequestsByHandle;
  std::shared_ptr<ConnectionDispatch> mDispatch;
  // The upward-interface leaf shim (section 8.2A.13): owned strongly; hands out weak/strong role subobject
  // handles (WireOps / SubscriptionOps / SupportOps) to consumers (the SubscriptionsPipeline below + tier-2
  // facades). The shim weak-refs this orchestrator, so no strong cycle forms back into it.
  std::shared_ptr<ConnectionOpsShim> mConnectionOps;
  // The client SubscriptionsPipeline (section 8.4): constructed eagerly in create(); lifetime co-terminal
  // with this orchestrator. Strong ref (single owner). The pipeline owns its host, which holds this
  // orchestrator weakly - so no ownership cycle forms back into ConnectionImpl.
  std::shared_ptr<SubscriptionsPipeline> mPipeline;
  // The connection-lifetime data-change MonitoredItemOwner (section 7.4): held strongly, weak-refs this
  // orchestrator. A self-acting MonitoredItem weak-references it. Constructed in wire_pipeline_and_ops.
  std::shared_ptr<DataChangeMonitoredItemOwner> mMonitoredItemOwner;
  // The lazily-constructed, co-owned tier-2 EventSubscriber backbone (section 8.13). Constructed on first
  // Connection::events()/alarms(); survives reconnect. Its backbone-ops shim weak-refs this orchestrator,
  // and the subscriber weak-holds the shim, so no ownership cycle forms back into ConnectionImpl. Guarded
  // by mEventSubscriberOnce for thread-safe lazy init. ATOMIC because the connect-path Publish demux reads it
  // from the connection strand while user threads may store it via events_impl()/`Connection::events()`
  // (call_once establishes happens-before only among its own participants, not with a plain member read).
  std::once_flag mEventSubscriberOnce;
  std::atomic<std::shared_ptr<detail::EventSubscriberImpl>> mEventSubscriber;
  std::shared_ptr<ConnectionEventBackboneOps> mEventBackboneOps;
  // The per-Connection EventSubscriber to observer/cache routing router (section 8.13 / Slice W8b).
  // Constructed eagerly in wire_pipeline_and_ops (it needs weak_from_this); weak-refs this orchestrator, so
  // no ownership cycle forms back into ConnectionImpl. start()ed on first reach-Active
  // (on_first_session_active), stop()ped in begin_close. Routes the four NS0 model / semantic / audit event
  // types into the observer fan-out + the two caches. Held strongly (single owner); its subscribe callbacks
  // weak-capture it.
  std::shared_ptr<EventRouter> mEventRouter;
  // The lazily-constructed, co-owned tier-2 TypeResolver (section 8.6). Constructed on first type_resolver()
  // over this orchestrator's strand + upward interfaces (which it holds WEAK), so no ownership cycle forms
  // back into ConnectionImpl. Guarded by mTypeResolverOnce for thread-safe lazy init.
  std::once_flag mTypeResolverOnce;
  std::shared_ptr<detail::TypeResolver> mTypeResolver;
  // The lazily-constructed, co-owned per-Connection SemanticChangeCache (section 8.18.2 / Slice W2a).
  // Constructed on first semantic_change_cache() with THIS orchestrator's strand injected (no private
  // strand); its own mutations self-marshal onto that strand. It holds only weak(TypedPropertiesState)
  // entries + a hook sentinel, so no ownership cycle forms back into ConnectionImpl. Guarded by
  // mSemanticChangeCacheOnce for thread-safe lazy init; close()d in begin_close. The accessor is
  // FREE-THREADED (reached off-strand from the DataAccess handle-build completion), so the call_once WRITE of
  // mSemanticChangeCache races the strand-side READ in begin_close. mSemanticChangeCacheConstructed publishes
  // the completed construction: the init lambda stores it release AFTER assigning the member, and begin_close
  // loads it acquire before touching the member  -  so a torn/racing read of mSemanticChangeCache cannot
  // occur (C1).
  std::once_flag mSemanticChangeCacheOnce;
  std::atomic<bool> mSemanticChangeCacheConstructed{false};
  std::shared_ptr<detail::SemanticChangeCache> mSemanticChangeCache;
  // The lazily-constructed, co-owned per-Connection AddressSpaceCache (section 8.7 / Slice W8a  -  the
  // orphaned cache wired into ConnectionImpl so the CL-EVT-003 model-change flush has a reachable target).
  // Constructed on first address_space_cache() with THIS orchestrator's strand injected (no private strand)
  // over the WEAK WireOps interface, so no ownership cycle forms back into ConnectionImpl. Guarded by
  // mAddressSpaceCacheOnce for thread-safe lazy init. Default (disabled) policy -> a no-op pass-through until
  // a per-Connection policy is threaded through ConnectionConfig (W8a judgment call). No mConstructed atomic
  // is needed (unlike the semantic cache): W8a adds no strand-side begin_close reader that would race the
  // off-strand call_once write.
  std::once_flag mAddressSpaceCacheOnce;
  std::shared_ptr<detail::AddressSpaceCache> mAddressSpaceCache;
  // The immutable per-Connection address-space cache policy (Slice V1). Decomposed out of the ctor's
  // ConnectionConfig (which keeps no whole mConfig) and injected into the lazily-constructed cache above, so
  // an ENABLED policy from the connect config reaches the real cache. Opt-in: the default is disabled, and
  // EVERY cache-wiring site below gates on `mAddressSpaceCachePolicy.enabled` BEFORE touching the cache  - so
  // a disabled Connection (the default) never constructs or consults the cache and behaves exactly as before.
  // const after ctor; read from any thread (plain value, no synchronisation needed).
  const ua::client::AddressSpaceCachePolicy mAddressSpaceCachePolicy;

  // The immutable per-Connection diagnostics policy (section 7.10.4, CL-DIAG-012/009). Decomposed out of the
  // ctor's ConnectionConfig; const after ctor so surface_response_diagnostics (a const method reachable from
  // the wire-completion continuation on any thread) reads it without synchronisation. Gates the observer fire
  // (emitOnErrorChainObserver) and caps the decoded chain (maxChainDepth). The always-on CL-DIAG-005
  // Result-marker is independent of this policy.
  const ua::client::ClientDiagnosticPolicy mDiagnosticPolicy;
  // Polled-Read Subscription-fallback engagement mode (CL-SUB-019), decomposed from the config. Immutable.
  const ua::client::SubscriptionFallbackPolicy::Mode mSubscriptionFallbackMode;
  // The type-resolution policy this Connection was configured with (section 8.6). Immutable after the ctor,
  // so the lazily-constructed TypeResolver reads it without synchronisation whichever call first forces
  // construction.
  const ua::client::TypeResolutionPolicy mTypeResolutionPolicy;
  // Synthetic ids of the fallback (server-less) Subscriptions this Connection engaged, mapped to their
  // polling interval (strand-only). A monitor / delete against one of these ids is handled pipeline-locally
  // (no wire CreateMonitoredItems / DeleteSubscriptions). Ids come from a high, server-id-disjoint range so
  // they never collide with a server-assigned Subscription id.
  std::unordered_map<std::uint32_t, double> mFallbackSubscriptions;
  std::uint32_t mNextFallbackSubscriptionId = 0x80000000u;
  // The CreateSubscription parameter set the server currently holds for each live Subscription, keyed by its
  // CURRENT server id (strand-only). Written at create, at every successful modify, and re-keyed alongside
  // mStagedRekeys when a session-CHANGED recreate assigns new ids; erased on delete and on the
  // authoritative Bad_SubscriptionIdInvalid. Read by modify and by the recreate, both of which re-send the
  // WHOLE parameter set (OPC 10000-4 5.13.3.1), so an absent entry there would substitute the SDK defaults
  // for the caller's tuning.
  std::unordered_map<std::uint32_t, SubscriptionTuning> mSubscriptionTuning;
  // Live `Subscription` handles' server-id cells, so a recreate can carry them forward.
  //
  // A session-CHANGED reconnect recreates each Subscription under a NEW server id and re-keys the
  // pipeline, the tuning record, the owner routing and the event subscriber's trackers. The public
  // handle was the one thing left behind: `SubscriptionImpl` is owned by the handle and this
  // connection holds no reference to it, so every operation routed through a handle held across the
  // outage - modify, set publishing mode, add a monitored item, delete, condition refresh - carried
  // the dead id and came back Bad_SubscriptionIdInvalid, while notifications kept arriving because
  // those route through the pipeline, which WAS re-keyed.
  //
  // Only the id cell is registered, not the impl, so the handle's layout stays private to
  // ua_client_subscription.cpp. The separately synchronized leaf accepts registration from the public
  // callback executor while reconnect commit runs on this component's strand; ConnectionImpl itself keeps
  // the strand as its single synchronization strategy.
  std::unique_ptr<SubscriptionIdCellRegistry> mSubscriptionIdCellRegistry;
  // Per-Connection unique client-handle allocator (CL-MI-003). Strand-only (allocation happens on the
  // connection strand in monitor_data_change_async).
  ClientHandleAllocator mHandleAllocator;

  // Observer fan-out (section 7.8 / wiring section 1). The sink is created in wire_pipeline_and_ops
  // (weak-refs this orchestrator, so no cycle) and holds only a Rule-4 atomic resolved-slots snapshot.
  // mPerConnectionObservers are the config's per-Connection slots, mutated by the setters (strand-only);
  // mClientObserverDefaults are the Client-level defaults captured at construction (const after ctor). A
  // setter re-resolves the two into the sink's snapshot (per-Connection non-null wins).
  std::shared_ptr<ObserverSink> mObserverSink;
  ObserverSlots mPerConnectionObservers;  // strand-only
  ObserverSlots mClientObserverDefaults;  // const after ctor

  // Tier-2 redundancy (section 8.11 / W4). Eagerly constructed together, RECONNECT-WIRED ONLY (both null on a
  // single-shot Connection), WRITE-ONCE in create*() before `self` is published  -  so @ref redundancy is a
  // plain synchronous member read. `mRedundancyHost` is declared BEFORE `mRedundancyManager` so the manager
  // (which holds the host STRONG  -  the one intentional cycle-exception, section 8.11.3) is destroyed FIRST
  // at teardown, i.e. the host strictly outlives the manager. The host weak-refs this orchestrator (no
  // cycle).
  std::shared_ptr<RedundancyManagerConnectionHost> mRedundancyHost;
  std::shared_ptr<detail::RedundancyManagerImpl> mRedundancyManager;
  // Strand-only: the single in-flight redundancy-reconnect completion awaiting the FSM outcome (fired from
  // the notify handlers / begin_close  -  never dropped; P3).
  std::function<void(ua::VoidResult)> mRedundancyReconnectPending;
  // Strand-only test hook (empty in production): records the source-level order of the W4 close steps
  // ("manager_close" then "fsm_cancel") so a test can assert the section 8.11.3 close ordering (F5).
  // Installed via ConnectionImplTestAccess::set_close_step_probe.
  std::function<void(std::string_view)> mCloseStepProbe;

  // Strand-only state.
  ConnectionState mState = ConnectionState::Connecting;
  std::vector<std::function<void(ua::VoidResult)>> mPendingCloseCompletions;
  // Latches the FIRST reach-Active (bootstrap complete) so @ref on_first_session_active fires the initial
  // on_connected / on_session_activated fan-out (and the W4 RedundancyManager attach) exactly once - a later
  // reconnect reaches Active again but that is `on_reconnected`, not a fresh `on_connected`. Strand-only.
  bool mFirstActiveReached = false;
  // Only one in-place ActivateSession may be outstanding. This prevents concurrent identity changes from
  // racing to replace the stored reconnect credential.
  bool mReactivateInFlight = false;
  ua::NodeId mSessionId;
  std::shared_ptr<const NamespaceTable> mNamespaceTable;
  std::shared_ptr<const ServerTable> mServerTable;

  // The server's per-call OperationLimits (CL-BASE-003), read at bootstrap and refreshed on every reconnect
  // re-read; consumed by the batched-service chunking. Strand-only (mutated + read on the connection strand).
  OperationLimits mOperationLimits;
  ContinuationPointLimits mContinuationPointLimits;
  OpenContinuationPointTracker mBrowseContinuationPoints;
  OpenContinuationPointTracker mQueryContinuationPoints;
  OpenContinuationPointTracker mHistoryContinuationPoints;

  // The server's MaxNodesPerRead operation limit, published to the WireOps interface (section 8.4,
  // CL-SUB-020). A constant 100 until the server-published value is fetched (tier-2); atomic so a later fetch
  // can update it and the cross-thread interface read stays safe. Any thread.
  std::atomic<std::uint32_t> mMaxNodesPerRead{100};

  // Reconnect wiring (engaged only when created with ReconnectWiring; nullptr FSM = single-shot).
  ReopenChannelOps mReopen;
  ua::client::Session::ActivateConfig mActivateConfig;
  // Server-certificate re-validation interface (section 722/section 727, CL-SECADMIN-004). Strand-only; empty
  // on the current bootstrap-only path (no retained secured channel), so revalidate_server_cert_async is a
  // Good no-op. Set in create()/create_with_ops() from the ReconnectWiring; the connect path fills it in a
  // later slice.
  ServerCertValidator mServerCertValidator;
  std::shared_ptr<ReconnectionFSM> mReconnectFsm;
  // Strand-only: the channel/session a reconnect attempt is building, installed at commit.
  std::shared_ptr<ChannelOps> mPendingChannel;
  std::shared_ptr<SessionOps> mPendingSession;
  // Strand-only reconnect-attempt epoch (section 3.1 finding D). Bumped once per attempt at the open-channel
  // step; a reopen / create-session completion captures the epoch it was issued under and no-ops if a
  // newer attempt has since superseded it, so a late completion cannot clobber the next attempt's pending.
  std::uint64_t mReconnectAttemptEpoch = 0;
  // Strand-only GetEndpoints epoch (CL-RECONN-005, section 3.1). The attempt epoch above is bumped at the
  // OPEN-CHANNEL step, which runs AFTER get_endpoints within one attempt  -  so two attempts' GetEndpoints
  // both run under the same attempt epoch and it cannot distinguish them. This dedicated counter is bumped
  // at the START of every reconnect_get_endpoints; the GetEndpoints completion captures it and drops its
  // snapshot-refresh side effect if a newer GetEndpoints has since superseded it. Without this a stalled
  // discovery GetEndpoints from a timed-out attempt could regress the published endpoint snapshot (stale
  // server certificate) after a newer attempt already refreshed it and reached Active.
  std::uint64_t mReconnectGetEndpointsEpoch = 0;
  // Strand-only: true only for the duration of the reconnect recover-subscriptions step, which runs while
  // mState == Reconnecting (after the Session is re-activated, before commit/reach_active). It relaxes the
  // pipeline_republish Active-gate so the recovery Republishes issue during the outage; cleared on the
  // strand when the pipeline's per-sub recovery barrier completes (success AND failure), on close, and on
  // the terminal Failed path.
  bool mRecoveryInProgress = false;
  // Strand-only (section 6.7 / #24 session-CHANGED recovery). True for the current attempt once a FRESH
  // Session was created (activate-on-existing returned Bad_SessionIdInvalid -> create_session): the old
  // server-side Subscription ids are gone, so the recover step transfers-or-recreates rather than
  // Republish-draining. Set in create_session_on success; RESET at reconnect_open_secure_channel (every
  // attempt begins there), so it tracks the CURRENT attempt's semantic fact rather than mPendingSession's
  // holder liveness.
  bool mSessionChangedThisAttempt = false;
  // Strand-only outcome facts for the current reconnect attempt. Populated by the session-changed recovery
  // barrier and copied into ReconnectOutcome at reach-Active.
  bool mSubscriptionsTransferredThisAttempt = false;
  std::size_t mMonitoredItemsRecreatedThisAttempt = 0;
  // Separately synchronized cross-thread generation. Incremented at commit only when a fresh Session
  // replaces the prior one; preserved-session channel reactivation leaves it unchanged (CL-VIEW-001).
  std::shared_ptr<std::atomic<std::uint64_t>> mSessionGeneration =
    std::make_shared<std::atomic<std::uint64_t>>(0);
  // Strand-only STAGE-AND-COMMIT area (section 6.7 / #24, NEW HAZARD 1). The session-CHANGED recover step
  // accumulates recreated-Subscription re-keys {oldId -> newId} here and reconnect_commit applies them
  // atomically AFTER the whole barrier succeeds - so a stale response from a superseded attempt can never
  // re-key the live pipeline. RESET at reconnect_open_secure_channel (discarding any superseded attempt's
  // staging) and cleared as it is applied at commit; left empty (nothing applied) on the recover-failure
  // path.
  std::vector<std::pair<std::uint32_t, std::uint32_t>> mStagedRekeys;
  // Strand-only STAGE-AND-COMMIT area for the owner-routing re-keys (CRITICAL 1), staged in lock-step with
  // mStagedRekeys and applied atomically at reconnect_commit via mMonitoredItemOwner->rekey_items. RESET at
  // reconnect_open_secure_channel and cleared as applied at commit; left empty on the recover-failure path.
  std::vector<DataChangeMonitoredItemOwner::ItemRekey> mStagedOwnerRekeys;

  // KeepAlive poll state (section 8.2A.6). Only engaged when reconnect is wired AND mKeepAlivePolicy.interval
  // > 0. mKeepAlivePolicy is set at create()/create_with_ops() from the ReconnectWiring; mKeepAliveTracker is
  // reconstructed on every arm (a fresh miss count per Active lifetime). mKeepAliveTimer is declared AFTER
  // mStrand (above) so it is destroyed BEFORE the strand it is bound to (Asio executor-lifetime contract);
  // the timer member cancels on destruction, so a notifier that races teardown is inert.
  // mKeepAlivePollInFlight enforces one poll at a time (a slow read does not stack a second poll on the next
  // tick). All strand-only.
  KeepAlivePolicy mKeepAlivePolicy;
  KeepAliveTracker mKeepAliveTracker{mKeepAlivePolicy.missedBeforeReconnect};
  ua::Timer mKeepAliveTimer;
  bool mKeepAlivePollInFlight = false;
  // Effective keep-alive poll interval (CL-SESS-020, section 8.2A.6): mKeepAlivePolicy.interval bounded by
  // the server's revised session timeout / (missedBeforeReconnect + 1) so the client polls in time to prevent
  // the Session auto-closing. Recomputed at each arm from mSessionOps->revised_session_timeout_ms(); a
  // pathologically small bound is clamped to a floor (and logged). Equals the configured interval when the
  // revised timeout is unknown (0). strand-only.
  std::chrono::milliseconds mEffectiveKeepAliveInterval{0};

  std::atomic<std::shared_ptr<const ConnectionInfo>> mInfoSnapshot;
  // Cross-strand snapshot of the current NamespaceTable (Rule 4): republished by publish_info() on every
  // visible state change, read cross-thread via namespace_table_snapshot() / the SupportOps interface.
  std::atomic<std::shared_ptr<const NamespaceTable>> mNamespaceTableSnapshot;
  std::atomic<std::shared_ptr<const ServerTable>> mServerTableSnapshot;
  // Cross-strand snapshot of the bound endpoint (Rule 4; F1/J45): published ONCE from
  // ConnectionConfig::endpoint in the ctor (the connect path fills it; a reconnect-commit republish is a W9
  // concern), read cross-thread by the tier-2 redundancy host's synchronous identity reads. Mirrors
  // mNamespaceTableSnapshot.
  std::atomic<std::shared_ptr<const ua::EndpointDescription>> mEndpointSnapshot;
  /// ConnectionConfig::ecdhPolicyUri / requestEphemeralKey, for the CreateSession of a reconnect.
  std::string mEcdhPolicyUri;
  bool mRequestEphemeralKey = true;
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_IMPL_H
