// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_OPS_H
#define UA_CONNECTION_OPS_H

/// @file
/// @brief The UPWARD tier-1 interface for @ref ua::client::detail::ConnectionImpl (client design
/// section 8.2A.13):
///        the narrow role interfaces (@ref ua::client::detail::WireOps /
///        @ref ua::client::detail::SubscriptionOps / @ref ua::client::detail::SupportOps) a tier-2
///        facade or the tier-1 @ref ua::client::detail::SubscriptionsPipeline consumes, plus the leaf
///        @ref ua::client::detail::ConnectionOpsShim that implements them by weak-referencing the
///        orchestrator.
///
/// The DOWNWARD interface (@ref ua::client::detail::SessionOps, @ref ua_session_ops.h) lets `ConnectionImpl`
/// be faked from BELOW (tier-0 Sessions/channels). This upward interface lets it be faked from ABOVE, so a
/// consumer's own logic can be unit-tested with no real `ConnectionImpl`, `Session`, or executor. The
/// interface is a `detail::` interface, not part of the public API.
/// @ingroup client

#include "ua_ack_queue.h"  // SubscriptionAcknowledgement (the send interface's ack batch)
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_connection_state.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_result.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace ua::client
{
class NamespaceTable;
}  // namespace ua::client

namespace ua::client::detail
{

class ConnectionImpl;
class EventSubscriberImpl;
class TypeResolver;
class SubscriptionFactoryOps;
class SemanticChangeCache;

/// Role 1 - the managed wire-op surface (the `invoke_wire_op` funnel, section 7.2, as an interface).
///
/// Each method posts to the connection strand and applies the single tier-1 contract (closing-guard +
/// NamespaceTable remap + default timeout + ErrorDetail wrap, exactly once), dispatches onto the active
/// Session, and hands the result back on the executor. The implementations are one-line adapters over
/// @ref ConnectionImpl's already-tested public wire ops, so the CL-DIAG single-code-path remap/wrap
/// invariant (section 7.2) is untouched. This slice exposes the wire ops the current consumers need
/// (@ref SubscriptionsPipeline's polled-Read fallback plus the base facade set); the remaining ServiceSet
/// ops (query / add / delete nodes+refs / cancel / monitored-item wire ops) are added to this role as
/// their tier-2 consumers land (section 8.2A.13 "as needed").
class WireOps
{
public:
  WireOps() = default;
  WireOps(const WireOps&) = delete;
  WireOps& operator=(const WireOps&) = delete;
  WireOps(WireOps&&) = delete;
  WireOps& operator=(WireOps&&) = delete;
  virtual ~WireOps() = default;

  /// Issues a Read; the callback delivers the @ref ua::ReadResponse (or a bad Result) on the executor.
  virtual void read_async(
    ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) noexcept = 0;

  /// Issues a Write; the callback delivers the @ref ua::WriteResponse (or a bad Result) on the executor.
  virtual void write_async(
    ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) noexcept = 0;

  /// Issues a Browse; the callback delivers the @ref ua::BrowseResponse (or a bad Result) on the executor.
  virtual void browse_async(
    ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) noexcept = 0;

  /// Issues a BrowseNext (continuation of a prior Browse); delivers the response (or a bad Result) on the
  /// executor.
  virtual void browse_next_async(ua::BrowseNextRequest request,
    std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept = 0;

  /// Issues BrowseNext only if @p expectedSessionGeneration is still current when the Connection strand
  /// selects the Session. The default preserves compatibility for non-cursor interfaces; production
  /// overrides.
  virtual void browse_next_on_session_async(std::uint64_t expectedSessionGeneration,
    ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept
  {
    static_cast<void>(expectedSessionGeneration);
    browse_next_async(std::move(request), std::move(callback));
  }

  /// Issues a TranslateBrowsePathsToNodeIds; delivers the response (or a bad Result) on the executor.
  virtual void translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
    std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) noexcept = 0;

  /// Issues a Call; the callback delivers the @ref ua::CallResponse (or a bad Result) on the executor.
  virtual void call_async(
    ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) noexcept = 0;

  /// Issues a HistoryRead; the callback delivers the @ref ua::HistoryReadResponse (or a bad Result) on the
  /// executor.
  virtual void history_read_async(ua::HistoryReadRequest request,
    std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) noexcept = 0;

  /// Issues a HistoryUpdate; the callback delivers the @ref ua::HistoryUpdateResponse (or a bad Result) on
  /// the executor.
  virtual void history_update_async(ua::HistoryUpdateRequest request,
    std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) noexcept = 0;

  /// Issues a RegisterNodes; the callback delivers the @ref ua::RegisterNodesResponse (or a bad Result) on
  /// the executor.
  virtual void register_nodes_async(ua::RegisterNodesRequest request,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) noexcept = 0;

  /// Issues an UnregisterNodes; the callback delivers the @ref ua::UnregisterNodesResponse (or a bad
  /// Result) on the executor.
  virtual void unregister_nodes_async(ua::UnregisterNodesRequest request,
    std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) noexcept = 0;

  /// The server's `MaxNodesPerRead` operation limit used to page the polled-Read fallback
  /// (CL-SUB-019..022). Absent a server-published value, defaults to 100 (section 8.4, CL-SUB-020).
  [[nodiscard]] virtual std::uint32_t max_nodes_per_read() const noexcept = 0;
};

/// Role 2 - the subscription send interface the @ref SubscriptionsPipeline drives its Publish pump through.
///
/// This is today's `SubscriptionsPipelineHost` (section 8.4), re-homed onto the @ref ConnectionOps aggregate.
/// It carries the two higher-level send primitives the pipeline strand orders - NOT the wire-shaped
/// `publish_async` / `republish_async` - because the request BUILDING and the reconnect epoch-guard
/// (`mReconnectAttemptEpoch`) that classifies a channel/session-fatal Publish into an automatic drop live
/// on the @ref ConnectionImpl strand (`pipeline_send_publish` / `pipeline_republish`); moving them into
/// the pipeline would break drop detection. The implementation runs on the connection strand and
/// Active-gates before touching the tier-0 session. The wire-shaped subscription surface (section 8.2A.13) is
/// added to this role when its tier-2 consumers land.
class SubscriptionOps
{
public:
  SubscriptionOps() = default;
  SubscriptionOps(const SubscriptionOps&) = delete;
  SubscriptionOps& operator=(const SubscriptionOps&) = delete;
  SubscriptionOps(SubscriptionOps&&) = delete;
  SubscriptionOps& operator=(SubscriptionOps&&) = delete;
  virtual ~SubscriptionOps() = default;

  /// Sends one Publish request carrying the batched @p acknowledgements (may be empty).
  virtual void send_publish(std::vector<SubscriptionAcknowledgement> acknowledgements) = 0;

  /// Sends a Republish for one retained notification message (gap recovery, section 8.4.5).
  ///
  /// @param subscriptionId The Subscription to republish from.
  /// @param sequenceNumber The retained sequence number to request.
  virtual void republish(std::uint32_t subscriptionId, std::uint32_t sequenceNumber) = 0;

  /// Applies one automatic oversized-message recovery step (CL-SUB-005).
  ///
  /// The implementation preserves the Subscription's publishing cadence and replaces only
  /// `maxNotificationsPerPublish`. The callback receives the effective service outcome on the executor;
  /// a bad result retains its complete ErrorDetail chain. An outcome that is not Bad (a Good code, or an
  /// Uncertain ServiceResult with the response) means the new cap is in force; an Uncertain answer without a
  /// response is refused (Bad_InternalError, `ServiceAnswerUncertain`).
  virtual void adjust_max_notifications_per_publish(std::uint32_t subscriptionId, double publishingInterval,
    std::uint32_t maxNotificationsPerPublish, std::function<void(ua::VoidResult)> callback) = 0;
};

/// Role 3 - the shared support surface (the single home for the cross-cutting queries a
/// @ref WireOps / @ref SubscriptionOps consumer also needs). Exactly one `namespace_table()` signature
/// across the whole interface - no cross-role name/return collision.
///
/// This slice exposes the three base support methods plus the three tier-2 reach-through handles the wiring
/// phase (section 2) wires in: @ref event_subscriber (backs CL-SM-010 subscribe_transitions + the
/// event-observer routing), @ref type_resolver (section 8.6), and @ref subscription_factory (a NEW
/// purpose-built ISP-narrow role so the ServerDiagnostics streaming accessor, CL-BASEDIAG-004, creates a
/// managed Subscription + data-change MI WITHOUT holding `ConnectionImpl`). Each returns a `shared_ptr` to a
/// forward-declared `detail::` component (no heavy include in the interface header); consumers lock-then-use
/// per op and never hold it long-term-strong, so no ownership cycle forms. @ref semantic_change_cache
/// (section 8.2A.13 / Slice W2a) backs the DataAccess CL-DA-010/011 Property-invalidation cache.
class SupportOps
{
public:
  SupportOps() = default;
  SupportOps(const SupportOps&) = delete;
  SupportOps& operator=(const SupportOps&) = delete;
  SupportOps(SupportOps&&) = delete;
  SupportOps& operator=(SupportOps&&) = delete;
  virtual ~SupportOps() = default;

  /// The current immutable NamespaceTable snapshot (== `Connection::namespace_table()`), or null before
  /// bootstrap completes / when the Connection is gone.
  [[nodiscard]] virtual std::shared_ptr<const NamespaceTable> namespace_table() const = 0;

  /// Hands @p work to the executor for a user-callback fire (the design specification: user callbacks run on
  /// the executor, never on a component strand).
  virtual void post_to_executor(std::function<void()> work) = 0;

  /// The Connection's current lifecycle state (a facade's fast-fail closing-guard). Reports
  /// @ref ConnectionState::Closed when the Connection is gone.
  [[nodiscard]] virtual ConnectionState state() const = 0;

  /// The lazily-constructed, co-owned tier-2 event backbone (section 8.13). Backs CL-SM-010
  /// subscribe_transitions and the event-observer routing. Null when the Connection is gone. Free-threaded
  /// (once_flag lazy on `ConnectionImpl`); consumers lock-then-use per op (no long-term-strong hold  to  no
  /// cycle).
  [[nodiscard]] virtual std::shared_ptr<EventSubscriberImpl> event_subscriber() const = 0;

  /// The per-Connection type-resolution component (section 8.6). Null when the Connection is gone.
  /// Free-threaded; consumers lock-then-use per op.
  [[nodiscard]] virtual std::shared_ptr<TypeResolver> type_resolver() const = 0;

  /// The narrow subscription-creation interface (wiring section 2) the ServerDiagnostics streaming accessor
  /// (CL-BASEDIAG-004) uses to stand up a managed Subscription + data-change MI without holding
  /// `ConnectionImpl`. Null when the Connection is gone. Consumers lock-then-use per op.
  [[nodiscard]] virtual std::shared_ptr<SubscriptionFactoryOps> subscription_factory() const = 0;

  /// The per-Connection, lazily-constructed DataAccess Property invalidation cache (section 8.18.2 / Slice
  /// W2a). Backs CL-DA-010/011: a DataAccess typed handle registers its Property snapshot here at
  /// construction, and the in-band `SemanticsChanged` / `SemanticChangeEventType` paths invalidate it. Null
  /// when the Connection is gone (a DataAccess handle then simply skips registration  -  the manual refresh
  /// path still works). Its state is strand-confined (mutations self-marshal onto `ConnectionImpl`'s strand);
  /// consumers hold it per op only (no long-term-strong hold  to  no cycle).
  [[nodiscard]] virtual std::shared_ptr<SemanticChangeCache> semantic_change_cache() const = 0;
};

/// Aggregate - a documentation grouping of the three roles. NOT a base of @ref ConnectionImpl (that would
/// reintroduce the pipeline-leak cycle); it is the base of the leaf @ref ConnectionOpsShim only.
class ConnectionOps : public WireOps, public SubscriptionOps, public SupportOps
{};

/// The leaf shim that IMPLEMENTS the upward interface by weak-referencing @ref ConnectionImpl (mirrors the
/// downward @ref RealSessionOps and the former `ConnectionSubscriptionsHost`).
///
/// @ref ConnectionImpl owns this strongly and hands out role subobject handles
/// (`shared_ptr<WireOps>` / `shared_ptr<SubscriptionOps>` / `shared_ptr<SupportOps>`, all aliasing the one
/// shim's control block) to its consumers. The shim only WEAK-references `ConnectionImpl`, so no strong
/// cycle forms back into the orchestrator:
///   `ConnectionImpl --owns(strong)--> ConnectionOpsShim --weak--> ConnectionImpl`.
///
/// Each role method locks the weak `ConnectionImpl`; if it is gone, a callback-bearing wire op completes
/// on the executor with `Bad_ConnectionClosed` carrying an @ref ua::ErrorDetail whose source is
/// `client.tier1.connection_ops_shim.connection_gone` (a manufactured boundary failure carries a source
/// tag, the design specification). Otherwise it forwards to the matching @ref ConnectionImpl entry point
/// (which posts to the connection strand and applies the single tier-1 ErrorDetail wrap exactly once - the
/// shim never double-wraps). The executor is captured at construction so a boundary failure is still
/// delivered on it after `ConnectionImpl` is destroyed.
class ConnectionOpsShim final : public ConnectionOps
{
public:
  /// @param connection The orchestrator this shim forwards to (weak; the shim must not own it).
  /// @param executor   The executor boundary failures are delivered on (outlives `ConnectionImpl`).
  ConnectionOpsShim(std::weak_ptr<ConnectionImpl> connection, boost::asio::any_io_executor executor);

  // --- WireOps ---
  void read_async(
    ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) noexcept override;
  void write_async(
    ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) noexcept override;
  void browse_async(ua::BrowseRequest request,
    std::function<void(ua::Result<ua::BrowseResponse>)> callback) noexcept override;
  void browse_next_async(ua::BrowseNextRequest request,
    std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept override;
  void browse_next_on_session_async(std::uint64_t expectedSessionGeneration, ua::BrowseNextRequest request,
    std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept override;
  void translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
    std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) noexcept override;
  void call_async(
    ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) noexcept override;
  void history_read_async(ua::HistoryReadRequest request,
    std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) noexcept override;
  void history_update_async(ua::HistoryUpdateRequest request,
    std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) noexcept override;
  void register_nodes_async(ua::RegisterNodesRequest request,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) noexcept override;
  void unregister_nodes_async(ua::UnregisterNodesRequest request,
    std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) noexcept override;
  [[nodiscard]] std::uint32_t max_nodes_per_read() const noexcept override;

  // --- SubscriptionOps (the send interface) ---
  void send_publish(std::vector<SubscriptionAcknowledgement> acknowledgements) override;
  void republish(std::uint32_t subscriptionId, std::uint32_t sequenceNumber) override;
  void adjust_max_notifications_per_publish(std::uint32_t subscriptionId, double publishingInterval,
    std::uint32_t maxNotificationsPerPublish, std::function<void(ua::VoidResult)> callback) override;

  // --- SupportOps ---
  [[nodiscard]] std::shared_ptr<const NamespaceTable> namespace_table() const override;
  void post_to_executor(std::function<void()> work) override;
  [[nodiscard]] ConnectionState state() const override;
  [[nodiscard]] std::shared_ptr<EventSubscriberImpl> event_subscriber() const override;
  [[nodiscard]] std::shared_ptr<TypeResolver> type_resolver() const override;
  [[nodiscard]] std::shared_ptr<SubscriptionFactoryOps> subscription_factory() const override;
  [[nodiscard]] std::shared_ptr<SemanticChangeCache> semantic_change_cache() const override;

private:
  std::weak_ptr<ConnectionImpl> mConnection;
  boost::asio::any_io_executor mExecutor;
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_OPS_H
