// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SESSION_OPS_H
#define UA_SESSION_OPS_H

/// @file
/// @brief Injectable tier-0 interface for @ref ua::client::detail::ConnectionImpl: the narrow set of
///        Session / SecureChannel operations the tier-1 hub orders (see
///        the design specification).
/// @ingroup client

#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
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
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_node_id.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_query_first_request.h"
#include "ua_query_first_response.h"
#include "ua_query_next_request.h"
#include "ua_query_next_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_register_nodes_request.h"
#include "ua_register_nodes_response.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_result.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_set_triggering_request.h"
#include "ua_set_triggering_response.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_unregister_nodes_request.h"
#include "ua_unregister_nodes_response.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <functional>
#include <memory>
#include <optional>

namespace ua::client::detail
{

class ChannelOps;

/// Narrow injectable interface over a tier-0 client @ref ua::client::Session (the design specification).
///
/// Exposes ONLY the operations @ref ConnectionImpl orders - the wire ops it funnels, the two activate
/// shapes the reconnect state machine drives, close, and the session-id query - as async primitives that
/// complete on the executor with a @ref ua::Result / @ref ua::VoidResult. Production wires this to the
/// concrete tier-0 handle (@ref RealSessionOps); unit tests wire it to a fake that scripts responses. It
/// never leaks the whole tier-0 surface. The interface is a `detail::` interface, not part of the public API.
class SessionOps
{
public:
  SessionOps() = default;
  SessionOps(const SessionOps&) = delete;
  SessionOps& operator=(const SessionOps&) = delete;
  SessionOps(SessionOps&&) = delete;
  SessionOps& operator=(SessionOps&&) = delete;
  virtual ~SessionOps() = default;

  /// Configures the owning Connection's returnDiagnostics override on this private Session.
  virtual void set_return_diagnostics_override(std::optional<uint32_t> mask) = 0;

  /// Issues a Read; the callback delivers the @ref ua::ReadResponse (or a bad Result) on the executor.
  virtual void read_async(
    ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) = 0;

  /// Issues a HistoryRead; the callback delivers the @ref ua::HistoryReadResponse (or a bad Result) on the
  /// executor. The tier-1 hub funnels the request opaquely - the history-read details (raw / processed /
  /// events) and continuation points are the caller's / a tier-2 cursor's concern.
  virtual void history_read_async(
    ua::HistoryReadRequest request, std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) = 0;

  /// Issues a Write; the callback delivers the @ref ua::WriteResponse (or a bad Result) on the executor.
  virtual void write_async(
    ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) = 0;

  /// Issues a Browse; the callback delivers the @ref ua::BrowseResponse (or a bad Result) on the executor.
  virtual void browse_async(
    ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) = 0;

  /// Issues a BrowseNext (continuation of a prior Browse); delivers the @ref ua::BrowseNextResponse (or a
  /// bad Result) on the executor.
  virtual void browse_next_async(
    ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) = 0;

  /// Issues a TranslateBrowsePathsToNodeIds (resolve browse paths to NodeIds); delivers the
  /// @ref ua::TranslateBrowsePathsToNodeIdsResponse (or a bad Result) on the executor.
  virtual void translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
    std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) = 0;

  /// Issues a Call; the callback delivers the @ref ua::CallResponse (or a bad Result) on the executor.
  virtual void call_async(
    ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) = 0;

  /// Issues a Cancel (request cancellation of outstanding requests); delivers the @ref ua::CancelResponse (or
  /// a bad Result) on the executor.
  virtual void cancel_async(
    ua::CancelRequest request, std::function<void(ua::Result<ua::CancelResponse>)> callback) = 0;

  /// Issues a RegisterNodes; the callback delivers the @ref ua::RegisterNodesResponse (or a bad Result) on
  /// the executor.
  virtual void register_nodes_async(ua::RegisterNodesRequest request,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) = 0;

  /// Issues an UnregisterNodes; the callback delivers the @ref ua::UnregisterNodesResponse (or a bad Result)
  /// on the executor.
  virtual void unregister_nodes_async(ua::UnregisterNodesRequest request,
    std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) = 0;

  /// Issues an AddNodes; the callback delivers the @ref ua::AddNodesResponse (or a bad Result) on the
  /// executor.
  virtual void add_nodes_async(
    ua::AddNodesRequest request, std::function<void(ua::Result<ua::AddNodesResponse>)> callback) = 0;

  /// Issues an AddReferences; the callback delivers the @ref ua::AddReferencesResponse (or a bad Result) on
  /// the executor.
  virtual void add_references_async(ua::AddReferencesRequest request,
    std::function<void(ua::Result<ua::AddReferencesResponse>)> callback) = 0;

  /// Issues a DeleteNodes; the callback delivers the @ref ua::DeleteNodesResponse (or a bad Result) on the
  /// executor.
  virtual void delete_nodes_async(
    ua::DeleteNodesRequest request, std::function<void(ua::Result<ua::DeleteNodesResponse>)> callback) = 0;

  /// Issues a DeleteReferences; the callback delivers the @ref ua::DeleteReferencesResponse (or a bad Result)
  /// on the executor.
  virtual void delete_references_async(ua::DeleteReferencesRequest request,
    std::function<void(ua::Result<ua::DeleteReferencesResponse>)> callback) = 0;

  /// Issues a HistoryUpdate; the callback delivers the @ref ua::HistoryUpdateResponse (or a bad Result) on
  /// the executor.
  virtual void history_update_async(ua::HistoryUpdateRequest request,
    std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) = 0;

  /// Issues a SetMonitoringMode; the callback delivers the @ref ua::SetMonitoringModeResponse (or a bad
  /// Result) on the executor.
  virtual void set_monitoring_mode_async(ua::SetMonitoringModeRequest request,
    std::function<void(ua::Result<ua::SetMonitoringModeResponse>)> callback) = 0;

  /// Issues a ModifyMonitoredItems; the callback delivers the @ref ua::ModifyMonitoredItemsResponse (or a bad
  /// Result) on the executor.
  virtual void modify_monitored_items_async(ua::ModifyMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::ModifyMonitoredItemsResponse>)> callback) = 0;

  /// Issues a SetTriggering (configure triggering links between monitored items); delivers the
  /// @ref ua::SetTriggeringResponse (or a bad Result) on the executor.
  virtual void set_triggering_async(ua::SetTriggeringRequest request,
    std::function<void(ua::Result<ua::SetTriggeringResponse>)> callback) = 0;

  /// Issues a QueryFirst; the callback delivers the @ref ua::QueryFirstResponse (or a bad Result) on the
  /// executor.
  virtual void query_first_async(
    ua::QueryFirstRequest request, std::function<void(ua::Result<ua::QueryFirstResponse>)> callback) = 0;

  /// Issues a QueryNext (continuation of a prior QueryFirst); the callback delivers the
  /// @ref ua::QueryNextResponse (or a bad Result) on the executor.
  virtual void query_next_async(
    ua::QueryNextRequest request, std::function<void(ua::Result<ua::QueryNextResponse>)> callback) = 0;

  /// Issues a CreateSubscription; the callback delivers the response (or a bad Result) on the executor.
  virtual void create_subscription_async(ua::CreateSubscriptionRequest request,
    std::function<void(ua::Result<ua::CreateSubscriptionResponse>)> callback) = 0;

  /// Issues a CreateMonitoredItems; the callback delivers the response (or a bad Result) on the executor.
  virtual void create_monitored_items_async(ua::CreateMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::CreateMonitoredItemsResponse>)> callback) = 0;

  /// Issues a Publish; the callback delivers the @ref ua::PublishResponse (or a bad Result) on the executor.
  virtual void publish_async(
    ua::PublishRequest request, std::function<void(ua::Result<ua::PublishResponse>)> callback) = 0;

  /// Issues a Republish; the callback delivers the response (or a bad Result) on the executor.
  virtual void republish_async(
    ua::RepublishRequest request, std::function<void(ua::Result<ua::RepublishResponse>)> callback) = 0;

  /// Issues a DeleteSubscriptions; the callback delivers the response (or a bad Result) on the executor.
  virtual void delete_subscriptions_async(ua::DeleteSubscriptionsRequest request,
    std::function<void(ua::Result<ua::DeleteSubscriptionsResponse>)> callback) = 0;

  /// Issues a DeleteMonitoredItems; the callback delivers the response (or a bad Result) on the executor.
  virtual void delete_monitored_items_async(ua::DeleteMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::DeleteMonitoredItemsResponse>)> callback) = 0;

  /// Issues a ModifySubscription; the callback delivers the response (or a bad Result) on the executor.
  virtual void modify_subscription_async(ua::ModifySubscriptionRequest request,
    std::function<void(ua::Result<ua::ModifySubscriptionResponse>)> callback) = 0;

  /// Issues a SetPublishingMode; the callback delivers the response (or a bad Result) on the executor.
  virtual void set_publishing_mode_async(ua::SetPublishingModeRequest request,
    std::function<void(ua::Result<ua::SetPublishingModeResponse>)> callback) = 0;

  /// Issues a TransferSubscriptions; the callback delivers the response (or a bad Result) on the executor.
  ///
  /// The reconnect session-CHANGED recovery orders this to move the outage-orphaned Subscriptions onto the
  /// freshly-created Session before deciding, per result, whether each is kept (transferred) or recreated.
  virtual void transfer_subscriptions_async(ua::TransferSubscriptionsRequest request,
    std::function<void(ua::Result<ua::TransferSubscriptionsResponse>)> callback) noexcept = 0;

  /// Rebinds this (existing) session onto a freshly-opened channel and activates it (reconnect happy path).
  ///
  /// The adapter consumes @p channel's inner tier-0 SecureChannel, flipping @ref ChannelOps::is_open to
  /// false. The callback delivers the activation outcome on the executor.
  virtual void activate_on_channel_async(std::shared_ptr<ChannelOps> channel,
    ua::client::Session::ActivateConfig config, std::function<void(ua::VoidResult)> callback) = 0;

  /// Activates this (freshly-created) session on its already-bound channel (reconnect create-session path).
  ///
  /// The callback delivers the activation outcome on the executor.
  virtual void activate_on_bound_channel_async(
    ua::client::Session::ActivateConfig config, std::function<void(ua::VoidResult)> callback) = 0;

  /// Gracefully closes the session; the callback delivers the outcome on the executor.
  virtual void close_async(std::function<void(ua::VoidResult)> callback) = 0;

  /// Returns the server-assigned session identifier (null before the session is created server-side).
  [[nodiscard]] virtual ua::NodeId session_id() const = 0;

  /// Returns the server's revised session timeout in milliseconds (from the CreateSession response), or 0
  /// when unknown (before the session is created server-side). @ref ConnectionImpl bounds its keep-alive
  /// poll interval by this value so a server that revises the timeout DOWN cannot expire the session between
  /// polls (CL-SESS-020, section 8.2A.6).
  [[nodiscard]] virtual double revised_session_timeout_ms() const = 0;
};

/// Narrow injectable interface over a tier-0 @ref ua::client::SecureChannel's create-session op.
///
/// The reconnect state machine opens a fresh channel through @ref ReopenChannelOps and, on the
/// create-session fallback route, orders a new session on it. Production wires this to the concrete
/// tier-0 channel (@ref RealChannelOps); unit tests wire it to a fake.
class ChannelOps
{
public:
  ChannelOps() = default;
  ChannelOps(const ChannelOps&) = delete;
  ChannelOps& operator=(const ChannelOps&) = delete;
  ChannelOps(ChannelOps&&) = delete;
  ChannelOps& operator=(ChannelOps&&) = delete;
  virtual ~ChannelOps() = default;

  /// Creates and activates a fresh session on this channel; the callback delivers a @ref SessionOps
  /// (wrapping the new session) or a bad Result on the executor.
  virtual void create_session_async(ua::client::SecureChannel::CreateSessionConfig config,
    std::function<void(ua::Result<std::shared_ptr<SessionOps>>)> callback) = 0;

  /// Issues a session-less GetEndpoints on this channel (CL-RECONN-005): the callback delivers the
  /// @ref ua::GetEndpointsResponse (or a bad Result) on the executor. Used by the reconnect FSM on a
  /// security-class failure to fetch the server's most up-to-date security information (Part 4 section 6.7).
  virtual void get_endpoints_async(
    ua::GetEndpointsRequest request, std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) = 0;

  /// Gracefully closes this session-less channel.
  virtual void close_async(std::function<void(ua::VoidResult)> callback) = 0;

  /// Reports whether the underlying channel is currently open (false once its inner channel is consumed).
  [[nodiscard]] virtual bool is_open() const = 0;
};

/// Re-opens a fresh channel to the same endpoint and yields it as a @ref ChannelOps (the interface-level
/// reconnect open-channel step). The caller-facing @ref ReopenChannel is adapted into this via
/// @ref make_real_reopen; the callback it is handed fires on the executor with the new channel (or a bad
/// Result carrying an @ref ua::ErrorDetail).
using ReopenChannelOps = std::function<void(std::function<void(ua::Result<std::shared_ptr<ChannelOps>>)>)>;

}  // namespace ua::client::detail

#endif  // UA_SESSION_OPS_H
