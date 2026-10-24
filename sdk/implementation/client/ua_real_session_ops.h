// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REAL_SESSION_OPS_H
#define UA_REAL_SESSION_OPS_H

/// @file
/// @brief Production adapters wiring the @ref ua::client::detail::ConnectionImpl tier-0 interface
///        (@ref ua::client::detail::SessionOps / @ref ua::client::detail::ChannelOps) to the concrete
///        tier-0 @ref ua::client::Session / @ref ua::client::SecureChannel handles.
/// @ingroup client

#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_connection_impl.h"  // for ReopenChannel (the caller-facing SecureChannel-returning alias)
#include "ua_session_ops.h"

#include <functional>
#include <memory>

namespace ua::client::detail
{

/// Production @ref SessionOps: owns a concrete tier-0 @ref ua::client::Session by value and forwards each
/// ordered op to the matching service-set accessor.
class RealSessionOps final : public SessionOps
{
public:
  /// Adopts @p session (moved in and owned) as the concrete tier-0 session this interface forwards to.
  explicit RealSessionOps(ua::client::Session session);

  void set_return_diagnostics_override(std::optional<uint32_t> mask) override;

  void read_async(
    ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) override;
  void history_read_async(ua::HistoryReadRequest request,
    std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) override;
  void write_async(
    ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) override;
  void browse_async(
    ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) override;
  void browse_next_async(
    ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) override;
  void translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
    std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) override;
  void call_async(
    ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) override;
  void cancel_async(
    ua::CancelRequest request, std::function<void(ua::Result<ua::CancelResponse>)> callback) override;
  void register_nodes_async(ua::RegisterNodesRequest request,
    std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) override;
  void unregister_nodes_async(ua::UnregisterNodesRequest request,
    std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) override;
  void add_nodes_async(
    ua::AddNodesRequest request, std::function<void(ua::Result<ua::AddNodesResponse>)> callback) override;
  void add_references_async(ua::AddReferencesRequest request,
    std::function<void(ua::Result<ua::AddReferencesResponse>)> callback) override;
  void delete_nodes_async(ua::DeleteNodesRequest request,
    std::function<void(ua::Result<ua::DeleteNodesResponse>)> callback) override;
  void delete_references_async(ua::DeleteReferencesRequest request,
    std::function<void(ua::Result<ua::DeleteReferencesResponse>)> callback) override;
  void history_update_async(ua::HistoryUpdateRequest request,
    std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) override;
  void set_monitoring_mode_async(ua::SetMonitoringModeRequest request,
    std::function<void(ua::Result<ua::SetMonitoringModeResponse>)> callback) override;
  void modify_monitored_items_async(ua::ModifyMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::ModifyMonitoredItemsResponse>)> callback) override;
  void set_triggering_async(ua::SetTriggeringRequest request,
    std::function<void(ua::Result<ua::SetTriggeringResponse>)> callback) override;
  void query_first_async(
    ua::QueryFirstRequest request, std::function<void(ua::Result<ua::QueryFirstResponse>)> callback) override;
  void query_next_async(
    ua::QueryNextRequest request, std::function<void(ua::Result<ua::QueryNextResponse>)> callback) override;
  void create_subscription_async(ua::CreateSubscriptionRequest request,
    std::function<void(ua::Result<ua::CreateSubscriptionResponse>)> callback) override;
  void create_monitored_items_async(ua::CreateMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::CreateMonitoredItemsResponse>)> callback) override;
  void publish_async(
    ua::PublishRequest request, std::function<void(ua::Result<ua::PublishResponse>)> callback) override;
  void republish_async(
    ua::RepublishRequest request, std::function<void(ua::Result<ua::RepublishResponse>)> callback) override;
  void delete_subscriptions_async(ua::DeleteSubscriptionsRequest request,
    std::function<void(ua::Result<ua::DeleteSubscriptionsResponse>)> callback) override;
  void delete_monitored_items_async(ua::DeleteMonitoredItemsRequest request,
    std::function<void(ua::Result<ua::DeleteMonitoredItemsResponse>)> callback) override;
  void modify_subscription_async(ua::ModifySubscriptionRequest request,
    std::function<void(ua::Result<ua::ModifySubscriptionResponse>)> callback) override;
  void set_publishing_mode_async(ua::SetPublishingModeRequest request,
    std::function<void(ua::Result<ua::SetPublishingModeResponse>)> callback) override;
  void transfer_subscriptions_async(ua::TransferSubscriptionsRequest request,
    std::function<void(ua::Result<ua::TransferSubscriptionsResponse>)> callback) noexcept override;
  void activate_on_channel_async(std::shared_ptr<ChannelOps> channel,
    ua::client::Session::ActivateConfig config, std::function<void(ua::VoidResult)> callback) override;
  void activate_on_bound_channel_async(
    ua::client::Session::ActivateConfig config, std::function<void(ua::VoidResult)> callback) override;
  void close_async(std::function<void(ua::VoidResult)> callback) override;
  [[nodiscard]] ua::NodeId session_id() const override;
  [[nodiscard]] double revised_session_timeout_ms() const override;

private:
  ua::client::Session mSession;
};

/// Production @ref ChannelOps: owns a concrete tier-0 @ref ua::client::SecureChannel by value.
///
/// @ref RealSessionOps::activate_on_channel_async is a friend so it can MOVE the inner channel out on a
/// rebind (which flips @ref is_open to false - the consumed-channel invariant the reconnect logic relies
/// on).
class RealChannelOps final : public ChannelOps
{
public:
  /// Adopts @p channel (moved in and owned) as the concrete tier-0 channel this interface wraps.
  explicit RealChannelOps(ua::client::SecureChannel channel);

  void create_session_async(ua::client::SecureChannel::CreateSessionConfig config,
    std::function<void(ua::Result<std::shared_ptr<SessionOps>>)> callback) override;
  void get_endpoints_async(ua::GetEndpointsRequest request,
    std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) override;
  void close_async(std::function<void(ua::VoidResult)> callback) override;
  [[nodiscard]] bool is_open() const override;

private:
  friend class RealSessionOps;

  ua::client::SecureChannel mChannel;
};

/// Wraps a caller-facing @ref ReopenChannel (which yields a concrete @ref ua::client::SecureChannel) into
/// an interface-level @ref ReopenChannelOps (which yields a @ref ChannelOps): each yielded channel is wrapped in
/// a @ref RealChannelOps on success, and a bad status (with its @ref ua::ErrorDetail) is forwarded on
/// failure.
[[nodiscard]] ReopenChannelOps make_real_reopen(ReopenChannel userReopen);

}  // namespace ua::client::detail

#endif  // UA_REAL_SESSION_OPS_H
