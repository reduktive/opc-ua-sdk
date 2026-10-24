// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_real_session_ops.h"

#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_node_management_services.h"
#include "ua_session_query_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"
#include "ua_status.h"

#include <memory>
#include <utility>

namespace ua::client::detail
{

RealSessionOps::RealSessionOps(ua::client::Session session) : mSession(std::move(session))
{}

void RealSessionOps::set_return_diagnostics_override(std::optional<uint32_t> mask)
{
  mSession.set_return_diagnostics_override(mask);
}

void RealSessionOps::read_async(
  ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback)
{
  mSession.attributes().read_async(std::move(request), std::move(callback));
}

void RealSessionOps::history_read_async(
  ua::HistoryReadRequest request, std::function<void(ua::Result<ua::HistoryReadResponse>)> callback)
{
  mSession.attributes().history_read_async(std::move(request), std::move(callback));
}

void RealSessionOps::write_async(
  ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback)
{
  mSession.attributes().write_async(std::move(request), std::move(callback));
}

void RealSessionOps::browse_async(
  ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback)
{
  mSession.view().browse_async(std::move(request), std::move(callback));
}

void RealSessionOps::browse_next_async(
  ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback)
{
  mSession.view().browse_next_async(std::move(request), std::move(callback));
}

void RealSessionOps::translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
  std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback)
{
  mSession.view().translate_browse_paths_async(std::move(request), std::move(callback));
}

void RealSessionOps::call_async(
  ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback)
{
  mSession.methods().call_async(std::move(request), std::move(callback));
}

void RealSessionOps::cancel_async(
  ua::CancelRequest request, std::function<void(ua::Result<ua::CancelResponse>)> callback)
{
  mSession.cancel_async(std::move(request), std::move(callback));
}

void RealSessionOps::register_nodes_async(
  ua::RegisterNodesRequest request, std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback)
{
  mSession.view().register_nodes_async(std::move(request), std::move(callback));
}

void RealSessionOps::unregister_nodes_async(
  ua::UnregisterNodesRequest request, std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback)
{
  mSession.view().unregister_nodes_async(std::move(request), std::move(callback));
}

void RealSessionOps::add_nodes_async(
  ua::AddNodesRequest request, std::function<void(ua::Result<ua::AddNodesResponse>)> callback)
{
  mSession.node_management().add_nodes_async(std::move(request), std::move(callback));
}

void RealSessionOps::add_references_async(
  ua::AddReferencesRequest request, std::function<void(ua::Result<ua::AddReferencesResponse>)> callback)
{
  mSession.node_management().add_references_async(std::move(request), std::move(callback));
}

void RealSessionOps::delete_nodes_async(
  ua::DeleteNodesRequest request, std::function<void(ua::Result<ua::DeleteNodesResponse>)> callback)
{
  mSession.node_management().delete_nodes_async(std::move(request), std::move(callback));
}

void RealSessionOps::delete_references_async(
  ua::DeleteReferencesRequest request, std::function<void(ua::Result<ua::DeleteReferencesResponse>)> callback)
{
  mSession.node_management().delete_references_async(std::move(request), std::move(callback));
}

void RealSessionOps::history_update_async(
  ua::HistoryUpdateRequest request, std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback)
{
  mSession.attributes().history_update_async(std::move(request), std::move(callback));
}

void RealSessionOps::set_monitoring_mode_async(ua::SetMonitoringModeRequest request,
  std::function<void(ua::Result<ua::SetMonitoringModeResponse>)> callback)
{
  mSession.monitored_items().set_monitoring_mode_async(std::move(request), std::move(callback));
}

void RealSessionOps::modify_monitored_items_async(ua::ModifyMonitoredItemsRequest request,
  std::function<void(ua::Result<ua::ModifyMonitoredItemsResponse>)> callback)
{
  mSession.monitored_items().modify_monitored_items_async(std::move(request), std::move(callback));
}

void RealSessionOps::set_triggering_async(
  ua::SetTriggeringRequest request, std::function<void(ua::Result<ua::SetTriggeringResponse>)> callback)
{
  mSession.monitored_items().set_triggering_async(std::move(request), std::move(callback));
}

void RealSessionOps::query_first_async(
  ua::QueryFirstRequest request, std::function<void(ua::Result<ua::QueryFirstResponse>)> callback)
{
  mSession.query().query_first_async(std::move(request), std::move(callback));
}

void RealSessionOps::query_next_async(
  ua::QueryNextRequest request, std::function<void(ua::Result<ua::QueryNextResponse>)> callback)
{
  mSession.query().query_next_async(std::move(request), std::move(callback));
}

void RealSessionOps::create_subscription_async(ua::CreateSubscriptionRequest request,
  std::function<void(ua::Result<ua::CreateSubscriptionResponse>)> callback)
{
  mSession.subscriptions().create_subscription_async(std::move(request), std::move(callback));
}

void RealSessionOps::create_monitored_items_async(ua::CreateMonitoredItemsRequest request,
  std::function<void(ua::Result<ua::CreateMonitoredItemsResponse>)> callback)
{
  mSession.monitored_items().create_monitored_items_async(std::move(request), std::move(callback));
}

void RealSessionOps::publish_async(
  ua::PublishRequest request, std::function<void(ua::Result<ua::PublishResponse>)> callback)
{
  mSession.subscriptions().publish_async(std::move(request), std::move(callback));
}

void RealSessionOps::republish_async(
  ua::RepublishRequest request, std::function<void(ua::Result<ua::RepublishResponse>)> callback)
{
  mSession.subscriptions().republish_async(std::move(request), std::move(callback));
}

void RealSessionOps::delete_subscriptions_async(ua::DeleteSubscriptionsRequest request,
  std::function<void(ua::Result<ua::DeleteSubscriptionsResponse>)> callback)
{
  mSession.subscriptions().delete_subscriptions_async(std::move(request), std::move(callback));
}

void RealSessionOps::delete_monitored_items_async(ua::DeleteMonitoredItemsRequest request,
  std::function<void(ua::Result<ua::DeleteMonitoredItemsResponse>)> callback)
{
  mSession.monitored_items().delete_monitored_items_async(std::move(request), std::move(callback));
}

void RealSessionOps::modify_subscription_async(ua::ModifySubscriptionRequest request,
  std::function<void(ua::Result<ua::ModifySubscriptionResponse>)> callback)
{
  mSession.subscriptions().modify_subscription_async(std::move(request), std::move(callback));
}

void RealSessionOps::set_publishing_mode_async(ua::SetPublishingModeRequest request,
  std::function<void(ua::Result<ua::SetPublishingModeResponse>)> callback)
{
  mSession.subscriptions().set_publishing_mode_async(std::move(request), std::move(callback));
}

void RealSessionOps::transfer_subscriptions_async(ua::TransferSubscriptionsRequest request,
  std::function<void(ua::Result<ua::TransferSubscriptionsResponse>)> callback) noexcept
{
  mSession.subscriptions().transfer_subscriptions_async(std::move(request), std::move(callback));
}

void RealSessionOps::activate_on_channel_async(std::shared_ptr<ChannelOps> channel,
  ua::client::Session::ActivateConfig config, std::function<void(ua::VoidResult)> callback)
{
  // The reconnect happy path rebinds the existing session onto a freshly-opened channel. The channel
  // MUST be a RealChannelOps (production only ever pairs the two); a null cast is a defensive mispair.
  auto* realChannel = dynamic_cast<RealChannelOps*>(channel.get());
  if (realChannel == nullptr)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState});
    return;
  }
  // MOVE the inner tier-0 channel into activate_async (the session takes ownership). This flips the
  // RealChannelOps' is_open() to false - the consumed-channel invariant the reconnect logic relies on.
  mSession.activate_async(std::move(realChannel->mChannel), std::move(config), std::move(callback));
}

void RealSessionOps::activate_on_bound_channel_async(
  ua::client::Session::ActivateConfig config, std::function<void(ua::VoidResult)> callback)
{
  mSession.activate_async(std::move(config), std::move(callback));
}

void RealSessionOps::close_async(std::function<void(ua::VoidResult)> callback)
{
  mSession.close_async(std::move(callback));
}

ua::NodeId RealSessionOps::session_id() const
{
  return mSession.session_id();
}

double RealSessionOps::revised_session_timeout_ms() const
{
  return mSession.revised_session_timeout_ms();
}

RealChannelOps::RealChannelOps(ua::client::SecureChannel channel) : mChannel(std::move(channel))
{}

void RealChannelOps::create_session_async(ua::client::SecureChannel::CreateSessionConfig config,
  std::function<void(ua::Result<std::shared_ptr<SessionOps>>)> callback)
{
  mChannel.create_session_async(std::move(config),
    [callback = std::move(callback)](ua::client::SecureChannel::SessionResult sessionResult) mutable
    {
      if (!sessionResult.has_value())
      {
        callback(ua::Result<std::shared_ptr<SessionOps>>{sessionResult.status_code()});
        return;
      }
      const ua::StatusCode status = sessionResult.status_code();
      std::shared_ptr<SessionOps> ops = std::make_shared<RealSessionOps>(std::move(sessionResult).value());
      callback(ua::detail::held(std::move(ops), status));
    });
}

void RealChannelOps::get_endpoints_async(
  ua::GetEndpointsRequest request, std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback)
{
  mChannel.get_endpoints_async(std::move(request), std::move(callback));
}

void RealChannelOps::close_async(std::function<void(ua::VoidResult)> callback)
{
  mChannel.close_async(std::move(callback));
}

bool RealChannelOps::is_open() const
{
  return mChannel.is_open();
}

ReopenChannelOps make_real_reopen(ReopenChannel userReopen)
{
  return [userReopen = std::move(userReopen)](
           std::function<void(ua::Result<std::shared_ptr<ChannelOps>>)> yield) mutable
  {
    userReopen(
      [yield = std::move(yield)](ua::Result<ua::client::SecureChannel> channelResult) mutable
      {
        if (!channelResult.has_value())
        {
          yield(ua::Result<std::shared_ptr<ChannelOps>>{channelResult.status_code()});
          return;
        }
        const ua::StatusCode status = channelResult.status_code();
        std::shared_ptr<ChannelOps> ops = std::make_shared<RealChannelOps>(std::move(channelResult).value());
        yield(ua::detail::held(std::move(ops), status));
      });
  };
}

}  // namespace ua::client::detail
