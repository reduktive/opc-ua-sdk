// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_connection_ops.h"

#include "ua_connection_impl.h"
#include "ua_error_detail.h"
#include "ua_namespace_table.h"
#include "ua_status.h"

#include <boost/asio/post.hpp>

#include <string>
#include <utility>
#include "ua_on_strand.h"

namespace ua::client::detail
{

namespace
{
/// Source tag for the manufactured connection-gone boundary failure (the design specification).
constexpr std::string_view connectionGoneSource = "client.tier1.connection_ops_shim.connection_gone";

/// Completes @p callback on @p executor with `Bad_ConnectionClosed` carrying a source-tagged ErrorDetail,
/// for a wire op issued after the tier-1 @ref ConnectionImpl was destroyed. Posts (never fires inline) so
/// the callback runs on the executor, never on the shim caller's thread (the design specification).
template<typename Response>
void complete_connection_gone(
  const boost::asio::any_io_executor& executor, std::function<void(ua::Result<Response>)> callback) noexcept
{
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback)]() mutable
      {
        callback(ua::Result<Response>{ua::Status::BadConnectionClosed,
          ua::make_error_detail("ConnectionGone",
            "the tier-1 Connection was destroyed before the wire operation could be dispatched",
            std::string{connectionGoneSource})});
      }));
}
}  // namespace

ConnectionOpsShim::ConnectionOpsShim(
  std::weak_ptr<ConnectionImpl> connection, boost::asio::any_io_executor executor)
  : mConnection(std::move(connection)), mExecutor(std::move(executor))
{}

// --- WireOps: forward to the already-tested ConnectionImpl public wire ops (which own the single tier-1
//     remap/wrap); a gone Connection completes the source-tagged boundary failure on the executor. ---

void ConnectionOpsShim::read_async(
  ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->read_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::ReadResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::write_async(
  ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->write_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::WriteResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::browse_async(
  ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->browse_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::BrowseResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::browse_next_async(
  ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->browse_next_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::BrowseNextResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::browse_next_on_session_async(std::uint64_t expectedSessionGeneration,
  ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->browse_next_on_session_async(
      expectedSessionGeneration, std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::BrowseNextResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
  std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->translate_browse_paths_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::TranslateBrowsePathsToNodeIdsResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::call_async(
  ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->call_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::CallResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::history_read_async(
  ua::HistoryReadRequest request, std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->history_read_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::HistoryReadResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::history_update_async(ua::HistoryUpdateRequest request,
  std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->history_update_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::HistoryUpdateResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::register_nodes_async(ua::RegisterNodesRequest request,
  std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->register_nodes_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::RegisterNodesResponse>(mExecutor, std::move(callback));
}

void ConnectionOpsShim::unregister_nodes_async(ua::UnregisterNodesRequest request,
  std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->unregister_nodes_async(std::move(request), std::move(callback));
    return;
  }
  complete_connection_gone<ua::UnregisterNodesResponse>(mExecutor, std::move(callback));
}

std::uint32_t ConnectionOpsShim::max_nodes_per_read() const noexcept
{
  if (const auto connection = mConnection.lock())
  {
    return connection->max_nodes_per_read();
  }
  // Gone Connection: the polled-Read fallback default (section 8.4, CL-SUB-020).
  return 100;
}

// --- SubscriptionOps (the send interface): forward to ConnectionImpl's strand-hopping, Active-gated,
//     epoch-guarding pipeline entries. A gone Connection drops the work (the pump simply stops). ---

void ConnectionOpsShim::send_publish(std::vector<SubscriptionAcknowledgement> acknowledgements)
{
  if (const auto connection = mConnection.lock())
  {
    connection->pipeline_send_publish(std::move(acknowledgements));
  }
}

void ConnectionOpsShim::republish(std::uint32_t subscriptionId, std::uint32_t sequenceNumber)
{
  if (const auto connection = mConnection.lock())
  {
    connection->pipeline_republish(subscriptionId, sequenceNumber);
  }
}

void ConnectionOpsShim::adjust_max_notifications_per_publish(std::uint32_t subscriptionId,
  double publishingInterval, std::uint32_t maxNotificationsPerPublish,
  std::function<void(ua::VoidResult)> callback)
{
  if (const auto connection = mConnection.lock())
  {
    connection->adjust_max_notifications_per_publish_async(
      subscriptionId, publishingInterval, maxNotificationsPerPublish, std::move(callback));
    return;
  }
  complete_connection_gone<void>(mExecutor, std::move(callback));
}

// --- SupportOps ---

std::shared_ptr<const NamespaceTable> ConnectionOpsShim::namespace_table() const
{
  if (const auto connection = mConnection.lock())
  {
    return connection->namespace_table_snapshot();
  }
  return nullptr;
}

void ConnectionOpsShim::post_to_executor(std::function<void()> work)
{
  // The executor outlives ConnectionImpl, so a user-callback hand-off is delivered whether or not the
  // Connection is still alive.
  boost::asio::post(mExecutor, ua::async::guarded(ua::Logger{}, std::move(work)));
}

ConnectionState ConnectionOpsShim::state() const
{
  if (const auto connection = mConnection.lock())
  {
    const auto info = connection->info();
    return info ? info->state : ConnectionState::Closed;
  }
  return ConnectionState::Closed;
}

// --- SupportOps: tier-2 reach-through handles (wiring section 2). Weak-upward: a gone Connection yields null
// (the
//     tier-2 consumer treats it as a gone interface and completes Bad_ConnectionClosed itself). ---

std::shared_ptr<EventSubscriberImpl> ConnectionOpsShim::event_subscriber() const
{
  if (const auto connection = mConnection.lock())
  {
    return connection->events_impl();
  }
  return nullptr;
}

std::shared_ptr<TypeResolver> ConnectionOpsShim::type_resolver() const
{
  if (const auto connection = mConnection.lock())
  {
    return connection->type_resolver();
  }
  return nullptr;
}

std::shared_ptr<SubscriptionFactoryOps> ConnectionOpsShim::subscription_factory() const
{
  if (const auto connection = mConnection.lock())
  {
    return connection->subscription_factory();
  }
  return nullptr;
}

std::shared_ptr<SemanticChangeCache> ConnectionOpsShim::semantic_change_cache() const
{
  if (const auto connection = mConnection.lock())
  {
    return connection->semantic_change_cache();
  }
  return nullptr;
}

}  // namespace ua::client::detail
