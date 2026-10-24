// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the data-change @ref ua::client::detail::MonitoredItemOwner (client design
/// section 7.4).

#include "ua_data_change_monitored_item_owner.h"

#include "ua_connection_impl.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_error_detail.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitoring_parameters.h"
#include "ua_set_monitoring_mode_request.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_status.h"

#include <utility>

namespace ua::client::detail
{

namespace
{

/// The `Bad_SubscriptionIdInvalid` a self-action completes with on a routing-registry MISS: this owner no
/// longer knows the item's `clientHandle` (the server item was explicitly deleted / is non-recoverable).
/// section 7.4 distinguishes this from a fully-closed Connection (which yields `Bad_ConnectionClosed` below).
ua::VoidResult lookup_miss_result()
{
  return ua::VoidResult{ua::StatusCode{ua::Status::BadSubscriptionIdInvalid},
    ua::make_error_detail("BadSubscriptionIdInvalid",
      "MonitoredItem self-action found no live server item for its clientHandle",
      "client.tier1.data_change_owner.lookup_miss")};
}

/// The `Bad_ConnectionClosed` a self-action completes with when the back-lock to the owning Connection fails
///  -  the owner only dies with its `ConnectionImpl`, so a failed lock IS a fully-closed Connection
///  (section 7.4,
/// distinct from a routing-registry miss above).
ua::VoidResult connection_gone_result()
{
  return ua::VoidResult{ua::StatusCode{ua::Status::BadConnectionClosed},
    ua::make_error_detail("BadConnectionClosed",
      "MonitoredItem self-action could not reach its Connection (the Connection is closed)",
      "client.tier1.data_change_owner.connection_gone")};
}

/// Flattens a service response carrying a single per-item `StatusCode` result (Delete / SetMonitoringMode)
/// into a @ref ua::VoidResult, preserving the downstream @ref ua::ErrorDetail (never re-wraps). The result
/// carries the ServiceResult and the item's code combined, so a Good subcode or an Uncertain code on either
/// reaches the caller.
template<class Response>
ua::VoidResult flatten_status_result(ua::Result<Response> result)
{
  if (!result.has_value())
  {
    return ua::VoidResult{result.status_code(), result.shared_detail()};
  }
  const auto& response = result.value();
  const auto serviceResult =
    ua::detail::combined_status(result.status_code(), response.response_header().service_result());
  if (serviceResult.is_bad())
  {
    return ua::VoidResult{serviceResult};
  }
  if (response.results().size() == 0)
  {
    return ua::VoidResult{ua::StatusCode{ua::Status::BadUnexpectedError}};
  }
  return ua::VoidResult{ua::detail::combined_status(serviceResult, response.results()[0])};
}

}  // namespace

std::shared_ptr<DataChangeMonitoredItemOwner> DataChangeMonitoredItemOwner::create(
  std::weak_ptr<ConnectionImpl> connection)
{
  return std::shared_ptr<DataChangeMonitoredItemOwner>(
    new DataChangeMonitoredItemOwner(std::move(connection)));
}

DataChangeMonitoredItemOwner::DataChangeMonitoredItemOwner(std::weak_ptr<ConnectionImpl> connection)
  : mConnection(std::move(connection))
{}

void DataChangeMonitoredItemOwner::register_item(std::uint32_t clientHandle, std::uint32_t subscriptionId,
  std::uint32_t monitoredItemId, std::shared_ptr<MonitoredItemState> state) noexcept
{
  std::lock_guard<std::mutex> lock(mMutex);
  mRouting[clientHandle] = Routing{subscriptionId, monitoredItemId, std::move(state)};
}

boost::asio::any_io_executor DataChangeMonitoredItemOwner::executor() const noexcept
{
  const auto connection = mConnection.lock();
  return connection ? connection->executor() : boost::asio::any_io_executor{};
}

void DataChangeMonitoredItemOwner::unregister_item(std::uint32_t clientHandle) noexcept
{
  std::lock_guard<std::mutex> lock(mMutex);
  mRouting.erase(clientHandle);
}

void DataChangeMonitoredItemOwner::unregister_subscription(std::uint32_t subscriptionId) noexcept
{
  // Purge every routing entry the closed Subscription owned in one pass (WARNING 3): otherwise a
  // DeleteSubscriptions success leaves the items' owner-routing entries behind (unbounded growth, and a
  // server-id-reuse mis-route hazard). Takes mMutex once for the whole purge.
  std::lock_guard<std::mutex> lock(mMutex);
  for (auto it = mRouting.begin(); it != mRouting.end();)
  {
    if (it->second.subscriptionId == subscriptionId)
    {
      it = mRouting.erase(it);
    }
    else
    {
      ++it;
    }
  }
}

void DataChangeMonitoredItemOwner::rekey_items(const std::vector<ItemRekey>& rekeys) noexcept
{
  // Apply the whole session-CHANGED recreate batch atomically (CRITICAL 1): each preserved clientHandle is
  // repointed to its NEW {subscriptionId, monitoredItemId} so subsequent self-actions target the recreated
  // server item, not the stale ids. One mMutex acquisition for the batch.
  std::lock_guard<std::mutex> lock(mMutex);
  for (const auto& rekey : rekeys)
  {
    // Repoint the ids IN PLACE so the shared MonitoredItemState (held by the handle + its copies) SURVIVES
    // the re-key  -  a reconnect-recreated item keeps its handle's revised-value state (refreshing those
    // values from the recreate response is the batched follow-up; the state object must not be dropped here).
    auto& routing = mRouting[rekey.clientHandle];
    routing.subscriptionId = rekey.subscriptionId;
    routing.monitoredItemId = rekey.monitoredItemId;
  }
}

std::optional<DataChangeMonitoredItemOwner::Routing> DataChangeMonitoredItemOwner::lookup(
  std::uint32_t clientHandle) const noexcept
{
  std::lock_guard<std::mutex> lock(mMutex);
  const auto it = mRouting.find(clientHandle);
  if (it == mRouting.end())
  {
    return std::nullopt;
  }
  return it->second;
}

std::optional<std::uint32_t> DataChangeMonitoredItemOwner::server_item_id(
  std::uint32_t clientHandle) const noexcept
{
  const auto routing = lookup(clientHandle);
  return routing ? std::optional<std::uint32_t>{routing->monitoredItemId} : std::nullopt;
}

std::optional<std::uint32_t> DataChangeMonitoredItemOwner::subscription_of(
  std::uint32_t clientHandle) const noexcept
{
  const auto routing = lookup(clientHandle);
  return routing ? std::optional<std::uint32_t>{routing->subscriptionId} : std::nullopt;
}

void DataChangeMonitoredItemOwner::mi_modify_async(
  MonitoredItemId clientHandle, MonitorRequest request, std::function<void(ua::VoidResult)> callback) noexcept
{
  const auto routing = lookup(clientHandle);
  if (!routing)
  {
    callback(lookup_miss_result());
    return;
  }
  auto connection = mConnection.lock();
  if (!connection)
  {
    callback(connection_gone_result());
    return;
  }

  const bool discardOldest = request.discardOldest;

  ua::MonitoringParameters parameters;
  parameters.client_handle() = clientHandle;
  parameters.sampling_interval() = request.samplingIntervalMs;
  parameters.queue_size() = request.queueSize.value_or(1);
  parameters.discard_oldest() = discardOldest;
  // NOTE: the DataChangeFilter/AggregateFilter variant is not yet plumbed onto the wire MonitoringParameters
  // (a ConnectionImpl-richness follow-up); modify carries the sampling/queue changes today.

  ua::MonitoredItemModifyRequest itemToModify;
  itemToModify.monitored_item_id() = routing->monitoredItemId;
  itemToModify.requested_parameters() = std::move(parameters);

  ua::ModifyMonitoredItemsRequest modifyRequest;
  modifyRequest.subscription_id() = routing->subscriptionId;
  modifyRequest.timestamps_to_return() = ua::TimestampsToReturn::Both;
  modifyRequest.items_to_modify().push_back(std::move(itemToModify));

  connection->modify_monitored_items_async(std::move(modifyRequest),
    [state = routing->state, discardOldest, callback = std::move(callback)](
      ua::Result<ua::ModifyMonitoredItemsResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::VoidResult{result.status_code(), result.shared_detail()});
        return;
      }
      const auto& response = result.value();
      const auto serviceResult =
        ua::detail::combined_status(result.status_code(), response.response_header().service_result());
      if (serviceResult.is_bad())
      {
        callback(ua::VoidResult{serviceResult});
        return;
      }
      if (response.results().size() == 0)
      {
        callback(ua::VoidResult{ua::StatusCode{ua::Status::BadUnexpectedError}});
        return;
      }
      const auto& itemResult = response.results()[0];
      if (itemResult.status_code().is_bad())
      {
        // A bad modify must NOT touch the shared state  -  the handle keeps its create-time revised snapshot.
        callback(ua::VoidResult{itemResult.status_code()});
        return;
      }
      // SUCCESS: refresh the shared state so this item's handle (and every copy) surfaces the server's
      // revised sampling interval / queue size + the applied discardOldest (D5, CL-MI-019/020). Runs on the
      // executor; handle accessors read via atomics from any thread, so no torn read (strand_components Rule
      // 3). An Uncertain answer holds the revised values the caller receives, so it refreshes the state as a
      // Good one does.
      const ua::StatusCode code = ua::detail::combined_status(serviceResult, itemResult.status_code());
      if (state)
      {
        state->revisedSamplingIntervalMs.store(itemResult.revised_sampling_interval());
        state->revisedQueueSize.store(itemResult.revised_queue_size());
        state->discardOldest.store(discardOldest);
      }
      // A Good subcode or an Uncertain code on the ServiceResult or the item's result reaches the caller.
      callback(ua::VoidResult{code});
    });
}

void DataChangeMonitoredItemOwner::mi_set_mode_async(MonitoredItemId clientHandle, ua::MonitoringMode mode,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  const auto routing = lookup(clientHandle);
  if (!routing)
  {
    callback(lookup_miss_result());
    return;
  }
  auto connection = mConnection.lock();
  if (!connection)
  {
    callback(connection_gone_result());
    return;
  }

  ua::SetMonitoringModeRequest request;
  request.subscription_id() = routing->subscriptionId;
  request.monitoring_mode() = mode;
  request.monitored_item_ids().push_back(routing->monitoredItemId);

  connection->set_monitoring_mode_async(std::move(request),
    [state = routing->state, mode, callback = std::move(callback)](
      ua::Result<ua::SetMonitoringModeResponse> result) mutable
    {
      const bool answered = result.has_value();
      ua::VoidResult flattened = flatten_status_result(std::move(result));
      // SUCCESS-gated (like modify): a Good answer, or an Uncertain one holding the item's result, updates
      // the shared mode so the handle (and copies) reflect the APPLIED mode (CL-MI-021); a bad set-mode, or
      // an Uncertain answer without a response, leaves the prior mode intact. Executor thread; atomic store
      // read cross-thread by the handle accessor.
      if (answered && !flattened.is_bad() && state)
      {
        state->mode.store(mode);
      }
      callback(std::move(flattened));
    });
}

void DataChangeMonitoredItemOwner::mi_delete_async(
  MonitoredItemId clientHandle, std::function<void(ua::VoidResult)> callback) noexcept
{
  const auto routing = lookup(clientHandle);
  if (!routing)
  {
    callback(lookup_miss_result());
    return;
  }
  auto connection = mConnection.lock();
  if (!connection)
  {
    callback(connection_gone_result());
    return;
  }

  auto self = shared_from_this();
  connection->delete_monitored_item_async(routing->subscriptionId,
    routing->monitoredItemId,
    clientHandle,
    [self, clientHandle, callback = std::move(callback)](
      ua::Result<ua::DeleteMonitoredItemsResponse> result) mutable
    {
      // The item is gone once the server answers its delete Good or Uncertain; an Uncertain answer without a
      // response leaves it registered.
      const bool answered = result.has_value();
      ua::VoidResult flattened = flatten_status_result(std::move(result));
      if (answered && !flattened.is_bad())
      {
        self->unregister_item(clientHandle);
      }
      callback(std::move(flattened));
    });
}

}  // namespace ua::client::detail
