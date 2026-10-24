// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the tier-1 public @ref ua::client::Subscription handle (client design
/// section 7.4).

#include "ua_client_subscription.h"

#include "ua_sync_wait.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_connection_impl.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_error_detail.h"
#include "ua_method_id.h"
#include "ua_modify_subscription_response.h"
#include "ua_object_id.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_status.h"
#include "ua_variant.h"

#include <atomic>
#include <memory>
#include <utility>

namespace ua::client
{

namespace detail
{

/// The client-side per-Subscription state a @ref Subscription handle owns (shared_ptr pimpl). Owned by the
/// handle; the reconnect-surviving server state lives in the `SubscriptionsPipeline` (section 8.4).
struct SubscriptionImpl
{
  std::shared_ptr<ConnectionImpl> connection;
  // The server's id for this Subscription, in a shared atomic cell rather than a plain member: a
  // session-CHANGED reconnect RECREATES the Subscription under a new id, and the connection holds a
  // weak reference to this cell so it can carry the handle forward with everything else it re-keys.
  std::shared_ptr<std::atomic<std::uint32_t>> serverSubscriptionId =
    std::make_shared<std::atomic<std::uint32_t>>(0);
  // The server-REVISED publishing interval. Mutable + atomic (like publishingEnabled): create records the
  // create-time revised value; a Good modify updates it to the modify-time revised value (CL-SUB-011). Shared
  // across handle copies via the pimpl, so every copy of the Subscription observes the current cadence.
  std::atomic<double> publishingInterval{0.0};
  std::atomic<bool> publishingEnabled{true};
  std::atomic<std::size_t> itemCount{0};
};

Subscription SubscriptionFactory::create(std::shared_ptr<ConnectionImpl> connection,
  std::uint32_t subscriptionId, double publishingInterval, bool publishingEnabled)
{
  auto impl = std::make_shared<SubscriptionImpl>();
  impl->connection = std::move(connection);
  impl->serverSubscriptionId->store(subscriptionId, std::memory_order_relaxed);
  impl->connection->register_subscription_id_cell(impl->serverSubscriptionId);
  impl->publishingInterval.store(publishingInterval);
  impl->publishingEnabled.store(publishingEnabled);
  return Subscription{std::move(impl)};
}

}  // namespace detail

namespace
{

using ua::Result;
using ua::Status;
using ua::VoidResult;

/// The status a call completes with on a moved-from / detached handle (null pimpl).
constexpr ua::Status detachedStatus = ua::Status::BadInvalidState;
constexpr std::string_view getMonitoredItemsSource = "client.tier1.subscription.get_monitored_items";
constexpr std::string_view resendDataSource = "client.tier1.subscription.resend_data";

VoidResult detached_result()
{
  return VoidResult{ua::StatusCode{detachedStatus},
    ua::make_error_detail("BadInvalidState",
      "Subscription handle is detached (moved-from / null)",
      "client.tier1.subscription.detached")};
}

/// The @ref SetTriggeringResult-typed detached completion (moved-from / null handle), mirroring
/// @ref detached_result but carried in the SetTriggering per-link Result type (CL-MI-029).
Result<SetTriggeringResult> detached_triggering_result()
{
  return Result<SetTriggeringResult>{ua::StatusCode{detachedStatus},
    ua::make_error_detail("BadInvalidState",
      "Subscription handle is detached (moved-from / null)",
      "client.tier1.subscription.detached")};
}

Result<MonitoredItemHandles> detached_monitored_items_result()
{
  return Result<MonitoredItemHandles>{ua::StatusCode{detachedStatus},
    ua::make_error_detail("BadInvalidState",
      "Subscription handle is detached (moved-from / null)",
      "client.tier1.subscription.detached")};
}

/// Flattens a response carrying a `response_header().service_result()` and a single per-item `StatusCode`
/// result (SetPublishingMode / DeleteSubscriptions) into a @ref VoidResult, preserving the ErrorDetail. The
/// result carries the ServiceResult and the item's code combined, so a Good subcode or an Uncertain code
/// on either reaches the caller.
template<class Response>
VoidResult flatten_status_result(Result<Response> result)
{
  if (!result.has_value())
  {
    return VoidResult{result.status_code(), result.shared_detail()};
  }
  const auto& response = result.value();
  const auto serviceResult =
    ua::detail::combined_status(result.status_code(), response.response_header().service_result());
  if (serviceResult.is_bad())
  {
    return VoidResult{serviceResult};
  }
  if (response.results().size() == 0)
  {
    return VoidResult{ua::StatusCode{Status::BadUnexpectedError}};
  }
  return VoidResult{ua::detail::combined_status(serviceResult, response.results()[0])};
}

/// State threaded through the sequential bulk-monitor create (v1: one CreateMonitoredItems per item).
struct BulkMonitorState
{
  std::shared_ptr<detail::SubscriptionImpl> impl;
  std::vector<MonitorRequest> requests;
  DataChangeCallback onData;
  std::vector<MonitoredItemResult> results;
  std::size_t next = 0;
  std::function<void(Subscription::BulkMonitorResult)> callback;
};

void bulk_monitor_step(std::shared_ptr<BulkMonitorState> state)
{
  if (state->next >= state->requests.size())
  {
    auto callback = std::move(state->callback);
    callback(Subscription::BulkMonitorResult{std::move(state->results)});
    return;
  }
  auto request = state->requests[state->next];
  auto onData = state->onData;
  auto& connection = state->impl->connection;
  connection->monitor_data_change_async(state->impl->serverSubscriptionId->load(std::memory_order_relaxed),
    std::move(request),
    std::move(onData),
    [state](MonitoredItemResult result) mutable
    {
      // A monitor created with a Good subcode or an Uncertain code exists on the server.
      if (result.has_value())
      {
        state->impl->itemCount.fetch_add(1);
      }
      state->results.push_back(std::move(result));
      ++state->next;
      bulk_monitor_step(state);
    });
}

}  // namespace

// --- Item lifecycle ---

void Subscription::monitor_async(MonitorRequest request, DataChangeCallback onData,
  std::function<void(MonitoredItemResult)> callback) noexcept
{
  if (!mImpl || !mImpl->connection)
  {
    callback(MonitoredItemResult{ua::StatusCode{detachedStatus}});
    return;
  }
  auto impl = mImpl;
  impl->connection->monitor_data_change_async(impl->serverSubscriptionId->load(std::memory_order_relaxed),
    std::move(request),
    std::move(onData),
    [impl, callback = std::move(callback)](MonitoredItemResult result) mutable
    {
      // A monitor created with a Good subcode or an Uncertain code exists on the server.
      if (result.has_value())
      {
        impl->itemCount.fetch_add(1);
      }
      callback(std::move(result));
    });
}

MonitoredItem Subscription::monitor_sync(MonitorRequest request, DataChangeCallback onData)
{
  return ua::detail::good_value(try_monitor_sync(std::move(request), std::move(onData)));
}

MonitoredItemResult Subscription::try_monitor_sync(MonitorRequest request, DataChangeCallback onData) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MonitoredItem>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request), onData = std::move(onData)](auto completion) mutable
    { monitor_async(std::move(request), std::move(onData), std::move(completion)); });
}

void Subscription::monitor_event_async(EventMonitorRequest /*request*/, EventCallback /*onEvent*/,
  std::function<void(MonitoredItemResult)> callback) noexcept
{
  // DEFERRED to Slice 10a: the event-consumer MonitoredItemOwner (EventSubscriberImpl, section 8.13) that
  // demuxes EventNotificationList and recomputes the composite EventFilter is not built here. Surface the API
  // and fail explicitly so a caller is never silently left without notifications.
  callback(MonitoredItemResult{ua::StatusCode{Status::BadNotSupported},
    ua::make_error_detail("BadNotSupported",
      "event monitors are delivered by the tier-2 EventSubscriber (Slice 10a); not yet wired",
      "client.tier1.subscription.monitor_event.deferred_s10a")});
}

MonitoredItem Subscription::monitor_event_sync(EventMonitorRequest request, EventCallback onEvent)
{
  return ua::detail::good_value(try_monitor_event_sync(std::move(request), std::move(onEvent)));
}

MonitoredItemResult Subscription::try_monitor_event_sync(
  EventMonitorRequest request, EventCallback onEvent) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MonitoredItem>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request), onEvent = std::move(onEvent)](auto completion) mutable
    { monitor_event_async(std::move(request), std::move(onEvent), std::move(completion)); });
}

void Subscription::monitor_many_async(std::vector<MonitorRequest> requests, DataChangeCallback onData,
  std::function<void(BulkMonitorResult)> callback) noexcept
{
  if (!mImpl || !mImpl->connection)
  {
    callback(BulkMonitorResult{ua::StatusCode{detachedStatus}});
    return;
  }
  auto state = std::make_shared<BulkMonitorState>();
  state->impl = mImpl;
  state->requests = std::move(requests);
  state->onData = std::move(onData);
  state->results.reserve(state->requests.size());
  state->callback = std::move(callback);
  bulk_monitor_step(std::move(state));
}

std::vector<MonitoredItemResult> Subscription::monitor_many_sync(
  std::vector<MonitorRequest> requests, DataChangeCallback onData)
{
  return ua::detail::good_value(try_monitor_many_sync(std::move(requests), std::move(onData)));
}

Subscription::BulkMonitorResult Subscription::try_monitor_many_sync(
  std::vector<MonitorRequest> requests, DataChangeCallback onData) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<MonitoredItemResult>>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this, requests = std::move(requests), onData = std::move(onData)](auto completion) mutable
    { monitor_many_async(std::move(requests), std::move(onData), std::move(completion)); });
}

// --- Triggering (T18) ---

void Subscription::set_triggering_async(MonitoredItem trigger, std::vector<MonitoredItem> linksToAdd,
  std::vector<MonitoredItem> linksToRemove,
  std::function<void(ua::Result<SetTriggeringResult>)> callback) noexcept
{
  if (!mImpl || !mImpl->connection)
  {
    callback(detached_triggering_result());
    return;
  }
  std::vector<std::uint32_t> addHandles;
  addHandles.reserve(linksToAdd.size());
  for (const auto& item : linksToAdd)
  {
    addHandles.push_back(item.client_handle());
  }
  std::vector<std::uint32_t> removeHandles;
  removeHandles.reserve(linksToRemove.size());
  for (const auto& item : linksToRemove)
  {
    removeHandles.push_back(item.client_handle());
  }
  mImpl->connection->set_triggering_by_handles_async(
    mImpl->serverSubscriptionId->load(std::memory_order_relaxed),
    trigger.client_handle(),
    std::move(addHandles),
    std::move(removeHandles),
    std::move(callback));
}

SetTriggeringResult Subscription::set_triggering_sync(const MonitoredItem& trigger,
  const std::vector<MonitoredItem>& linksToAdd, const std::vector<MonitoredItem>& linksToRemove)
{
  return ua::detail::good_value(try_set_triggering_sync(trigger, linksToAdd, linksToRemove));
}

ua::Result<SetTriggeringResult> Subscription::try_set_triggering_sync(const MonitoredItem& trigger,
  const std::vector<MonitoredItem>& linksToAdd, const std::vector<MonitoredItem>& linksToRemove) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<SetTriggeringResult>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this, trigger, linksToAdd, linksToRemove](auto completion)
    { set_triggering_async(trigger, linksToAdd, linksToRemove, std::move(completion)); });
}

// --- Server-object methods ---

void Subscription::get_monitored_items_async(
  std::function<void(ua::Result<MonitoredItemHandles>)> callback) noexcept
{
  if (!mImpl || !mImpl->connection)
  {
    callback(detached_monitored_items_result());
    return;
  }

  ua::CallMethodRequest method;
  method.object_id() = ua::NodeId{ua::ObjectId::Server};
  method.method_id() = ua::NodeId{ua::MethodId::Server_GetMonitoredItems};
  method.input_arguments().push_back(
    ua::Variant{mImpl->serverSubscriptionId->load(std::memory_order_relaxed)});
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(method));

  auto impl = mImpl;
  impl->connection->call_async(std::move(request),
    [impl = std::move(impl), callback = std::move(callback)](ua::Result<ua::CallResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::Result<MonitoredItemHandles>{result.status_code(), result.shared_detail()});
        return;
      }
      const auto serviceStatus =
        ua::detail::combined_status(result.status_code(), result.value().response_header().service_result());
      if (serviceStatus.is_bad())
      {
        callback(ua::Result<MonitoredItemHandles>{serviceStatus});
        return;
      }
      if (result.value().results().size() != 1)
      {
        callback(ua::Result<MonitoredItemHandles>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("GetMonitoredItemsResultCountMismatch",
            "GetMonitoredItems returned an unexpected number of method results",
            std::string{getMonitoredItemsSource})});
        return;
      }
      const auto& methodResult = result.value().results()[0];
      if (methodResult.status_code().is_bad())
      {
        callback(ua::Result<MonitoredItemHandles>{methodResult.status_code(),
          ua::ErrorDetail::build("GetMonitoredItemsMethodFailed",
            "Server.GetMonitoredItems returned a bad method status",
            std::string{getMonitoredItemsSource})
            .context(
              ua::ContextKeys::subscriptionId, impl->serverSubscriptionId->load(std::memory_order_relaxed))
            .cause(methodResult.status_code())});
        return;
      }
      if (methodResult.output_arguments().size() != 2)
      {
        callback(ua::Result<MonitoredItemHandles>{ua::Status::BadDecodingError,
          ua::make_error_detail("GetMonitoredItemsOutputCountMismatch",
            "Server.GetMonitoredItems did not return two output arrays",
            std::string{getMonitoredItemsSource})});
        return;
      }

      auto serverHandles = methodResult.output_arguments()[0].to_vector<std::uint32_t>();
      auto clientHandles = methodResult.output_arguments()[1].to_vector<std::uint32_t>();
      if (serverHandles.is_bad() || clientHandles.is_bad())
      {
        const auto cause = serverHandles.is_bad() ? serverHandles.status_code() : clientHandles.status_code();
        callback(ua::Result<MonitoredItemHandles>{ua::Status::BadDecodingError,
          ua::ErrorDetail::build("GetMonitoredItemsOutputTypeMismatch",
            "Server.GetMonitoredItems output arguments were not UInt32 arrays",
            std::string{getMonitoredItemsSource})
            .context(
              ua::ContextKeys::subscriptionId, impl->serverSubscriptionId->load(std::memory_order_relaxed))
            .cause(cause)});
        return;
      }
      if (serverHandles.value().size() != clientHandles.value().size())
      {
        callback(ua::Result<MonitoredItemHandles>{ua::Status::BadDecodingError,
          ua::ErrorDetail::build("GetMonitoredItemsArrayLengthMismatch",
            "Server.GetMonitoredItems returned handle arrays with different lengths",
            std::string{getMonitoredItemsSource})
            .context(ua::ContextKeys::sizeExpected, serverHandles.value().size())
            .context(ua::ContextKeys::sizeActual, clientHandles.value().size())});
        return;
      }
      MonitoredItemHandles handles;
      handles.serverHandles = std::move(serverHandles).value();
      handles.clientHandles = std::move(clientHandles).value();
      // A Good subcode or an Uncertain code on the ServiceResult or the method's status reaches the caller.
      callback(ua::detail::held(
        std::move(handles), ua::detail::combined_status(serviceStatus, methodResult.status_code())));
    });
}

MonitoredItemHandles Subscription::get_monitored_items_sync()
{
  return ua::detail::good_value(try_get_monitored_items_sync());
}

ua::Result<MonitoredItemHandles> Subscription::try_get_monitored_items_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MonitoredItemHandles>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this](auto completion) { get_monitored_items_async(std::move(completion)); });
}

void Subscription::resend_data_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl || !mImpl->connection)
  {
    callback(detached_result());
    return;
  }

  ua::CallMethodRequest method;
  method.object_id() = ua::NodeId{ua::ObjectId::Server};
  method.method_id() = ua::NodeId{ua::MethodId::Server_ResendData};
  method.input_arguments().push_back(
    ua::Variant{mImpl->serverSubscriptionId->load(std::memory_order_relaxed)});
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(method));

  auto impl = mImpl;
  impl->connection->call_async(std::move(request),
    [impl = std::move(impl), callback = std::move(callback)](ua::Result<ua::CallResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::VoidResult{result.status_code(), result.shared_detail()});
        return;
      }
      const auto serviceStatus =
        ua::detail::combined_status(result.status_code(), result.value().response_header().service_result());
      if (serviceStatus.is_bad())
      {
        callback(ua::VoidResult{serviceStatus});
        return;
      }
      if (result.value().results().size() != 1)
      {
        callback(ua::VoidResult{ua::Status::BadUnexpectedError,
          ua::make_error_detail("ResendDataResultCountMismatch",
            "ResendData returned an unexpected number of method results",
            std::string{resendDataSource})});
        return;
      }
      const auto methodStatus = result.value().results()[0].status_code();
      if (methodStatus.is_bad())
      {
        callback(ua::VoidResult{methodStatus,
          ua::ErrorDetail::build("ResendDataMethodFailed",
            "Server.ResendData returned a bad method status",
            std::string{resendDataSource})
            .context(
              ua::ContextKeys::subscriptionId, impl->serverSubscriptionId->load(std::memory_order_relaxed))
            .cause(methodStatus)});
        return;
      }
      // A Good subcode or an Uncertain code on the ServiceResult or the method's status reaches the caller.
      callback(ua::VoidResult{ua::detail::combined_status(serviceStatus, methodStatus)});
    });
}

void Subscription::resend_data_sync()
{
  try_resend_data_sync().value();
}

ua::VoidResult Subscription::try_resend_data_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this](auto completion) { resend_data_async(std::move(completion)); });
}

// --- Subscription lifecycle ---

void Subscription::modify_async(
  SubscriptionModifyConfig config, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl || !mImpl->connection)
  {
    callback(detached_result());
    return;
  }
  auto impl = mImpl;
  // ModifySubscription replaces the whole parameter set (OPC 10000-4 5.13.3.1), so a field the caller leaves
  // unset must be re-sent from the retained tuning rather than defaulted. The optionals are passed through
  // rather than resolved here: the retained values are owned by the connection strand.
  impl->connection->modify_subscription_async(impl->serverSubscriptionId->load(std::memory_order_relaxed),
    config.publishingIntervalMs,
    config.lifetimeCount,
    config.maxKeepAliveCount,
    config.priority,
    config.maxNotificationsPerPublish,
    [impl, callback = std::move(callback)](Result<ua::ModifySubscriptionResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(VoidResult{result.status_code(), result.shared_detail()});
        return;
      }
      const auto& response = result.value();
      // CL-SUB-013: surface Bad_SubscriptionIdInvalid from the service result without retrying (post
      // CL-DIAG-005 the funnel already collapses a bad service_result to a bad Result above; this is a
      // defensive guard).
      const auto serviceResult =
        ua::detail::combined_status(result.status_code(), response.response_header().service_result());
      if (serviceResult.is_bad())
      {
        callback(VoidResult{serviceResult});
        return;
      }
      // CL-SUB-011: record the server-REVISED publishing interval so publishing_interval() reflects the
      // current cadence, not the create-time or the requested value. A failed modify does not change the
      // snapshot; an Uncertain answer holds the revised interval the caller receives, so it is recorded.
      impl->publishingInterval.store(response.revised_publishing_interval());
      // A Good subcode or an Uncertain ServiceResult reaches the caller.
      callback(VoidResult{serviceResult});
    });
}

void Subscription::modify_sync(SubscriptionModifyConfig config)
{
  try_modify_sync(std::move(config)).value();
}

ua::VoidResult Subscription::try_modify_sync(SubscriptionModifyConfig config) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this, config = std::move(config)](auto completion) mutable
    { modify_async(std::move(config), std::move(completion)); });
}

void Subscription::set_publishing_mode_async(
  bool enabled, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl || !mImpl->connection)
  {
    callback(detached_result());
    return;
  }
  auto impl = mImpl;
  impl->connection->set_publishing_mode_async(impl->serverSubscriptionId->load(std::memory_order_relaxed),
    enabled,
    [impl, enabled, callback = std::move(callback)](Result<ua::SetPublishingModeResponse> result) mutable
    {
      // CL-SUB-014: SetPublishingMode results are per-Subscription; honour results[0] even when service-level
      // is Good.
      // A Good answer, or an Uncertain one holding the Subscription's result, applies the mode; an Uncertain
      // answer without a response leaves it.
      const bool answered = result.has_value();
      VoidResult flattened = flatten_status_result(std::move(result));
      if (answered && !flattened.is_bad())
      {
        impl->publishingEnabled.store(enabled);
      }
      callback(std::move(flattened));
    });
}

void Subscription::set_publishing_mode_sync(bool enabled)
{
  try_set_publishing_mode_sync(enabled).value();
}

ua::VoidResult Subscription::try_set_publishing_mode_sync(bool enabled) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this, enabled](auto completion) { set_publishing_mode_async(enabled, std::move(completion)); });
}

void Subscription::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl || !mImpl->connection)
  {
    callback(detached_result());
    return;
  }
  mImpl->connection->delete_subscription_async(mImpl->serverSubscriptionId->load(std::memory_order_relaxed),
    [callback = std::move(callback)](Result<ua::DeleteSubscriptionsResponse> result) mutable
    { callback(flatten_status_result(std::move(result))); });
}

void Subscription::close_sync()
{
  try_close_sync().value();
}

ua::VoidResult Subscription::try_close_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl && mImpl->connection ? mImpl->connection->executor() : boost::asio::any_io_executor{}),
    [this](auto completion) { close_async(std::move(completion)); });
}

// --- Queries ---

ua::IntegerId Subscription::server_subscription_id() const noexcept
{
  return mImpl ? mImpl->serverSubscriptionId->load(std::memory_order_relaxed) : 0;
}

ua::Duration Subscription::publishing_interval() const noexcept
{
  return mImpl ? mImpl->publishingInterval.load() : 0.0;
}

bool Subscription::is_publishing_enabled() const noexcept
{
  return mImpl ? mImpl->publishingEnabled.load() : false;
}

std::size_t Subscription::item_count() const noexcept
{
  return mImpl ? mImpl->itemCount.load() : 0;
}

}  // namespace ua::client
