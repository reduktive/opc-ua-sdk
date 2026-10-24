// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the public @ref ua::client::EventSubscriber value handle (client design
/// section 8.13):
///        a move-only shared_ptr pimpl forwarding its consumer surface one-hop to the strand-bearing
///        @ref ua::client::detail::EventSubscriberImpl.

#include "ua_event_subscriber.h"

#include "ua_sync_wait.h"
#include "ua_error_detail.h"
#include "ua_event_subscriber_impl.h"
#include "ua_status.h"

#include <utility>

namespace ua::client
{

namespace
{

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;

SubscribeResult detached_subscribe_result()
{
  return SubscribeResult{StatusCode{Status::BadInvalidState},
    ua::make_error_detail("BadInvalidState",
      "EventSubscriber handle is detached (moved-from / null)",
      "client.tier2.event_subscriber.detached")};
}

VoidResult detached_void_result()
{
  return VoidResult{StatusCode{Status::BadInvalidState},
    ua::make_error_detail("BadInvalidState",
      "EventSubscriber handle is detached (moved-from / null)",
      "client.tier2.event_subscriber.detached")};
}

}  // namespace

void EventSubscriber::subscribe_async(EventSubscription subscription, EventNotificationCallback onEvent,
  std::function<void(SubscribeResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_subscribe_result());
    return;
  }
  mImpl->subscribe_async(std::move(subscription), std::move(onEvent), std::move(callback));
}

void EventSubscriber::subscribe_to_type_async(ua::NodeId eventType, EventNotificationCallback onEvent,
  std::function<void(SubscribeResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_subscribe_result());
    return;
  }
  mImpl->subscribe_to_type_async(std::move(eventType), std::move(onEvent), std::move(callback));
}

void EventSubscriber::unsubscribe_async(
  MonitoredItem item, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(detached_void_result());
    return;
  }
  mImpl->unsubscribe_async(std::move(item), std::move(callback));
}

MonitoredItem EventSubscriber::subscribe_sync(
  EventSubscription subscription, EventNotificationCallback onEvent)
{
  return ua::detail::good_value(try_subscribe_sync(std::move(subscription), std::move(onEvent)));
}

SubscribeResult EventSubscriber::try_subscribe_sync(
  EventSubscription subscription, EventNotificationCallback onEvent) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MonitoredItem>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, subscription = std::move(subscription), onEvent = std::move(onEvent)](auto completion) mutable
    { subscribe_async(std::move(subscription), std::move(onEvent), std::move(completion)); });
}

void EventSubscriber::unsubscribe_sync(MonitoredItem item)
{
  try_unsubscribe_sync(std::move(item)).value();
}

ua::VoidResult EventSubscriber::try_unsubscribe_sync(MonitoredItem item) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, item = std::move(item)](auto completion) mutable
    { unsubscribe_async(std::move(item), std::move(completion)); });
}

std::shared_ptr<const EventSubscriberInfo> EventSubscriber::info() const noexcept
{
  return mImpl ? mImpl->info() : nullptr;
}

// ============================================================================
// Blocking wrappers
//
// One blocking_call per asynchronous operation, the shape every tier-2 facade uses
// (ua_sync_wait.h): the throwing form is `try_*_sync(...).value()`, and the non-throwing
// form arms the existing `*_async`. No operation is reimplemented here.
//
// Each blocks the calling thread until the completion runs; called from the executor thread that
// would run it, each refuses with Bad_WouldBlock before starting anything.
// ============================================================================

ua::client::MonitoredItem EventSubscriber::subscribe_to_type_sync(
  ua::NodeId eventType, EventNotificationCallback onEvent)
{
  return ua::detail::good_value(try_subscribe_to_type_sync(std::move(eventType), std::move(onEvent)));
}

ua::Result<ua::client::MonitoredItem> EventSubscriber::try_subscribe_to_type_sync(
  ua::NodeId eventType, EventNotificationCallback onEvent) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::client::MonitoredItem>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, eventType = std::move(eventType), onEvent = std::move(onEvent)](auto completion) mutable
    { subscribe_to_type_async(std::move(eventType), std::move(onEvent), std::move(completion)); });
}

}  // namespace ua::client
