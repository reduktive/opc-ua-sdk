// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the real @ref ua::client::detail::ConnectionSubscriptionFactory leaf (a
///        @ref ua::client::detail::SubscriptionFactoryOps shim, wiring section 2): forwards the two
///        subscription primitives to @ref ua::client::detail::ConnectionImpl.

#include "ua_connection_subscription_factory.h"

#include "ua_connection_impl.h"
#include "ua_error_detail.h"
#include "ua_status.h"

#include <string>
#include <utility>

namespace ua::client::detail
{

namespace
{
/// Source tag for the manufactured connection-gone boundary failure (the design specification).
constexpr std::string_view connectionGoneSource = "client.tier1.subscription_factory.connection_gone";
}  // namespace

std::shared_ptr<ConnectionSubscriptionFactory> ConnectionSubscriptionFactory::create(
  std::weak_ptr<ConnectionImpl> connection)
{
  return std::shared_ptr<ConnectionSubscriptionFactory>(
    new ConnectionSubscriptionFactory(std::move(connection)));
}

ConnectionSubscriptionFactory::ConnectionSubscriptionFactory(std::weak_ptr<ConnectionImpl> connection)
  : mConnection(std::move(connection))
{}

void ConnectionSubscriptionFactory::create_subscription_managed_async(double publishingInterval,
  bool publishingEnabled, std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->create_subscription_managed_async(publishingInterval, publishingEnabled, std::move(callback));
    return;
  }
  callback(ua::Result<SubscriptionCreated>{ua::Status::BadConnectionClosed,
    ua::make_error_detail("ConnectionGone",
      "the tier-1 Connection was destroyed before the Subscription could be created",
      std::string{connectionGoneSource})});
}

void ConnectionSubscriptionFactory::monitor_data_change_async(std::uint32_t subscriptionId,
  ua::client::MonitorRequest request, ua::client::DataChangeCallback onData,
  std::function<void(ua::client::MonitoredItemResult)> callback) noexcept
{
  if (const auto connection = mConnection.lock())
  {
    connection->monitor_data_change_async(
      subscriptionId, std::move(request), std::move(onData), std::move(callback));
    return;
  }
  callback(ua::client::MonitoredItemResult{ua::Status::BadConnectionClosed,
    ua::make_error_detail("ConnectionGone",
      "the tier-1 Connection was destroyed before the data-change monitor could be attached",
      std::string{connectionGoneSource})});
}

}  // namespace ua::client::detail
