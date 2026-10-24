// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_SUBSCRIPTION_FACTORY_H
#define UA_CONNECTION_SUBSCRIPTION_FACTORY_H

/// @file
/// @brief The real @ref ua::client::detail::SubscriptionFactoryOps implementation (wiring section 2)  -  a
/// leaf shim that
///        weak-references @ref ua::client::detail::ConnectionImpl and forwards the two subscription
///        primitives (create managed Subscription, attach data-change MonitoredItem) to it. Mirrors
///        @ref ua::client::detail::ConnectionEventBackboneOps / @ref ua_connection_ops.h: the shim only
///        weak-refs `ConnectionImpl`, so no strong cycle forms (ConnectionImpl hands this leaf out; the leaf
///        weak-holds ConnectionImpl).
/// @ingroup client

#include "ua_subscription_factory.h"

#include <cstdint>
#include <functional>
#include <memory>

namespace ua::client::detail
{

class ConnectionImpl;

/// Forwards @ref SubscriptionFactoryOps to @ref ConnectionImpl (weak). A gone `ConnectionImpl` completes
/// with `Bad_ConnectionClosed` carrying a source-tagged @ref ua::ErrorDetail.
class ConnectionSubscriptionFactory final : public SubscriptionFactoryOps,
                                            public std::enable_shared_from_this<ConnectionSubscriptionFactory>
{
public:
  [[nodiscard]] static std::shared_ptr<ConnectionSubscriptionFactory> create(
    std::weak_ptr<ConnectionImpl> connection);

  void create_subscription_managed_async(double publishingInterval, bool publishingEnabled,
    std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept override;

  void monitor_data_change_async(std::uint32_t subscriptionId, ua::client::MonitorRequest request,
    ua::client::DataChangeCallback onData,
    std::function<void(ua::client::MonitoredItemResult)> callback) noexcept override;

private:
  explicit ConnectionSubscriptionFactory(std::weak_ptr<ConnectionImpl> connection);

  std::weak_ptr<ConnectionImpl> mConnection;
};

}  // namespace ua::client::detail

#endif  // UA_CONNECTION_SUBSCRIPTION_FACTORY_H
