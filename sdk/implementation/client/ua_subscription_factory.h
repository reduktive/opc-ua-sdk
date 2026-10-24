// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTION_FACTORY_H
#define UA_SUBSCRIPTION_FACTORY_H

/// @file
/// @brief A NEW purpose-built, ISP-narrow tier-1 interface (client design wiring section 2): the two subscription
///        primitives a tier-2 streaming accessor (`ServerDiagnosticsAccessor::subscribe_*`, CL-BASEDIAG-004)
///        needs to stand up a managed Subscription + a data-change MonitoredItem WITHOUT holding
///        @ref ua::client::detail::ConnectionImpl. Mirrors @ref ua_event_backbone_ops.h: the built
///        `SubscriptionOps` role (@ref ua_connection_ops.h) is the pipeline SEND interface (send_publish /
///        republish), not the wire-shaped create/monitor surface  -  rather than widen that role for one
///        consumer, this slice introduces a narrow interface that captures EXACTLY the two operations the
///        streaming accessor needs. A tier-2 unit test drives the accessor's own request-building / decode
///        logic against a `FakeSubscriptionFactory` with NO `ConnectionImpl`; the real implementation
///        (@ref ua::client::detail::ConnectionSubscriptionFactory) forwards to `ConnectionImpl`.
/// @ingroup client

#include "ua_client_monitored_item.h"  // MonitorRequest / DataChangeCallback / MonitoredItemResult
#include "ua_result.h"

#include <cstdint>
#include <functional>
#include <memory>

namespace ua::client::detail
{

/// The details a public @ref ua::client::Subscription handle snapshots from a `CreateSubscription` success
/// (section 7.4): the server-assigned id plus the server-revised publishing interval + publishing-enabled
/// flag.
///
/// Homed here (not on @ref ConnectionImpl) so the narrow @ref SubscriptionFactoryOps interface and the tier-2
/// streaming accessor can name it without pulling in the heavy orchestrator header.
struct SubscriptionCreated
{
  std::uint32_t subscriptionId = 0;
  double revisedPublishingInterval = 0.0;
  bool publishingEnabled = true;
};

/// The narrow subscription-creation interface (wiring section 2). Two primitives only: create a managed
/// Subscription and attach a data-change MonitoredItem to it. Both post to the connection strand and deliver
/// on the executor (the tier-1 contract)  -  the accessor calling them holds no strand of its own. A tier-2
/// accessor reaches this via @ref SupportOps::subscription_factory (locked per op; never held
/// long-term-strong  to  no cycle).
///
/// Named `*Ops` (not the design's bare `SubscriptionFactory`) because that name is already taken by the
/// public-handle construction interface in `ua_client_subscription.h` (a DIFFERENT concept  -  it stamps a
/// `Subscription` value handle from primitives, whereas this stands up the server-side Subscription + MI).
class SubscriptionFactoryOps
{
public:
  SubscriptionFactoryOps() = default;
  SubscriptionFactoryOps(const SubscriptionFactoryOps&) = delete;
  SubscriptionFactoryOps& operator=(const SubscriptionFactoryOps&) = delete;
  SubscriptionFactoryOps(SubscriptionFactoryOps&&) = delete;
  SubscriptionFactoryOps& operator=(SubscriptionFactoryOps&&) = delete;
  virtual ~SubscriptionFactoryOps() = default;

  /// Creates a managed Subscription (`CreateSubscription`) and delivers the @ref SubscriptionCreated snapshot
  /// (or a bad Result) on the executor.
  virtual void create_subscription_managed_async(double publishingInterval, bool publishingEnabled,
    std::function<void(ua::Result<SubscriptionCreated>)> callback) noexcept = 0;

  /// Attaches a data-change MonitoredItem to @p subscriptionId and delivers the unified
  /// @ref ua::client::MonitoredItem (or a bad Result) on the executor. @p onData receives each
  /// @ref ua::client::DataChangeEvent on the executor.
  virtual void monitor_data_change_async(std::uint32_t subscriptionId, ua::client::MonitorRequest request,
    ua::client::DataChangeCallback onData,
    std::function<void(ua::client::MonitoredItemResult)> callback) noexcept = 0;
};

}  // namespace ua::client::detail

#endif  // UA_SUBSCRIPTION_FACTORY_H
