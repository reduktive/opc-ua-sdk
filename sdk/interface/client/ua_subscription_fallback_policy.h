// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTION_FALLBACK_POLICY_H
#define UA_SUBSCRIPTION_FALLBACK_POLICY_H

/// @file
/// @brief Polled-Read Subscription-fallback policy (client tier-1, ConnectionConfig; CL-SUB-019).
/// @ingroup client

namespace ua::client
{

/// Governs whether a Connection transparently replaces a Subscription the server could NOT create with a
/// timer-driven bulk-`Read` polling driver that feeds the user's MonitoredItem callbacks (client design
/// section 7.7 / section 8.4, CL-SUB-019). The swap is transparent: the user's @ref ua::client::Subscription
/// /
/// @ref ua::client::MonitoredItem handles stay valid and unaware.
///
/// The default (@ref Mode::Disabled) preserves the pre-fallback behaviour exactly: a failed
/// `CreateSubscription` surfaces its bad status to the caller and no polling driver starts.
/// @ingroup client
struct SubscriptionFallbackPolicy
{
  /// When the polled-Read fallback engages on a failed `CreateSubscription`.
  enum class Mode
  {
    /// Never engage a fallback  -  a failed `CreateSubscription` surfaces its bad status verbatim (the
    /// default,
    /// == today's behaviour).
    Disabled,
    /// Engage ONLY when the server reports the Subscription service is unsupported
    /// (`Bad_ServiceUnsupported`); any other failure surfaces verbatim.
    OptIn,
    /// Engage on ANY `CreateSubscription` failure.
    Auto,
  };

  /// The active engagement mode. Defaults to @ref Mode::Disabled.
  Mode mode = Mode::Disabled;
};

}  // namespace ua::client

#endif  // UA_SUBSCRIPTION_FALLBACK_POLICY_H
