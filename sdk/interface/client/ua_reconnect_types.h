// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RECONNECT_TYPES_H
#define UA_RECONNECT_TYPES_H

/// @file
/// @brief Public reconnect cause / outcome types (client tier-1 observer surface).
/// @ingroup client

#include "ua_redundancy_support.h"  // ua::RedundancySupport

#include <cstddef>
#include <optional>
#include <string>
#include <variant>

namespace ua::client
{

/// The transport connection was lost (socket closed / reset).
/// @ingroup client
struct TransportDropped
{};

/// The KeepAlive poll missed `KeepAlivePolicy.missedBeforeReconnect` consecutive reads.
/// @ingroup client
struct KeepAliveMissed
{};

/// A security-class failure was observed (bad/untrusted certificate, policy rejected, ...).
/// @ingroup client
struct SecurityFailure
{};

/// The Session is no longer valid on the server (`Bad_SessionIdInvalid`).
/// @ingroup client
struct SessionInvalid
{};

/// The client's application-instance certificate was rotated (CL-RECONN-006).
/// @ingroup client
struct CertRotated
{};

/// The server announced a shutdown (`ServerState = Shutdown`); reconnect is deferred (CL-SESS-025).
/// @ingroup client
struct ServerShutdown
{};

/// A redundant-server switch was requested; carries the redundancy triple the tier-2 paths need.
/// @ingroup client
struct RedundancySwitchInfo
{
  /// The server set's redundancy support level.
  ua::RedundancySupport mode = ua::RedundancySupport::None;
  /// URI of the server the connection was on.
  std::string fromUri;
  /// URI of the server the connection switched to.
  std::string toUri;
};

/// Why a reconnect is being attempted. A tagged sum-type: most causes are payload-free tags; consumers
/// `std::visit` it. Delivered to `ConnectionObserver::on_reconnecting`.
using ReconnectCause = std::variant<TransportDropped, KeepAliveMissed, SecurityFailure, SessionInvalid,
  CertRotated, ServerShutdown, RedundancySwitchInfo>;

/// The result of a completed reconnect, delivered to `ConnectionObserver::on_reconnected`.
/// @ingroup client
struct ReconnectOutcome
{
  /// `ActivateSession` on the existing sessionId succeeded (no new Session was created).
  bool sessionPreserved = false;
  /// `TransferSubscriptions` succeeded (as opposed to recreating subscriptions).
  bool subscriptionsTransferred = false;
  /// The number of monitored items that had to be recreated.
  std::size_t monitoredItemsRecreated = 0;
  /// The cause the completed reconnect was driven by (`nullopt` = unknown / not reported). The tier-2
  /// redundancy manager uses this to tell its OWN `RedundancySwitch` failover apart from an unrelated
  /// reconnect that merely completed while it was `FailingOver`, and to learn which server was actually
  /// landed on (`RedundancySwitchInfo::toUri`) when a fallback diverged from the requested target.
  std::optional<ReconnectCause> cause;
};

}  // namespace ua::client

#endif  // UA_RECONNECT_TYPES_H
