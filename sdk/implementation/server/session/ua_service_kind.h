// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The services a server Session dispatches. Shared by the Session, which classifies each request, and the
// RequestLatencyTracker, which keeps one slot per service (public API review D3, API-D3.2).

#ifndef UA_SERVICE_KIND_H
#define UA_SERVICE_KIND_H

#include "ua_utilities.h"

#include <cstddef>

namespace ua::server
{

/// One enumerator per service the server implements; `Unknown` marks a request of no known type and is
/// always last.
enum class ServiceKind
{
  DiscoveryFindServers,
  DiscoveryFindServersOnNetwork,
  DiscoveryGetEndpoints,
  Read,
  Write,
  Browse,
  BrowseNext,
  Call,
  TranslateBrowsePathsToNodeIds,
  RegisterNodes,
  UnregisterNodes,
  CreateSubscription,
  ModifySubscription,
  DeleteSubscriptions,
  SetPublishingMode,
  Publish,
  Republish,
  CreateMonitoredItems,
  DeleteMonitoredItems,
  ModifyMonitoredItems,
  SetMonitoringMode,
  SetTriggering,
  TransferSubscriptions,
  AddNodes,
  AddReferences,
  DeleteNodes,
  DeleteReferences,
  HistoryRead,
  HistoryUpdate,
  Unknown
};

/// The number of services: every enumerator before `Unknown`.
inline constexpr std::size_t serviceKindCount =
  static_cast<std::size_t>(utils::to_underlying(ServiceKind::Unknown));

}  // namespace ua::server

#endif  // UA_SERVICE_KIND_H
