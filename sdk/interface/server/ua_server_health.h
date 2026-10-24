// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Point-in-time health and diagnostics snapshots for the server and its sessions.
/// @ingroup server

#ifndef UA_SERVER_HEALTH_H
#define UA_SERVER_HEALTH_H

#include "ua_node_id.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ua::server
{

/// A point-in-time snapshot of server-wide health and diagnostics metrics.
///
/// Each field is read independently from an atomic counter, so the snapshot is not a coherent
/// cross-field capture: different fields may reflect slightly different instants. This is
/// acceptable per the OPC UA "approximate" guidance for diagnostics. Counters named
/// `current_*` are gauges (instantaneous occupancy), `cumulated_*` are monotonically
/// increasing totals over the server's lifetime, and `rejected_*` count refused attempts.
/// @ingroup server
struct ServerHealthSnapshot
{
  // OPC UA spec-aligned (ServerDiagnosticsSummaryDataType)
  uint32_t currentSessionCount{};  ///< Sessions currently open.
  uint32_t cumulatedSessionCount{};  ///< Sessions opened since server start.
  uint32_t securityRejectedSessionCount{};  ///< Session creations refused for security reasons.
  uint32_t rejectedSessionCount{};  ///< Session creations refused for any reason.
  uint32_t sessionTimeoutCount{};  ///< Sessions closed because they timed out.
  uint32_t sessionAbortCount{};  ///< Sessions closed abnormally (aborted).
  uint32_t currentSubscriptionCount{};  ///< Subscriptions currently active across all sessions.
  uint32_t cumulatedSubscriptionCount{};  ///< Subscriptions created since server start.
  uint32_t serverViewCount{};  ///< Views present in the server's address space.
  uint32_t publishingIntervalCount{};  ///< Distinct publishing intervals currently in use.
  uint32_t securityRejectedRequestsCount{};  ///< Requests refused for security reasons.
  uint32_t rejectedRequestsCount{};  ///< Requests refused for any reason.

  // Secure channel (SDK extension)
  uint32_t currentSecureChannelCount{};  ///< Secure channels currently open.
  uint32_t cumulatedSecureChannelCount{};  ///< Secure channels opened since server start.
  uint32_t rejectedSecureChannelCount{};  ///< Secure-channel open attempts that were refused.

  // Connection (SDK extension)
  uint32_t currentConnectionCount{};  ///< Transport connections currently open.
  uint32_t cumulatedConnectionCount{};  ///< Transport connections accepted since server start.
  uint32_t rejectedConnectionCount{};  ///< Transport connection attempts that were refused.

  // Per-service latency (SDK extension)

  /// Latency statistics for one service.
  ///
  /// All durations are in microseconds. The values are eventually-consistent observability
  /// figures sampled from relaxed atomics, not exact measurements.
  struct LatencyEntry
  {
    uint64_t averageUs{};  ///< Exponential moving average request latency, in microseconds.
    uint64_t maxUs{};  ///< High-watermark request latency observed, in microseconds.
    uint32_t sampleCount{};  ///< Number of latency samples folded into the statistics.
  };

  /// Request latency per implemented service, by name; the names are those of the counters in
  /// @ref SessionHealthSnapshot.
  /// The Query services are not implemented and have no entry.
  struct ServiceLatency
  {
    LatencyEntry read;  ///< Read.
    LatencyEntry write;  ///< Write.
    LatencyEntry browse;  ///< Browse.
    LatencyEntry browseNext;  ///< BrowseNext.
    LatencyEntry translateBrowsePaths;  ///< TranslateBrowsePathsToNodeIds.
    LatencyEntry registerNodes;  ///< RegisterNodes.
    LatencyEntry unregisterNodes;  ///< UnregisterNodes.
    LatencyEntry call;  ///< Call.
    LatencyEntry historyRead;  ///< HistoryRead.
    LatencyEntry historyUpdate;  ///< HistoryUpdate.
    LatencyEntry createSubscription;  ///< CreateSubscription.
    LatencyEntry modifySubscription;  ///< ModifySubscription.
    LatencyEntry deleteSubscriptions;  ///< DeleteSubscriptions.
    LatencyEntry setPublishingMode;  ///< SetPublishingMode.
    LatencyEntry publish;  ///< Publish.
    LatencyEntry republish;  ///< Republish.
    LatencyEntry transferSubscriptions;  ///< TransferSubscriptions.
    LatencyEntry createMonitoredItems;  ///< CreateMonitoredItems.
    LatencyEntry modifyMonitoredItems;  ///< ModifyMonitoredItems.
    LatencyEntry deleteMonitoredItems;  ///< DeleteMonitoredItems.
    LatencyEntry setMonitoringMode;  ///< SetMonitoringMode.
    LatencyEntry setTriggering;  ///< SetTriggering.
    LatencyEntry addNodes;  ///< AddNodes.
    LatencyEntry addReferences;  ///< AddReferences.
    LatencyEntry deleteNodes;  ///< DeleteNodes.
    LatencyEntry deleteReferences;  ///< DeleteReferences.
    LatencyEntry findServers;  ///< FindServers.
    LatencyEntry findServersOnNetwork;  ///< FindServersOnNetwork.
    LatencyEntry getEndpoints;  ///< GetEndpoints.
  };

  /// Request latency per service, by name (SDK extension).
  ServiceLatency latency{};
};

/// A point-in-time snapshot of per-session health and diagnostics metrics.
///
/// Identifies one session and reports its request counters, authorization failures, and
/// subscription/monitored-item occupancy. As with @ref ServerHealthSnapshot, fields are sampled
/// independently and are approximate rather than a coherent cross-field capture.
/// @ingroup server
struct SessionHealthSnapshot
{
  NodeId sessionId;  ///< Identifier of the session this snapshot describes.
  std::string sessionName;  ///< Human-readable session name, as supplied by the client.

  /// Total and error request tallies for one service kind.
  struct ServiceCount
  {
    uint32_t total{};  ///< Requests of this kind processed for the session.
    uint32_t errors{};  ///< Subset of @ref total that completed with an error status.
  };

  uint32_t unauthorizedRequestCount{};  ///< Requests refused because the session lacked permission.

  // Subscription/MonitoredItem gauges (queried from SubscriptionsPipeline at snapshot time).
  uint32_t currentSubscriptionCount{};  ///< Subscriptions currently owned by the session.
  uint32_t currentMonitoredItemsCount{};  ///< Monitored items currently owned by the session.

  ServiceCount totalRequests;  ///< All requests, summed across every service kind.
  ServiceCount read;  ///< Read service requests.
  ServiceCount browse;  ///< Browse service requests.
  ServiceCount browseNext;  ///< BrowseNext service requests.
  ServiceCount write;  ///< Write service requests.
  ServiceCount call;  ///< Call (method) service requests.
  ServiceCount historyRead;  ///< HistoryRead service requests.
  ServiceCount historyUpdate;  ///< HistoryUpdate service requests.
  ServiceCount createMonitoredItems;  ///< CreateMonitoredItems service requests.
  ServiceCount modifyMonitoredItems;  ///< ModifyMonitoredItems service requests.
  ServiceCount setMonitoringMode;  ///< SetMonitoringMode service requests.
  ServiceCount setTriggering;  ///< SetTriggering service requests.
  ServiceCount deleteMonitoredItems;  ///< DeleteMonitoredItems service requests.
  ServiceCount createSubscription;  ///< CreateSubscription service requests.
  ServiceCount modifySubscription;  ///< ModifySubscription service requests.
  ServiceCount setPublishingMode;  ///< SetPublishingMode service requests.
  ServiceCount publish;  ///< Publish service requests.
  ServiceCount republish;  ///< Republish service requests.
  ServiceCount transferSubscriptions;  ///< TransferSubscriptions service requests.
  ServiceCount deleteSubscriptions;  ///< DeleteSubscriptions service requests.
  ServiceCount addNodes;  ///< AddNodes service requests.
  ServiceCount addReferences;  ///< AddReferences service requests.
  ServiceCount deleteNodes;  ///< DeleteNodes service requests.
  ServiceCount deleteReferences;  ///< DeleteReferences service requests.
  ServiceCount translateBrowsePaths;  ///< TranslateBrowsePathsToNodeIds service requests.
  ServiceCount queryFirst;  ///< QueryFirst service requests.
  ServiceCount queryNext;  ///< QueryNext service requests.
  ServiceCount registerNodes;  ///< RegisterNodes service requests.
  ServiceCount unregisterNodes;  ///< UnregisterNodes service requests.
};

}  // namespace ua::server

#endif  // UA_SERVER_HEALTH_H
