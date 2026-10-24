// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_configuration.h"

namespace ua::server
{

void apply_embedded_server_profile(ServerConfig& config)
{
  // Embedded tier: a small, coherent cap set for a low-MB-class device. The numbers are intentionally
  // conservative - a host that needs more headroom applies this preset first and then raises the
  // specific caps it cares about. Every cap stays strictly positive so the config still validates.

  // --- Transport / channel / per-session admission -------------------------------------------------
  config.maxConnections = 16;  // concurrent transport connections (incl. in-handshake)
  config.maxSecureChannels = 10;  // BELOW mMaxConnections, so the evicting gate is reachable
  config.maxRequestsPerSession = 10;  // in-flight non-Publish requests per session
  config.maxInFlightRequests = 100;  // server-wide in-flight non-Publish requests
  config.maxInFlightRequestsPerConnection = 10;  // per-connection in-flight non-Publish requests
  config.connectionThrottling.maxConnectionsPerEndpoint = 4;  // per remote IP

  auto& caps = config.server_capabilities();
  auto& subLimits = config.subscriptionLimits;

  // --- Sessions / subscriptions / MonitoredItems ---------------------------------------------------
  caps.maxSessions = 5;
  caps.maxSubscriptions = 10;
  caps.maxSubscriptionsPerSession = 2;
  caps.maxMonitoredItems = 200;
  caps.maxMonitoredItemsPerSubscription = 100;

  // --- Notification / publish flow control ---------------------------------------------------------
  caps.maxMonitoredItemsQueueSize = 10;
  subLimits.defaultEventQueueSize = 10;
  subLimits.maxNotificationsPerPublish = 1000;
  subLimits.maxPublishRequestsPerSession = 10;

  // --- Continuation points (per session) -----------------------------------------------------------
  caps.maxBrowseContinuationPoints = 10;
  caps.maxQueryContinuationPoints = 10;
  caps.maxHistoryContinuationPoints = 10;

  // --- EventFilter clause limits (enforced at MonitoredItem create, P0.4) --------------------------
  caps.maxSelectClauseParameters = 10;
  caps.maxWhereClauseParameters = 10;

  // --- Per-value encoding size caps (tighter than the managed bounded floor) -----------------------
  caps.maxArrayLength = 4096;
  caps.maxStringLength = 64u * 1024u;  // 64 KB
  caps.maxByteStringLength = 256u * 1024u;  // 256 KB

  // --- Per-service OperationLimits -----------------------------------------------------------------
  auto& ops = caps.operationLimits;
  ops.maxNodesPerRead = 100;
  ops.maxNodesPerWrite = 100;
  ops.maxNodesPerBrowse = 100;
  ops.maxNodesPerRegisterNodes = 100;
  ops.maxNodesPerTranslateBrowsePathsToNodeIds = 100;
  ops.maxNodesPerMethodCall = 10;
  ops.maxNodesPerNodeManagement = 10;
  ops.maxMonitoredItemsPerCall = 100;
  ops.maxNodesPerHistoryReadData = 50;
  ops.maxNodesPerHistoryReadEvents = 50;
  ops.maxNodesPerHistoryUpdateData = 50;
  ops.maxNodesPerHistoryUpdateEvents = 50;

  // --- Durable subscriptions: off (keeps the per-MonitoredItem queue term finite) ------------------
  // Durable subscriptions lift the MI-queue ceiling for offline buffering; that unbounds the working
  // set, so the memory-bounded profile refuses them (SetSubscriptionDurable -> Bad_ServiceUnsupported).
  subLimits.durableSubscriptionsEnabled = false;

  // --- Server-internal resource caps (P1.D fail-closed/drop-oldest backstops) ----------------------
  auto& limits = config.resourceLimits;
  limits.eventDispatchQueueDepth = 256;
  limits.conditionBranchesPerCondition = 16;
  limits.orphanedSubscriptionStore = 16;
  limits.bufferedResponsesPerSession = 64;
  limits.writeQueueDepthPerConnection = 64;
  // Applied at message starts (a message admitted is queued whole), so this bounds the backlog
  // BETWEEN messages at eight 64 KiB chunks; one maximum-size message on top is the true bound.
  limits.writeQueueBytesPerConnection = 512u * 1024u;
  limits.incomingChunkQueueDepth = 8;  // read-pause sooner on a small device (~8x ReceiveBufferSize)
  limits.openFileHandlesPerSession = 4;  // a small device has few file descriptors to spare
  limits.openFileHandles = 32;

  // Attacker-keyed throttle maps: fewer distinct keys tracked on a small device.
  config.connectionThrottling.maxTrackedEndpoints = 256;
  config.identityThrottling.maxTrackedIdentities = 256;

  // --- Diagnostics: bound the returned DiagnosticInfo to Summary -----------------------------------
  // Full DiagnosticInfo is unbounded per-response context; Summary keeps the symbolic id/text only.
  config.diagnosticPolicy.maxLevel = ServerConfig::DiagnosticPolicy::Level::Summary;
  if (config.diagnosticPolicy.defaultLevel == ServerConfig::DiagnosticPolicy::Level::Full)
  {
    config.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Summary;
  }
}

}  // namespace ua::server
