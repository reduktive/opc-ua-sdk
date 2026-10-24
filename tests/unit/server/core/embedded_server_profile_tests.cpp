// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_server_configuration.h"

using namespace ua::server;

// The Embedded profile must tighten every cap it sets to strictly below the Standard default, while
// keeping the config valid and leaving the deployment-shaped fields (listeners, identity, feature
// gates, advertised profiles, LDS) untouched.

TEST(EmbeddedServerProfileTests, TightensCapsBelowStandardDefaults)
{
  ServerConfig standard;  // Standard defaults
  ServerConfig embedded;
  apply_embedded_server_profile(embedded);

  // Transport / channel / per-session admission.
  EXPECT_LT(*embedded.maxConnections, *standard.maxConnections);
  EXPECT_LT(*embedded.maxSecureChannels, *standard.maxSecureChannels);
  EXPECT_LT(*embedded.maxRequestsPerSession, *standard.maxRequestsPerSession);
  EXPECT_LT(embedded.connectionThrottling.maxConnectionsPerEndpoint,
    standard.connectionThrottling.maxConnectionsPerEndpoint);

  const auto& ec = embedded.server_capabilities();
  const auto& sc = standard.server_capabilities();
  const auto& esl = embedded.subscriptionLimits;
  const auto& ssl = standard.subscriptionLimits;

  // Sessions / subscriptions / MonitoredItems.
  EXPECT_LT(*ec.maxSessions, *sc.maxSessions);
  EXPECT_LT(*ec.maxSubscriptions, *sc.maxSubscriptions);
  EXPECT_LT(*ec.maxSubscriptionsPerSession, *sc.maxSubscriptionsPerSession);
  EXPECT_LT(*ec.maxMonitoredItems, *sc.maxMonitoredItems);
  EXPECT_LT(*ec.maxMonitoredItemsPerSubscription, *sc.maxMonitoredItemsPerSubscription);

  // Notification / publish flow control.
  EXPECT_LT(*ec.maxMonitoredItemsQueueSize, *sc.maxMonitoredItemsQueueSize);
  EXPECT_LT(*esl.defaultEventQueueSize, *ssl.defaultEventQueueSize);
  EXPECT_LT(*esl.maxNotificationsPerPublish, *ssl.maxNotificationsPerPublish);
  EXPECT_LT(*esl.maxPublishRequestsPerSession, *ssl.maxPublishRequestsPerSession);

  // Continuation points.
  EXPECT_LT(ec.maxBrowseContinuationPoints, sc.maxBrowseContinuationPoints);
  EXPECT_LT(ec.maxQueryContinuationPoints, sc.maxQueryContinuationPoints);
  EXPECT_LT(ec.maxHistoryContinuationPoints, sc.maxHistoryContinuationPoints);

  // EventFilter clause limits.
  EXPECT_LT(*ec.maxSelectClauseParameters, *sc.maxSelectClauseParameters);
  EXPECT_LT(*ec.maxWhereClauseParameters, *sc.maxWhereClauseParameters);

  // Per-value encoding size caps.
  EXPECT_LT(*ec.maxArrayLength, *sc.maxArrayLength);
  EXPECT_LT(*ec.maxStringLength, *sc.maxStringLength);
  EXPECT_LT(*ec.maxByteStringLength, *sc.maxByteStringLength);

  // OperationLimits.
  const auto& eo = ec.operationLimits;
  const auto& so = sc.operationLimits;
  EXPECT_LT(*eo.maxNodesPerRead, *so.maxNodesPerRead);
  EXPECT_LT(*eo.maxNodesPerWrite, *so.maxNodesPerWrite);
  EXPECT_LT(*eo.maxNodesPerBrowse, *so.maxNodesPerBrowse);
  EXPECT_LT(*eo.maxNodesPerMethodCall, *so.maxNodesPerMethodCall);
  EXPECT_LT(*eo.maxNodesPerRegisterNodes, *so.maxNodesPerRegisterNodes);
  EXPECT_LT(*eo.maxNodesPerTranslateBrowsePathsToNodeIds, *so.maxNodesPerTranslateBrowsePathsToNodeIds);
  EXPECT_LT(*eo.maxNodesPerNodeManagement, *so.maxNodesPerNodeManagement);
  EXPECT_LT(*eo.maxMonitoredItemsPerCall, *so.maxMonitoredItemsPerCall);
  EXPECT_LT(*eo.maxNodesPerHistoryReadData, *so.maxNodesPerHistoryReadData);
  EXPECT_LT(*eo.maxNodesPerHistoryReadEvents, *so.maxNodesPerHistoryReadEvents);
  EXPECT_LT(*eo.maxNodesPerHistoryUpdateData, *so.maxNodesPerHistoryUpdateData);
  EXPECT_LT(*eo.maxNodesPerHistoryUpdateEvents, *so.maxNodesPerHistoryUpdateEvents);
}

// @verifies AC-SVR-TCP-040-THE-WRITE-QUEUE-HAS-A-BYTE-BUDGET
TEST(EmbeddedServerProfileTests, TightensInternalResourceLimits)
{
  ServerConfig standard;
  ServerConfig embedded;
  apply_embedded_server_profile(embedded);

  const auto& el = embedded.resourceLimits;
  const auto& sl = standard.resourceLimits;
  EXPECT_LT(el.eventDispatchQueueDepth, sl.eventDispatchQueueDepth);
  EXPECT_LT(el.conditionBranchesPerCondition, sl.conditionBranchesPerCondition);
  EXPECT_LT(el.orphanedSubscriptionStore, sl.orphanedSubscriptionStore);
  EXPECT_LT(el.bufferedResponsesPerSession, sl.bufferedResponsesPerSession);
  EXPECT_LT(el.writeQueueDepthPerConnection, sl.writeQueueDepthPerConnection);
  EXPECT_LT(el.writeQueueBytesPerConnection, sl.writeQueueBytesPerConnection);

  // All stay strictly positive (the consuming components clamp to >= 1 anyway).
  EXPECT_GT(el.eventDispatchQueueDepth, 0u);
  EXPECT_GT(el.conditionBranchesPerCondition, 0u);
  EXPECT_GT(el.orphanedSubscriptionStore, 0u);
  EXPECT_GT(el.bufferedResponsesPerSession, 0u);
  EXPECT_GT(el.writeQueueDepthPerConnection, 0u);
  EXPECT_GT(el.writeQueueBytesPerConnection, 0u);

  // Attacker-keyed throttle-map caps tightened too.
  EXPECT_LT(
    embedded.connectionThrottling.maxTrackedEndpoints, standard.connectionThrottling.maxTrackedEndpoints);
  EXPECT_LT(
    embedded.identityThrottling.maxTrackedIdentities, standard.identityThrottling.maxTrackedIdentities);
}

TEST(EmbeddedServerProfileTests, AllSetCapsStayStrictlyPositiveAndValidate)
{
  ServerConfig config;
  apply_embedded_server_profile(config);

  // The headline non-optional gates that validate() guards must remain non-zero.
  EXPECT_GT(*config.maxConnections, 0u);
  EXPECT_GT(*config.maxSecureChannels, 0u);

  const auto& caps = config.server_capabilities();
  EXPECT_GT(*caps.maxSessions, 0u);
  EXPECT_GT(*caps.maxSubscriptions, 0u);
  EXPECT_GT(*caps.maxMonitoredItems, 0u);
  EXPECT_GT(*caps.maxArrayLength, 0u);
  EXPECT_GT(*caps.maxStringLength, 0u);
  EXPECT_GT(*caps.maxByteStringLength, 0u);

  EXPECT_NO_THROW(config.validate());
}

TEST(EmbeddedServerProfileTests, BoundsDiagnosticInfoToSummary)
{
  ServerConfig config;
  config.diagnosticPolicy.maxLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  config.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;

  apply_embedded_server_profile(config);

  EXPECT_EQ(config.diagnosticPolicy.maxLevel, ServerConfig::DiagnosticPolicy::Level::Summary);
  // A Full default is pulled down to the new Summary ceiling.
  EXPECT_EQ(config.diagnosticPolicy.defaultLevel, ServerConfig::DiagnosticPolicy::Level::Summary);
}

TEST(EmbeddedServerProfileTests, PreservesDeploymentShapedFields)
{
  ServerConfig config;

  // Stand up a listener and flip the feature gates / advertised profiles / LDS, then confirm the
  // preset leaves them exactly as they were (it tightens resource caps, not deployment policy).
  ServerConfig::ListenerConfig listener;
  listener.name = "primary";
  listener.bind.address = "0.0.0.0";
  config.listeners().push_back(listener);

  config.auditingEnabled = true;
  config.roleManagementEnabled = true;
  config.server_capabilities().serverProfiles = {"http://opcfoundation.org/UA-Profile/Server/Embedded"};
  config.localDiscoveryServer.enabled = true;

  apply_embedded_server_profile(config);

  ASSERT_EQ(config.listeners().size(), 1u);
  EXPECT_EQ(config.listeners().front().name, "primary");
  EXPECT_TRUE(config.auditingEnabled);
  EXPECT_TRUE(config.roleManagementEnabled);
  ASSERT_EQ(config.server_capabilities().serverProfiles.size(), 1u);
  EXPECT_EQ(config.server_capabilities().serverProfiles.front(),
    "http://opcfoundation.org/UA-Profile/Server/Embedded");
  EXPECT_TRUE(config.localDiscoveryServer.enabled);
}

TEST(EmbeddedServerProfileTests, IsIdempotent)
{
  ServerConfig once;
  apply_embedded_server_profile(once);

  ServerConfig twice;
  apply_embedded_server_profile(twice);
  apply_embedded_server_profile(twice);

  EXPECT_EQ(once.server_capabilities(), twice.server_capabilities());
  EXPECT_EQ(*once.maxConnections, *twice.maxConnections);
  EXPECT_EQ(*once.maxSecureChannels, *twice.maxSecureChannels);
  EXPECT_EQ(*once.maxRequestsPerSession, *twice.maxRequestsPerSession);
}

// @verifies AC-SVR-SC-002-EVICTION-REACHABLE-AT-DEFAULTS
TEST(EmbeddedServerProfileTests, EvictingGateStaysReachable)
{
  ua::server::ServerConfig config;
  ua::server::apply_embedded_server_profile(config);
  ASSERT_TRUE(config.maxConnections.has_value());
  ASSERT_TRUE(config.maxSecureChannels.has_value());
  EXPECT_GT(*config.maxConnections, *config.maxSecureChannels)
    << "the embedded preset must keep the secure-channel eviction reachable too";
}
