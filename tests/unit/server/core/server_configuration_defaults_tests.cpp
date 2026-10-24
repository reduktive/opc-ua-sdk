// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <functional>
#include <vector>
#include <gtest/gtest.h>
#include "ua_application_configuration.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_server_configuration.h"

using namespace ua::server;

/// Tests that ServerConfig defaults match spec-mandated or safety-critical values.
/// These defaults are the canonical source of truth for the SDK. Changing a default silently
/// (e.g., MaxSessions from 100 to unlimited) would break server security posture. Each test
/// here guards a specific default that, if changed, requires conscious review.
class ServerConfigurationDefaultsTests : public ::testing::Test
{
protected:
  ServerConfig mConfig;
};

// RATIFIED EXPECTATION CHANGE (DEF-3): 100 -> 200. The two limits are consecutive gates; equal
// defaults made the secure-channel eviction Part 4 5.5.2.1 requires unreachable at the defaults.
TEST_F(ServerConfigurationDefaultsTests, MaxConnectionsDefault)
{
  ASSERT_TRUE(mConfig.maxConnections.has_value());
  EXPECT_EQ(*mConfig.maxConnections, 200u);
}

// @verifies AC-SVR-SC-002-EVICTION-REACHABLE-AT-DEFAULTS
TEST_F(ServerConfigurationDefaultsTests, DefaultConnectionCeilingExceedsTheSecureChannelCeiling)
{
  ASSERT_TRUE(mConfig.maxConnections.has_value());
  ASSERT_TRUE(mConfig.maxSecureChannels.has_value());
  EXPECT_GT(*mConfig.maxConnections, *mConfig.maxSecureChannels)
    << "the reject gate must sit above the evict gate or the eviction is never reached";
}

TEST_F(ServerConfigurationDefaultsTests, MaxSecureChannelsDefault)
{
  ASSERT_TRUE(mConfig.maxSecureChannels.has_value());
  EXPECT_EQ(*mConfig.maxSecureChannels, 100u);
}

TEST_F(ServerConfigurationDefaultsTests, MaxSessionsDefault)
{
  ASSERT_TRUE(mConfig.server_capabilities().maxSessions.has_value());
  EXPECT_EQ(*mConfig.server_capabilities().maxSessions, 100u);
}

TEST_F(ServerConfigurationDefaultsTests, MaxSubscriptionsDefault)
{
  ASSERT_TRUE(mConfig.server_capabilities().maxSubscriptions.has_value());
  EXPECT_EQ(*mConfig.server_capabilities().maxSubscriptions, 1000u);
}

TEST_F(ServerConfigurationDefaultsTests, MaxNodesPerReadDefault)
{
  ASSERT_TRUE(mConfig.server_capabilities().operationLimits.maxNodesPerRead.has_value());
  EXPECT_EQ(*mConfig.server_capabilities().operationLimits.maxNodesPerRead, 1000u);
}

TEST_F(ServerConfigurationDefaultsTests, MaxNodesPerWriteDefault)
{
  ASSERT_TRUE(mConfig.server_capabilities().operationLimits.maxNodesPerWrite.has_value());
  EXPECT_EQ(*mConfig.server_capabilities().operationLimits.maxNodesPerWrite, 1000u);
}

TEST_F(ServerConfigurationDefaultsTests, MaxNodesPerRegisterNodesDefault)
{
  ASSERT_TRUE(mConfig.server_capabilities().operationLimits.maxNodesPerRegisterNodes.has_value());
  EXPECT_EQ(*mConfig.server_capabilities().operationLimits.maxNodesPerRegisterNodes, 1000u);
}

TEST_F(ServerConfigurationDefaultsTests, MaxBrowseContinuationPointsDefault)
{
  EXPECT_GT(mConfig.server_capabilities().maxBrowseContinuationPoints, 0u);
  EXPECT_EQ(mConfig.server_capabilities().maxBrowseContinuationPoints, 100u);
}

TEST_F(ServerConfigurationDefaultsTests, ConnectionThrottlingEnabledByDefault)
{
  EXPECT_TRUE(mConfig.connectionThrottling.enabled);
}

TEST_F(ServerConfigurationDefaultsTests, IdentityThrottlingEnabledByDefault)
{
  EXPECT_TRUE(mConfig.identityThrottling.enabled);
}

TEST_F(ServerConfigurationDefaultsTests, DiscoveryThrottlingDefaults)
{
  EXPECT_EQ(mConfig.discoveryThrottling.concurrencyThreshold, 10u);
  EXPECT_EQ(mConfig.discoveryThrottling.delayPerRequest, std::chrono::milliseconds{100});
}

TEST_F(ServerConfigurationDefaultsTests, MaxRequestsPerSessionDefault)
{
  ASSERT_TRUE(mConfig.maxRequestsPerSession.has_value());
  EXPECT_EQ(*mConfig.maxRequestsPerSession, 100u);
}

TEST_F(ServerConfigurationDefaultsTests, IncomingChunkQueueDepthDefault)
{
  EXPECT_EQ(mConfig.resourceLimits.incomingChunkQueueDepth, 64u);
}

// @relation(AC-SVR-FILE-032-OPEN-HANDLES-PER-SESSION-BOUNDED, scope=function)
// @relation(AC-SVR-FILE-033-OPEN-HANDLES-SERVER-WIDE-BOUNDED, scope=function)
TEST_F(ServerConfigurationDefaultsTests, OpenFileHandleLimitsDefault)
{
  EXPECT_EQ(mConfig.resourceLimits.openFileHandlesPerSession, 16u);
  EXPECT_EQ(mConfig.resourceLimits.openFileHandles, 256u);
}

TEST_F(ServerConfigurationDefaultsTests, AccessControlLimitsDefault)
{
  EXPECT_EQ(mConfig.maxAccessIdentities, 10000U);
  EXPECT_EQ(mConfig.authzTimeout, std::chrono::milliseconds{1000});
  EXPECT_EQ(mConfig.monitoredItemAccessRecheckInterval, std::chrono::seconds{60});
  EXPECT_FALSE(mConfig.enableClaimToRoleMapping);
}

// The default configuration must be valid - validate() is called on the Server::create path.
TEST_F(ServerConfigurationDefaultsTests, Validate_DefaultConfigPasses)
{
  EXPECT_NO_THROW(mConfig.validate());
}

// Every server-internal admission/memory cap must be >= 1; 0 is invalid (there is no "unlimited"
// setting for a control whose purpose is to bound growth). Drive each field to 0 in turn and confirm
// validate() rejects it - guards the contract that 0 is a config error, not silently normalised.
// @verifies AC-SVR-TCP-040-THE-WRITE-QUEUE-HAS-A-BYTE-BUDGET
// @verifies AC-SVR-TCP-040-THE-PER-IP-THROTTLE-KEYS-IPV6-BY-THE-CONFIGURED-PREFIX
// @relation(AC-SVR-FILE-033-OPEN-HANDLES-SERVER-WIDE-BOUNDED, scope=function)
TEST_F(ServerConfigurationDefaultsTests, Validate_RejectsZeroInternalResourceCap)
{
  const std::vector<std::function<void(ServerConfig&)>> zeroers{
    [](ServerConfig& c) { c.resourceLimits.eventDispatchQueueDepth = 0; },
    [](ServerConfig& c) { c.resourceLimits.conditionBranchesPerCondition = 0; },
    [](ServerConfig& c) { c.resourceLimits.orphanedSubscriptionStore = 0; },
    [](ServerConfig& c) { c.resourceLimits.bufferedResponsesPerSession = 0; },
    [](ServerConfig& c) { c.resourceLimits.writeQueueDepthPerConnection = 0; },
    [](ServerConfig& c) { c.resourceLimits.writeQueueBytesPerConnection = 0; },
    [](ServerConfig& c) { c.resourceLimits.incomingChunkQueueDepth = 0; },
    [](ServerConfig& c) { c.resourceLimits.openFileHandlesPerSession = 0; },
    [](ServerConfig& c) { c.resourceLimits.openFileHandles = 0; },
    [](ServerConfig& c) { c.connectionThrottling.maxTrackedEndpoints = 0; },
    [](ServerConfig& c) { c.connectionThrottling.ipv6PrefixLength = 0; },
    [](ServerConfig& c) { c.identityThrottling.maxTrackedIdentities = 0; },
    [](ServerConfig& c) { c.subscriptionLimits.maxPublishRequestsPerSession = 0u; },
    [](ServerConfig& c) { c.maxAccessIdentities = 0; },
    [](ServerConfig& c) { c.authzTimeout = std::chrono::milliseconds{0}; },
    [](ServerConfig& c) { c.monitoredItemAccessRecheckInterval = std::chrono::seconds{0}; },
  };

  for (const auto& zero : zeroers)
  {
    ServerConfig config;
    ASSERT_NO_THROW(config.validate());  // clean before the field is zeroed
    zero(config);
    EXPECT_THROW(config.validate(), ua::UaException);
  }
}

// An IPv6 prefix longer than the address is meaningless; 128 (per address) is the default and the
// maximum.
// @verifies AC-SVR-TCP-040-THE-PER-IP-THROTTLE-KEYS-IPV6-BY-THE-CONFIGURED-PREFIX
TEST_F(ServerConfigurationDefaultsTests, Validate_RejectsAnIpv6PrefixLongerThanTheAddress)
{
  EXPECT_EQ(mConfig.connectionThrottling.ipv6PrefixLength, 128u) << "per address by default";
  mConfig.connectionThrottling.ipv6PrefixLength = 129;
  try
  {
    mConfig.validate();
    FAIL() << "a 129-bit prefix must be refused";
  }
  catch (const ua::UaException& ex)
  {
    EXPECT_EQ(ex.status_code().as_status(), ua::Status::BadConfigurationError);
    ASSERT_NE(ex.detail(), nullptr);
    EXPECT_EQ(ex.detail()->code, "InvalidResourceLimit");
    bool namesTheField = false;
    for (const auto& entry : ex.detail()->context)
      namesTheField = namesTheField || entry.value == "ConnectionThrottling.Ipv6PrefixLength";
    EXPECT_TRUE(namesTheField) << "the refusal names the field";
  }
  mConfig.connectionThrottling.ipv6PrefixLength = 64;
  EXPECT_NO_THROW(mConfig.validate());
}

// The byte budget's zero refusal names its field, so the generic zero-cap arm above cannot pass on
// some other check firing.
// @verifies AC-SVR-TCP-040-THE-WRITE-QUEUE-HAS-A-BYTE-BUDGET
TEST_F(ServerConfigurationDefaultsTests, Validate_RejectsAZeroWriteQueueByteBudgetByName)
{
  mConfig.resourceLimits.writeQueueBytesPerConnection = 0;
  try
  {
    mConfig.validate();
    FAIL() << "a zero byte budget must be refused";
  }
  catch (const ua::UaException& ex)
  {
    EXPECT_EQ(ex.status_code().as_status(), ua::Status::BadConfigurationError);
    ASSERT_NE(ex.detail(), nullptr);
    bool namesTheField = false;
    for (const auto& entry : ex.detail()->context)
      namesTheField = namesTheField || entry.value == "ResourceLimits.WriteQueueBytesPerConnection";
    EXPECT_TRUE(namesTheField) << "the refusal names the field";
  }
}

// @relation(AC-SVR-AUTHZ-009-RECHECK-INTERVAL-POSITIVE, scope=function)
TEST_F(ServerConfigurationDefaultsTests, Validate_RejectsNonPositiveMonitoredItemAccessRecheckInterval)
{
  for (const auto interval : {std::chrono::seconds{0}, std::chrono::seconds{-1}})
  {
    mConfig.monitoredItemAccessRecheckInterval = interval;
    try
    {
      mConfig.validate();
      FAIL() << "expected a non-positive authorization recheck interval to be rejected";
    }
    catch (const ua::UaException& ex)
    {
      EXPECT_EQ(ex.status(), ua::Status::BadConfigurationError);
      ASSERT_NE(ex.detail(), nullptr);
      EXPECT_EQ(ex.detail()->code, "InvalidMonitoredItemAccessRecheckInterval");
    }
  }
}

// The rejection must carry BadConfigurationError (the canonical config-error status).
TEST_F(ServerConfigurationDefaultsTests, Validate_ZeroCapThrowsBadConfigurationError)
{
  mConfig.resourceLimits.incomingChunkQueueDepth = 0;
  try
  {
    mConfig.validate();
    FAIL() << "expected validate() to throw on a zero internal cap";
  }
  catch (const ua::UaException& ex)
  {
    EXPECT_EQ(ex.status(), ua::Status::BadConfigurationError);
  }
}

// S3: First-OPN timeout default.
TEST(ApplicationConfigurationDefaults, FirstOpnTimeoutDefault)
{
  auto cfg = ua::ApplicationConfig::load_default();
  EXPECT_EQ(cfg.stack_limits().firstOpnTimeout, std::chrono::seconds{30});
}

// Session timeout defaults.
TEST(ApplicationConfigurationDefaults, SessionMinimumTimeoutDefault)
{
  auto cfg = ua::ApplicationConfig::load_default();
  EXPECT_EQ(cfg.stack_limits().sessionMinimumTimeout, std::chrono::milliseconds{60'000});
}

TEST(ApplicationConfigurationDefaults, SessionMaximumTimeoutDefault)
{
  auto cfg = ua::ApplicationConfig::load_default();
  EXPECT_EQ(cfg.stack_limits().sessionMaximumTimeout, std::chrono::milliseconds{3'600'000});
}

// S4: Deprecated security policies disabled by default.
TEST(ApplicationConfigurationDefaults, DeprecatedSecurityPoliciesDisabledByDefault)
{
  auto cfg = ua::ApplicationConfig::load_default();
  EXPECT_FALSE(cfg.allowDeprecatedSecurityPolicies);
}
