// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/json.hpp>

#include <algorithm>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "ua_memory_stream.h"
#include "ua_application_configuration.h"
#include "ua_application_overrides.h"
#include "ua_client_configuration.h"
#include "ua_error_detail_keys.h"
#include "ua_process_configuration_file.h"
#include "ua_node_id.h"

#include <chrono>
#include <optional>
#include <limits>
#include <filesystem>
#include <fstream>

using namespace ua;

TEST(ConfigurationTests, Success)
{
  auto configuration = ApplicationConfig::load_default();
  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};

  configuration.store(stream);
  span<const char> result{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  auto jsonText = std::string{result.begin(), result.end()};

  // JSON keys should align with member names (drop the 'm' prefix).
  EXPECT_NE(jsonText.find("\"ApplicationUri\""), std::string::npos);
  EXPECT_EQ(jsonText.find("\"ServerUri\""), std::string::npos);

  stream.seek_from_start(0);
  auto parsedConfig = ApplicationConfig::load(stream);
  check_true(configuration.application_description_part() == parsedConfig.application_description_part());
  check_true(configuration.stack_limits() == parsedConfig.stack_limits());
  check_true(configuration.file_trust_list_configuration() == parsedConfig.file_trust_list_configuration());
}

// The rejected-certificate-store bound (anti pre-auth cert-flood DoS) must be operator-configurable and
// survive a JSON round-trip with a NON-default value - a default-only round-trip would false-pass because
// both sides fall back to the struct default (100). Falsifiable: if MaxRejectedCertificates is dropped
// from to_json/from_json, the parsed value reverts to 100 != 7.
TEST(ConfigurationTests, MaxRejectedCertificates_RoundTripsJsonWithNonDefaultValue)
{
  auto configuration = ApplicationConfig::load_default();
  configuration.file_trust_list_configuration().maxRejectedCertificates = 7;

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  configuration.store(stream);

  span<const char> result{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  const auto jsonText = std::string{result.begin(), result.end()};
  EXPECT_NE(jsonText.find("\"MaxRejectedCertificates\""), std::string::npos)
    << "the bound must be emitted to JSON so operators can configure it";

  stream.seek_from_start(0);
  auto parsedConfig = ApplicationConfig::load(stream);
  EXPECT_EQ(parsedConfig.file_trust_list_configuration().maxRejectedCertificates, 7u)
    << "the configured bound must survive the JSON round-trip";
}

// Every public configuration field must be proven end to end at a NON-DEFAULT value.
// Rejected-certificate persistence is what gives an operator the
// evidence for a failed connection attempt, and switching it OFF is a deliberate choice on a host
// with no writable store - so a value that did not survive the round-trip would silently restore
// the writes the operator asked to stop.
TEST(ConfigurationTests, StoreRejectedCertificates_RoundTripsJsonWithNonDefaultValue)
{
  auto configuration = ApplicationConfig::load_default();
  ASSERT_TRUE(configuration.file_trust_list_configuration().storeRejectedCertificates)
    << "precondition: persistence is on by default, so false is the non-default value";
  configuration.file_trust_list_configuration().storeRejectedCertificates = false;

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  configuration.store(stream);

  span<const char> result{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  const auto jsonText = std::string{result.begin(), result.end()};
  EXPECT_NE(jsonText.find("\"StoreRejectedCertificates\""), std::string::npos)
    << "the flag must be emitted to JSON so operators can configure it";

  stream.seek_from_start(0);
  auto parsedConfig = ApplicationConfig::load(stream);
  EXPECT_FALSE(parsedConfig.file_trust_list_configuration().storeRejectedCertificates)
    << "an operator who turned persistence off must not have it turned back on by a reload";
}

TEST(ConfigurationTests, Validate_RejectsInvalidLimits)
{
  auto configuration = ApplicationConfig::load_default();

  configuration.execution_limits().decodeWorkLimit = 0;
  EXPECT_THROW(configuration.validate(), UaException);

  configuration.execution_limits().decodeWorkLimit = 100;
  configuration.execution_limits().loopLimit = 0;
  EXPECT_THROW(configuration.validate(), UaException);
}

TEST(ConfigurationTests, ApplicationOverrides_JsonKeysAlignWithMemberNames)
{
  ApplicationOverrides overrides;
  overrides.decodeWorkLimit = 123;
  overrides.loopLimit = 456;
  overrides.allowInsecureEndpoints = true;

  auto jsonText = overrides.to_json_string(false);

  EXPECT_NE(jsonText.find("\"DecodeWorkLimit\""), std::string::npos);
  EXPECT_NE(jsonText.find("\"LoopLimit\""), std::string::npos);
  EXPECT_NE(jsonText.find("\"AllowInsecureEndpoints\""), std::string::npos);
  EXPECT_EQ(jsonText.find("decodeWorkLimit"), std::string::npos);
  EXPECT_EQ(jsonText.find("loopLimit"), std::string::npos);
}

TEST(ConfigurationTests, ApplyOverrides_OverrideWinsOverBase)
{
  auto base = ApplicationConfig::load_default();
  base.execution_limits().decodeWorkLimit = 100;
  base.execution_limits().loopLimit = 100;

  ApplicationOverrides overrides;
  overrides.decodeWorkLimit = 200;

  auto merged = apply_overrides(base, overrides);
  EXPECT_EQ(merged.execution_limits().decodeWorkLimit, 200u);
  EXPECT_EQ(merged.execution_limits().loopLimit, 100u);
}

TEST(ConfigurationTests, Validate_RejectsZeroSessionMinimumTimeout)
{
  auto configuration = ApplicationConfig::load_default();
  configuration.stack_limits().sessionMinimumTimeout = std::chrono::milliseconds{0};
  EXPECT_THROW(configuration.validate(), UaException);
}

TEST(ConfigurationTests, Validate_RejectsSessionMaximumBelowMinimum)
{
  auto configuration = ApplicationConfig::load_default();
  configuration.stack_limits().sessionMinimumTimeout = std::chrono::milliseconds{60'000};
  configuration.stack_limits().sessionMaximumTimeout = std::chrono::milliseconds{30'000};
  EXPECT_THROW(configuration.validate(), UaException);
}

TEST(ConfigurationTests, ProcessConfigurationFile_RoundTripJson_SessionTimeouts)
{
  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());

  // Set non-default session timeout values.
  file.application.stack_limits().sessionMinimumTimeout = std::chrono::milliseconds{120'000};
  file.application.stack_limits().sessionMaximumTimeout = std::chrono::milliseconds{7'200'000};

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);

  span<const char> result{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  auto jsonText = std::string{result.begin(), result.end()};

  EXPECT_NE(jsonText.find("\"SessionMinimumTimeout\""), std::string::npos);
  EXPECT_NE(jsonText.find("\"SessionMaximumTimeout\""), std::string::npos);

  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  EXPECT_EQ(parsed.application.stack_limits().sessionMinimumTimeout, std::chrono::milliseconds{120'000});
  EXPECT_EQ(parsed.application.stack_limits().sessionMaximumTimeout, std::chrono::milliseconds{7'200'000});
}

TEST(ConfigurationTests, ProcessConfigurationFile_RoundTripJson)
{
  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());
  file.servers.front().server.maxConnections = 7;

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);

  span<const char> result{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  auto jsonText = std::string{result.begin(), result.end()};

  EXPECT_NE(jsonText.find("\"Application\""), std::string::npos);
  EXPECT_NE(jsonText.find("\"Servers\""), std::string::npos);
  EXPECT_NE(jsonText.find("\"Clients\""), std::string::npos);
  EXPECT_NE(jsonText.find("\"MaxConnections\""), std::string::npos);

  EXPECT_TRUE(file.application.application_description_part().applicationUri.starts_with("urn:"));

  // Identity is intentionally not persisted.
  EXPECT_EQ(jsonText.find("\"Identity\""), std::string::npos);
  EXPECT_EQ(jsonText.find("\"ApplicationIdentity\""), std::string::npos);

  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  EXPECT_EQ(parsed.servers.size(), file.servers.size());
  ASSERT_FALSE(parsed.servers.empty());
  EXPECT_EQ(parsed.servers.front().name, file.servers.front().name);
  ASSERT_TRUE(parsed.servers.front().server.maxConnections.has_value());
  EXPECT_EQ(*parsed.servers.front().server.maxConnections, 7u);
  // Default config has no listeners - the application fills these in.
  EXPECT_TRUE(parsed.servers.front().server.listeners().empty());
}

// Stage 3c config-wiring completeness: every server-side limit/cap must survive a JSON round-trip with
// a NON-DEFAULT value. Non-default values make this falsifiable - if a field is dropped from the
// to/from JSON wiring, both sides fall back to the struct default and the specific assertion fails.
// @verifies AC-SVR-TCP-040-THE-WRITE-QUEUE-HAS-A-BYTE-BUDGET
// @verifies AC-SVR-TCP-040-THE-PER-IP-THROTTLE-KEYS-IPV6-BY-THE-CONFIGURED-PREFIX
TEST(ConfigurationTests, ProcessConfigurationFile_RoundTripJson_AllServerLimitsAndCaps)
{
  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());
  auto& srv = file.servers.front().server;

  // ServerConfig top-level security / throttling scalars.
  srv.maxSecureChannels = 77;
  srv.maxRequestsPerSession = 33;
  srv.maxInFlightRequests = 1234;
  srv.maxInFlightRequestsPerConnection = 21;
  srv.maxAccessIdentities = 444;
  srv.authzTimeout = std::chrono::milliseconds{2750};

  // Nested throttling / resource-limit structs.
  srv.connectionThrottling.enabled = false;
  srv.connectionThrottling.maxConnectionsPerEndpoint = 3;
  srv.connectionThrottling.maxConnectionAttemptsPerMinute = 17;
  srv.connectionThrottling.maxTrackedEndpoints = 222;
  srv.connectionThrottling.ipv6PrefixLength = 64;
  srv.identityThrottling.enabled = false;
  srv.identityThrottling.maxFailedAttemptsBeforeLockout = 9;
  srv.identityThrottling.lockoutDuration = std::chrono::seconds{120};
  srv.identityThrottling.maxTrackedIdentities = 333;
  srv.discoveryThrottling.concurrencyThreshold = 4;
  srv.discoveryThrottling.delayPerRequest = std::chrono::milliseconds{250};
  srv.resourceLimits.eventDispatchQueueDepth = 5000;
  srv.resourceLimits.conditionBranchesPerCondition = 42;
  srv.resourceLimits.orphanedSubscriptionStore = 500;
  srv.resourceLimits.bufferedResponsesPerSession = 600;
  srv.resourceLimits.writeQueueDepthPerConnection = 2048;
  srv.resourceLimits.writeQueueBytesPerConnection = 3u * 1024u * 1024u;
  srv.resourceLimits.incomingChunkQueueDepth = 32;
  srv.resourceLimits.openFileHandlesPerSession = 5;
  srv.resourceLimits.openFileHandles = 77;

  // SubscriptionLimits / continuation-point timeouts that were previously NOT wired.
  auto& subLimits = srv.subscriptionLimits;
  subLimits.maxPendingStatusChanges = 55;
  subLimits.durableSubscriptionsEnabled = false;
  subLimits.maxDurableSubscriptionLifetimeHours = 12;
  subLimits.maxDurableMonitoredItemQueueSize = 5000;
  subLimits.maxWhereClauseOperandBytes = 4096;  // Stage-3c #6 (non-default; default 65536)
  subLimits.maxLifetimeCount = 777;  // default 10000
  srv.historyContinuationPointTimeout = std::chrono::milliseconds{45000};

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);
  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  ASSERT_FALSE(parsed.servers.empty());
  const auto& psrv = parsed.servers.front().server;

  EXPECT_EQ(psrv.maxSecureChannels, 77u);
  EXPECT_EQ(psrv.maxRequestsPerSession, 33u);
  EXPECT_EQ(psrv.maxInFlightRequests, 1234u);
  EXPECT_EQ(psrv.maxInFlightRequestsPerConnection, 21u);
  EXPECT_EQ(psrv.maxAccessIdentities, 444u);
  EXPECT_EQ(psrv.authzTimeout, std::chrono::milliseconds{2750});

  EXPECT_FALSE(psrv.connectionThrottling.enabled);
  EXPECT_EQ(psrv.connectionThrottling.maxConnectionsPerEndpoint, 3u);
  EXPECT_EQ(psrv.connectionThrottling.maxConnectionAttemptsPerMinute, 17u);
  EXPECT_EQ(psrv.connectionThrottling.maxTrackedEndpoints, 222u);
  EXPECT_EQ(psrv.connectionThrottling.ipv6PrefixLength, 64u);
  EXPECT_FALSE(psrv.identityThrottling.enabled);
  EXPECT_EQ(psrv.identityThrottling.maxFailedAttemptsBeforeLockout, 9u);
  EXPECT_EQ(psrv.identityThrottling.lockoutDuration.count(), 120);
  EXPECT_EQ(psrv.identityThrottling.maxTrackedIdentities, 333u);
  EXPECT_EQ(psrv.discoveryThrottling.concurrencyThreshold, 4u);
  EXPECT_EQ(psrv.discoveryThrottling.delayPerRequest.count(), 250);
  EXPECT_EQ(psrv.resourceLimits.eventDispatchQueueDepth, 5000u);
  EXPECT_EQ(psrv.resourceLimits.conditionBranchesPerCondition, 42u);
  EXPECT_EQ(psrv.resourceLimits.orphanedSubscriptionStore, 500u);
  EXPECT_EQ(psrv.resourceLimits.bufferedResponsesPerSession, 600u);
  EXPECT_EQ(psrv.resourceLimits.writeQueueDepthPerConnection, 2048u);
  EXPECT_EQ(psrv.resourceLimits.writeQueueBytesPerConnection, 3u * 1024u * 1024u);
  EXPECT_EQ(psrv.resourceLimits.incomingChunkQueueDepth, 32u);
  EXPECT_EQ(psrv.resourceLimits.openFileHandlesPerSession, 5u);
  EXPECT_EQ(psrv.resourceLimits.openFileHandles, 77u);

  const auto& psubLimits = psrv.subscriptionLimits;
  ASSERT_TRUE(psubLimits.maxPendingStatusChanges.has_value());
  EXPECT_EQ(*psubLimits.maxPendingStatusChanges, 55u);
  EXPECT_FALSE(psubLimits.durableSubscriptionsEnabled);
  EXPECT_EQ(psubLimits.maxDurableSubscriptionLifetimeHours, 12u);
  EXPECT_EQ(psubLimits.maxDurableMonitoredItemQueueSize, 5000u);
  ASSERT_TRUE(psubLimits.maxWhereClauseOperandBytes.has_value());  // Stage-3c #6
  EXPECT_EQ(*psubLimits.maxWhereClauseOperandBytes, 4096u);
  ASSERT_TRUE(psubLimits.maxLifetimeCount.has_value());
  EXPECT_EQ(*psubLimits.maxLifetimeCount, 777u);
  ASSERT_TRUE(psrv.historyContinuationPointTimeout.has_value());
  EXPECT_EQ(psrv.historyContinuationPointTimeout->count(), 45000);
}

// Config-field dispositions (2026-06-28): the nine server-side fields agreed for JSON wiring must each
// round-trip with a NON-DEFAULT value (falsifiable: a dropped field reverts to its default and the
// specific assertion fails). Covers scalars/bools, enum/NodeId/string lists, and the two nested
// feature structs (ReverseConnectTarget, LocalDiscoveryServer).
TEST(ConfigurationTests, ProcessConfigurationFile_RoundTripJson_ServerConfigDispositions)
{
  using ua::server::ServerConfig;
  using ua::server::WellKnownRole;

  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());
  auto& srv = file.servers.front().server;

  srv.monitoredItemAccessRecheckInterval = std::chrono::seconds{30};  // #1 (non-default; default 60s)
  srv.maxReferencesPerNode = 500;  // Stage-3c #3 (non-default; default 10000)
  srv.maxReferencesPerBrowseRequest = 4000;  // SVC-12 (non-default; default 1000000)
  srv.localDiscoveryServer.semaphoreFileDirectory = "/var/run/opcua/semaphores";  // SVC-15 (default unset)
  srv.maxBrowsePathWalkReferences = 250;  // Stage-3c #2 (non-default; default 100000)
  srv.defaultShutdownGracePeriodSeconds = 30;  // #2
  srv.roleManagementEnabled = true;  // #3
  srv.authnTimeout = std::chrono::milliseconds{2500};  // moved from the security hooks (default 1000 ms)
  srv.enableClaimToRoleMapping = true;  // #3a
  srv.wellKnownRoles =
    std::vector<WellKnownRole>{WellKnownRole::Observer, WellKnownRole::SecurityAdmin};  // #4
  ServerConfig::ReverseConnectTarget target;  // #6
  target.name = "rc1";
  target.clientApplicationUri = "urn:client:app";
  target.clientEndpointUrl = "opc.tcp://client:4840";
  target.serverEndpointUrl = "opc.tcp://server:4840";
  target.periodicConnectInterval = std::chrono::seconds{45};
  target.maxPendingSockets = 9;
  srv.reverseConnectTargets = {target};

  srv.localDiscoveryServer.enabled = true;  // #7
  srv.localDiscoveryServer.registrationExpiry = std::chrono::seconds{900};
  srv.localDiscoveryServer.maxRegistrations = 42;

  srv.server_capabilities().localeIds = {"de", "fr"};  // #8
  srv.server_capabilities().serverProfiles = {// #9
    "http://opcfoundation.org/UA-Profile/Server/StandardUA2017"};

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);
  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  ASSERT_FALSE(parsed.servers.empty());
  const auto& p = parsed.servers.front().server;

  EXPECT_EQ(p.monitoredItemAccessRecheckInterval.count(), 30);  // #1
  ASSERT_TRUE(p.maxReferencesPerNode.has_value());  // Stage-3c #3
  EXPECT_EQ(*p.maxReferencesPerNode, 500u);
  ASSERT_TRUE(p.maxReferencesPerBrowseRequest.has_value());  // SVC-12
  EXPECT_EQ(*p.maxReferencesPerBrowseRequest, 4000u);
  ASSERT_TRUE(p.localDiscoveryServer.semaphoreFileDirectory.has_value());  // SVC-15
  EXPECT_EQ(*p.localDiscoveryServer.semaphoreFileDirectory, "/var/run/opcua/semaphores");
  ASSERT_TRUE(p.maxBrowsePathWalkReferences.has_value());  // Stage-3c #2
  EXPECT_EQ(*p.maxBrowsePathWalkReferences, 250u);
  EXPECT_EQ(p.defaultShutdownGracePeriodSeconds, 30u);
  EXPECT_TRUE(p.roleManagementEnabled);
  EXPECT_EQ(p.authnTimeout.count(), 2500);
  EXPECT_TRUE(p.enableClaimToRoleMapping);
  ASSERT_TRUE(p.wellKnownRoles.has_value());
  EXPECT_EQ(
    *p.wellKnownRoles, (std::vector<WellKnownRole>{WellKnownRole::Observer, WellKnownRole::SecurityAdmin}));

  ASSERT_EQ(p.reverseConnectTargets.size(), 1u);
  EXPECT_EQ(p.reverseConnectTargets[0].name, "rc1");
  EXPECT_EQ(p.reverseConnectTargets[0].clientApplicationUri, "urn:client:app");
  EXPECT_EQ(p.reverseConnectTargets[0].clientEndpointUrl, "opc.tcp://client:4840");
  EXPECT_EQ(p.reverseConnectTargets[0].serverEndpointUrl, "opc.tcp://server:4840");
  EXPECT_EQ(p.reverseConnectTargets[0].periodicConnectInterval.count(), 45);
  EXPECT_EQ(p.reverseConnectTargets[0].maxPendingSockets, 9u);

  EXPECT_TRUE(p.localDiscoveryServer.enabled);
  EXPECT_EQ(p.localDiscoveryServer.registrationExpiry.count(), 900);
  ASSERT_TRUE(p.localDiscoveryServer.maxRegistrations.has_value());
  EXPECT_EQ(*p.localDiscoveryServer.maxRegistrations, 42u);

  EXPECT_EQ(p.server_capabilities().localeIds, (std::vector<std::string>{"de", "fr"}));
  EXPECT_EQ(p.server_capabilities().serverProfiles,
    (std::vector<std::string>{"http://opcfoundation.org/UA-Profile/Server/StandardUA2017"}));
}

// Owner decision Q3 (2026-10-04): PushCertificateManagementEnabled round-trips with its non-default value (a
// dropped field reverts to true and the assertion fails), and a file without the key keeps the default
// (true).
// @verifies AC-SVR-PULLCRT-042-PUSH-MANAGEMENT-OFF-PUBLISHES-NO-SERVER-CONFIGURATION
TEST(ConfigurationTests, ProcessConfigurationFile_RoundTripJson_PushCertificateManagementEnabled)
{
  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());
  EXPECT_TRUE(file.servers.front().server.pushCertificateManagementEnabled) << "on by default";
  file.servers.front().server.pushCertificateManagementEnabled = false;

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);
  span<const char> bytes{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  const std::string json{bytes.begin(), bytes.end()};
  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  ASSERT_FALSE(parsed.servers.empty());
  EXPECT_FALSE(parsed.servers.front().server.pushCertificateManagementEnabled);

  // Without the key (a file written before the field existed) push management stays on. The member is cut
  // from the text up to and including the comma that follows it (more members follow it).
  std::string withoutKey = json;
  const auto keyPosition = withoutKey.find("\"PushCertificateManagementEnabled\"");
  ASSERT_NE(keyPosition, std::string::npos) << json;
  const auto commaPosition = withoutKey.find(',', keyPosition);
  ASSERT_NE(commaPosition, std::string::npos);
  withoutKey.erase(keyPosition, commaPosition + 1 - keyPosition);
  const auto path = std::filesystem::temp_directory_path() / "ua_push_management_default_config.json";
  {
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    out << withoutKey;
  }
  bool enabled = false;
  try
  {
    auto legacy = ProcessConfigurationFile::load(path);
    ASSERT_FALSE(legacy.servers.empty());
    enabled = legacy.servers.front().server.pushCertificateManagementEnabled;
  }
  catch (...)
  {
    std::filesystem::remove(path);
    throw;
  }
  std::filesystem::remove(path);
  EXPECT_TRUE(enabled);
}

TEST(ConfigurationTests, ProcessConfigurationFile_RoundTripJson_ClientConfiguration)
{
  auto file = ProcessConfigurationFile::load_default();

  // Add a client instance with non-default values.
  ua::ProcessConfigurationFile::ClientInstanceConfig clientEntry{
    .name = "TestClient", .applicationOverrides = {}, .client = {}};
  clientEntry.client.defaultServiceTimeout = std::chrono::milliseconds{5000};
  clientEntry.client.defaultSessionTimeout = std::chrono::milliseconds{600'000};
  clientEntry.client.defaultChannelLifetime = std::chrono::milliseconds{1'800'000};
  clientEntry.client.writeQueueDepthPerConnection = 512;
  clientEntry.client.writeQueueBytesPerConnection = 2u * 1024u * 1024u;
  file.clients.push_back(std::move(clientEntry));

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);

  span<const char> result{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  auto jsonText = std::string{result.begin(), result.end()};

  // Verify JSON keys are present.
  EXPECT_NE(jsonText.find("\"DefaultServiceTimeoutMs\""), std::string::npos);
  EXPECT_NE(jsonText.find("\"DefaultSessionTimeoutMs\""), std::string::npos);
  EXPECT_NE(jsonText.find("\"DefaultChannelLifetimeMs\""), std::string::npos);

  // Round-trip: deserialize and verify values survived.
  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  ASSERT_EQ(parsed.clients.size(), 1u);
  EXPECT_EQ(parsed.clients.front().name, "TestClient");
  EXPECT_EQ(parsed.clients.front().client.defaultServiceTimeout, std::chrono::milliseconds{5000});
  EXPECT_EQ(parsed.clients.front().client.writeQueueDepthPerConnection, 512u);
  EXPECT_EQ(parsed.clients.front().client.writeQueueBytesPerConnection, 2u * 1024u * 1024u);
  EXPECT_EQ(parsed.clients.front().client.defaultSessionTimeout, std::chrono::milliseconds{600'000});
  EXPECT_EQ(parsed.clients.front().client.defaultChannelLifetime, std::chrono::milliseconds{1'800'000});
}

// The writer must emit a JSON OBJECT, because the reader requires one (`from_json_string` opens with
// `jv.as_object()`). Stated as its own row because the six round-trip rows above all failed with a bare
// Bad_DecodingError, which says a file did not load but not that THE SDK ITSELF WROTE IT that way: every
// configuration this SDK stored was unloadable, `load_or_create_and_store_default` included.
//
// The cause was `boost::json::value v{std::move(obj)}` - brace-initialisation selects Boost.JSON's
// initializer-list constructor, which wraps the single object in a one-element ARRAY. Parenthesised
// initialisation keeps the object. Falsifiable at the exact granularity of that mistake: it fails on the
// document's kind, before any field is looked at.
TEST(ConfigurationTests, ProcessConfigurationFile_WriterEmitsAnObjectTheReaderAccepts)
{
  const auto file = ProcessConfigurationFile::load_default();

  const auto json = file.to_json_string(true);
  const auto parsed = boost::json::parse(json);
  ASSERT_TRUE(parsed.is_object()) << "the stored configuration must be a JSON object, not a "
                                  << (parsed.is_array() ? "one-element array" : "non-object value")
                                  << "; the reader opens with as_object() and nothing else can load it";
  EXPECT_TRUE(parsed.as_object().contains("Application"))
    << "the object the reader expects is the one carrying Application/Servers/Clients";

  EXPECT_NO_THROW((void)ProcessConfigurationFile::from_json_string(json))
    << "what the writer produced must be exactly what the reader accepts";
}

// A document of the wrong SHAPE must say so. The six round-trip rows above failed with a bare
// Bad_DecodingError that named neither the shape nor the writer, which is what turned a one-line defect
// into a debugger session. ErrorDetail propagation is the repository's first rule.
TEST(ConfigurationTests, ProcessConfigurationFile_NonObjectRootIsDiagnosedByShape)
{
  try
  {
    (void)ProcessConfigurationFile::from_json_string(R"([{"Application":{}}])");
    FAIL() << "an array root must be refused";
  }
  catch (const ua::UaException& e)
  {
    EXPECT_EQ(e.status_code(), ua::StatusCode{ua::Status::BadDecodingError});
    ASSERT_NE(e.detail(), nullptr) << "the refusal must be diagnosable";
    EXPECT_EQ(e.detail()->code, "ConfigurationRootIsNotAnObject");
    const auto& context = e.detail()->context;
    const auto actual = std::find_if(context.begin(),
      context.end(),
      [](const ua::NamedValue& value) { return value.key == ua::ContextKeys::actual.value(); });
    ASSERT_NE(actual, context.end()) << "the detail must name the shape it actually found";
    EXPECT_EQ(actual->value, "array");
  }
}

TEST(ConfigurationTests, ProcessConfigurationFile_RoundTripJson_ClientConfigurationDefaults)
{
  // A client entry with all defaults should round-trip cleanly.
  auto file = ProcessConfigurationFile::load_default();
  file.clients.push_back({.name = "DefaultClient", .applicationOverrides = {}, .client = {}});

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);

  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  ASSERT_EQ(parsed.clients.size(), 1u);

  ua::client::ClientConfig defaults;
  EXPECT_EQ(parsed.clients.front().client.defaultServiceTimeout, defaults.defaultServiceTimeout);
  EXPECT_EQ(parsed.clients.front().client.defaultSessionTimeout, defaults.defaultSessionTimeout);
  EXPECT_EQ(parsed.clients.front().client.defaultChannelLifetime, defaults.defaultChannelLifetime);
}

TEST(ConfigurationTests, ProcessConfigurationFile_RejectsRemovedMaxResponseMessageSizeKey)
{
  // ClientConfig::mMaxResponseMessageSize was removed: the session-level
  // maxResponseMessageSize is now DERIVED from the transport limit the same configuration already
  // sets. A file carrying the old key was written against a field that never reached the wire, so
  // loading it must FAIL rather than silently drop the value - silence is how the field stayed dead.
  const std::string json = R"({
    "Applications": [],
    "Servers": [],
    "Clients": [ { "Name": "Legacy", "Client": { "MaxResponseMessageSize": 4194304 } } ]
  })";

  // A path-based load, because the raw text is the point: no in-memory struct can carry the
  // removed field any more, so the only way to present the old key is a file that has it.
  const auto path = std::filesystem::temp_directory_path() / "ua_removed_key_config.json";
  {
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    out << json;
  }
  EXPECT_THROW(ProcessConfigurationFile::load(path), ua::UaException);
  std::filesystem::remove(path);
}

// @relation(AC-SVR-AUTHZ-009-RECHECK-INTERVAL-POSITIVE, scope=function)
TEST(ConfigurationTests, ProcessConfigurationFile_RejectsDisabledAccessRecheckInterval)
{
  auto file = ProcessConfigurationFile::load_default();
  file.servers.push_back({.name = "AccessRecheckServer", .applicationOverrides = {}, .server = {}});

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);
  span<const char> bytes{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  std::string json{bytes.begin(), bytes.end()};

  const std::string fieldName{"\"MonitoredItemAccessRecheckIntervalSeconds\""};
  const auto fieldPosition = json.find(fieldName);
  ASSERT_NE(fieldPosition, std::string::npos);
  const auto valuePosition = json.find("60", fieldPosition + fieldName.size());
  ASSERT_NE(valuePosition, std::string::npos);
  json.replace(valuePosition, 2, "0");

  const auto path = std::filesystem::temp_directory_path() / "ua_disabled_access_recheck_config.json";
  {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << json;
  }
  try
  {
    EXPECT_THROW(ProcessConfigurationFile::load(path), UaException);
  }
  catch (...)
  {
    std::filesystem::remove(path);
    throw;
  }
  std::filesystem::remove(path);
}

TEST(ConfigurationTests, ProcessConfigurationFile_Validate_RejectsEmptyEffectiveApplicationUri)
{
  auto app = ApplicationConfig::load_default();
  app.application_description_part().applicationUri.clear();

  ua::ProcessConfigurationFile::ServerInstanceConfig s{.name = "s", .applicationOverrides = {}, .server = {}};

  ProcessConfigurationFile file{std::move(app), {std::move(s)}, {}};
  EXPECT_THROW(file.validate(), UaException);
}

// clang-format off  -- this declaration must stay on ONE line: the requirements gate matches
// the JUnit test name against the tree-sitter function name, and a wrapped TEST_F cannot be
// matched (it fails the whole export, not just this test). Exceeds ColumnLimit by a few chars.
TEST(
  ConfigurationTests, ProcessConfigurationFile_Validate_AllowsEmptyBaseIfAllInstancesOverrideApplicationUri)
// clang-format on
{
  auto app = ApplicationConfig::load_default();
  app.application_description_part().applicationUri.clear();

  ApplicationOverrides overrides;
  overrides.applicationDescriptionPart = ApplicationConfig::ApplicationDescriptionPart{
    .applicationUri = "http://example.invalid/opcua-sdk/instance"};

  ua::ProcessConfigurationFile::ServerInstanceConfig s{
    .name = "s", .applicationOverrides = overrides, .server = {}};
  ua::ProcessConfigurationFile::ClientInstanceConfig c{
    .name = "c", .applicationOverrides = overrides, .client = {}};

  ProcessConfigurationFile file{std::move(app), {std::move(s)}, {std::move(c)}};
  EXPECT_NO_THROW(file.validate());
}

TEST(ConfigurationTests, ProcessConfigurationFile_Validate_RejectsApplicationUriWithoutScheme)
{
  auto app = ApplicationConfig::load_default();
  app.application_description_part().applicationUri.clear();

  ApplicationOverrides overrides;
  overrides.applicationDescriptionPart =
    ApplicationConfig::ApplicationDescriptionPart{.applicationUri = "not-a-uri"};

  ua::ProcessConfigurationFile::ServerInstanceConfig s{
    .name = "s", .applicationOverrides = overrides, .server = {}};

  ProcessConfigurationFile file{std::move(app), {std::move(s)}, {}};
  EXPECT_THROW(file.validate(), UaException);
}

TEST(ConfigurationTests, ProcessConfigurationFile_Validate_RejectsApplicationUriWithWhitespace)
{
  auto app = ApplicationConfig::load_default();
  app.application_description_part().applicationUri.clear();

  ApplicationOverrides overrides;
  overrides.applicationDescriptionPart =
    ApplicationConfig::ApplicationDescriptionPart{.applicationUri = "http://example.invalid/opc ua"};

  ua::ProcessConfigurationFile::ServerInstanceConfig s{
    .name = "s", .applicationOverrides = overrides, .server = {}};

  ProcessConfigurationFile file{std::move(app), {std::move(s)}, {}};
  EXPECT_THROW(file.validate(), UaException);
}

TEST(ConfigurationTests, ProcessConfigurationFile_Validate_RejectsDuplicateServerNames)
{
  auto app = ApplicationConfig::load_default();
  ua::ProcessConfigurationFile::ServerInstanceConfig s1{
    .name = "dup", .applicationOverrides = {}, .server = {}};
  ua::ProcessConfigurationFile::ServerInstanceConfig s2{
    .name = "dup", .applicationOverrides = {}, .server = {}};

  ProcessConfigurationFile file{std::move(app), {std::move(s1), std::move(s2)}, {}};
  EXPECT_THROW(file.validate(), UaException);
}

// --- load_or_create_and_store_default: an existing file is never destroyed -------------------
//
// The wrapper used to catch EVERY failure from load() and write the default over the file, so a
// present-but-corrupt configuration was silently replaced with the listener-less default - the
// operator lost both their settings and the evidence of what broke. The header had always promised
// the opposite ("an existing file ... is never overwritten"). These arms hold the code to it.
//
// The load-safe assertion in each is not that it threw, but that the BYTES ON DISK are unchanged: a
// version that threw after overwriting would satisfy a throw-only test while still destroying the
// file.
namespace
{

/// A path in a fresh temp directory, removed with the directory when the guard dies.
class TempConfigDir
{
public:
  TempConfigDir()
    : mDir(std::filesystem::temp_directory_path() / ("ua_cfg_" + ua::Guid::create_and_generate().as_string()))
  {
    std::filesystem::create_directories(mDir);
  }

  ~TempConfigDir()
  {
    std::error_code ignored;
    std::filesystem::remove_all(mDir, ignored);
  }

  TempConfigDir(const TempConfigDir&) = delete;
  TempConfigDir& operator=(const TempConfigDir&) = delete;

  std::filesystem::path file(std::string_view name) const
  {
    return mDir / name;
  }

private:
  std::filesystem::path mDir;
};

constexpr std::string_view corruptConfig = "{ \"Application\": { this is not json";

void write_file(const std::filesystem::path& path, std::string_view text)
{
  std::ofstream out{path, std::ios::binary | std::ios::trunc};
  out << text;
}

std::string read_file(const std::filesystem::path& path)
{
  std::ifstream in{path, std::ios::binary};
  return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

}  // namespace

// @relation(AC-COMP-SDK-POST-CONFIG, scope=function)
TEST(ConfigurationTests, LoadOrCreate_UnreadableFile_ThrowsAndLeavesTheFileByteIdentical)
{
  const TempConfigDir dir;
  const auto path = dir.file("ProcessConfiguration.json");
  write_file(path, corruptConfig);

  EXPECT_THROW((void)ua::ProcessConfigurationFile::load_or_create_and_store_default(path), ua::UaException);

  // The point of the arm: the operator's file survives untouched.
  EXPECT_EQ(read_file(path), corruptConfig);
}

// @relation(AC-COMP-SDK-POST-CONFIG, scope=function)
TEST(ConfigurationTests, LoadOrCreate_RecoverAndPreserve_KeepsTheOriginalUnderASiblingName)
{
  const TempConfigDir dir;
  const auto path = dir.file("ProcessConfiguration.json");
  write_file(path, corruptConfig);

  const auto recovered = ua::ProcessConfigurationFile::load_or_create_and_store_default(
    path, ua::ProcessConfigurationFile::OnUnreadableFile::RecoverAndPreserve);

  // A default was written in its place...
  EXPECT_NE(read_file(path), corruptConfig);
  EXPECT_FALSE(recovered.servers.empty());
  // ...and the unreadable original is still on disk, byte for byte, for the operator to diagnose.
  auto preserved = path;
  preserved += ".unreadable";
  ASSERT_TRUE(std::filesystem::exists(preserved));
  EXPECT_EQ(read_file(preserved), corruptConfig);
}

// @relation(AC-COMP-SDK-POST-CONFIG, scope=function)
TEST(ConfigurationTests, LoadOrCreate_AbsentFile_StillCreatesTheDefault)
{
  const TempConfigDir dir;
  const auto path = dir.file("ProcessConfiguration.json");
  ASSERT_FALSE(std::filesystem::exists(path));

  const auto created = ua::ProcessConfigurationFile::load_or_create_and_store_default(path);

  EXPECT_TRUE(std::filesystem::exists(path));
  EXPECT_FALSE(created.servers.empty());
}

// SVC-12: the budget is refused when it is zero or below MaxNodesPerBrowse (each operation must keep a
// page), and a disabled budget (nullopt) survives the configuration file as null.
// @verifies AC-SVR-VIEW-BRW-002-A-BROWSE-REQUEST-SHARES-ONE-REFERENCE-BUDGET
TEST(ConfigurationTests, MaxReferencesPerBrowseRequest_ValidatesAgainstMaxNodesPerBrowseAndRoundTripsNull)
{
  ua::server::ServerConfig configuration;
  const auto refusedWith = [&](std::string_view fragment)
  {
    try
    {
      configuration.validate();
    }
    catch (const UaException& e)
    {
      EXPECT_EQ(e.status_code(), Status::BadConfigurationError);
      return std::string_view{e.what()}.find(fragment) != std::string_view::npos;
    }
    return false;
  };
  configuration.maxReferencesPerBrowseRequest = 0;
  EXPECT_TRUE(refusedWith("greater than zero")) << "the zero rule, not the MaxNodesPerBrowse rule";
  configuration.server_capabilities().operationLimits.maxNodesPerBrowse = 1000;
  configuration.maxReferencesPerBrowseRequest = 999;
  EXPECT_TRUE(refusedWith("at least MaxNodesPerBrowse"))
    << "below MaxNodesPerBrowse some operation would get no page";
  configuration.server_capabilities().operationLimits.maxNodesPerBrowse = std::nullopt;
  configuration.maxReferencesPerBrowseRequest = 100;
  EXPECT_TRUE(refusedWith("unlimited operation count")) << "an unlimited operation count cannot be budgeted";
  configuration.server_capabilities().operationLimits.maxNodesPerBrowse = 1000;
  configuration.maxReferencesPerBrowseRequest = 1000;
  EXPECT_NO_THROW(configuration.validate());
  configuration.maxReferencesPerBrowseRequest = std::nullopt;
  EXPECT_NO_THROW(configuration.validate());

  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());
  file.servers.front().server.maxReferencesPerBrowseRequest = std::nullopt;
  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);
  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  ASSERT_FALSE(parsed.servers.empty());
  EXPECT_FALSE(parsed.servers.front().server.maxReferencesPerBrowseRequest.has_value())
    << "a disabled budget is written as null and read back as disabled, not as the default";
}

// DEF-6: with a finite default, an explicit 0 ("unlimited") must survive the configuration file; the
// history section is therefore always written.
// @verifies AC-SVR-HIST-CAP-004-DEFAULT-RETURN-LIMITS-ARE-FINITE
TEST(ConfigurationTests, HistoryUnlimitedZeroRoundTripsThroughTheConfigFile)
{
  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());
  auto& hist = file.servers.front().server.historyConfiguration;
  EXPECT_EQ(hist.maxReturnDataValues, 10000u) << "the default is finite";
  EXPECT_EQ(hist.maxReturnEventValues, 10000u);
  hist.maxReturnDataValues = 0;
  hist.maxReturnEventValues = 0;
  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);
  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  ASSERT_FALSE(parsed.servers.empty());
  EXPECT_EQ(parsed.servers.front().server.historyConfiguration.maxReturnDataValues, 0u)
    << "an explicit 0 is written and read back as 0, not as the default";
  EXPECT_EQ(parsed.servers.front().server.historyConfiguration.maxReturnEventValues, 0u);
}

// OPC 10000-12: the default TrustListValidationOptions has CheckRevocationStatusOffline set (owner decision
// 22.1, certificate-validation test plan U10). Both certificate groups, in the member defaults and in the
// configuration load_default() yields.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-29-REVOCATION-DEFAULT, scope=function)
TEST(ConfigurationTests, TrustListValidationOptionsDefaultToOfflineRevocationChecking)
{
  using Bit = TrustListValidationOptions::Bit;
  const ApplicationConfig::FileTrustListConfig members{};
  EXPECT_TRUE(
    members.defaultApplicationGroupTrustListValidationOptions.test(Bit::CheckRevocationStatusOffline))
    << "the application group's default options must check revocation offline";
  EXPECT_TRUE(members.defaultUserTokenGroupTrustListValidationOptions.test(Bit::CheckRevocationStatusOffline))
    << "the user-token group's default options must check revocation offline";

  auto loaded = ApplicationConfig::load_default();
  EXPECT_TRUE(loaded.file_trust_list_configuration().defaultApplicationGroupTrustListValidationOptions.test(
    Bit::CheckRevocationStatusOffline));
  EXPECT_TRUE(loaded.file_trust_list_configuration().defaultUserTokenGroupTrustListValidationOptions.test(
    Bit::CheckRevocationStatusOffline));
}

// The options survive the JSON round trip both ON (the default) and OFF (an operator's explicit choice):
// a reload must neither drop the default nor turn back on a check the operator switched off.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-29-REVOCATION-DEFAULT, scope=function)
TEST(ConfigurationTests, TrustListValidationOptions_RoundTripJson)
{
  using Bit = TrustListValidationOptions::Bit;
  for (const auto options :
    {TrustListValidationOptions{Bit::CheckRevocationStatusOffline}, TrustListValidationOptions{}})
  {
    auto configuration = ApplicationConfig::load_default();
    configuration.file_trust_list_configuration().defaultApplicationGroupTrustListValidationOptions = options;
    configuration.file_trust_list_configuration().defaultUserTokenGroupTrustListValidationOptions = options;

    memory_stream_device::Dynamic storage{1'000'000, false};
    MemoryStream stream{storage};
    configuration.store(stream);
    stream.seek_from_start(0);
    auto parsed = ApplicationConfig::load(stream);

    EXPECT_EQ(
      parsed.file_trust_list_configuration().defaultApplicationGroupTrustListValidationOptions, options)
      << "the application group's options must survive the JSON round trip";
    EXPECT_EQ(parsed.file_trust_list_configuration().defaultUserTokenGroupTrustListValidationOptions, options)
      << "the user-token group's options must survive the JSON round trip";
  }
}

// The partial-result deadline fraction survives the configuration file with a non-default value; a
// dropped key would read back as the 0.8 default and fail the comparison.
// @relation(AC-SVR-PARTIAL-RESULTS-004-JSON-ROUND-TRIP, scope=function)
TEST(ConfigurationTests, PartialResultDeadlineFraction_RoundTripsJsonWithNonDefaultValue)
{
  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());
  file.servers.front().server.partialResultDeadlineFraction = 0.35;

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);
  stream.seek_from_start(0);
  auto parsed = ProcessConfigurationFile::load(stream);
  ASSERT_FALSE(parsed.servers.empty());
  EXPECT_DOUBLE_EQ(parsed.servers.front().server.partialResultDeadlineFraction, 0.35);
}

// Only a fraction strictly between 0 and 1 is accepted; each refusal is BadConfigurationError naming the
// field. NaN is the case a "f <= 0 || f >= 1" test would let through.
// @relation(AC-SVR-PARTIAL-RESULTS-004-VALIDATION, scope=function)
TEST(ConfigurationTests, PartialResultDeadlineFraction_RejectsValuesOutsideTheOpenInterval)
{
  ua::server::ServerConfig configuration;
  for (const double refused : {0.0, 1.0, -0.25, 1.5, std::numeric_limits<double>::quiet_NaN()})
  {
    configuration.partialResultDeadlineFraction = refused;
    try
    {
      configuration.validate();
      ADD_FAILURE() << "fraction " << refused << " was accepted";
    }
    catch (const UaException& e)
    {
      EXPECT_EQ(e.status_code(), Status::BadConfigurationError) << refused;
      ASSERT_NE(e.detail(), nullptr);
      EXPECT_EQ(e.detail()->code, "InvalidPartialResultDeadlineFraction") << refused;
    }
  }
  for (const double accepted : {0.05, 0.5, 0.95})
  {
    configuration.partialResultDeadlineFraction = accepted;
    EXPECT_NO_THROW(configuration.validate()) << accepted;
  }
}

// A configuration file carrying an invalid fraction is refused when it is loaded, not when a request
// first uses it.
// @relation(AC-SVR-PARTIAL-RESULTS-004-VALIDATION, scope=function)
TEST(ConfigurationTests, PartialResultDeadlineFraction_InvalidValueInFileIsRefusedAtLoad)
{
  auto file = ProcessConfigurationFile::load_default();
  ASSERT_FALSE(file.servers.empty());
  file.servers.front().server.partialResultDeadlineFraction = 0.5;

  memory_stream_device::Dynamic storage{1'000'000, false};
  MemoryStream stream{storage};
  file.store(stream);
  span<const char> bytes{utils::bytes_to_chars(storage.get_data().data()), stream.get_length()};
  std::string json{bytes.begin(), bytes.end()};

  const std::string fieldName{"\"PartialResultDeadlineFraction\""};
  const auto fieldPosition = json.find(fieldName);
  ASSERT_NE(fieldPosition, std::string::npos) << "the writer must emit the key";
  const auto valueStart = json.find_first_of("0123456789-", fieldPosition + fieldName.size());
  const auto valueEnd = json.find_first_of(",}\n", valueStart);
  ASSERT_NE(valueStart, std::string::npos);
  json.replace(valueStart, valueEnd - valueStart, "1.25");

  const auto path = std::filesystem::temp_directory_path() / "ua_invalid_partial_result_fraction.json";
  {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << json;
  }
  try
  {
    EXPECT_THROW(ProcessConfigurationFile::load(path), UaException);
  }
  catch (...)
  {
    std::filesystem::remove(path);
    throw;
  }
  std::filesystem::remove(path);
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-ROUTE-03-A-SERVER-CONFIGURATION-WITH-A-ZERO-LIMIT-IS-REFUSED, scope=function)
TEST(ServiceOperationLimitsType, AServerConfigurationWithAZeroLimitIsRefused)
{
  ua::server::ServerConfig configuration;
  ASSERT_NO_THROW(configuration.validate()) << "a default ServerConfig validates";

  configuration.server_capabilities().operationLimits.maxNodesPerWrite = 0;
  std::optional<StatusCode> refusal;
  try
  {
    configuration.validate();
  }
  catch (const UaException& e)
  {
    refusal = e.status_code();
  }
  EXPECT_TRUE(refusal.has_value()) << "validate() accepted maxNodesPerWrite 0";
  if (refusal)
  {
    EXPECT_EQ(refusal->as_status(), Status::BadConfigurationError);
    ASSERT_NE(refusal->shared_detail(), nullptr);
    EXPECT_EQ(refusal->shared_detail()->code, "InvalidOperationLimit");
    const auto& context = refusal->shared_detail()->context;
    EXPECT_TRUE(std::any_of(context.begin(),
      context.end(),
      [](const NamedValue& entry)
      { return entry.key == ContextKeys::fieldName.value() && entry.value == "maxNodesPerWrite"; }))
      << "the refusal's context does not name maxNodesPerWrite";
  }

  configuration.server_capabilities().operationLimits.maxNodesPerWrite = 1;
  EXPECT_NO_THROW(configuration.validate());
}
