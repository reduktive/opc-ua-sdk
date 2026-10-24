// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_application_configuration.h"
#include "ua_client_configuration.h"
#include "ua_client_encoding_limits.h"

#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <set>
#include <string>
#include <string_view>

namespace
{

using CapacityMap = std::map<std::string, std::string>;

std::string trimmed(std::string value)
{
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
  {
    return {};
  }
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

// Parses the PACKAGED manifest - the revision-substituted artifact copied beside this binary, i.e. the
// document a customer actually receives, not the source template it is generated from.
CapacityMap parse_packaged_manifest()
{
  std::ifstream input{"standard_client_2025_capacities.md"};
  EXPECT_TRUE(input.is_open())
    << "rendered capacity manifest must be delivered beside the package smoke test";

  CapacityMap capacities;
  bool inManifest = false;
  std::string line;
  while (std::getline(input, line))
  {
    if (trimmed(line) == "```uasdk-capacities-v1")
    {
      inManifest = true;
      continue;
    }
    if (inManifest && trimmed(line) == "```")
    {
      break;
    }
    if (!inManifest || trimmed(line).empty())
    {
      continue;
    }
    const auto delimiter = line.find('=');
    if (delimiter == std::string::npos)
    {
      continue;
    }
    capacities.emplace(trimmed(line.substr(0, delimiter)), trimmed(line.substr(delimiter + 1)));
  }
  EXPECT_TRUE(inManifest) << "packaged manifest must carry a uasdk-capacities-v1 block";
  return capacities;
}

// A "figure" is a bare decimal number - a published claim that the client enforces exactly that value.
// Anything else (server-negotiated, resource-bounded, a policy URI plus classification) is prose.
bool is_figure(const std::string& value)
{
  return !value.empty() && value.find_first_not_of("0123456789") == std::string::npos;
}

std::string documented(const CapacityMap& capacities, std::string_view key)
{
  const auto position = capacities.find(std::string{key});
  EXPECT_NE(position, capacities.end()) << "capacity manifest omits an enforced limit: " << key;
  return position == capacities.end() ? std::string{} : position->second;
}

// @verifies CL-DOC-001
// @relation(CL-DOC-001, scope=function)
TEST(StandardClientCapacityPackage, RenderedManifestCarriesExactSourceRevision)
{
  // The release capacity artifact is copied beside the test binary from the development checkout
  // only; its absence is a missing precondition and fails here by name.
  std::ifstream input{"standard_client_2025_capacities.md"};
  ASSERT_TRUE(input.is_open()) << "missing precondition: the rendered capacity manifest "
                                  "standard_client_2025_capacities.md is not beside the test binary";

  const std::string contents{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
  EXPECT_EQ(contents.find("@UASDK_SOURCE_REVISION@"), std::string::npos)
    << "a package must never ship the unresolved source-revision token";
  EXPECT_NE(contents.find("release.source_revision=" UASDK_TEST_SOURCE_REVISION), std::string::npos)
    << "packaged capacity manifest must identify the exact configured source revision";
}

// CL-DOC-001: the manifest must record the transport/message, operation-limit, subscription and
// MonitoredItem families, every figure it publishes must be the limit the client enforces, and where a
// value is server-negotiated or bounded only by available memory it must say so rather than invent a
// fixed number. A plausible implementation hand-writes the figures from the struct literals it happened
// to know about at authoring time, so a figure keeps agreeing with a constant that is no longer the one
// the client installs on the wire because the value now flows through a production derivation the
// manifest never followed. This test therefore reads each figure back through the production path the
// client itself uses - ua::client::make_client_encoding_limits, the same call SecureChannelImpl makes
// when it builds a channel's inbound decode limits, and the connection-protocol limits the client offers
// in Hello - and then checks the other direction only as far as the obligation reaches: a published fixed
// figure must trace to a limit the client really enforces.
// @relation(AC-CL-DOC-001-CAPACITY-MANIFEST, scope=function)
TEST(StandardClientCapacityPackage, PublishedCapacitiesMatchAndCoverTheEnforcedClientLimits)
{
  ASSERT_TRUE(std::ifstream{"standard_client_2025_capacities.md"}.is_open())
    << "missing precondition: the rendered capacity manifest standard_client_2025_capacities.md is not "
       "beside the test binary";
  const auto capacities = parse_packaged_manifest();
  ASSERT_FALSE(capacities.empty()) << "no capacity entries parsed; the comparison would be vacuous";

  auto applicationConfiguration = ua::ApplicationConfig::load_default();
  const auto& transport = applicationConfiguration.stack_limits().connectionProtocolLimits;
  const ua::client::ClientConfig clientConfiguration;
  // Not a re-read of the struct literals: this is the production function ua::client::SecureChannelImpl
  // calls to build a channel's inbound decode limits, fed with the shipped client defaults. If a default
  // override is ever introduced in ClientConfig the derived cap moves and the manifest must follow.
  const auto decode = ua::client::make_client_encoding_limits(applicationConfiguration,
    clientConfiguration.maxInboundStringLength,
    clientConfiguration.maxInboundByteStringLength,
    clientConfiguration.maxInboundArrayLength);

  const CapacityMap enforced{{"transport.default_buffer_size_bytes", std::to_string(transport.maxBufferSize)},
    {"transport.default_max_message_size_bytes", std::to_string(transport.maxMessageSize)},
    {"transport.default_max_chunk_count", std::to_string(transport.maxChunkCount)},
    // DERIVED, not separately configured: CreateSession states back the MaxMessageSize already advertised
    // in Hello, so the published figure must track the transport limit rather than a literal of its own.
    {"client.default_max_response_message_size_bytes", std::to_string(transport.maxMessageSize)},
    {"client.default_incoming_chunk_queue_depth",
      std::to_string(clientConfiguration.incomingChunkQueueDepth)},
    {"client.default_write_queue_depth_per_connection",
      std::to_string(clientConfiguration.writeQueueDepthPerConnection)},
    {"decode.default_max_string_length_bytes", std::to_string(decode.maxStringLength)},
    {"decode.default_max_byte_string_length_bytes", std::to_string(decode.maxByteStringLength)},
    {"decode.default_max_array_length", std::to_string(decode.maxArrayLength)}};

  // Conjunct 1a - every published figure is the limit the client actually enforces.
  for (const auto& [key, enforcedValue] : enforced)
  {
    EXPECT_EQ(documented(capacities, key), enforcedValue)
      << "published figure for " << key << " is not the limit the client enforces";
  }

  // Conjunct 1b - where the value is negotiated or resource-bounded the manifest must say so rather than
  // publish a number the client does not enforce.
  for (const auto* negotiated :
    {"operation_limits.per_service", "subscription.max_subscriptions", "subscription.max_monitored_items"})
  {
    const auto value = documented(capacities, negotiated);
    EXPECT_FALSE(value.empty()) << "server-negotiated capacity must still be stated: " << negotiated;
    EXPECT_FALSE(is_figure(value)) << "the SDK must not invent a fixed numerical limit for " << negotiated;
  }

  std::set<std::string> publishedFigures;
  for (const auto& [key, value] : capacities)
  {
    // release.* identifies the build, it does not claim a capacity - and an all-digit short revision
    // would otherwise read as a published figure with no enforced counterpart behind it.
    if (key.starts_with("release.") || !is_figure(value))
    {
      continue;
    }
    publishedFigures.insert(value);
  }
  ASSERT_FALSE(publishedFigures.empty()) << "manifest publishes no figures at all; nothing to compare";

  std::set<std::string> enforcedValues;
  for (const auto& [key, enforcedValue] : enforced)
  {
    static_cast<void>(key);
    enforcedValues.insert(enforcedValue);
  }
  // The inbound decode budgets ride on the same installed EncodingLimits as the string/byte-string/array
  // caps, so publishing either is a legitimate capacity claim even though nothing obliges it; they belong
  // in the enforced set so conjunct 2 admits them rather than reading them as invented.
  enforcedValues.insert(std::to_string(decode.execution.decodeRecursionDepthLimit));
  enforcedValues.insert(std::to_string(decode.execution.decodeWorkLimit));

  // Conjunct 2 - nothing invented: every fixed figure in the manifest traces to an enforced client limit.
  for (const auto& figure : publishedFigures)
  {
    EXPECT_NE(enforcedValues.find(figure), enforcedValues.end())
      << "manifest publishes the fixed figure " << figure << " that no enforced client limit produces";
  }
}

}  // namespace
