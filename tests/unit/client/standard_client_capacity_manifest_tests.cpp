// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_client_configuration.h"
#include "ua_connection_protocol_limits.h"
#include "ua_encoding_limits.h"
#include "ua_security_policy.h"
#include "ua_user_identity.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <concepts>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>

namespace
{

using CapacityMap = std::map<std::string, std::string>;

std::string trim(std::string value)
{
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
  {
    return {};
  }
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

CapacityMap load_capacity_manifest()
{
  std::ifstream input{"standard_client_2025_capacities.md"};
  EXPECT_TRUE(input.is_open())
    << "the committed release capacity artifact must be copied beside the test binary";

  CapacityMap capacities;
  bool inManifest = false;
  std::string line;
  while (std::getline(input, line))
  {
    if (line == "```uasdk-capacities-v1")
    {
      inManifest = true;
      continue;
    }
    if (inManifest && line == "```")
    {
      break;
    }
    if (!inManifest || line.empty())
    {
      continue;
    }

    const auto delimiter = line.find('=');
    EXPECT_NE(delimiter, std::string::npos) << "invalid capacity entry: " << line;
    if (delimiter == std::string::npos)
    {
      continue;
    }
    const auto [position, inserted] =
      capacities.emplace(trim(line.substr(0, delimiter)), trim(line.substr(delimiter + 1)));
    EXPECT_TRUE(inserted) << "duplicate capacity key: " << position->first;
  }
  EXPECT_TRUE(inManifest) << "missing uasdk-capacities-v1 block";
  return capacities;
}

const std::string& capacity(const CapacityMap& capacities, std::string_view key)
{
  const auto position = capacities.find(std::string{key});
  EXPECT_NE(position, capacities.end()) << "missing capacity key: " << key;
  static const std::string missing;
  return position == capacities.end() ? missing : position->second;
}

std::set<std::string> keys_with_prefix(const CapacityMap& capacities, std::string_view prefix)
{
  std::set<std::string> keys;
  for (const auto& [key, value] : capacities)
  {
    static_cast<void>(value);
    if (key.starts_with(prefix))
    {
      keys.insert(key.substr(prefix.size()));
    }
  }
  return keys;
}

std::string value_before_classification(const std::string& value)
{
  const auto separator = value.find('|');
  return trim(value.substr(0, separator));
}

}  // namespace

// @verifies CL-DOC-001
// @relation(CL-DOC-001, scope=function)
/// True when the release capacity artifact sits beside the test binary.
///
/// It is copied there from the development checkout only, and the build copies it solely when
/// that source is present. Its absence fails these tests and names the missing file; a tree that
/// cannot carry the artifact keeps these tests out of its run by label, not by a skip.
bool capacity_manifest_available()
{
  return std::ifstream{"standard_client_2025_capacities.md"}.is_open();
}

TEST(StandardClientCapacityManifest, FixedValuesMatchCompiledProductionDefaults)
{
  ASSERT_TRUE(capacity_manifest_available())
    << "missing standard_client_2025_capacities.md beside the test binary (the private release capacity "
       "artifact, copied from the development checkout)";
  const auto capacities = load_capacity_manifest();
  const ua::client::ClientConfig clientDefaults;
  const ua::EncodingLimits decodeDefaults;

  EXPECT_EQ(capacity(capacities, "release.sdk_version"), UASDK_TEST_RELEASE_VERSION);
  EXPECT_EQ(
    capacity(capacities, "release.profile_uri"), "http://opcfoundation.org/UA-Profile/Client/Standard2025");
  EXPECT_FALSE(capacity(capacities, "release.source_revision").empty());
  EXPECT_EQ(capacity(capacities, "transport.default_buffer_size_bytes"),
    std::to_string(ua::connection_protocol::Limits::defaultBufferSize));
  EXPECT_EQ(capacity(capacities, "transport.default_max_message_size_bytes"),
    std::to_string(ua::connection_protocol::Limits::defaultMaxMessageSize));
  EXPECT_EQ(capacity(capacities, "transport.default_max_chunk_count"),
    std::to_string(ua::connection_protocol::Limits::defaultMaxChunkCount));
  // DERIVED from the transport limit, not a separate client field: the client states in
  // CreateSession the same MaxMessageSize it advertises in Hello. Asserting it against the
  // transport constant is what makes this falsifiable - if the derivation is ever replaced by a
  // literal, the two stop agreeing.
  EXPECT_EQ(capacity(capacities, "client.default_max_response_message_size_bytes"),
    std::to_string(ua::connection_protocol::Limits::defaultMaxMessageSize));
  EXPECT_EQ(capacity(capacities, "client.default_incoming_chunk_queue_depth"),
    std::to_string(clientDefaults.incomingChunkQueueDepth));
  EXPECT_EQ(capacity(capacities, "client.default_write_queue_depth_per_connection"),
    std::to_string(clientDefaults.writeQueueDepthPerConnection));
  EXPECT_EQ(capacity(capacities, "client.default_write_queue_bytes_per_connection"),
    std::to_string(clientDefaults.writeQueueBytesPerConnection));
  EXPECT_EQ(capacity(capacities, "decode.default_max_string_length_bytes"),
    std::to_string(decodeDefaults.maxStringLength));
  EXPECT_EQ(capacity(capacities, "decode.default_max_byte_string_length_bytes"),
    std::to_string(decodeDefaults.maxByteStringLength));
  EXPECT_EQ(
    capacity(capacities, "decode.default_max_array_length"), std::to_string(decodeDefaults.maxArrayLength));
  EXPECT_EQ(capacity(capacities, "operation_limits.per_service"), "server-advertised-and-enforced");
  EXPECT_EQ(capacity(capacities, "subscription.max_subscriptions"), "server-and-resource-bounded");
  EXPECT_EQ(capacity(capacities, "subscription.max_monitored_items"), "server-and-resource-bounded");
}

// @verifies CL-DOC-001
// @relation(CL-DOC-001, scope=function)
TEST(StandardClientCapacityManifest, CoversCompiledSecurityAndIdentityCapabilitiesBidirectionally)
{
  ASSERT_TRUE(capacity_manifest_available())
    << "missing standard_client_2025_capacities.md beside the test binary (the private release capacity "
       "artifact, copied from the development checkout)";
  const auto capacities = load_capacity_manifest();

  std::set<std::string> documentedPolicyUris;
  for (const auto& [key, value] : capacities)
  {
    if (key.starts_with("security_policy."))
    {
      documentedPolicyUris.insert(value_before_classification(value));
    }
  }

  std::set<std::string> compiledPolicyUris;
  for (const auto policyId : ua::SecurityPolicy::supported_policy_ids())
  {
    const auto policy = ua::SecurityPolicy::create(policyId);
    ASSERT_NE(policy, nullptr);
    compiledPolicyUris.emplace(policy->uri());
  }
  EXPECT_EQ(documentedPolicyUris, compiledPolicyUris);
  EXPECT_NE(
    capacity(capacities, "security_policy.Basic256Sha256").find("standard-required"), std::string::npos);
  EXPECT_NE(
    capacity(capacities, "security_policy.Aes128Sha256RsaOaep").find("standard-required"), std::string::npos);

  EXPECT_EQ(keys_with_prefix(capacities, "message_security_mode."),
    (std::set<std::string>{"None", "Sign", "SignAndEncrypt"}));

  static_assert(std::variant_size_v<ua::client::UserIdentity> == 4);
  static_assert(
    std::same_as<std::variant_alternative_t<0, ua::client::UserIdentity>, ua::client::AnonymousIdentity>);
  static_assert(std::same_as<std::variant_alternative_t<1, ua::client::UserIdentity>,
    ua::client::UsernamePasswordIdentity>);
  static_assert(
    std::same_as<std::variant_alternative_t<2, ua::client::UserIdentity>, ua::client::X509Identity>);
  static_assert(
    std::same_as<std::variant_alternative_t<3, ua::client::UserIdentity>, ua::client::IssuedTokenIdentity>);
  EXPECT_EQ(keys_with_prefix(capacities, "user_token."),
    (std::set<std::string>{"Anonymous", "IssuedToken", "UsernamePassword", "X509"}));
  EXPECT_EQ(capacity(capacities, "user_token.Anonymous"), "standard-qualified");
  EXPECT_EQ(capacity(capacities, "user_token.UsernamePassword"), "standard-qualified");
}
