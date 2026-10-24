// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Startup consistency check for the advertised ServerProfileArray.
//
// find_advertised_profile_inconsistencies() scans the advertised conformance profile URIs against
// the SDK's boolean feature toggles and reports any profile that claims a feature this configuration
// has disabled. It is deliberately lightweight - only the unambiguous boolean-gated facets
// (auditing, durable subscriptions). These tests pin the detection, the case-insensitive matching,
// and the "no false positive" cases. (Falsifiable: stubbing the function to return {} makes the
// positive-detection tests fail.)

#include <memory>
#include <mutex>
#include <string>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_server_configuration.h"
#include "ua_server_model.h"
#include "ua_test_server.h"

namespace ua::server
{
namespace
{

constexpr const char* auditingProfile = "http://opcfoundation.org/UA-Profile/Server/Auditing";
constexpr const char* durableProfile = "http://opcfoundation.org/UA-Profile/Server/DurableSubscription";
constexpr const char* standardProfile = "http://opcfoundation.org/UA-Profile/Server/StandardUA2017";

// A LogSink that records entries for assertion. It copies everything it needs (message is owned;
// category and the "profile" field's string_view are caller-owned and only valid during the call).
class CapturingLogSink : public ua::LogSink
{
public:
  struct Record
  {
    ua::LogLevel level;
    std::string message;
    std::string profile;  ///< the "profile" structured field, if present
  };

  void log(const ua::LogEntry& entry) override
  {
    std::string profile;
    for (const auto& field : entry.fields)
    {
      if (field.key == "profile")
      {
        if (const auto* text = std::get_if<std::string_view>(&field.value))
        {
          profile = std::string{*text};
        }
      }
    }
    std::lock_guard lock{mMutex};
    mRecords.push_back({entry.level, entry.message, std::move(profile)});
  }

  std::vector<Record> records()
  {
    std::lock_guard lock{mMutex};
    return mRecords;
  }

private:
  std::mutex mMutex;
  std::vector<Record> mRecords;
};

TEST(AdvertisedProfileConsistency, NoProfilesAdvertisedIsConsistent)
{
  ServerConfig config;  // default: empty ServerProfileArray
  EXPECT_TRUE(find_advertised_profile_inconsistencies(config).empty());
}

TEST(AdvertisedProfileConsistency, UnrelatedProfileWithFeaturesOffIsConsistent)
{
  ServerConfig config;
  config.auditingEnabled = false;
  config.subscriptionLimits.durableSubscriptionsEnabled = false;
  config.server_capabilities().serverProfiles = {standardProfile};
  EXPECT_TRUE(find_advertised_profile_inconsistencies(config).empty())
    << "a profile that gates no checked feature must not be flagged";
}

TEST(AdvertisedProfileConsistency, AuditingProfileWithAuditingDisabledIsFlagged)
{
  ServerConfig config;
  config.auditingEnabled = false;
  config.server_capabilities().serverProfiles = {auditingProfile};

  const auto issues = find_advertised_profile_inconsistencies(config);
  ASSERT_EQ(issues.size(), 1u);
  EXPECT_EQ(issues[0].profileUri, auditingProfile);
  EXPECT_EQ(issues[0].disabledSetting, "ServerConfig::auditingEnabled");
}

TEST(AdvertisedProfileConsistency, AuditingProfileWithAuditingEnabledIsConsistent)
{
  ServerConfig config;
  config.auditingEnabled = true;
  config.server_capabilities().serverProfiles = {auditingProfile};
  EXPECT_TRUE(find_advertised_profile_inconsistencies(config).empty());
}

TEST(AdvertisedProfileConsistency, DurableSubscriptionProfileWithFeatureDisabledIsFlagged)
{
  ServerConfig config;
  config.subscriptionLimits.durableSubscriptionsEnabled = false;
  config.server_capabilities().serverProfiles = {durableProfile};

  const auto issues = find_advertised_profile_inconsistencies(config);
  ASSERT_EQ(issues.size(), 1u);
  EXPECT_EQ(issues[0].disabledSetting, "ServerConfig::subscriptionLimits.durableSubscriptionsEnabled");
}

TEST(AdvertisedProfileConsistency, MatchIsCaseInsensitive)
{
  ServerConfig config;
  config.auditingEnabled = false;
  config.server_capabilities().serverProfiles = {"urn:example:server:profile:auditing-facet"};
  EXPECT_EQ(find_advertised_profile_inconsistencies(config).size(), 1u)
    << "the marker must match case-insensitively against the operator-provided URI";
}

TEST(AdvertisedProfileConsistency, MultipleProfilesEachReported)
{
  ServerConfig config;
  config.auditingEnabled = false;
  config.subscriptionLimits.durableSubscriptionsEnabled = false;
  config.server_capabilities().serverProfiles = {auditingProfile, durableProfile, standardProfile};
  EXPECT_EQ(find_advertised_profile_inconsistencies(config).size(), 2u)
    << "both the auditing and durable-subscription claims are inconsistent; the standard profile is not";
}

// --- startup wiring -------------------------------------------------------------------------------
//
// The pure function above is only useful if start() actually invokes it through the operator's
// configured log sink. The check runs in ServerImpl::start() - NOT at model creation - precisely
// because set_log_sink() is installed after Server::create() returns; a warning emitted at
// construction would be discarded by the not-yet-configured (sink-less) logger.
//
// Falsifiable: reverting the check back to ServerModel::create() (construction time) makes
// StartupWiring_LogsWarningForInconsistentProfile fail - the warning lands in the no-op construction
// logger and never reaches the capturing sink installed afterwards.

TEST(AdvertisedProfileConsistency, StartupWiring_LogsWarningForInconsistentProfile)
{
  auto sink = std::make_shared<CapturingLogSink>();
  ua::test_helpers::TestServer server;
  server.create(
    [](ServerConfig& cfg)
    {
      cfg.auditingEnabled = false;  // disabled...
      cfg.server_capabilities().serverProfiles = {auditingProfile};  // ...yet advertised
    },
    sink,
    ua::LogLevel::Warning);
  // The sink is installed at construction; ServerImpl::start() runs the profile-consistency check.
  server.start();

  bool warned = false;
  for (const auto& record : sink->records())
  {
    if (record.level == ua::LogLevel::Warning && record.profile == auditingProfile &&
        record.message.find("ServerProfile") != std::string::npos)
    {
      warned = true;
    }
  }
  EXPECT_TRUE(warned)
    << "ServerImpl::start() must surface the advertised-profile inconsistency through the configured sink";
}

TEST(AdvertisedProfileConsistency, StartupWiring_SilentWhenConsistent)
{
  auto sink = std::make_shared<CapturingLogSink>();
  ua::test_helpers::TestServer server;
  server.create(
    [](ServerConfig& cfg)
    {
      cfg.auditingEnabled = true;  // enabled...
      cfg.server_capabilities().serverProfiles = {auditingProfile};  // ...and advertised - consistent
    },
    sink,
    ua::LogLevel::Warning);
  server.start();

  for (const auto& record : sink->records())
  {
    EXPECT_EQ(record.message.find("ServerProfile claims a feature"), std::string::npos)
      << "a consistent configuration must not emit the advertised-profile warning";
  }
}

}  // namespace
}  // namespace ua::server
