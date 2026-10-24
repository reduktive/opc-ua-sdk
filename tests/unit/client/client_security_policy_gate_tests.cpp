// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_client_security_policy_gate.h"

#include "ua_error_detail.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_sec_pol_aes128_sha256_rsa_oaep.h"
#include "ua_sec_pol_basic128_rsa15.h"
#include "ua_sec_pol_basic256.h"
#include "ua_status.h"
#include "ua_utilities.h"

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace
{

using ua::client::detail::validate_client_security_policy;

class RecordingLogSink final : public ua::LogSink
{
public:
  void log(const ua::LogEntry& entry) override
  {
    const std::lock_guard lock{mMutex};
    mMessages.push_back(entry.message);
  }

  [[nodiscard]] std::vector<std::string> messages() const
  {
    const std::lock_guard lock{mMutex};
    return mMessages;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mMessages;
};

// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST(ClientSecurityPolicyGate, RejectsEveryDeprecatedPolicyByDefault)
{
  for (const auto policyId : {ua::SecurityPolicyId::Basic128Rsa15, ua::SecurityPolicyId::Basic256})
  {
    auto result = validate_client_security_policy(policyId, false);
    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadSecurityPolicyRejected});
    ASSERT_TRUE(result.shared_detail());
    EXPECT_EQ(result.shared_detail()->code, "DeprecatedSecurityPolicy");
    const auto detail = ua::to_string(*result.shared_detail());
    EXPECT_NE(detail.find(std::string{ua::utils::get_security_policy_uri(policyId)}), std::string::npos);
    EXPECT_NE(detail.find("AllowDeprecatedSecurityPolicies"), std::string::npos);
  }
}

// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST(ClientSecurityPolicyGate, AllowsDeprecatedPolicyOnlyWithExplicitOptIn)
{
  EXPECT_TRUE(validate_client_security_policy(ua::SecurityPolicyId::Basic128Rsa15, true).is_good());
  EXPECT_TRUE(validate_client_security_policy(ua::SecurityPolicyId::Basic256, true).is_good());
}

// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST(ClientSecurityPolicyGate, AllowsCurrentPolicyWithoutOptIn)
{
  EXPECT_TRUE(validate_client_security_policy(ua::SecurityPolicyId::Aes128Sha256RsaOaep, false).is_good());
}

// Classification delegates to the virtual policy contract rather than duplicating a deprecated ID list.
// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST(ClientSecurityPolicyGate, UtilityClassificationMatchesPolicyVirtual)
{
  for (const auto policyId : ua::SecurityPolicy::supported_policy_ids())
  {
    EXPECT_EQ(ua::utils::is_deprecated_security_policy(policyId),
      ua::SecurityPolicy::create(policyId)->is_deprecated());
  }
}

// The client policy registry warns once for each deprecated policy, not once per Client/use.
// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST(ClientSecurityPolicyGate, WarningCadenceIsOncePerDeprecatedPolicy)
{
  auto sink = std::make_shared<RecordingLogSink>();
  auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
  ua::Logger logger{sink, level, "client"};

  ua::client::detail::warn_deprecated_client_security_policy_once(
    ua::SecurityPolicyId::Basic128Rsa15, logger);
  ua::client::detail::warn_deprecated_client_security_policy_once(
    ua::SecurityPolicyId::Basic128Rsa15, logger);
  ua::client::detail::warn_deprecated_client_security_policy_once(ua::SecurityPolicyId::Basic256, logger);
  ua::client::detail::warn_deprecated_client_security_policy_once(ua::SecurityPolicyId::Basic256, logger);
  ua::client::detail::warn_deprecated_client_security_policy_once(
    ua::SecurityPolicyId::Aes128Sha256RsaOaep, logger);

  const auto messages = sink->messages();
  ASSERT_EQ(messages.size(), 2u);
  EXPECT_EQ(messages[0], "Deprecated security policy enabled by AllowDeprecatedSecurityPolicies");
  EXPECT_EQ(messages[1], "Deprecated security policy enabled by AllowDeprecatedSecurityPolicies");
}

}  // namespace
