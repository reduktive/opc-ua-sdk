// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_client_security_policy_gate.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_logger.h"
#include "ua_security_policy.h"
#include "ua_to_result.h"

#include <mutex>
#include <unordered_set>

namespace ua::client::detail
{

namespace
{

ua::VoidResult validate_policy(const ua::SecurityPolicy& policy, bool allowDeprecatedSecurityPolicies)
{
  if (!policy.is_deprecated() || allowDeprecatedSecurityPolicies)
  {
    return ua::VoidResult{};
  }

  return ua::VoidResult{ua::Status::BadSecurityPolicyRejected,
    ua::ErrorDetail::build("DeprecatedSecurityPolicy",
      "deprecated security policies are disabled by the application configuration",
      "client.security_policy")
      .context(ua::ContextKeys::securityPolicy, std::string{policy.uri()})
      .context(ua::ContextKeys::fieldName, std::string{"AllowDeprecatedSecurityPolicies"})
      .context(ua::ContextKeys::actual, std::string{"false"})};
}

}  // namespace

ua::VoidResult validate_client_security_policy(
  ua::SecurityPolicyId securityPolicyId, bool allowDeprecatedSecurityPolicies)
{
  const auto policy = ua::SecurityPolicy::create(securityPolicyId);
  return validate_policy(*policy, allowDeprecatedSecurityPolicies);
}

ua::VoidResult validate_client_security_policy_uri(
  std::string_view securityPolicyUri, bool allowDeprecatedSecurityPolicies) noexcept
{
  try
  {
    return validate_policy(*ua::SecurityPolicy::create(securityPolicyUri), allowDeprecatedSecurityPolicies);
  }
  catch (...)
  {
    auto status = ua::exception_to_status_code(std::current_exception());
    if (status == ua::StatusCode{ua::Status::BadInvalidArgument})
    {
      // This helper owns only the deprecation decision. An unknown URI is not in the SDK's deprecated set;
      // the normal policy-support validator retains responsibility for rejecting it with its richer error.
      return ua::VoidResult{};
    }
    return ua::VoidResult{std::move(status)};
  }
}

bool is_deprecated_client_security_policy_uri(std::string_view securityPolicyUri) noexcept
{
  try
  {
    return ua::SecurityPolicy::create(securityPolicyUri)->is_deprecated();
  }
  catch (...)
  {
    return false;
  }
}

void warn_deprecated_client_security_policy_once(
  ua::SecurityPolicyId securityPolicyId, const ua::Logger& logger)
{
  const auto policy = ua::SecurityPolicy::create(securityPolicyId);
  if (!policy->is_deprecated() || !logger.is_enabled(ua::LogLevel::Warning))
  {
    return;
  }

  static std::mutex warnedMutex;
  static std::unordered_set<std::string> warnedPolicies;
  const std::string policyUri{policy->uri()};
  {
    const std::lock_guard lock{warnedMutex};
    if (!warnedPolicies.insert(policyUri).second)
    {
      return;
    }
  }

  // Log outside the registry lock: a user-provided sink must never be invoked while SDK state is locked.
  logger.warning({{"security_policy", policyUri}},
    "Deprecated security policy enabled by AllowDeprecatedSecurityPolicies");
}

}  // namespace ua::client::detail
