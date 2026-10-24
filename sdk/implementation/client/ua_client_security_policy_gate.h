// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side deprecated SecurityPolicy classification and fail-closed gate.

#ifndef UA_CLIENT_SECURITY_POLICY_GATE_H
#define UA_CLIENT_SECURITY_POLICY_GATE_H

#include "ua_crypto_types.h"
#include "ua_result.h"

#include <string_view>

namespace ua
{
class Logger;
}

namespace ua::client::detail
{

/// Validates a client-selected SecurityPolicy against the frozen application opt-in.
///
/// Deprecation is read exclusively through SecurityPolicy::is_deprecated(); this function does not maintain
/// a policy-id list.
[[nodiscard]] ua::VoidResult validate_client_security_policy(
  ua::SecurityPolicyId securityPolicyId, bool allowDeprecatedSecurityPolicies);

/// URI-form gate used for remote/manual endpoint descriptions. Unknown policy URIs are not classified as
/// deprecated here; the normal supported-policy validation remains responsible for rejecting them.
[[nodiscard]] ua::VoidResult validate_client_security_policy_uri(
  std::string_view securityPolicyUri, bool allowDeprecatedSecurityPolicies) noexcept;

/// Reports whether a recognised policy URI delegates to an `is_deprecated() == true` implementation.
[[nodiscard]] bool is_deprecated_client_security_policy_uri(std::string_view securityPolicyUri) noexcept;

/// Emits the process-registry warning for an explicitly permitted deprecated policy at most once.
void warn_deprecated_client_security_policy_once(
  ua::SecurityPolicyId securityPolicyId, const ua::Logger& logger);

}  // namespace ua::client::detail

#endif  // UA_CLIENT_SECURITY_POLICY_GATE_H
