// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/lexical_cast.hpp>
#include "ua_server_endpoint_configuration.h"

#include "ua_error_detail_keys.h"
#include "ua_security_policy.h"
#include "ua_error_detail.h"
#include "ua_security_policy_compatibility.h"

namespace ua::server
{

namespace
{
const std::string userTokenPolicyIdPrefix{"UserTokenPolicyId:"};
}

UserTokenPolicy create_user_token_policy(UserTokenType userTokenType, SecurityPolicyId securityPolicyId)
{
  UserTokenPolicy userTokenPolicy;
  userTokenPolicy.security_policy_uri() = utils::get_security_policy_uri(securityPolicyId);
  userTokenPolicy.token_type() = userTokenType;
  userTokenPolicy.policy_id() = userTokenPolicyIdPrefix +
                                std::to_string(utils::to_underlying(userTokenType)) + ":" +
                                std::to_string(utils::to_underlying(securityPolicyId));
  return userTokenPolicy;
}

UserTokenPolicy create_user_token_policy(string_view policyId)
{
  const std::string id{policyId};

  auto parts = utils::split(id, ':');
  if ((parts.size() != 3) || (parts.front() != userTokenPolicyIdPrefix))
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("InvalidPolicyId",
        "Policy id is not in expected format '<prefix>:<tokenType>:<securityPolicyId>'",
        "EndpointConfiguration")
        .context(ua::ContextKeys::tokenPolicyId, id)};
  }

  return create_user_token_policy(
    utils::from_underlying<UserTokenType>(boost::lexical_cast<uint8_t>(parts[1])),
    utils::from_underlying<SecurityPolicyId>(boost::lexical_cast<uint8_t>(parts[2])));
}

VoidResult validate_endpoint_user_token_policies(const ServerEndpointConfig& config)
{
  for (const auto& tokenPolicy : config.userIdentityTokens)
  {
    auto result =
      validate_user_token_policy(tokenPolicy, config.securityPolicyId, config.messageSecurityMode);
    if (result.is_bad())
      return result;
  }

  auto consistency =
    validate_user_token_policy_certificate_consistency(config.securityPolicyId, config.userIdentityTokens);
  if (consistency.is_bad())
    return consistency;

  return VoidResult{};
}

VoidResult validate_endpoint_security_gates(
  const ApplicationConfig& application, const ServerEndpointConfig& endpoint)
{
  if ((endpoint.securityPolicyId == SecurityPolicyId::None) ||
      (endpoint.messageSecurityMode == MessageSecurityMode::None))
  {
    if (!application.allowInsecureEndpoints)
    {
      return VoidResult{StatusCode{Status::BadSecurityModeRejected},
        ErrorDetail::build(
          "InsecureEndpointRejected", "Insecure endpoints are not allowed by configuration", "ServerImpl")};
    }
  }

  const auto securityPolicy = SecurityPolicy::create(endpoint.securityPolicyId);
  if (securityPolicy->is_deprecated() && !application.allowDeprecatedSecurityPolicies)
  {
    return VoidResult{StatusCode{Status::BadSecurityPolicyRejected},
      ErrorDetail::build("DeprecatedSecurityPolicy",
        "Deprecated security policies are not allowed by configuration",
        "ServerImpl")
        .context(ua::ContextKeys::securityPolicy, std::string{securityPolicy->uri()})};
  }

  // CRY-9: a UserTokenPolicy naming a deprecated SecurityPolicy of its own (the secret is then
  // wrapped with RSA PKCS#1 v1.5) passes the same opt-in as the channel policy. An empty URI inherits
  // the channel policy, gated above.
  for (const auto& tokenPolicy : endpoint.userIdentityTokens)
  {
    const auto& tokenPolicyUri = tokenPolicy.security_policy_uri();
    if (tokenPolicyUri.empty())
      continue;
    const auto tokenPolicyId = utils::get_security_policy_id(tokenPolicyUri);
    if (tokenPolicyId == SecurityPolicyId::Invalid)
      continue;  // validate_endpoint_user_token_policies reports an unknown policy
    if (SecurityPolicy::create(tokenPolicyId)->is_deprecated() &&
        !application.allowDeprecatedSecurityPolicies)
    {
      return VoidResult{StatusCode{Status::BadSecurityPolicyRejected},
        ErrorDetail::build("DeprecatedUserTokenSecurityPolicy",
          "A user token policy names a deprecated security policy, which the configuration does not allow",
          "ServerImpl")
          .context(ua::ContextKeys::securityPolicy, std::string{tokenPolicyUri})
          .context(ua::ContextKeys::tokenPolicyId, std::string{tokenPolicy.policy_id()})};
    }
  }

  return validate_endpoint_user_token_policies(endpoint);
}

}  // namespace ua::server
