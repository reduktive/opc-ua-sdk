// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_ENDPOINT_CONFIGURATION_H
#define UA_SERVER_ENDPOINT_CONFIGURATION_H

#include "ua_application_configuration.h"
#include "ua_message_security_mode.h"
#include "ua_result.h"
#include "ua_user_token_policy.h"

/// @file
/// @brief Endpoint security configuration for a server listener.
/// @ingroup server

namespace ua
{

namespace server
{

/// Security configuration for a single server endpoint exposed by a listener.
///
/// Describes one endpoint a client may connect to: its message security mode,
/// security policy, transport profile, and the user identity tokens it accepts.
/// A listener typically exposes several of these (e.g. one per security
/// policy/mode pairing). The defaults select the most secure common
/// combination (Sign-and-encrypt with @ref SecurityPolicyId::Aes128Sha256RsaOaep
/// over UA-TCP UA-SC UA-Binary).
///
/// @ingroup server
struct ServerEndpointConfig
{
  /// Stable endpoint identifier, unique within its listener.
  ///
  /// Used to derive the mandatory endpoint policy id, formed as
  /// `"{listenerName}/{endpointName}"`. Must be unique among the endpoints of
  /// the same listener.
  std::string name;

  /// Message security mode required on the secure channel (default Sign-and-encrypt).
  MessageSecurityMode messageSecurityMode{MessageSecurityMode::SignAndEncrypt};

  /// Security policy applied to the secure channel (default Aes128Sha256RsaOaep).
  SecurityPolicyId securityPolicyId{SecurityPolicyId::Aes128Sha256RsaOaep};

  /// Transport profile for the endpoint (default UA-TCP UA-SC UA-Binary).
  TransportProfileId transportProfile{TransportProfileId::UaTcpUaScUaBinary};

  /// User identity tokens this endpoint accepts, in order of server preference.
  std::vector<UserTokenPolicy> userIdentityTokens;

  /// Compares two configurations field by field for equality.
  ///
  /// @param obj Configuration to compare against.
  /// @return true when every field compares equal, otherwise false.
  bool operator==(const ServerEndpointConfig& obj) const = default;
};

/// Builds a user token policy for the given token type and security policy.
///
/// The policy id is derived from @p userTokenType and @p securityPolicyId so
/// that it is unique within an endpoint.
///
/// @param userTokenType    Kind of identity token the policy describes.
/// @param securityPolicyId Security policy used to secure the token.
/// @return The constructed `UserTokenPolicy`.
UserTokenPolicy create_user_token_policy(UserTokenType userTokenType, SecurityPolicyId securityPolicyId);

/// Builds a user token policy from a pre-formed policy id.
///
/// @param policyId Policy id whose embedded token type and security policy are decoded.
/// @return The constructed `UserTokenPolicy`.
UserTokenPolicy create_user_token_policy(string_view policyId);

/// Validates that an endpoint's user token policies are compatible with its
/// channel security settings.
///
/// Checks each entry of `ServerEndpointConfig::userIdentityTokens`
/// against the endpoint's message security mode and security policy.
///
/// @param config Endpoint configuration to validate.
/// @return A successful result if every policy is compatible; otherwise a bad
///         result whose `ErrorDetail` describes the first invalid
///         combination found. Never throws.
VoidResult validate_endpoint_user_token_policies(const ServerEndpointConfig& config);

/// Runs the security gates every endpoint the server serves must pass, whatever path declared it:
/// an insecure endpoint (SecurityPolicy None or MessageSecurityMode None) needs
/// `ApplicationConfig::allowInsecureEndpoints`, a deprecated security policy needs
/// `mAllowDeprecatedSecurityPolicies`, and the user token policies must fit the channel
/// (@ref ua::server::validate_endpoint_user_token_policies). `Server::add_endpoint`, the endpoints declared
/// on a listener or a reverse-connect target in `ServerConfig` (checked by `Server::create`) and a
/// reverse-connect target started at runtime all go through this one function.
///
/// @param application Application security permissions applied to the endpoint.
/// @param endpoint Endpoint configuration to validate.
/// @return Good, or the first gate's refusal: `Bad_SecurityModeRejected` (`InsecureEndpointRejected`),
///         `Bad_SecurityPolicyRejected` (`DeprecatedSecurityPolicy`), or the token-policy result.
VoidResult validate_endpoint_security_gates(
  const ApplicationConfig& application, const ServerEndpointConfig& endpoint);

}  // namespace server

}  // namespace ua

#endif  // !UA_SERVER_ENDPOINT_CONFIGURATION_H
