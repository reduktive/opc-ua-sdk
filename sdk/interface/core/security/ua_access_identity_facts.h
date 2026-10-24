// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Immutable authenticated-user and endpoint facts shared by authentication and authorization.
/// @ingroup security

#ifndef UA_ACCESS_IDENTITY_FACTS_H
#define UA_ACCESS_IDENTITY_FACTS_H

#include "ua_crypto_types.h"
#include "ua_defines.h"
#include "ua_string.h"

#include <string>
#include <unordered_map>

namespace ua
{

/// Normalized kind of user identity token presented by a client.
///
/// Mirrors the OPC UA UserIdentityToken families, collapsed to the distinctions used by the
/// authentication and authorization surfaces.
/// @ingroup security
enum class UserTokenKind
{
  Anonymous,  ///< No credentials presented (anonymous identity token).
  UserName,  ///< Username/password identity token.
  X509,  ///< X.509 certificate identity token.
  IssuedToken,  ///< Opaque issued identity token, validated by the application.
  Unsupported  ///< Token kind the stack could not normalize; never used post-authentication.
};

/// Symbolic, capitalised rendering of a `UserTokenKind`.
///
/// @param kind Token kind to render.
/// @return The capitalised symbolic name of @p kind.
inline std::string to_string(UserTokenKind kind)
{
  switch (kind)
  {
  case UserTokenKind::Anonymous:
    return "Anonymous";
  case UserTokenKind::UserName:
    return "UserName";
  case UserTokenKind::X509:
    return "X509";
  case UserTokenKind::IssuedToken:
    return "IssuedToken";
  case UserTokenKind::Unsupported:
    return "Unsupported";
  }
  return "Unsupported";
}

/// Sanitized, non-secret security context describing the negotiated endpoint.
///
/// This core value is constructed once after endpoint and token-policy selection, then shared
/// unchanged by authentication, Role evaluation, namespace authorization and Session state.
/// @ingroup security
struct EndpointSecurityContext
{
  MessageSecurityMode messageSecurityMode{};  ///< Negotiated message security mode of the channel.
  SecurityPolicyId securityPolicyId{};  ///< Negotiated security policy of the channel.

  /// Mandatory stable endpoint identifier, formatted as "{listenerName}/{endpointName}".
  std::string endpointPolicyId;

  /// UA UserTokenPolicy policyId selected by the stack, or empty if none applied.
  optional<std::string> userTokenPolicyId;

  /// Certificate-verified calling-client application URI, or empty on an unsecured channel.
  String clientApplicationUri;

  /// Endpoint URL the client connected to.
  String endpointUrl;

  /// Transport profile URI of the negotiated channel.
  String transportProfileUri;
};

/// Stable, SDK-owned identity bound to a Session after successful activation.
/// @ingroup security
struct UserIdentity
{
  std::string userId;  ///< Stable identifier for the authenticated principal.
  std::string displayName;  ///< Human-readable name for display and audit.
  UserTokenKind kind{UserTokenKind::Anonymous};  ///< Token family used to authenticate the principal.

  /// Application-defined identity claims, keyed by claim name.
  std::unordered_map<std::string, std::string> claims;
};

}  // namespace ua

#endif  // UA_ACCESS_IDENTITY_FACTS_H
