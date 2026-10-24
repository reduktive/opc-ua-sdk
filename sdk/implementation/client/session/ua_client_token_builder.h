// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CLIENT_TOKEN_BUILDER_H
#define UA_CLIENT_TOKEN_BUILDER_H

#include "ua_user_identity.h"

#include "ua_message_security_mode.h"
#include "ua_result.h"
#include "ua_security_policy.h"
#include "ua_user_identity_token.h"
#include "ua_user_token_policy.h"

#include <memory>
#include <string>
#include <vector>

namespace ua::client
{

/// Result of preparing a user identity token for ActivateSession.
struct PreparedToken
{
  std::unique_ptr<ua::UserIdentityToken> wireToken;
  std::shared_ptr<ua::SecurityPolicy> encryptionPolicy;  // null = no encryption needed
  std::shared_ptr<ua::SecurityPolicy> signingPolicy;  // For X509 UserTokenSignature
  std::shared_ptr<const ua::AsymmetricKeyPair> userKeyPair;  // non-null for X509
};

using PreparedTokenResult = ua::Result<PreparedToken>;

/// Build the wire-level user identity token from a high-level UserIdentity.
///
/// Resolves the matching UserTokenPolicy, validates the identity type, constructs
/// the appropriate wire token (AnonymousIdentityToken, UserNameIdentityToken,
/// X509IdentityToken), and determines the encryption/signing policies per
/// Part 4 Table 193.
PreparedTokenResult build_user_token(const UserIdentity& identity, const std::string& policyId,
  const std::vector<ua::UserTokenPolicy>& endpointPolicies,
  const std::shared_ptr<ua::SecurityPolicy>& channelPolicy, ua::MessageSecurityMode channelSecurityMode);

}  // namespace ua::client

#endif  // !UA_CLIENT_TOKEN_BUILDER_H
