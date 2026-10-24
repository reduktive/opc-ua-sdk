// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_security.h"

#include "ua_server_authentication.h"
#include "ua_utilities.h"

namespace ua::server
{

void SessionSecurityState::update_on_activate(
  const UserIdentity& user, const EndpointSecurityContext& endpoint)
{
  const std::lock_guard lock{mutex};
  // Spec: "Each time the active user changes, an entry shall be made at the end of the array."
  if (clientUserId != user.userId)
  {
    clientUserId = user.userId;
    if (!clientUserId.empty())
    {
      if (clientUserIdHistory.size() >= maxClientUserIdHistory)
        clientUserIdHistory.erase(clientUserIdHistory.begin(),
          clientUserIdHistory.begin() +
            static_cast<std::ptrdiff_t>(clientUserIdHistory.size() - maxClientUserIdHistory + 1));
      clientUserIdHistory.push_back(clientUserId);
    }
  }

  switch (user.kind)
  {
  case UserTokenKind::Anonymous:
    authenticationMechanism = "Anonymous";
    break;
  case UserTokenKind::UserName:
    authenticationMechanism = "UserName";
    break;
  case UserTokenKind::X509:
    authenticationMechanism = "Certificate";
    break;
  case UserTokenKind::IssuedToken:
    authenticationMechanism = "IssuedToken";
    break;
  case UserTokenKind::Unsupported:
    authenticationMechanism = "Unknown";
    break;
  }

  securityMode = endpoint.messageSecurityMode;
  securityPolicyUri = ua::utils::get_security_policy_uri(endpoint.securityPolicyId);
}

}  // namespace ua::server
