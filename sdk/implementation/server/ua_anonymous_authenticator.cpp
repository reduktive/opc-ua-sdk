// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_built_in_authenticators.h"

namespace ua::server
{

void AnonymousAuthenticator::authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept
{
  if (req.identity.kind == UserTokenKind::Anonymous)
  {
    completion(AuthnResult{AuthnSuccess{
      .user =
        UserIdentity{
          .userId = "anonymous", .displayName = "Anonymous", .kind = UserTokenKind::Anonymous, .claims = {}},
      .audit = {}}});
  }
  else
  {
    completion(AuthnResult{ua::StatusCode{ua::Status::BadUserAccessDenied},
      ua::ErrorDetail::build("AnonymousTokenExpected",
        "AnonymousAuthenticator: only anonymous tokens are accepted",
        "AnonymousAuthenticator")
        .context(ua::ContextKeys::tokenKind, to_string(req.identity.kind))});
  }
}

}  // namespace ua::server
