// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_built_in_authenticators.h"

namespace ua::server
{

void CompositeAuthenticator::add(UserTokenKind kind, std::shared_ptr<UserAuthenticator> authenticator)
{
  mDelegates.push_back({kind, std::move(authenticator)});
}

void CompositeAuthenticator::authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept
{
  for (const auto& entry : mDelegates)
  {
    if (entry.kind == req.identity.kind)
    {
      entry.authenticator->authenticate_async(std::move(req), std::move(completion));
      return;
    }
  }

  completion(AuthnResult{ua::StatusCode{ua::Status::BadIdentityTokenRejected},
    ua::ErrorDetail::build("NoDelegateForTokenKind",
      "CompositeAuthenticator: no delegate registered for this token kind",
      "CompositeAuthenticator")
      .context(ua::ContextKeys::tokenKind, ua::server::to_string(req.identity.kind))});
}

}  // namespace ua::server
