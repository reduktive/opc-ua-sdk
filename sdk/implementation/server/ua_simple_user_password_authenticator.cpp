// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_built_in_authenticators.h"

#include "ua_to_string.h"
#include "ua_to_result.h"

namespace ua::server
{

SimpleUserPasswordAuthenticator::SimpleUserPasswordAuthenticator(ValidateFn validate)
  : mValidate(std::move(validate))
{}

void SimpleUserPasswordAuthenticator::authenticate_async(AuthnRequest req, AuthnComplete completion) noexcept
{
  static const std::string source{"SimpleUserPasswordAuthenticator"};

  if (req.identity.kind != UserTokenKind::UserName)
  {
    completion(AuthnResult{ua::StatusCode{ua::Status::BadUserAccessDenied},
      ua::ErrorDetail::build("UserNameTokenExpected",
        "SimpleUserPasswordAuthenticator: only username/password tokens are accepted",
        source)
        .context(ua::ContextKeys::sessionId, ua::to_string(req.sessionId))
        .context(ua::ContextKeys::requestHandle, std::to_string(req.requestHandle))});
    return;
  }

  if (!req.identity.userName || !req.identity.password)
  {
    completion(AuthnResult{ua::StatusCode{ua::Status::BadIdentityTokenInvalid},
      ua::ErrorDetail::build(
        "MissingCredentials", "SimpleUserPasswordAuthenticator: missing username or password", source)
        .context(ua::ContextKeys::sessionId, ua::to_string(req.sessionId))
        .context(ua::ContextKeys::requestHandle, std::to_string(req.requestHandle))});
    return;
  }

  bool valid = false;
  try
  {
    valid = mValidate(*req.identity.userName, *req.identity.password);
  }
  catch (...)
  {
    completion(AuthnResult{ua::StatusCode{ua::Status::BadInternalError},
      ua::ErrorDetail::build("ValidationCallbackThrew",
        "SimpleUserPasswordAuthenticator: validation callback threw an exception",
        source)
        .context(ua::ContextKeys::sessionId, ua::to_string(req.sessionId))
        .context(ua::ContextKeys::requestHandle, std::to_string(req.requestHandle))
        .cause(ua::exception_to_status_code(std::current_exception()))});
    return;
  }

  if (valid)
  {
    completion(AuthnResult{AuthnSuccess{.user = UserIdentity{.userId = *req.identity.userName,
                                          .displayName = *req.identity.userName,
                                          .kind = UserTokenKind::UserName,
                                          .claims = {}},
      .audit = {}}});
  }
  else
  {
    completion(AuthnResult{ua::StatusCode{ua::Status::BadUserAccessDenied},
      ua::ErrorDetail::build(
        "InvalidCredentials", "SimpleUserPasswordAuthenticator: invalid credentials", source)
        .context(ua::ContextKeys::sessionId, ua::to_string(req.sessionId))
        .context(ua::ContextKeys::requestHandle, std::to_string(req.requestHandle))});
  }
}

}  // namespace ua::server
