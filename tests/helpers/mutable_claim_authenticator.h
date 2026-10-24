// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_HELPERS_MUTABLE_CLAIM_AUTHENTICATOR_H
#define UA_TEST_HELPERS_MUTABLE_CLAIM_AUTHENTICATOR_H

#include "ua_server_authentication.h"
#include "ua_to_result.h"

#include <chrono>
#include <exception>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace ua::test_helpers
{

/// Anonymous test authenticator whose claim set can be changed before a new
/// Session is activated. Its empty-claim behaviour matches
/// `AnonymousAuthenticator`; mutation is test-fixture configuration, not a
/// production authentication surface.
class MutableClaimAuthenticator final : public ua::server::UserAuthenticator
{
public:
  void set_claims(std::unordered_map<std::string, std::string> claims)
  {
    std::lock_guard lock(mMutex);
    mClaims = std::move(claims);
  }

  void authenticate_async(
    ua::server::AuthnRequest request, ua::server::AuthnComplete completion) noexcept override
  {
    {
      std::lock_guard lock(mMutex);
      if (request.deadline)
        mLastDeadlineBudget = std::chrono::duration_cast<std::chrono::milliseconds>(
          *request.deadline - std::chrono::steady_clock::now());
      else
        mLastDeadlineBudget.reset();
    }
    completion(authenticate(std::move(request)));
  }

  [[nodiscard]] std::optional<std::chrono::milliseconds> last_deadline_budget() const
  {
    std::lock_guard lock(mMutex);
    return mLastDeadlineBudget;
  }

private:
  ua::server::AuthnResult authenticate(ua::server::AuthnRequest request) noexcept
  {
    try
    {
      if (request.identity.kind != ua::server::UserTokenKind::Anonymous)
      {
        return ua::server::AuthnResult{ua::StatusCode{ua::Status::BadUserAccessDenied},
          ua::ErrorDetail::build("AnonymousTokenExpected",
            "MutableClaimAuthenticator: only anonymous tokens are accepted",
            "MutableClaimAuthenticator")
            .context(ua::ContextKeys::tokenKind, ua::server::to_string(request.identity.kind))};
      }

      std::unordered_map<std::string, std::string> claims;
      {
        std::lock_guard lock(mMutex);
        claims = mClaims;
      }

      ua::server::UserIdentity user{.userId = "anonymous",
        .displayName = "Anonymous",
        .kind = ua::server::UserTokenKind::Anonymous,
        .claims = std::move(claims)};
      return ua::server::make_authn_success(std::move(user));
    }
    catch (...)
    {
      return ua::server::AuthnResult{ua::exception_to_status_code(std::current_exception())};
    }
  }

  mutable std::mutex mMutex;
  std::unordered_map<std::string, std::string> mClaims;
  std::optional<std::chrono::milliseconds> mLastDeadlineBudget;
};

}  // namespace ua::test_helpers

#endif  // !UA_TEST_HELPERS_MUTABLE_CLAIM_AUTHENTICATOR_H
