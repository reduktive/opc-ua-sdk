// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_built_in_authenticators.h"
#include "ua_exceptions.h"
#include "ua_to_string.h"

#include <gtest/gtest.h>
#include <optional>
#include <stdexcept>

using namespace ua;
using namespace ua::server;

// @relation(AC-SVR-DIAG-002-PASSWORD-VALIDATOR-CAUSE, scope=function)
TEST(SimpleUserPasswordAuthenticatorTest, ValidatorExceptionsRetainTheirCauses)
{
  const std::shared_ptr<const ErrorDetail> cause =
    ErrorDetail::build("DirectoryUnavailable", "Credential directory is unavailable", "test.authentication");
  for (const bool rich : {true, false})
  {
    SCOPED_TRACE(rich);
    SimpleUserPasswordAuthenticator authenticator{[rich, cause](std::string_view, const SecureString&) -> bool
      {
        if (rich)
          throw UaException{Status::BadResourceUnavailable, cause};
        throw std::runtime_error{"credential directory sentinel"};
      }};
    AuthnRequest request;
    request.identity.kind = UserTokenKind::UserName;
    request.identity.userName = "review-user";
    request.identity.password = SecureString{"secret"};
    size_t completions = 0;
    std::optional<AuthnResult> result;
    authenticator.authenticate_async(std::move(request),
      [&](AuthnResult answer)
      {
        ++completions;
        result.emplace(std::move(answer));
      });
    ASSERT_EQ(completions, 1u);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status_code(), StatusCode{Status::BadInternalError});
    ASSERT_NE(result->shared_detail(), nullptr);
    EXPECT_EQ(result->shared_detail()->code, "ValidationCallbackThrew");
    ASSERT_NE(result->shared_detail()->cause, nullptr);
    if (rich)
    {
      EXPECT_EQ(result->shared_detail()->innerStatus, StatusCode{Status::BadResourceUnavailable}.value());
      EXPECT_EQ(result->shared_detail()->cause, cause);
    }
    else
      EXPECT_NE(
        to_string(*result->shared_detail()->cause).find("credential directory sentinel"), std::string::npos);
  }
}

// @relation(AC-SVR-DIAG-002-PASSWORD-VALIDATOR-CAUSE, scope=function)
TEST(SimpleUserPasswordAuthenticatorTest, CredentialControlsReturnExactlyOneExpectedOutcome)
{
  for (size_t scenario = 0; scenario < 5; ++scenario)
  {
    SCOPED_TRACE(scenario);
    size_t validations = 0;
    SimpleUserPasswordAuthenticator authenticator{
      [&validations, scenario](std::string_view username, const SecureString&)
      {
        ++validations;
        EXPECT_EQ(username, "review-user");
        return scenario == 0;
      }};
    AuthnRequest request;
    request.identity.kind = scenario == 2 ? UserTokenKind::Anonymous : UserTokenKind::UserName;
    if (scenario != 3)
      request.identity.userName = "review-user";
    if (scenario != 4)
      request.identity.password = SecureString{"secret"};
    size_t completions = 0;
    std::optional<AuthnResult> result;
    authenticator.authenticate_async(std::move(request),
      [&](AuthnResult answer)
      {
        ++completions;
        result.emplace(std::move(answer));
      });
    ASSERT_EQ(completions, 1u);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(validations, scenario < 2 ? 1u : 0u);
    if (scenario == 0)
    {
      ASSERT_TRUE(result->is_good());
      EXPECT_EQ(result->value().user.userId, "review-user");
      EXPECT_EQ(result->value().user.kind, UserTokenKind::UserName);
    }
    else
      EXPECT_EQ(result->status_code(),
        StatusCode{scenario < 3 ? Status::BadUserAccessDenied : Status::BadIdentityTokenInvalid});
  }
}
