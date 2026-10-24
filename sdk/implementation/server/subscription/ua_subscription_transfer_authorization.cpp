// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_subscription_transfer_authorization.h"

#include "ua_claim_keys.h"

#include "ua_error_detail.h"
#include "ua_to_string.h"

#include <string>
#include <string_view>

namespace ua::server
{
namespace
{

bool is_signed(MessageSecurityMode mode) noexcept
{
  return mode == MessageSecurityMode::Sign || mode == MessageSecurityMode::SignAndEncrypt;
}

StatusCode deny_anonymous_transfer(std::string_view reason, const SubscriptionTransferContext& source,
  const EndpointSecurityContext& requestingSecurity)
{
  return StatusCode{Status::BadUserAccessDenied,
    ErrorDetail::build("AnonymousTransferContextInvalid",
      std::string{"Anonymous subscription transfer refused: "} + std::string{reason},
      "SubscriptionTransferAuthorization")
      .context(
        ContextKeys::expected, std::string{static_cast<std::string_view>(source.verifiedApplicationUri)})
      .context(ContextKeys::actual,
        std::string{static_cast<std::string_view>(requestingSecurity.clientApplicationUri)})
      .context(ContextKeys::securityMode, to_string(requestingSecurity.messageSecurityMode))};
}

}  // namespace

StatusCode validate_subscription_transfer(const SubscriptionTransferContext& source,
  const UserIdentity& requestingUser, const EndpointSecurityContext& requestingSecurity)
{
  if (source.owningUser.kind != UserTokenKind::Anonymous)
  {
    // The principal is the (token kind, user id) pair: an X.509 identity whose certificate name equals
    // a UserName user's name does not own that user's Subscriptions. For X.509 the user id is the
    // certificate's common name, which two different certificates can share, so the principal there
    // is the thumbprint claim the authenticator stored; a missing claim on either side fails closed.
    if (source.owningUser.kind == requestingUser.kind)
    {
      if (source.owningUser.kind == UserTokenKind::X509)
      {
        const auto owner = source.owningUser.claims.find(ClaimKeys::thumbprint);
        const auto requester = requestingUser.claims.find(ClaimKeys::thumbprint);
        if (owner != source.owningUser.claims.end() && requester != requestingUser.claims.end() &&
            !owner->second.empty() && owner->second == requester->second)
        {
          return StatusCode{Status::Good};
        }
      }
      else if (source.owningUser.userId == requestingUser.userId)
      {
        return StatusCode{Status::Good};
      }
    }
    return StatusCode{Status::BadUserAccessDenied,
      ErrorDetail::build("SubscriptionTransferUserMismatch",
        "The requesting user does not own the Subscription",
        "SubscriptionTransferAuthorization")};
  }

  if (requestingUser.kind != UserTokenKind::Anonymous)
  {
    return deny_anonymous_transfer("the target Session is not anonymous", source, requestingSecurity);
  }
  if (!is_signed(source.sourceSecurityMode))
  {
    return deny_anonymous_transfer("the source channel was not signed", source, requestingSecurity);
  }
  if (!is_signed(requestingSecurity.messageSecurityMode))
  {
    return deny_anonymous_transfer("the target channel is not signed", source, requestingSecurity);
  }

  const std::string_view sourceApplicationUri = source.verifiedApplicationUri;
  const std::string_view targetApplicationUri = requestingSecurity.clientApplicationUri;
  if (sourceApplicationUri.empty() || targetApplicationUri.empty() ||
      sourceApplicationUri != targetApplicationUri)
  {
    return deny_anonymous_transfer(
      "the verified source and target ApplicationUris do not match", source, requestingSecurity);
  }

  return StatusCode{Status::Good};
}

}  // namespace ua::server
