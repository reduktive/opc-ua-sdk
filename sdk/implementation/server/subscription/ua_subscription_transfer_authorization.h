// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SUBSCRIPTION_TRANSFER_AUTHORIZATION_H
#define UA_SUBSCRIPTION_TRANSFER_AUTHORIZATION_H

#include "ua_message_security_mode.h"
#include "ua_server_authentication.h"
#include "ua_status_code.h"
#include "ua_string.h"

namespace ua::server
{

/// Immutable security facts retained with a live or orphaned Subscription's source Session.
struct SubscriptionTransferContext
{
  UserIdentity owningUser;
  String verifiedApplicationUri;
  MessageSecurityMode sourceSecurityMode{MessageSecurityMode::Invalid};
};

/// Applies the Part 4 subscription-transfer identity rule to both live and orphaned sources.
///
/// Non-anonymous callers must retain the owning user id. Anonymous transfer additionally requires
/// the same non-empty, certificate-verified ApplicationUri and signed source and target channels.
StatusCode validate_subscription_transfer(const SubscriptionTransferContext& source,
  const UserIdentity& requestingUser, const EndpointSecurityContext& requestingSecurity);

}  // namespace ua::server

#endif  // UA_SUBSCRIPTION_TRANSFER_AUTHORIZATION_H
