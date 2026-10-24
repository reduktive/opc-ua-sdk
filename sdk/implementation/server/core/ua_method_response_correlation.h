// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_METHOD_RESPONSE_CORRELATION_H
#define UA_METHOD_RESPONSE_CORRELATION_H

#include "ua_node.h"

namespace ua::server
{

/// Private transport correlation for one Service response on one Session channel association.
///
/// The request id alone is only unique within a SecureChannel. The monotonically changing Session
/// association epoch prevents a response or late registration from an old channel releasing an
/// action registered for a new channel that reused the same numeric request id.
struct MethodResponseCorrelation
{
  uint64_t channelAssociationEpoch{0};
  uint32_t requestId{0};

  friend bool operator==(const MethodResponseCorrelation&, const MethodResponseCorrelation&) = default;
};

}  // namespace ua::server

namespace ua::detail
{

/// Friend-only access to MethodCallContext's transport correlation. This implementation header is
/// not part of the public SDK surface and stays neutral to the address-space/server layering split.
class MethodCallContextInternalAccess final
{
public:
  static void set_response_correlation(
    MethodCallContext& context, server::MethodResponseCorrelation correlation)
  {
    context.mServerChannelAssociationEpoch = correlation.channelAssociationEpoch;
    context.mServerRequestId = correlation.requestId;
    context.mHasServerResponseCorrelation = true;
  }

  static std::optional<server::MethodResponseCorrelation> response_correlation(
    const MethodCallContext& context)
  {
    if (!context.mHasServerResponseCorrelation)
      return std::nullopt;

    return server::MethodResponseCorrelation{
      context.mServerChannelAssociationEpoch, context.mServerRequestId};
  }
};

}  // namespace ua::detail

#endif  // UA_METHOD_RESPONSE_CORRELATION_H
