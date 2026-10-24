// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_METHOD_CALL_AUTHORIZATION_INTERNAL_H
#define UA_METHOD_CALL_AUTHORIZATION_INTERNAL_H

#include "ua_node.h"

namespace ua::detail
{

/// Private bridge for the per-call authorization facts produced by the Call service and consumed by
/// address-space Method handlers. Keeping this behind a friend accessor avoids making server policy
/// state part of MethodCallContext's public API.
class MethodCallAuthorizationInternalAccess final
{
public:
  static void set_object_write_authorizer(MethodCallContext& context, std::function<VoidResult()> authorize)
  {
    context.mAuthorizeObjectWrite = std::move(authorize);
  }

  static std::optional<VoidResult> authorize_object_write(const MethodCallContext& context)
  {
    if (!context.mAuthorizeObjectWrite)
      return std::nullopt;
    return context.mAuthorizeObjectWrite();
  }
};

}  // namespace ua::detail

#endif  // UA_METHOD_CALL_AUTHORIZATION_INTERNAL_H
