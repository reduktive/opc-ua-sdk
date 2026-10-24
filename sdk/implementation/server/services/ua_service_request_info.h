// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVICE_REQUEST_INFO_H
#define UA_SERVICE_REQUEST_INFO_H

#include "ua_access_control.h"
#include "ua_locale_id.h"
#include "ua_request_info.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace ua::server
{

/// The @ref RequestInfo a service passes to the namespaces for the request it serves.
///
/// @param arrival     When the service started the request, the instant its `timeoutHint` timer counts
///                    from.
/// @param timeoutHint The request header's `timeoutHint` in milliseconds; 0 sets no deadline
///                    (OPC 10000-4 7.33).
/// @param answerBy    The partial-results deadline, for a service that can answer part of a batch;
///                    otherwise `nullopt`.
/// @param cancelled   The service's cancellation flag, set when the client cancels the request or it
///                    times out; a null flag is replaced by the flag that is never set.
/// @param locales     The Session's locales, most preferred first.
/// @return The request: deadline `arrival + timeoutHint`, or `time_point::max()` for a hint of 0.
inline RequestInfo service_request_info(std::chrono::steady_clock::time_point arrival, uint32_t timeoutHint,
  std::optional<std::chrono::steady_clock::time_point> answerBy,
  const std::shared_ptr<std::atomic_bool>& cancelled, std::vector<LocaleId> locales)
{
  RequestInfo request;
  request.answerBy = answerBy;
  if (timeoutHint != 0)
  {
    request.deadline = arrival + std::chrono::milliseconds{timeoutHint};
  }
  if (cancelled)
  {
    request.cancelled = cancelled;
  }
  request.locales = std::move(locales);
  return request;
}

/// On whose behalf a Session's request is made: the Session's own CallerInfo, with the identity the
/// authorization used, so that the namespace answers for the identity the request was authorized for; the
/// identity alone where the Session keeps no CallerInfo.
///
/// @param sessionInfo The Session the request arrived on.
/// @param control     The Session's access control for the request.
/// @return The caller; null without the Session's access control, which is the server's own call.
inline std::shared_ptr<const CallerInfo> session_caller(
  const SessionInfo& sessionInfo, const std::optional<SessionAccessControl>& control)
{
  if (!control)
  {
    return nullptr;
  }
  CallerInfo caller;
  if (const auto* security = dynamic_cast<const SessionSecurityContext*>(&sessionInfo))
  {
    if (auto current = security->caller())
    {
      caller = *current;
    }
  }
  caller.identity = control->identity();
  return std::make_shared<const CallerInfo>(std::move(caller));
}

}  // namespace ua::server

#endif  // UA_SERVICE_REQUEST_INFO_H
