// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#ifndef UA_VERDICT_RULES_H
#define UA_VERDICT_RULES_H

#include "ua_access_control.h"
#include "ua_error_detail.h"
#include "ua_status.h"
#include "ua_status_code.h"

#include <cstddef>
#include <optional>
#include <span>

namespace ua::server::detail
{

/// The one rule every authorization site applies to a verdict list (SVR-AUTHZ-015): exactly @p expected
/// verdicts, every one permitted. A short, empty or long list is a denial (Bad_UserAccessDenied), never a
/// permission - an engine that answered nothing has authorized nothing. Returns the status a denied item
/// carries, or nothing when the list permits.
[[nodiscard]] inline std::optional<ua::StatusCode> first_denial(
  std::span<const AccessControl::Verdict> verdicts, std::size_t expected)
{
  if (verdicts.size() != expected)
  {
    return ua::StatusCode{ua::Status::BadUserAccessDenied,
      ua::ErrorDetail::build("VerdictCountMismatch",
        "the access-control engine returned a verdict list of another size than the items it was asked "
        "about; the request is refused, not permitted",
        "server.authorization")};
  }
  for (const auto& verdict : verdicts)
  {
    if (!verdict.permitted)
    {
      return verdict.cause;
    }
  }
  return std::nullopt;
}

}  // namespace ua::server::detail

#endif  // UA_VERDICT_RULES_H
