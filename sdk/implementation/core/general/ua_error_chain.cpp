// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_error_chain.h"

#include "ua_to_string.h"

namespace ua
{

std::string format(const StatusCode& status)
{
  // Always lead with the top-level status name/code: it lives on the StatusCode, not the ErrorDetail, and
  // to_string(ErrorDetail) renders only the outermost link's inner-cause status (innerStatus)  -  so a naive
  // delegation would silently drop the primary status whenever it differs from the inner cause (the
  // canonical "status X wrapping cause Y" shape). Below it, to_string(ErrorDetail) renders the chain
  // outermost-first with per-inner-link indentation and stable key=value context.
  std::string result = to_string(status);
  if (const ErrorDetail* detail = status.detail())
  {
    result += '\n';
    result += to_string(*detail);
  }
  return result;
}

}  // namespace ua
