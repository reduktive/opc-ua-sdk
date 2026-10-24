// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#ifndef UA_SESSION_TIMEOUT_REVISION_H
#define UA_SESSION_TIMEOUT_REVISION_H

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>

namespace ua::server::detail
{

/// Revises a client's requestedSessionTimeout (a Double in milliseconds, wholly client-controlled) into the
/// server's [minimum, maximum] window (SVR-SESS-014). NaN, zero, a negative value and negative infinity mean
/// "use the minimum"; positive infinity means "use the maximum"; anything else is clamped in the double
/// domain BEFORE the integer conversion, so no value the wire can carry reaches an undefined cast.
[[nodiscard]] inline std::chrono::milliseconds revise_session_timeout(
  double requestedMs, std::chrono::milliseconds minimum, std::chrono::milliseconds maximum)
{
  if (maximum < minimum)
  {
    maximum = minimum;
  }
  if (std::isnan(requestedMs) || requestedMs <= 0.0)
  {
    return minimum;
  }
  // +infinity clamps to the maximum; the clamp is done in double so no cast can overflow.
  const double clamped =
    std::clamp(requestedMs, static_cast<double>(minimum.count()), static_cast<double>(maximum.count()));
  return std::chrono::milliseconds{static_cast<int64_t>(clamped)};
}

}  // namespace ua::server::detail

#endif  // UA_SESSION_TIMEOUT_REVISION_H
