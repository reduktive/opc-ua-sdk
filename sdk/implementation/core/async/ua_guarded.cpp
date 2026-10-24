// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_on_strand.h"

#include "ua_log_exception.h"

#include <exception>

namespace ua::async::detail
{

void report_guarded_exception(const Logger& logger, const char* site) noexcept
{
  // nosemgrep: catch-all-empty-body (noexcept-boundary containment; exception already logged in the try)
  try
  {
    // Reuse the shared, ErrorDetail-aware exception logger: it extracts the
    // StatusCode (and any attached ErrorDetail) from a UaException, falls back
    // to what() for other std::exceptions, and records "unknown" otherwise.
    ua::log_exception(logger, ua::LogLevel::Error, site, std::current_exception());
  }
  catch (...)
  {
    // Logging must never propagate out of a noexcept async boundary. If the
    // sink itself throws there is nothing more we can safely do here.
  }
}

}  // namespace ua::async::detail
