// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief How long a cursor keeps asking when the server answers with empty pages.
/// @ingroup client

#ifndef UA_CONTINUATION_LIMITS_H
#define UA_CONTINUATION_LIMITS_H

#include <cstdint>

namespace ua::client
{

/// Bounds a cursor's re-requests when the server returns empty pages.
///
/// A server may answer a Browse, BrowseNext or HistoryRead with an empty page and a continuation point
/// (OPC 10000-4 5.8.2.1 for Browse; OPC 10000-11 6.3 for HistoryRead: it may stop at its own limits,
/// including time). `BrowseCursor` and `HistoryReadCursor` then ask again themselves, so an empty page
/// they deliver always means the walk is finished. This bounds how many empty pages in a row they accept:
/// one more than @ref maxConsecutiveEmptyPages fails the cursor's `next` with `Bad_Timeout` and an
/// @ref ErrorDetail giving the count (`count.actual`, `limit`), and the continuation point is released.
/// @ingroup client
struct ContinuationLimits
{
  /// Empty pages with a continuation point accepted in a row before the cursor gives up. A page with data
  /// resets the count.
  std::uint32_t maxConsecutiveEmptyPages = 10;
};

}  // namespace ua::client

#endif  // UA_CONTINUATION_LIMITS_H
