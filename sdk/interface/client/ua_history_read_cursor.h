// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_READ_CURSOR_H
#define UA_HISTORY_READ_CURSOR_H

/// @file
/// @brief Tier-2 public `HistoryReadCursor`: a forward, per-page cursor over historical `DataValue`s that
///        hides the HistoryRead continuation-point dance (client design section 8.9). Unified with the
///        Slice-6 `BrowseCursor` idiom (section 7.5).
/// @ingroup client

#include "ua_data_value.h"
#include "ua_result.h"

#include <functional>
#include <memory>
#include <vector>

namespace ua::client
{

namespace detail
{
struct HistoryReadCursorState;
struct HistoryFacadeTestAccess;
}  // namespace detail

class HistoryFacade;

/// A forward, per-page cursor over historical `DataValue`s (client design section 8.9).
///
/// `HistoryReadCursor` hides the HistoryRead / continuation-point dance behind a forward-iterator shape:
/// @ref next_async yields one page (a `std::vector<ua::DataValue>`) at a time, transparently re-sending the
/// cached continuation point (CL-HIST-008/-013) when the caller asks for more. The cursor idiom is unified
/// with `BrowseCursor` (section 7.5): the same @ref has_more predicate name, the same section 7.0 async /
/// sync / try_sync triple on @ref next_async, and the same close-on-destruct + explicit-@ref close_async
/// continuation-point release (a release-only HistoryRead, CL-HIST-009). Element granularity is per-page (a
/// vector) here  -  vs the browse cursor's per-`Entry`  -  an intentional, kept difference (history pages are
/// the natural unit).
///
/// Move-only: the moved-from cursor releases its continuation point on drop. Not directly constructible;
/// obtained from `HistoryFacade::read_*`.
///
/// @warning A `HistoryReadCursor` is a forward iterator: issue one @ref next_async (or a `*_sync` variant) at
///          a time and await its completion before issuing the next. Overlapping advances are rejected.
/// @warning The `*_sync` / `try_*_sync` variants block the calling thread; they MUST NOT be called from the
///          Connection's executor thread.
/// @ingroup client
class HistoryReadCursor
{
public:
  HistoryReadCursor(const HistoryReadCursor&) = delete;
  HistoryReadCursor& operator=(const HistoryReadCursor&) = delete;
  /// Returns or updates the history read cursor.
  HistoryReadCursor(HistoryReadCursor&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  HistoryReadCursor& operator=(HistoryReadCursor&&) noexcept = default;

  /// Posts a release-only HistoryRead (`releaseContinuationPoints = true`) to free the server's continuation
  /// point (CL-HIST-009). Idempotent; skipped when no continuation point is held or the wire interface is
  /// gone.
  ~HistoryReadCursor();

  /// @return True iff more pages remain to yield  -  a buffered first page is still pending, or a non-null
  ///         continuation point is held. False once the cursor is drained or closed.
  ///
  /// @warning This reads the strand-free cursor state directly (no synchronization). Poll it only from the
  ///          same logical flow that awaits @ref next_async, never concurrently with an in-flight advance.
  [[nodiscard]] bool has_more() const noexcept;

  /// Fetches the next page of historical values. Stream-shaped: the first call yields the initial read's
  /// page; each subsequent call re-sends the cached continuation point to fetch the next page. The callback
  /// receives (on the executor):
  ///   - Good Result + non-empty vector   to  the page's values,
  ///   - Good Result + empty vector       to  no more data (the cursor is drained; CL-HIST-011),
  ///   - Uncertain Result + vector        to  the page's values the server answered with an Uncertain code,
  ///   - Uncertain Result, no vector      to  an Uncertain answer without values,
  ///   - Bad Result                       to  a server-side per-node failure (e.g.
  ///                                          `Bad_ContinuationPointInvalid`) or the wire interface being
  ///                                          gone (section 7.0 triple).
  ///
  /// The status of a page's Result is the code the server answered that page with: its ServiceResult and
  /// per-node statusCode combined (`ua::detail::combined_status`), so a Good subcode such as Good_NoData
  /// or Good_MoreData, or an Uncertain code, is kept. A drained cursor's empty page is plain Good.
  ///
  /// @param callback Receives the next page (or a bad Result) on the executor.
  void next_async(std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) noexcept;

  /// @return The operation result, including status and diagnostic detail on failure.
  /// Blocking `try_*` bridge over @ref next_async; never throws. MUST NOT run on the executor thread.
  ua::Result<std::vector<ua::DataValue>> try_next_sync() noexcept;

  /// @return The next page.
  /// Blocking bridge over @ref next_async; throws `UaException` when the Result is not Good (an Uncertain
  /// page included). A Good subcode on the answer is not returned; try_next_sync() returns it. MUST NOT run
  /// on the executor thread.
  std::vector<ua::DataValue> next_sync();

  /// Explicitly releases the continuation point now (a release-only HistoryRead). Idempotent (section 7.0
  /// triple).
  ///
  /// @param callback Receives the release's ServiceResult (a Good subcode or an Uncertain code kept), `Good`
  ///                 when nothing had to be released, or a bad Result, on the executor.
  void close_async(std::function<void(ua::VoidResult)> callback) noexcept;

  /// @return The requested value.
  /// Blocking `try_*` bridge over @ref close_async; never throws. MUST NOT run on the executor thread.
  ua::VoidResult try_close_sync() noexcept;

  /// Blocking bridge over @ref close_async; throws `UaException` on a bad Result. MUST NOT run on the
  /// executor thread.
  void close_sync();

private:
  friend class HistoryFacade;
  friend struct ua::client::detail::HistoryFacadeTestAccess;

  explicit HistoryReadCursor(std::shared_ptr<detail::HistoryReadCursorState> state);

  std::shared_ptr<detail::HistoryReadCursorState> mState;
};

}  // namespace ua::client

#endif  // UA_HISTORY_READ_CURSOR_H
