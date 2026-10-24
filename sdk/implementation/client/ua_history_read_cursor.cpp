// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_read_cursor.h"

#include "ua_sync_wait.h"
#include "ua_connection_ops.h"
#include "ua_continuation_point.h"
#include "ua_error_detail.h"
#include "ua_history_data.h"
#include "ua_history_read_cursor_state.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_result.h"
#include "ua_history_read_value_id.h"
#include "ua_status.h"

#include <boost/asio/post.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "ua_on_strand.h"

namespace ua::client
{

namespace detail
{

namespace
{

constexpr std::string_view nextSource = "client.tier2.history_reader.next";
constexpr std::string_view releaseSource = "client.tier2.history_reader.release_continuation_point";
constexpr std::string_view goneSource = "client.tier2.history_reader.connection_gone";

using PageResult = ua::Result<std::vector<ua::DataValue>>;

/// Posts @p result to @p executor for the page callback (callbacks always run on the executor). Falls back to
/// an inline invocation when no executor is set (a moved-from cursor).
void deliver_page(
  const boost::asio::any_io_executor& executor, std::function<void(PageResult)> callback, PageResult result)
{
  if (!executor)
  {
    callback(std::move(result));
    return;
  }
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

/// Posts @p result to @p executor for the void (close) callback.
void deliver_void(const boost::asio::any_io_executor& executor, std::function<void(ua::VoidResult)> callback,
  ua::VoidResult result)
{
  if (!executor)
  {
    callback(std::move(result));
    return;
  }
  boost::asio::post(executor,
    ua::async::guarded(ua::Logger{},
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

/// Rebuilds the wire `HistoryReadRequest` from the cursor's cached snapshot (same details + timestamps,
/// CL-HIST-013), targeting @p continuationPoint with the given release flag (CL-HIST-008 / -009).
ua::HistoryReadRequest make_history_read_request(
  const HistoryReadCursorState& state, const ua::ContinuationPoint& continuationPoint, bool release)
{
  ua::HistoryReadRequest request;
  request.history_read_details() = state.details;  // RefStructure copy = deep clone of the original details
  request.timestamps_to_return() = state.timestampsToReturn;
  request.release_continuation_points() = release;

  ua::HistoryReadValueId valueId;
  valueId.node_id() = state.nodeId;
  valueId.continuation_point() = continuationPoint;
  request.nodes_to_read().push_back(std::move(valueId));
  return request;
}

/// Extracts the `DataValue` page from a `HistoryReadResult` (both `HistoryData` and the derived
/// `HistoryModifiedData` expose `data_values()`). Returns an empty page for an unexpected / absent payload.
std::vector<ua::DataValue> extract_page(const ua::HistoryReadResult& result)
{
  if (const auto* data = dynamic_cast<const ua::HistoryData*>(result.history_data().get()))
  {
    return data->data_values().payload();
  }
  return {};
}

/// Logs the outcome of a best-effort release-only HistoryRead at the wire boundary (CL-HIST-009 /
/// section 8.9.6): Info on Good, Warning on Bad, both source-tagged. The @p logger is captured by value (the
/// cursor state may already be gone when this fires), so a bad release is never silently discarded. A default
/// (null) logger is a silent no-op.
void log_release_outcome(const ua::Logger& logger, const ua::Result<ua::HistoryReadResponse>& result)
{
  if (result.is_bad())
  {
    logger.warning(
      "{}: best-effort continuation-point release returned {} (advisory; server cleans up on "
      "Session close)",
      releaseSource,
      static_cast<std::uint32_t>(result.status_code().value()));
    return;
  }
  logger.info("{}: continuation point released", releaseSource);
}

/// Issues the best-effort release-only HistoryRead for @p state's held continuation point (CL-HIST-009,
/// idempotent). Skips when there is nothing to release or the wire interface is gone. Clears the local
/// continuation point.
void release_history_continuation_point(HistoryReadCursorState& state)
{
  if (state.closed || state.continuationPoint.empty())
  {
    return;
  }
  auto wireOps = state.wireOps.lock();
  if (!wireOps)
  {
    state.continuationPoint = ua::ContinuationPoint{};
    return;  // interface gone: nothing to free server-side, bail cleanly
  }
  // Fire-and-forget: no state capture (the cursor is being destroyed on the dtor path), but the logger is
  // captured by value so a Bad release is logged at the wire boundary rather than silently dropped
  // (log-at-wire-boundary rule / CL-HIST-009). section 8.9.6: this is intentional best-effort  -  a fresh
  // continuation point handed back by the release response (or a mid-advance orphan) is NOT chased; the
  // server reclaims it on Session close (Part 4 section 5.10.3.2).
  wireOps->history_read_async(make_history_read_request(state, state.continuationPoint, /*release=*/true),
    [logger = state.logger](ua::Result<ua::HistoryReadResponse> result)
    { log_release_outcome(logger, result); });
  state.continuationPoint = ua::ContinuationPoint{};
}

void issue_advance(
  const std::shared_ptr<HistoryReadCursorState>& state, std::function<void(PageResult)> callback);

/// Delivers @p page with @p pageStatus, or, when it is empty and a continuation point is held, asks again
/// (API-D1.1): Part 11 section 6.3 lets a server stop at its own limits with an empty page and a continuation
/// point, so an empty page the cursor delivers always means the history is exhausted. One more empty page in
/// a row than `continuationLimits` allows fails with Bad_Timeout and releases the continuation point.
///
/// @p pageStatus is the code the server answered the page with (its ServiceResult and per-node statusCode
/// combined); a Good subcode such as Good_NoData or Good_MoreData, or an Uncertain code, is the status of the
/// delivered Result. An Uncertain code with no values is delivered without a page.
void deliver_or_continue(const std::shared_ptr<HistoryReadCursorState>& state,
  std::vector<ua::DataValue> page, ua::StatusCode pageStatus, std::function<void(PageResult)> callback)
{
  if (!page.empty() || state->continuationPoint.empty())
  {
    state->consecutiveEmptyPages = 0;
    if (page.empty() && pageStatus.is_uncertain())
    {
      deliver_page(state->executor, std::move(callback), PageResult{std::move(pageStatus)});
      return;
    }
    deliver_page(
      state->executor, std::move(callback), ua::detail::held(std::move(page), std::move(pageStatus)));
    return;
  }
  const std::uint32_t limit = state->continuationLimits.maxConsecutiveEmptyPages;
  if (++state->consecutiveEmptyPages > limit)
  {
    const std::uint32_t count = state->consecutiveEmptyPages;
    release_history_continuation_point(*state);
    deliver_page(state->executor,
      std::move(callback),
      PageResult{ua::Status::BadTimeout,
        ua::ErrorDetail::build("HistoryCursorEmptyPageLimitExceeded",
          "the server returned more empty pages in a row than the cursor's ContinuationLimits allow; the "
          "continuation point was released",
          std::string{nextSource})
          .context(ua::ContextKeys::countActual, count)
          .context(ua::ContextKeys::limit, limit)});
    return;
  }
  issue_advance(state, std::move(callback));
}

/// Re-sends the held continuation point (CL-HIST-008/-013) and hands the returned page to
/// deliver_or_continue. The completion weak-captures the state: a cursor dropped mid-flight is not touched.
void issue_advance(
  const std::shared_ptr<HistoryReadCursorState>& state, std::function<void(PageResult)> callback)
{
  auto wireOps = state->wireOps.lock();
  if (!wireOps)
  {
    // The wire interface (and the Connection behind it) is gone: complete with a boundary failure rather than
    // dereferencing it (section 8.9 gone path).
    deliver_page(state->executor,
      std::move(callback),
      PageResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("HistoryCursorConnectionGone",
          "the Connection was dropped before the history advance could be issued",
          std::string{goneSource})});
    return;
  }
  state->advancing = true;
  std::weak_ptr<HistoryReadCursorState> weak = state;
  wireOps->history_read_async(make_history_read_request(*state, state->continuationPoint, /*release=*/false),
    [weak, callback = std::move(callback)](ua::Result<ua::HistoryReadResponse> response) mutable
    {
      auto locked = weak.lock();
      if (!locked)
      {
        return;  // the cursor was dropped mid-flight: bail (UAF guard) - do not touch freed state
      }
      locked->advancing = false;
      if (!response.has_value())
      {
        deliver_page(locked->executor,
          std::move(callback),
          PageResult{response.status_code(), response.shared_detail()});
        return;
      }
      // Facade flatten: the tier-0 funnel returns the HistoryReadResponse verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the facade surfaces as bad, preserving the
      // exact service status + ErrorDetail. Without this an empty results[] masks the fault as
      // Bad_UnexpectedError (empty-results branch below) and a non-empty results[] silently returns a page.
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        deliver_page(locked->executor,
          std::move(callback),
          PageResult{serviceResult,
            ua::make_error_detail("HistoryContinuationServiceFault",
              "the server returned a service-level fault on the history continuation read",
              std::string{nextSource},
              serviceResult)});
        return;
      }
      const auto& results = response.value().results();
      if (results.empty())
      {
        deliver_page(locked->executor,
          std::move(callback),
          PageResult{ua::Status::BadUnexpectedError,
            ua::make_error_detail("HistoryContinuationEmptyResults",
              "the server returned a Good HistoryRead continuation with no result",
              std::string{nextSource})});
        return;
      }
      const ua::HistoryReadResult& result = results[0];
      if (result.status_code().is_bad())
      {
        // A per-node Bad on continuation (e.g. Bad_ContinuationPointInvalid, CL-HIST-008): clear the
        // continuation point so has_more() flips false and the cursor does not retry, then surface the code.
        locked->continuationPoint = ua::ContinuationPoint{};
        deliver_page(locked->executor,
          std::move(callback),
          PageResult{result.status_code(),
            ua::make_error_detail("HistoryContinuationBad",
              "the server returned a bad per-node status on the history continuation read",
              std::string{nextSource})});
        return;
      }
      if (locked->closed)
      {
        // close_async raced this in-flight advance and marked the cursor closed. A freshly-returned
        // continuation point must not be stored into a closed cursor (~HistoryReadCursor early-returns on
        // `closed`, so it would leak server-side). Release it now, then complete the advance as closed.
        if (!result.continuation_point().empty())
        {
          if (auto lockedWireOps = locked->wireOps.lock())
          {
            // Fire-and-forget, but log the release outcome at the wire boundary (Info/Warning, source-tagged)
            // so a Bad release is not silently dropped (log-at-wire-boundary rule / CL-HIST-009).
            lockedWireOps->history_read_async(
              make_history_read_request(*locked, result.continuation_point(), /*release=*/true),
              [logger = locked->logger](ua::Result<ua::HistoryReadResponse> release)
              { log_release_outcome(logger, release); });
          }
        }
        deliver_page(locked->executor,
          std::move(callback),
          PageResult{ua::Status::BadInvalidState,
            ua::make_error_detail("HistoryCursorClosed",
              "the cursor was closed during an in-flight advance; its returned continuation point was "
              "released",
              std::string{releaseSource})});
        return;
      }
      locked->continuationPoint = result.continuation_point();
      deliver_or_continue(locked,
        extract_page(result),
        ua::detail::combined_status(serviceResult, result.status_code()),
        std::move(callback));
    });
}

}  // namespace

}  // namespace detail

HistoryReadCursor::HistoryReadCursor(std::shared_ptr<detail::HistoryReadCursorState> state)
  : mState(std::move(state))
{}

HistoryReadCursor::~HistoryReadCursor()
{
  if (!mState)
  {
    return;  // moved-from
  }
  // Best-effort release of the held continuation point (CL-HIST-009). N3/section 8.9.6: unlike close_async, a
  // destructor that races an in-flight advance cannot chase a fresh continuation point the advance later
  // returns (the state is being torn down)  -  that orphan is intentionally left for the server to reclaim on
  // Session close (Part 4 section 5.10.3.2). This asymmetry is bounded and self-healing, so no fix is
  // attempted.
  detail::release_history_continuation_point(*mState);
}

bool HistoryReadCursor::has_more() const noexcept
{
  if (!mState || mState->closed)
  {
    return false;
  }
  if (mState->firstPagePending)
  {
    return true;  // the initial read's page has not yet been delivered
  }
  return !mState->continuationPoint.empty();  // a further page can be fetched
}

void HistoryReadCursor::next_async(
  std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) noexcept
{
  if (!mState)
  {
    callback(detail::PageResult{ua::Status::BadInvalidState,
      ua::make_error_detail(
        "HistoryCursorEmpty", "next() called on a moved-from cursor", std::string{detail::nextSource})});
    return;
  }
  auto& state = *mState;
  if (state.closed)
  {
    detail::deliver_page(state.executor,
      std::move(callback),
      detail::PageResult{ua::Status::BadInvalidState,
        ua::make_error_detail(
          "HistoryCursorClosed", "next() called on a closed cursor", std::string{detail::nextSource})});
    return;
  }
  if (state.advancing)
  {
    detail::deliver_page(state.executor,
      std::move(callback),
      detail::PageResult{ua::Status::BadInvalidState,
        ua::make_error_detail("HistoryCursorBusy",
          "next() called while a prior advance is still in flight (forward-iterator: await each next)",
          std::string{detail::nextSource})});
    return;
  }

  if (state.firstPagePending)
  {
    // The page fetched by the initial read; when it is empty but a continuation point is held, the cursor
    // asks again before delivering anything (API-D1.1).
    state.firstPagePending = false;
    detail::deliver_or_continue(mState,
      std::exchange(state.firstPage, {}),
      std::exchange(state.firstPageStatus, ua::StatusCode{ua::Status::Good}),
      std::move(callback));
    return;
  }
  if (state.continuationPoint.empty())
  {
    // No buffered page and no continuation point: the cursor is drained. Report Good + empty (CL-HIST-011).
    detail::deliver_page(
      state.executor, std::move(callback), detail::PageResult{std::vector<ua::DataValue>{}});
    return;
  }
  detail::issue_advance(mState, std::move(callback));
}

ua::Result<std::vector<ua::DataValue>> HistoryReadCursor::try_next_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::DataValue>>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) { next_async(std::move(completion)); });
}

std::vector<ua::DataValue> HistoryReadCursor::next_sync()
{
  return ua::detail::good_value(try_next_sync());
}

void HistoryReadCursor::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mState)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState});
    return;
  }
  auto& state = *mState;
  if (state.closed || state.continuationPoint.empty())
  {
    // Nothing to release (idempotent): mark closed and report Good on the executor.
    state.closed = true;
    detail::deliver_void(state.executor, std::move(callback), ua::VoidResult{});
    return;
  }
  auto wireOps = state.wireOps.lock();
  if (!wireOps)
  {
    // The wire interface is gone: there is nothing to free server-side. Clear locally and report Good
    // (best-effort release, idempotent).
    state.closed = true;
    state.continuationPoint = ua::ContinuationPoint{};
    detail::deliver_void(state.executor, std::move(callback), ua::VoidResult{});
    return;
  }
  state.closed = true;
  auto continuationPoint = state.continuationPoint;
  state.continuationPoint = ua::ContinuationPoint{};
  auto executor = state.executor;
  wireOps->history_read_async(detail::make_history_read_request(state, continuationPoint, /*release=*/true),
    [callback = std::move(callback), executor](ua::Result<ua::HistoryReadResponse> response) mutable
    {
      // The continuation point is already cleared locally; surface the service result so a release failure is
      // not silently swallowed (the design specification), but the cursor is closed regardless.
      if (!response.has_value())
      {
        detail::deliver_void(
          executor, std::move(callback), ua::VoidResult{response.status_code(), response.shared_detail()});
        return;
      }
      // Facade flatten: a bad ResponseHeader.serviceResult on the release-only HistoryRead is a service-level
      // failure the facade surfaces as bad (the cursor is closed regardless), so a release failure is not
      // silently reported as success (the design specification).
      const ua::StatusCode serviceResult = response.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        detail::deliver_void(executor,
          std::move(callback),
          ua::VoidResult{serviceResult,
            ua::make_error_detail("HistoryReleaseServiceFault",
              "the server returned a bad serviceResult on the release-only HistoryRead",
              std::string{detail::releaseSource},
              serviceResult)});
        return;
      }
      // The release's ServiceResult is the result, so a Good subcode or an Uncertain code of it is kept.
      detail::deliver_void(executor, std::move(callback), ua::VoidResult{serviceResult});
    });
}

ua::VoidResult HistoryReadCursor::try_close_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mState ? mState->executor : boost::asio::any_io_executor{}),
    [this](auto completion) { close_async(std::move(completion)); });
}

void HistoryReadCursor::close_sync()
{
  try_close_sync().value();
}

}  // namespace ua::client
