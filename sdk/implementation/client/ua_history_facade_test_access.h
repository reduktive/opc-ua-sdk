// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_FACADE_TEST_ACCESS_H
#define UA_HISTORY_FACADE_TEST_ACCESS_H

/// @file
/// @brief Test-only construction of a @ref ua::client::HistoryFacade and a @ref ua::client::HistoryReadCursor
///        over a fake wire interface, for the HistoryFacade unit suite (see the design specification).
///
/// A friend of both handles. It adds NO public constructor: it builds the facade / the shared cursor state
/// directly and hands them to the private constructors, so the facade and cursor can be exercised against a
/// `FakeWireOps` with no real `ConnectionImpl`.

#include "ua_history_facade.h"
#include "ua_history_read_cursor.h"
#include "ua_history_read_cursor_state.h"

#include <boost/asio/any_io_executor.hpp>

#include <memory>
#include <utility>
#include <vector>

namespace ua::client::detail
{

/// Friend constructor for @ref HistoryFacade / @ref HistoryReadCursor unit tests.
struct HistoryFacadeTestAccess
{
  /// Builds a @ref HistoryFacade over @p wireOps delivering on @p executor.
  static HistoryFacade make_facade(std::weak_ptr<WireOps> wireOps, boost::asio::any_io_executor executor)
  {
    return HistoryFacade{std::move(wireOps), std::move(executor)};
  }

  /// Builds a @ref HistoryReadCursor directly over a scripted cursor state, so the paging / close / release
  /// paths can be exercised without going through an initial read. @p logger is stamped onto the state so the
  /// CP-release outcome logging (CL-HIST-009) can be asserted; it defaults to a null (no-op) logger.
  static HistoryReadCursor make_cursor(std::weak_ptr<WireOps> wireOps, boost::asio::any_io_executor executor,
    ua::NodeId node, ua::RefStructure<ua::Structure> details, ua::TimestampsToReturn timestampsToReturn,
    std::vector<ua::DataValue> firstPage, bool firstPagePending, ua::ContinuationPoint continuationPoint,
    ua::Logger logger = {})
  {
    auto state = std::make_shared<HistoryReadCursorState>();
    state->wireOps = std::move(wireOps);
    state->executor = std::move(executor);
    state->logger = std::move(logger);
    state->nodeId = std::move(node);
    state->details = std::move(details);
    state->timestampsToReturn = timestampsToReturn;
    state->firstPage = std::move(firstPage);
    state->firstPagePending = firstPagePending;
    state->continuationPoint = std::move(continuationPoint);
    return HistoryReadCursor{std::move(state)};
  }
};

}  // namespace ua::client::detail

#endif  // UA_HISTORY_FACADE_TEST_ACCESS_H
