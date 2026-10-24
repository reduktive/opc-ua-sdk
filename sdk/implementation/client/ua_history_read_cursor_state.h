// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_READ_CURSOR_STATE_H
#define UA_HISTORY_READ_CURSOR_STATE_H

/// @file
/// @brief The strand-free cursor state a @ref ua::client::HistoryReadCursor pages over (client design
/// section 8.9),
///        shared between the cursor implementation and the `HistoryFacade` reads that construct it.
/// @ingroup client

#include "ua_continuation_limits.h"
#include "ua_continuation_point.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_ref_structure.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_timestamps_to_return.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace ua::client::detail
{

class WireOps;

/// The paging state a @ref HistoryReadCursor iterates. Held by a `std::shared_ptr` so every wire-op
/// completion can weak-capture it and bail cleanly if the cursor was dropped mid-flight (section 9.8.3:
/// liveness is not guaranteed across an async boundary).
struct HistoryReadCursorState
{
  std::weak_ptr<WireOps>
    wireOps;  ///< the upward wire interface (section 8.2A.13); locked per op, bail if gone
  boost::asio::any_io_executor executor;  ///< where pages / boundary failures are delivered
  ua::Logger logger;  ///< logs the best-effort CP-release outcome at the wire boundary (CL-HIST-009); a
                      ///< default (null) logger is a silent no-op

  ua::NodeId nodeId;  ///< the single node the cursor pages over
  ua::RefStructure<ua::Structure>
    details;  ///< the original HistoryReadDetails, re-sent verbatim (CL-HIST-013)
  ua::TimestampsToReturn timestampsToReturn{};  ///< re-sent verbatim on each continuation (CL-HIST-013)

  std::vector<ua::DataValue> firstPage;  ///< the initial read's page, delivered by the first next_async
  /// The initial read's code (its ServiceResult and per-node statusCode combined), delivered with
  /// @ref firstPage so a Good subcode such as Good_NoData or an Uncertain code reaches the caller.
  ua::StatusCode firstPageStatus{ua::Status::Good};
  bool firstPagePending = false;  ///< the initial page has not yet been delivered by a next_async
  ua::ContinuationPoint continuationPoint;  ///< non-empty => a further page can be fetched (CL-HIST-008)
  ContinuationLimits continuationLimits;  ///< bounds the re-requests on empty pages (API-D1.1)
  std::uint32_t consecutiveEmptyPages = 0;  ///< empty pages with a continuation point in a row
  bool closed = false;  ///< the continuation point has been released; no more advances
  bool advancing = false;  ///< a wire op is in flight (single-in-flight forward-iterator guard)
};

}  // namespace ua::client::detail

#endif  // UA_HISTORY_READ_CURSOR_STATE_H
