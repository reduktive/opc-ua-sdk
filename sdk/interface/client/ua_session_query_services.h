// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side accessor for the OPC UA Query Service Set on a Session.
/// @ingroup client

#ifndef UA_SESSION_QUERY_SERVICES_H
#define UA_SESSION_QUERY_SERVICES_H

#include "ua_query_first_request.h"
#include "ua_query_first_response.h"
#include "ua_query_next_request.h"
#include "ua_query_next_response.h"
#include "ua_result.h"

#include <functional>
#include <memory>

namespace ua::client
{

class Session;
class SessionImpl;

/// Non-owning accessor for the OPC UA Query Service Set on a @ref Session.
///
/// Exposes the QueryFirst and QueryNext services, which query the server's
/// address space for nodes matching a content filter and page large result
/// sets through a continuation point. Obtained from a @ref Session; it holds a
/// weak reference to the owning session and does not extend the session's
/// lifetime. Operations issued after the session has been destroyed fail with
/// an @ref ErrorDetail (async / try variants) or throw (sync variants) rather
/// than dangling.
/// @ingroup client
class SessionQueryServices
{
public:
  // QueryFirst

  /// Result of a QueryFirst operation: the @ref QueryFirstResponse or an @ref ErrorDetail.
  using QueryFirstResponseResult = ua::Result<ua::QueryFirstResponse>;

  /// Completion callback for query_first_async, receiving the QueryFirst outcome.
  using QueryFirstCallback = std::function<void(QueryFirstResponseResult)>;

  /// Begins a query of the server address space and completes asynchronously.
  ///
  /// Sends the QueryFirst service request; the response may carry a continuation
  /// point when the result set exceeds the negotiated paging limits, which is
  /// then passed to query_next_async to retrieve the remaining results. The
  /// callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param request  The QueryFirst request: the node-types view, content filter
  ///                 and paging limits to query.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref QueryFirstResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see query_first_sync, try_query_first_sync, query_next_async
  void query_first_async(ua::QueryFirstRequest request, QueryFirstCallback callback) noexcept;

  /// Begins a query of the server address space, blocking until complete.
  ///
  /// @param request The QueryFirst request to send.
  /// @return The QueryFirst response.
  /// @throws UaException if the query fails or the owning session is gone.
  /// @see query_first_async, try_query_first_sync
  /// A Good subcode on the answer is not returned; try_query_first_sync() returns it.
  ua::QueryFirstResponse query_first_sync(ua::QueryFirstRequest request);

  /// Begins a query of the server address space, blocking until complete.
  ///
  /// @param request The QueryFirst request to send.
  /// @return The @ref QueryFirstResponse, or an @ref ErrorDetail on failure. Never throws.
  /// @see query_first_async, query_first_sync
  QueryFirstResponseResult try_query_first_sync(ua::QueryFirstRequest request) noexcept;

  // QueryNext

  /// Result of a QueryNext operation: the @ref QueryNextResponse or an @ref ErrorDetail.
  using QueryNextResponseResult = ua::Result<ua::QueryNextResponse>;

  /// Completion callback for query_next_async, receiving the QueryNext outcome.
  using QueryNextCallback = std::function<void(QueryNextResponseResult)>;

  /// Retrieves the next page of a query, or releases its continuation point,
  /// completing asynchronously.
  ///
  /// Sends the QueryNext service request using the continuation point returned by
  /// a prior QueryFirst (or QueryNext). The callback runs on an unspecified
  /// worker thread - do not block it.
  ///
  /// @param request  The QueryNext request, carrying the continuation point and
  ///                 whether to release it instead of fetching more results.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref QueryNextResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see query_next_sync, try_query_next_sync, query_first_async
  void query_next_async(ua::QueryNextRequest request, QueryNextCallback callback) noexcept;

  /// Retrieves the next page of a query, or releases its continuation point,
  /// blocking until complete.
  ///
  /// @param request The QueryNext request to send.
  /// @return The QueryNext response.
  /// @throws UaException if the query fails or the owning session is gone.
  /// @see query_next_async, try_query_next_sync
  /// A Good subcode on the answer is not returned; try_query_next_sync() returns it.
  ua::QueryNextResponse query_next_sync(ua::QueryNextRequest request);

  /// Retrieves the next page of a query, or releases its continuation point,
  /// blocking until complete.
  ///
  /// @param request The QueryNext request to send.
  /// @return The @ref QueryNextResponse, or an @ref ErrorDetail on failure. Never throws.
  /// @see query_next_async, query_next_sync
  QueryNextResponseResult try_query_next_sync(ua::QueryNextRequest request) noexcept;

private:
  friend class Session;
  explicit SessionQueryServices(std::weak_ptr<SessionImpl> impl);

  std::weak_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_SESSION_QUERY_SERVICES_H
