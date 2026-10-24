// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Asynchronous DNS resolution of a host/port pair to TCP endpoints.
/// @ingroup general

#ifndef UA_RESOLVER_H
#define UA_RESOLVER_H

#include <boost/asio.hpp>
#include "ua_includes.h"
#include "ua_timer.h"
#include "ua_status_code.h"
#include "ua_result.h"

namespace asio = boost::asio;
using namespace std::chrono_literals;

namespace ua
{

/// The resolved TCP endpoints (address/port pairs) for a host.
using EndpointList = std::vector<asio::ip::tcp::endpoint>;

/// Outcome of an endpoint resolution: the @ref EndpointList on success, or an @ref ErrorDetail.
using EndpointListResult = Result<EndpointList>;

/// Asynchronously resolves a hostname and port to a list of TCP endpoints.
///
/// Wraps an Asio TCP resolver with a configurable timeout. Instances are heap-managed and must be
/// created via @ref create so that `shared_from_this` is valid; the resolver keeps itself alive for
/// the duration of an in-flight resolution by capturing a weak reference in its handlers.
///
/// A single resolver serves one resolution at a time: while a resolve is in flight, a further call
/// to @ref resolve_endpoints_async fails with @ref ua::Status::BadInvalidState. The completion
/// callback runs on a worker thread of the executor passed to @ref create - do not block it.
/// @ingroup general
class Resolver : public std::enable_shared_from_this<Resolver>
{
public:
  /// Callback type that receives the resolution outcome.
  using CompleteCallback = std::function<void(EndpointListResult)>;

  /// Resolves @p hostname and @p port to TCP endpoints, completing asynchronously.
  ///
  /// The resolution runs on the executor supplied to @ref create; @p callback is invoked on one of
  /// that executor's worker threads when the resolve completes, times out, or fails. Only one
  /// resolution may be outstanding per resolver at a time.
  ///
  /// @param hostname Host to resolve. May be a DNS name or a literal IP address.
  /// @param port     TCP port number combined with each resolved address.
  /// @param timeout  Maximum time to wait, in seconds; `nullopt` uses the default supplied to
  ///                 @ref create.
  /// @param callback Receives the outcome: on success the Result holds the @ref EndpointList; on
  ///                 failure it carries an @ref ErrorDetail (for example
  ///                 @ref ua::Status::BadInvalidState if a resolution is already in progress,
  ///                 @ref ua::Status::BadTimeout on timeout, or
  ///                 @ref ua::Status::BadTcpInternalError on resolver error). Never throws.
  /// @see try_resolve_endpoints_sync, resolve_endpoints_sync
  void resolve_endpoints_async(string_view hostname, uint16_t port, optional<std::chrono::seconds> timeout,
    CompleteCallback callback) noexcept;

  /// Resolves @p hostname and @p port to TCP endpoints, blocking until complete.
  ///
  /// @param hostname Host to resolve. May be a DNS name or a literal IP address.
  /// @param port     TCP port number combined with each resolved address.
  /// @param timeout  Maximum time to wait, in seconds; `nullopt` uses the default supplied to
  ///                 @ref create.
  /// @return The resolved @ref EndpointList, or an @ref ErrorDetail on failure. Never throws.
  /// @see resolve_endpoints_async, resolve_endpoints_sync
  EndpointListResult try_resolve_endpoints_sync(
    string_view hostname, uint16_t port, optional<std::chrono::seconds> timeout) noexcept;

  /// Resolves @p hostname and @p port to TCP endpoints, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_resolve_endpoints_sync() returns it.
  ///
  /// @param hostname Host to resolve. May be a DNS name or a literal IP address.
  /// @param port     TCP port number combined with each resolved address.
  /// @param timeout  Maximum time to wait, in seconds; `nullopt` uses the default supplied to
  ///                 @ref create.
  /// @return The resolved @ref EndpointList.
  /// @throws UaException if the resolution fails or times out, or when the answer is not Good (an Uncertain
  /// one included).
  /// @see resolve_endpoints_async, try_resolve_endpoints_sync
  EndpointList resolve_endpoints_sync(
    string_view hostname, uint16_t port, optional<std::chrono::seconds> timeout);

  /// Creates a heap-managed resolver bound to @p executor.
  ///
  /// @param executor Executor on which resolutions run and on whose worker threads completion
  ///                 callbacks are invoked.
  /// @param timeout  Default resolution timeout, in seconds, applied when a per-call timeout is not
  ///                 given; `nullopt` selects a built-in default of 5 seconds.
  /// @return A shared owner of the new resolver.
  static shared_ptr<Resolver> create(
    boost::asio::any_io_executor executor, optional<std::chrono::seconds> timeout);

private:
  mutable std::mutex mMutex;
  const std::chrono::seconds mDefaultTimeout;
  boost::asio::any_io_executor mExecutor;
  asio::ip::tcp::resolver mResolver;
  Timer mTimeoutTimer;
  CompleteCallback mCallback;

  Resolver(boost::asio::any_io_executor executor, std::chrono::seconds defaultTimeout);

  std::chrono::seconds calc_timeout(optional<std::chrono::seconds> timeout) const;
};

}  // namespace ua

#endif  // UA_RESOLVER_H
