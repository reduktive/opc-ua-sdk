// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Asynchronous TCP client-side connector that produces a connected transport connection.
/// @ingroup transport

#ifndef UA_TCP_TRANSPORT_CONNECTOR_H
#define UA_TCP_TRANSPORT_CONNECTOR_H

#include <functional>
#include <vector>
#include <boost/asio/io_context.hpp>
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_tcp_transport_connection.h"
#include "ua_timer.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

namespace asio = boost::asio;

namespace ua
{

/// Maps a failed TCP connect's error code onto the OPC UA status that names WHAT failed.
///
/// A refused connection, an unreachable host and a timeout are different operator problems with
/// different responses, and the distinction exists only in the error code: reported as one blanket
/// status it survives nowhere but a platform message a caller would have to string-match. Errors this
/// mapping does not recognise keep `Bad_TcpInternalError`.
///
/// @param ec The error code the connect completed with.
/// @return `Bad_ConnectionRejected` for refused / unreachable / unresolvable, `Bad_Timeout` for a
///         timed-out connect, otherwise `Bad_TcpInternalError`.
///
/// @ingroup transport
[[nodiscard]] StatusCode connect_failure_status(const boost::system::error_code& ec);

/// Client-side TCP connector that asynchronously establishes one outbound connection.
///
/// Opens a socket to one endpoint or an ordered sequence of resolved endpoints; on success it delivers
/// a ready @ref TcpTransportConnection to the @ref ConnectedCallback supplied at creation, and on
/// aggregate failure it delivers the StatusCode and a diagnostic message instead. Instances are created
/// via @ref create and held through `shared_ptr`; the connector keeps itself alive across the in-flight
/// connect. All work runs on the executor passed to @ref create, and the completion callback is invoked
/// on one of that executor's worker threads - do not block it.
///
/// @ingroup transport
class TcpTransportConnector : public std::enable_shared_from_this<TcpTransportConnector>
{
public:
  /// Default construction is disabled; obtain instances through @ref create.
  TcpTransportConnector() = delete;

  /// Non-copyable: a connector owns a unique socket and an in-flight async operation.
  TcpTransportConnector(const TcpTransportConnector&) = delete;

  /// Non-movable: instances are referenced by `shared_ptr` and outstanding async handlers.
  ///
  /// @param other The connector to move from.
  TcpTransportConnector(TcpTransportConnector&& other) noexcept = delete;

  /// Non-copy-assignable. @see TcpTransportConnector(const TcpTransportConnector&)
  ///
  /// @param other The connector to copy from.
  /// @return A reference to this connector.
  TcpTransportConnector& operator=(const TcpTransportConnector& other) = delete;

  /// Non-move-assignable. @see TcpTransportConnector(TcpTransportConnector&&)
  ///
  /// @param other The connector to move from.
  /// @return A reference to this connector.
  TcpTransportConnector& operator=(TcpTransportConnector&& other) noexcept = delete;

  ~TcpTransportConnector() = default;

  /// Callback invoked once with the outcome of the connect attempt.
  ///
  /// The StatusCode reports success or the failure reason, the `string_view` carries a diagnostic
  /// message (empty on success), and the `shared_ptr` holds the ready connection on success or is
  /// null on failure. The view is only valid for the duration of the call; copy it to retain it.
  /// Invoked on a worker thread of the connector's executor - do not block it.
  using ConnectedCallback = std::function<void(StatusCode, string_view, shared_ptr<TcpTransportConnection>)>;

  /// Creates a connector and begins connecting to @p ipEndpoint asynchronously.
  ///
  /// The returned connector immediately starts a single `async_connect` on @p executor; the
  /// outcome is delivered exactly once to @p connectedCallback (see @ref ConnectedCallback). The
  /// connector retains itself for the duration of the connect, so the caller need not keep the
  /// returned `shared_ptr` alive solely to receive the callback.
  ///
  /// @param executor          Executor on which the connect and its completion handler run.
  /// @param ipEndpoint        Resolved TCP endpoint to connect to.
  /// @param connectedCallback Receives the connect outcome exactly once; must not be empty.
  /// @param logger            Logger for diagnostics; a disabled logger by default.
  /// @param writeQueueDepthCap Pending-write queue cap applied to the established connection (see
  ///                          @ref TcpTransportConnection::create). Bounds memory if the peer stops
  ///                          draining the socket - applies to outbound connections just as the
  ///                          acceptor's cap applies to inbound ones.
  /// @return A `shared_ptr` to the new connector with the connect already in flight.
  static shared_ptr<TcpTransportConnector> create(boost::asio::any_io_executor executor,
    asio::ip::tcp::endpoint ipEndpoint, ConnectedCallback connectedCallback, Logger logger = {},
    size_t writeQueueDepthCap = 4096,
    size_t writeQueueBytesCap = TcpTransportConnection::defaultWriteQueueBytesCap);

  /// Creates a connector and tries each resolved endpoint until one connects or all fail.
  ///
  /// Endpoint order is preserved. A refusal or other connect error from one address advances to the next
  /// address in the sequence, matching the multi-address semantics expected after DNS resolution.
  ///
  /// @param executor          Executor on which the connect attempts and completion handler run.
  /// @param ipEndpoints       Ordered resolved TCP endpoints; must not be empty.
  /// @param connectedCallback Receives the aggregate connect outcome exactly once; must not be empty.
  /// @param logger            Logger for diagnostics; a disabled logger by default.
  /// @param writeQueueDepthCap Pending-write queue cap applied to the established connection.
  /// @param writeQueueBytesCap Pending-write byte budget applied to the established connection.
  /// @return A `shared_ptr` to the new connector with the connect sequence already in flight.
  static shared_ptr<TcpTransportConnector> create(boost::asio::any_io_executor executor,
    std::vector<asio::ip::tcp::endpoint> ipEndpoints, ConnectedCallback connectedCallback, Logger logger = {},
    size_t writeQueueDepthCap = 4096,
    size_t writeQueueBytesCap = TcpTransportConnection::defaultWriteQueueBytesCap);

  /// Cancels an in-flight connect by closing the socket and reports when teardown has completed.
  ///
  /// Closing the socket causes the pending `async_connect` completion handler to run with
  /// `operation_aborted`; @p callback is invoked with a @ref VoidResult only after that handler
  /// has run, preserving drain-before-callback ordering. Safe to call from any thread. If no
  /// connect is in flight, @p callback is invoked promptly. Pass an empty callback for
  /// fire-and-forget cancellation. This method never throws; the outcome is delivered through the
  /// @ref VoidResult.
  ///
  /// @param callback Receives a @ref VoidResult once the close has drained; may be empty.
  void close_async(std::function<void(VoidResult)> callback = {});

private:
  Logger mLogger;
  std::mutex mMutex;
  ConnectedCallback mConnectedCallback;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  asio::ip::tcp::socket mSocket;
  // True from initialise() until the async_connect completion handler runs.
  // close_async uses this to know whether to defer the user callback until the
  // connect completion (which fires with operation_aborted on socket close)
  // has run, preserving drain-before-callback ordering.
  bool mConnectInFlight = false;
  std::vector<std::function<void(VoidResult)>> mPendingCloseCallbacks;
  std::vector<asio::ip::tcp::endpoint> mIpEndpoints;
  const size_t mWriteQueueDepthCap;  // applied to the established connection
  const size_t mWriteQueueBytesCap;  // applied to the established connection

  TcpTransportConnector(boost::asio::any_io_executor executor, ConnectedCallback connectedCallback,
    Logger logger, size_t writeQueueDepthCap, size_t writeQueueBytesCap);

  boost::asio::any_io_executor mExecutor;

  void initialise(std::vector<asio::ip::tcp::endpoint> ipEndpoints);
};

}  // namespace ua

#endif  // !UA_TCP_TRANSPORT_CONNECTOR_H
