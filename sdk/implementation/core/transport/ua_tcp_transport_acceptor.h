// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief TCP listening socket that accepts inbound transport connections.
/// @ingroup transport

#ifndef UA_TCP_TRANSPORT_ACCEPTOR_H
#define UA_TCP_TRANSPORT_ACCEPTOR_H

#include <chrono>
#include <functional>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_tcp_transport_connection.h"
#include "ua_timer.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>

namespace ua
{

/// A TCP listening socket that accepts inbound transport connections.
///
/// Binds a `tcp::endpoint` and runs a continuous `async_accept` loop on the
/// executor supplied at construction; each accepted socket is wrapped in a
/// @ref TcpTransportConnection and handed to the new-connection callback.
/// Construct only via @ref create - the instance is shared-owned
/// (`enable_shared_from_this`) and keeps itself alive across pending accepts.
/// The type is neither copyable nor movable.
/// @ingroup transport
class TcpTransportAcceptor : public std::enable_shared_from_this<TcpTransportAcceptor>
{
public:
  TcpTransportAcceptor() = delete;
  TcpTransportAcceptor(const TcpTransportAcceptor&) = delete;
  TcpTransportAcceptor(TcpTransportAcceptor&& other) noexcept = delete;
  TcpTransportAcceptor& operator=(const TcpTransportAcceptor& other) = delete;
  TcpTransportAcceptor& operator=(TcpTransportAcceptor&& other) noexcept = delete;
  ~TcpTransportAcceptor() = default;

  /// Invoked for each inbound connection accepted by the listening socket.
  ///
  /// On success the @ref StatusCode is good and the `shared_ptr` holds the
  /// newly accepted @ref TcpTransportConnection; on failure the status is bad
  /// and the connection pointer is null. The `string_view` carries a
  /// human-readable description of the accept outcome. The callback runs on the
  /// acceptor's executor.
  using NewConnectionCallback =
    std::function<void(StatusCode, string_view, shared_ptr<TcpTransportConnection>)>;

  /// Delay before the accept loop re-arms after @p consecutiveFailures accepts
  /// in a row failed for lack of resources: 0 after a success, then 100 ms
  /// doubling per failure up to 5 s. Such an accept (EMFILE/ENFILE, ENOBUFS,
  /// ENOMEM) fails again at once when re-armed immediately, so without this the
  /// loop spins a core and floods the log for as long as the condition lasts;
  /// the pending connection stays in the kernel backlog meanwhile and is
  /// accepted on the next success.
  static std::chrono::milliseconds accept_retry_delay(unsigned consecutiveFailures) noexcept;

  /// Whether a failed accept is a resource shortage of this process or host,
  /// which the backoff answers. Every other failure belongs to the one
  /// connection that was being accepted (the peer went away, its network is
  /// unreachable) and the loop re-arms at once, as accept(2) prescribes.
  static bool accept_failure_backs_off(const boost::system::error_code& ec) noexcept;

  /// Test seam: maps the operating system's accept outcome to the one the loop acts on, so a failed
  /// accept (a descriptor shortage, which a test cannot cause safely) can be driven. An injected
  /// failure drops the socket that was accepted, as a real failure produces none. Unset in
  /// production: the loop then acts on the real outcome. Safe to call from any thread.
  using AcceptOutcomeInjector = std::function<boost::system::error_code(boost::system::error_code)>;
  void set_accept_outcome_injector_for_tests(AcceptOutcomeInjector injector);

  /// Test observation: accepts that failed for lack of resources since the last success (the input
  /// of @ref accept_retry_delay). Safe to call from any thread.
  unsigned consecutive_accept_failures_for_tests() const;

  /// Returns the local endpoint (address and port) the acceptor is bound to.
  ///
  /// When the requested port is 0 the OS assigns an ephemeral port, which this
  /// reflects. Safe to call from any thread.
  ///
  /// @return The local endpoint (address and port) the acceptor is bound to.
  asio::ip::tcp::endpoint get_local_endpoint() const;

  /// Closes the acceptor and stops accepting new connections.
  ///
  /// Cancels the in-flight `async_accept` and invokes `callback` once the
  /// cancelled accept's `operation_aborted` handler has run, guaranteeing no
  /// further new-connection callbacks fire after `callback` is invoked. Safe to
  /// call from any thread. Closing is idempotent.
  ///
  /// @param[in] callback Receives a @ref VoidResult once the close completes;
  ///                     pass an empty callback for fire-and-forget close. This
  ///                     overload never throws.
  void close_async(std::function<void(VoidResult)> callback = {});

  /// Creates a listening acceptor bound to @p ipEndpoint and starts accepting.
  ///
  /// Begins the `async_accept` loop immediately; each accepted connection is
  /// delivered to @p newConnectionCallback on @p executor.
  ///
  /// @param[in] executor              Executor on which the accept loop runs and
  ///                                  callbacks are invoked.
  /// @param[in] ipEndpoint            Local address and port to bind and listen
  ///                                  on; port 0 selects an ephemeral port.
  /// @param[in] newConnectionCallback Invoked for each inbound connection (and
  ///                                  on accept failure); see
  ///                                  @ref NewConnectionCallback.
  /// @param[in] logger                Optional logger; a default-constructed
  ///                                  logger discards output.
  /// @param[in] writeQueueDepthCap    Pending-write queue cap applied to each
  ///                                  accepted connection (see
  ///                                  @ref TcpTransportConnection::create).
  /// @param[in] writeQueueBytesCap    Pending-write byte budget applied to each
  ///                                  accepted connection (same reference).
  /// @return A shared-owned acceptor that keeps itself alive across pending
  ///         accepts.
  static shared_ptr<TcpTransportAcceptor> create(boost::asio::any_io_executor executor,
    asio::ip::tcp::endpoint ipEndpoint, NewConnectionCallback newConnectionCallback, Logger logger = {},
    size_t writeQueueDepthCap = 4096,
    size_t writeQueueBytesCap = TcpTransportConnection::defaultWriteQueueBytesCap);

private:
  Logger mLogger;
  mutable std::mutex mMutex;
  NewConnectionCallback mNewConnectionCallback;
  asio::ip::tcp::acceptor mAcceptor;
  asio::ip::tcp::endpoint mEndpoint;
  // The actual bound endpoint (with the OS-assigned port when mEndpoint requested
  // port 0). Captured once in initialise() before the acceptor is shared with any
  // worker thread, then immutable - so get_local_endpoint() reads it without a
  // lock and never races a concurrent mAcceptor.close() in the close path.
  asio::ip::tcp::endpoint mBoundEndpoint;
  asio::ip::tcp::socket mSocket;
  // Guarded by mMutex. The accept loop and close_async serialize every
  // mAcceptor/mSocket operation through mMutex (asio sockets are not
  // thread-safe), so this is a plain bool, not an atomic (single-strategy rule).
  bool mClosed{false};
  // Failed accepts since the last successful one (guarded by mMutex); drives accept_retry_delay.
  unsigned mConsecutiveAcceptFailures{0};
  // Armed only after a failed accept (guarded by mMutex); cancelled by close_async.
  Timer mRetryTimer;
  AcceptOutcomeInjector mAcceptOutcomeInjectorForTests;  // guarded by mMutex
  const size_t mWriteQueueDepthCap;  // applied to each accepted connection
  const size_t mWriteQueueBytesCap;  // applied to each accepted connection

  TcpTransportAcceptor(boost::asio::any_io_executor executor, asio::ip::tcp::endpoint ipEndpoint,
    NewConnectionCallback newConnectionCallback, Logger logger, size_t writeQueueDepthCap,
    size_t writeQueueBytesCap);

  boost::asio::any_io_executor mExecutor;

  void async_accept();

  // Re-arms the accept loop after @p delay (the failed-accept path), unless closed meanwhile.
  void async_accept_after(std::chrono::milliseconds delay);

  void initialise();
};

}  // namespace ua

#endif  // !UA_TCP_TRANSPORT_ACCEPTOR_H
