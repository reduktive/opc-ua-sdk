// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief TCP/IP implementation of the byte-stream transport connection.
/// @ingroup transport

#ifndef UA_TCP_TRANSPORT_CONNECTION_H
#define UA_TCP_TRANSPORT_CONNECTION_H

#include <functional>
#include <optional>
#include <queue>
#include <boost/asio/ip/tcp.hpp>
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_transport_connection.h"

namespace asio = boost::asio;

namespace ua
{

/// A @ref TransportConnection over a connected Boost.Asio TCP socket.
///
/// Wraps an accepted or connected `asio::ip::tcp::socket` and adapts it to the
/// SDK byte-stream transport contract: registered completion callbacks plus
/// asynchronous reads and writes driven by the socket's executor. Instances are
/// always heap-allocated and reference-counted; construct via @ref create and
/// hold the returned `shared_ptr`. Reads and writes run on the socket's
/// executor, while their completion callbacks (registered via
/// @ref register_read_callback / @ref register_write_callback) are invoked on
/// the worker thread that ran the operation - do not block them.
///
/// Public methods are safe to call from any thread; mutable state is guarded by
/// an internal mutex and (for close) the socket's executor. The object keeps
/// itself alive across in-flight async operations through `shared_from_this`.
/// @ingroup transport
/// @see TransportConnection
class TcpTransportConnection : public TransportConnection,
                               public std::enable_shared_from_this<TcpTransportConnection>
{
public:
  TcpTransportConnection() = delete;
  TcpTransportConnection(const TcpTransportConnection&) = delete;
  TcpTransportConnection(TcpTransportConnection&& other) noexcept = delete;
  TcpTransportConnection& operator=(const TcpTransportConnection& other) = delete;
  TcpTransportConnection& operator=(TcpTransportConnection&& other) noexcept = delete;

  /// Destroys the connection, closing the underlying socket if still open.
  ~TcpTransportConnection();

  /// Registers the callback invoked on a transport-level socket error.
  ///
  /// @param callback Receives the failing @ref StatusCode and a human-readable
  ///                 description.
  /// @note This implementation reports socket errors through the read and write
  ///       completion callbacks instead, so the registered error callback is
  ///       never invoked. It is accepted to satisfy the base contract.
  void register_error_callback(ErrorCallback callback) override;

  /// Registers the callback invoked when an @ref async_read completes.
  ///
  /// @param callback Receives the @ref StatusCode, a description, and ownership
  ///                 of the filled buffer. Runs on the worker thread that
  ///                 completed the read; do not block it. Replaces any
  ///                 previously registered read callback.
  void register_read_callback(ReadCompleteCallback callback) override;

  /// Registers the callback invoked when a queued @ref async_write completes.
  ///
  /// @param callback Receives the @ref StatusCode and a description. Runs on the
  ///                 worker thread that completed the write; do not block it.
  ///                 Replaces any previously registered write callback.
  void register_write_callback(WriteCompleteCallback callback) override;

  /// Starts an asynchronous read that fills @p buffer from @p offset to its end.
  ///
  /// Takes ownership of @p buffer for the duration of the read and returns it,
  /// filled, to the registered read callback (see @ref register_read_callback)
  /// once exactly `buffer.size() - offset` bytes have been received. At most one
  /// read may be in flight at a time.
  ///
  /// @param[in,out] buffer Destination buffer; moved in and handed back through
  ///                       the read callback on completion.
  /// @param offset         Byte offset at which to begin writing into @p buffer.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p offset is not
  ///         less than `buffer.size()`, or @ref Status::BadInvalidState if a read
  ///         is already in progress.
  /// @see read
  void async_read(std::vector<byte>&& buffer, size_t offset = 0) override;

  /// Returns the number of bytes available to read without blocking.
  ///
  /// @return Count of bytes currently readable from the socket's receive buffer.
  size_t bytes_available_to_read() const override;
  /// A non-blocking one-byte peek: a byte means data waiting, "would block" means open, and end of stream
  /// or a connection error means the peer has closed.
  PeerState peer_state() const override;

  /// Reads synchronously into @p buffer from @p offset to its end, blocking until
  /// complete.
  ///
  /// Fills exactly `buffer.size() - offset` bytes before returning. At most one
  /// read (synchronous or asynchronous) may be in progress at a time.
  ///
  /// @param[in,out] buffer Destination buffer; the region from @p offset onward
  ///                       is overwritten with received bytes.
  /// @param offset         Byte offset at which to begin writing into @p buffer.
  /// @return @ref Status::Good on success, or @ref Status::BadInternalError if
  ///         the read fails or completes short.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p offset is not
  ///         less than `buffer.size()`, or @ref Status::BadInvalidState if a read
  ///         is already in progress.
  /// @see async_read
  StatusCode read(std::vector<byte>& buffer, size_t offset = 0) override;

  /// Queues @p buffer for asynchronous transmission.
  ///
  /// Takes ownership of @p buffer and sends its full contents. Concurrent calls
  /// are serialized: buffers are written in submission order and never overlap on
  /// the socket. The registered write callback (see @ref register_write_callback)
  /// fires once the queue has fully drained.
  ///
  /// If the pending-write queue is already at its depth cap, or the bytes queued
  /// plus in flight already reach the byte budget (a slow/stalled peer not
  /// draining the socket), a NEW message **fails closed**: its first chunk is
  /// dropped and the write callback is invoked with
  /// @ref Status::BadTcpNotEnoughResources rather than letting the queue grow
  /// without bound, and its later chunks are dropped silently. Both caps are
  /// applied at a message's first chunk only (the two-argument form says which
  /// chunk that is; this form treats every buffer as a message), so a message
  /// once admitted is queued whole and the memory bound is the cap plus one
  /// message.
  ///
  /// @param buffer Bytes to transmit; moved in and owned until the write
  ///               completes.
  void async_write(std::vector<byte>&& buffer) override;
  void async_write(std::vector<byte>&& buffer, bool startsMessage) override;

  /// Closes the socket and invokes @p callback once any cancellation handlers
  /// queued by the close have run.
  ///
  /// Posts the close onto the socket's executor, so it is safe to call from any
  /// thread, including from inside a read or write completion handler. If a read
  /// or write is in flight at close time, @p callback is deferred until that
  /// operation's completion handler has run, so callers observe all in-flight
  /// operations as resolved before the close completes. The connection keeps
  /// itself alive (via `shared_from_this`) until the close completes.
  ///
  /// With @p mode CloseMode::AfterPendingWrites the socket closes once the pending-write queue has
  /// drained, or at once if nothing is queued or in flight. The completion handler of the last queued
  /// write performs the close, so a buffer written before this call reaches the socket before it
  /// closes; an Immediate close issued meanwhile closes at once and completes @p callback too.
  ///
  /// @param callback Invoked with a successful @ref VoidResult once the close has
  ///                 drained. May be empty for fire-and-forget close. This
  ///                 overload never throws.
  /// @param mode     Whether to close now or after the queued writes. Defaults to Immediate.
  void close_async(
    std::function<void(VoidResult)> callback = {}, CloseMode mode = CloseMode::Immediate) override;

  /// Returns the local TCP endpoint of the connection.
  ///
  /// @return The local endpoint captured at construction, or a default-constructed
  ///         endpoint if it could not be determined.
  asio::ip::tcp::endpoint get_local_endpoint() const override;

  /// Returns the remote (peer) TCP endpoint of the connection.
  ///
  /// @return The remote endpoint captured at construction, or a
  ///         default-constructed endpoint if it could not be determined.
  asio::ip::tcp::endpoint get_remote_endpoint() const;

  /// Default byte budget for buffers queued or in flight on one connection (16 MiB).
  static constexpr size_t defaultWriteQueueBytesCap = static_cast<size_t>(16) * 1024 * 1024;

  /// Creates a reference-counted connection that adopts @p socket.
  ///
  /// The socket must already be connected; its local and remote endpoints are
  /// captured at this point. This is the only way to obtain an instance, since
  /// the class requires `shared_from_this`.
  ///
  /// @param socket Connected TCP socket; moved into and owned by the connection.
  /// @param logger Logger used for transport diagnostics; a default-constructed
  ///               logger disables logging.
  /// @param writeQueueDepthCap Number of buffers waiting in the pending-write
  ///               queue at or beyond which a NEW message is refused by
  ///               @ref async_write (`BadTcpNotEnoughResources`). Bounds memory
  ///               against a peer that stops draining the socket. Clamped to
  ///               >= 1.
  /// @param writeQueueBytesCap Bytes queued or in flight at or beyond which a
  ///               NEW message is refused the same way. The depth cap alone lets
  ///               a peer that stops reading hold depth x chunk size; this
  ///               bounds the bytes whatever the chunk size. Both caps are
  ///               applied at a message's first chunk only: a message that was
  ///               admitted is queued whole, so the true bound is the cap plus
  ///               one maximum-size message, and a peer that reads slowly is
  ///               never cut off mid-message. Clamped to >= 1 (which admits one
  ///               message at a time).
  /// @return A `shared_ptr` owning the new connection.
  static shared_ptr<TcpTransportConnection> create(asio::ip::tcp::socket&& socket, Logger logger = {},
    size_t writeQueueDepthCap = 4096, size_t writeQueueBytesCap = defaultWriteQueueBytesCap);

private:
  friend struct TcpTransportConnectionTestAccess;

  Logger mLogger;
  mutable std::mutex mMutex;
  asio::ip::tcp::socket mSocket;

  // Endpoints are captured once at construction (while the socket is freshly
  // accepted/connected and not yet shared with worker threads) and held
  // immutable thereafter. TCP endpoints do not change for the lifetime of a
  // connected socket, so caching is semantically correct and eliminates the
  // race between mSocket.close() (taken under mMutex by close_async) and
  // mSocket.{local,remote}_endpoint() reads elsewhere.
  const std::optional<asio::ip::tcp::endpoint> mLocalEndpoint;
  const std::optional<asio::ip::tcp::endpoint> mRemoteEndpoint;

  std::queue<std::vector<byte>> mPendingWriteBuffers;
  // Depth cap on mPendingWriteBuffers; async_write fails closed past it (see async_write).
  const size_t mWriteQueueDepthCap;
  // Byte budget over mPendingWriteBuffers AND mActiveWriteBuffers together (the bytes this connection
  // holds for a peer that is not draining); async_write fails closed past it. Guarded by mMutex.
  const size_t mWriteQueueBytesCap;
  size_t mQueuedWriteBytes{0};
  // True from a refused first chunk until the next first chunk: the refused message's continuation
  // chunks are dropped too, so a message is delivered whole or not at all. Guarded by mMutex.
  bool mDroppingMessage{false};
  std::vector<std::vector<byte>> mActiveWriteBuffers;
  std::vector<asio::const_buffer> mActiveAsioWriteBuffers;
  WriteCompleteCallback mWriteCompleteCallback;

  std::vector<byte> mReadBuffer;
  ReadCompleteCallback mReadCompleteCallback;

  // Deferred close_async callbacks waiting for in-flight async_read/async_write
  // ops to drain. close_async populates this when an op is in flight at close
  // time; the read/write completion handlers fire and clear it after invoking
  // their own user callback. Guarantees drain-before-callback ordering of the
  // close_async contract documented above.
  std::vector<std::function<void(VoidResult)>> mPendingCloseCallbacks;

  // CloseMode::AfterPendingWrites callbacks waiting for the write queue to drain. The write completion
  // that leaves nothing queued takes them and closes; an Immediate close taken first completes them.
  // Guarded by mMutex.
  std::vector<std::function<void(VoidResult)>> mCloseAfterWritesCallbacks;

  TcpTransportConnection(
    asio::ip::tcp::socket&& socket, Logger logger, size_t writeQueueDepthCap, size_t writeQueueBytesCap);

  void write();
};

}  // namespace ua

#endif  // !UA_TCP_TRANSPORT_CONNECTION_H
