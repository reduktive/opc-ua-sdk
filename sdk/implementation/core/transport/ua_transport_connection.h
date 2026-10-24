// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Abstract byte-stream connection underpinning the OPC UA transport.
/// @ingroup transport

#ifndef UA_TRANSPORT_CONNECTION_H
#define UA_TRANSPORT_CONNECTION_H

#include <functional>
#include <boost/asio/ip/basic_endpoint.hpp>
#include "ua_includes.h"
#include "ua_result.h"
#include "ua_status_code.h"

namespace asio = boost::asio;

namespace ua
{

/// A bidirectional byte-stream connection to a single peer.
///
/// Models one established transport-layer link (a connected TCP socket in the
/// reference implementation) as the framing layer above it sees it: a sink for
/// outbound bytes and a source for inbound bytes. Completion of asynchronous
/// reads and writes is delivered through callbacks registered up front rather
/// than per operation, so the framing layer registers its handlers once and
/// then drives `async_read` / `async_write` against them.
///
/// Implementations are internally synchronized and may be used from any thread;
/// registered callbacks run on an unspecified transport worker thread and must
/// not block it. Ownership is shared - the connection typically outlives the
/// call that issued an asynchronous operation, so completion handlers capture a
/// weak reference and become no-ops once the connection is gone.
/// @ingroup transport
class TransportConnection
{
public:
  virtual ~TransportConnection()
  {}

  /// Non-copyable and non-movable: instances form a polymorphic base held
  /// through `shared_ptr`/reference and must never be sliced (C.67).
  TransportConnection(const TransportConnection&) = delete;
  TransportConnection& operator=(const TransportConnection&) = delete;
  TransportConnection(TransportConnection&&) = delete;
  TransportConnection& operator=(TransportConnection&&) = delete;

protected:
  /// Default-constructs the abstract base; only derived transports are instantiable. Required
  /// because the deleted copy/move members above otherwise suppress the implicit default ctor.
  TransportConnection() = default;

public:
  /// Callback receiving an out-of-band socket error: status code and a
  /// human-readable description.
  using ErrorCallback = std::function<void(StatusCode, string_view)>;

  /// Registers the handler invoked when an out-of-band socket error is
  /// observed, replacing any previously registered handler.
  ///
  /// @param callback Receives the error status and a description. Runs on a
  ///                 transport worker thread; must not block.
  /// @note Some implementations report all errors through the read/write
  ///       completion callbacks instead and never invoke this handler.
  virtual void register_error_callback(ErrorCallback callback) = 0;

  /// Callback receiving the result of an `async_read`: status code, a
  /// description (set on failure), and the buffer handed to `async_read` moved
  /// back to the caller filled with the bytes read.
  using ReadCompleteCallback = std::function<void(StatusCode, string_view, std::vector<byte>&&)>;

  /// Registers the handler invoked when an `async_read` completes, replacing
  /// any previously registered handler.
  ///
  /// @param callback Receives `Good` and the filled buffer on success, or a
  ///                 `Bad*` status and description on failure. Runs on a
  ///                 transport worker thread; must not block.
  /// @pre A handler must be registered before issuing an `async_read`.
  /// @see async_read
  virtual void register_read_callback(ReadCompleteCallback callback) = 0;

  /// Callback receiving the result of an `async_write`: status code and a
  /// description (set on failure).
  using WriteCompleteCallback = std::function<void(StatusCode, string_view)>;

  /// Registers the handler invoked when an `async_write` completes, replacing
  /// any previously registered handler.
  ///
  /// @param callback Receives `Good` on success, or a `Bad*` status and
  ///                 description on failure. Runs on a transport worker thread;
  ///                 must not block.
  /// @pre A handler must be registered before issuing an `async_write`.
  /// @see async_write
  virtual void register_write_callback(WriteCompleteCallback callback) = 0;

  /// Returns the local endpoint (address and port) of this connection.
  ///
  /// @return The local endpoint (address and port) of this connection.
  virtual asio::ip::tcp::endpoint get_local_endpoint() const = 0;

  /// Starts an asynchronous read that fills `buffer` from `offset` to its end.
  ///
  /// Takes ownership of `buffer` by move for the duration of the operation and
  /// returns it through the registered @ref ReadCompleteCallback once exactly
  /// `buffer.size() - offset` bytes have been read or the read fails. At most
  /// one read may be in flight at a time.
  ///
  /// @param[in,out] buffer Storage to fill, moved into the connection; the
  ///                       region `[offset, size())` is the read target.
  /// @param offset         Index at which to begin writing read bytes; bytes
  ///                       before it are left untouched. Defaults to 0.
  /// @throws UaException with `BadInvalidArgument` if `offset >= buffer.size()`,
  ///         or `BadInvalidState` if a read is already in progress.
  /// @pre A read-complete callback has been registered.
  /// @see register_read_callback, read
  virtual void async_read(std::vector<byte>&& buffer, size_t offset = 0) = 0;

  /// Returns the number of bytes available to read immediately without
  /// blocking.
  ///
  /// @return The number of bytes available to read immediately without blocking.
  virtual size_t bytes_available_to_read() const = 0;

  /// What a liveness probe of the peer reports (see peer_state).
  enum class PeerState
  {
    Open,  ///< Open, with nothing waiting to be read.
    DataWaiting,  ///< Bytes are waiting to be read; whether a close follows them cannot be seen yet.
    Closed  ///< The peer has closed or reset the connection.
  };

  /// Probes the peer without blocking and without consuming data: open and idle, open with data waiting,
  /// or closed.
  ///
  /// For a connection with no read armed (a reverse connection waiting in the client's queue), a peer's
  /// close is otherwise noticed only when the connection is next used. Must not be called while an
  /// asynchronous read is outstanding.
  ///
  /// @return @ref PeerState::Closed when the peer has closed or reset the connection,
  ///         @ref PeerState::DataWaiting when bytes are waiting, otherwise @ref PeerState::Open. A transport
  ///         that cannot detect a close (the default) reports only whether bytes_available_to_read is
  ///         non-zero.
  virtual PeerState peer_state() const
  {
    return bytes_available_to_read() > 0 ? PeerState::DataWaiting : PeerState::Open;
  }

  /// Reads synchronously into `buffer` from `offset` to its end, blocking until
  /// the bytes arrive.
  ///
  /// @param[out] buffer Storage to fill; the region `[offset, size())` is the
  ///                    read target.
  /// @param offset      Index at which to begin writing read bytes. Defaults
  ///                    to 0.
  /// @return `Good` once the region is filled, or a `Bad*` status on error.
  /// @throws UaException with `BadInvalidArgument` if `offset >= buffer.size()`,
  ///         or `BadInvalidState` if a read is already in progress.
  /// @see async_read
  virtual StatusCode read(std::vector<byte>& buffer, size_t offset = 0) = 0;

  /// Queues `buffer` to be written and starts the write if the connection is
  /// idle.
  ///
  /// Takes ownership of `buffer` by move. Writes are serialized in submission
  /// order, so this may be called repeatedly before earlier writes complete;
  /// each completion is reported through the registered
  /// @ref WriteCompleteCallback.
  ///
  /// @param buffer Bytes to write, moved into the connection.
  /// @pre A write-complete callback has been registered.
  /// @see register_write_callback
  virtual void async_write(std::vector<byte>&& buffer) = 0;

  /// As the one-argument @ref async_write, stating whether @p buffer starts a new message
  /// (`true`, which the one-argument form assumes) or continues a message whose first chunk was
  /// already accepted. A transport with a send budget admits or refuses a MESSAGE at its first
  /// chunk and never drops a continuation chunk of a message it admitted, so a multi-chunk
  /// message is delivered whole or not at all. The default forwards to the one-argument form.
  virtual void async_write(std::vector<byte>&& buffer, bool startsMessage)
  {
    (void)startsMessage;
    async_write(std::move(buffer));
  }

  /// When @ref close_async closes the connection.
  enum class CloseMode
  {
    /// Close now, aborting any write still queued or in flight.
    Immediate,
    /// Close once every buffer handed to `async_write` before the call has been written (or has
    /// failed), so a final message is not cut off by the close: a client's CloseSecureChannel request
    /// after a fatal error (OPC 10000-6 7.1.4, 7.1.5). An Immediate close issued while the writes are
    /// still pending closes at once and completes the waiting callback as well. A transport that
    /// cannot tell when its writes have drained closes at once, giving up only the final message.
    AfterPendingWrites
  };

  /// Closes the connection and invokes `callback` once any cancellation
  /// handlers queued by the close have drained.
  ///
  /// Deferred so that in-flight read/write completions fire before the close
  /// callback, letting callers observe pending operations as resolved first.
  ///
  /// @param callback Receives a `VoidResult` once the close has drained. Pass
  ///                 an empty callback for fire-and-forget close (typical for
  ///                 inline error-recovery paths). Defaults to empty.
  /// @param mode     Whether to close now or after the writes already queued. Defaults to
  ///                 @ref CloseMode::Immediate.
  virtual void close_async(
    std::function<void(VoidResult)> callback = {}, CloseMode mode = CloseMode::Immediate) = 0;
};

}  // namespace ua

#endif  // !UA_TRANSPORT_CONNECTION_H
