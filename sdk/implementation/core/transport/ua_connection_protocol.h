// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CONNECTION_PROTOCOL_H
#define UA_CONNECTION_PROTOCOL_H

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include "ua_connection_protocol_limits.h"
#include "ua_encoding_limits.h"
#include "ua_guid.h"
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_reverse_hello.h"
#include "ua_timer.h"
#include "ua_transport_connection.h"

#include <boost/asio/ip/tcp.hpp>

namespace asio = boost::asio;

namespace ua
{

class TransportConnection;

enum class ConnectionProtocolRole
{
  Server,
  Client
};

class ConnectionProtocolDependencies
{
public:
  ConnectionProtocolDependencies() = default;
  ConnectionProtocolDependencies(const ConnectionProtocolDependencies&) = delete;
  ConnectionProtocolDependencies& operator=(const ConnectionProtocolDependencies&) = delete;
  ConnectionProtocolDependencies(ConnectionProtocolDependencies&&) = delete;
  ConnectionProtocolDependencies& operator=(ConnectionProtocolDependencies&&) = delete;
  virtual ~ConnectionProtocolDependencies() = default;
  virtual boost::asio::any_io_executor executor() = 0;
  virtual ua::EncodingLimits encoding_limits() const = 0;
  virtual ua::connection_protocol::Limits connection_protocol_limits() const = 0;
  virtual Logger logger() = 0;
};

class ConnectionProtocol : public std::enable_shared_from_this<ConnectionProtocol>
{
public:
  // mRole (a const member) is initialised in the sole real constructor, ConnectionProtocol(role, ...).
  // cppcheck misattributes uninitMemberVar to this deleted default constructor (which initialises
  // nothing by definition). Suppress only this false positive so the check keeps gating genuine
  // uninitialised-member bugs elsewhere.
  // cppcheck-suppress uninitMemberVar
  ConnectionProtocol() = delete;
  ConnectionProtocol(const ConnectionProtocol&) = delete;
  ConnectionProtocol(ConnectionProtocol&& other) noexcept = delete;
  ConnectionProtocol& operator=(const ConnectionProtocol& other) = delete;
  ConnectionProtocol& operator=(ConnectionProtocol&& other) noexcept = delete;
  ~ConnectionProtocol();

  asio::ip::tcp::endpoint get_local_endpoint() const;

  void send_message_chunk(std::vector<byte>&& messageChunk);

  /// Identity of the transport connection this protocol runs on; compared, never dereferenced (it
  /// keys the server's per-IP admission slot, reserved before the protocol exists).
  const TransportConnection* transport_identity() const noexcept
  {
    return mConnection.get();
  }

  void send_error(StatusCode, string_view);

  /// Close the connection protocol and invoke `callback` once the underlying
  /// transport has confirmed drain (no further read/write completion handlers
  /// will fire after `callback` runs). Pass an empty callback for
  /// fire-and-forget close (typical for inline error-recovery paths).
  ///
  /// With @p mode CloseMode::AfterPendingWrites the transport closes once every chunk already submitted
  /// through @ref send_message_chunk has been written, so a final response is not cut off: the server's
  /// answer to the ApplyChanges that closes its own channel (OPC 10000-12 7.10.6). The protocol keeps itself,
  /// and so the transport it owns, alive until then, bounded by the fallback timer (the create() argument
  /// `fatalCloseTimeout`), after which the transport closes at once. Cost: one timer per such close.
  void close_async(std::function<void(VoidResult)> callback = {},
    TransportConnection::CloseMode mode = TransportConnection::CloseMode::Immediate);

  /// Pause the inbound read pump for backpressure. The owning SecureChannel calls this when its
  /// incoming-chunk queue reaches its configured depth cap. Pausing does **not** cancel an in-flight
  /// read - the current message finishes and is delivered - it only inhibits re-arming the read for the
  /// *next* message header. No data is dropped; this is pure flow control. Thread-safe: posts to the
  /// protocol's private strand. Idempotent.
  void pause_reads();

  /// Resume the inbound read pump previously paused by @ref pause_reads. If a header read was withheld
  /// while paused, it is armed now. Thread-safe: posts to the private strand. A no-op if not paused.
  void resume_reads();

  /// Whether this connection is restricted to ECC security policies.
  /// Set when the client's Hello buffer sizes are below the non-ECC minimum (8192).
  /// Thread-safe - may be called from any strand.
  bool is_ecc() const
  {
    return mEccOnly.load(std::memory_order_relaxed);
  }

  using ConnectionCompleteCallback = std::function<void(StatusCode, shared_ptr<ConnectionProtocol>,
    ua::connection_protocol::NegotiatedLimits, std::optional<detail::ReverseHelloMessage>)>;
  using CloseObserver = std::function<void(StatusCode, string_view)>;

  /// Installs the post-handshake sinks. The error sink fires once, with the disposition of the
  /// transport. With @p delegateFatalClose (a client-role protocol whose SecureChannel sends the
  /// CloseSecureChannel request a fatal error calls for, Part 6 7.1.5), a fatal error that leaves the
  /// transport writable is reported as FatalCloseDisposition::AwaitingClose: the protocol has stopped
  /// reading but not closed, and closes when the channel calls @ref close_after_pending_writes or
  /// @ref close_async, or when the fallback timer (the create() argument `fatalCloseTimeout`) fires.
  /// Without it every fatal error closes the transport and is reported as TransportClosed.
  void set_callbacks(ua::connection_protocol::MessageChunkReceivedCallback messageChunkReceivedCallback,
    ua::connection_protocol::ErrorCallback errorCallback, bool delegateFatalClose = false);

  /// Close the transport once every chunk already submitted through @ref send_message_chunk has been
  /// written, bounded by the fallback timer, and report nothing further. The client SecureChannel calls
  /// it after its CloseSecureChannel request is encoded and may release its reference straight after:
  /// the protocol keeps itself alive until the transport is closed.
  void close_after_pending_writes();

  /// Begin the fatal close for an error the client SecureChannel detected itself (a chunk it could not
  /// decode, a failed renewal): stop reading and arm the fallback timer now, so the wait for its
  /// CloseSecureChannel request is bounded as it is for an error the protocol detected. The channel then
  /// calls @ref close_after_pending_writes once the request is encoded; if it never does, the timer
  /// closes the transport. Reports nothing: the channel reported the error.
  void begin_close_after_channel_error();

  using EndpointUrlValidator = std::function<bool(string_view endpointUrl)>;
  using ReverseHelloValidator = std::function<bool(const detail::ReverseHelloMessage&)>;

  static shared_ptr<ConnectionProtocol> create(ConnectionProtocolRole role,
    weak_ptr<ConnectionProtocolDependencies> dependencies, shared_ptr<TransportConnection> connection,
    bool reverseConnect, std::chrono::seconds timeout, ConnectionCompleteCallback connectionCompleteCallback,
    ua::connection_protocol::ErrorCallback errorCallback, std::string endpointUrl = {},
    EndpointUrlValidator endpointUrlValidator = {},
    std::chrono::milliseconds messageReadTimeout = std::chrono::milliseconds{10'000},
    std::string serverUri = {}, ReverseHelloValidator reverseHelloValidator = {},
    CloseObserver closeObserver = {}, std::chrono::milliseconds fatalCloseTimeout = defaultFatalCloseTimeout);

  /// How long a client-role protocol waits by default, after a fatal error, for the SecureChannel's
  /// CloseSecureChannel request to be written before it closes the transport itself. A
  /// CloseSecureChannel request is one small chunk; a peer that has not read it in this time is not
  /// reading at all.
  static constexpr std::chrono::milliseconds defaultFatalCloseTimeout{3000};

private:
  const Guid mId;
  const ConnectionProtocolRole mRole;
  const bool mReverseConnect;
  const weak_ptr<ConnectionProtocolDependencies> mDependencies;

  /// Config limits from the local application.
  ua::connection_protocol::Limits mConfigLimits;

  /// Raw Hello values from the client (server-side only, stored for ACK construction).
  struct HelloValues
  {
    uint32_t receiveBufferSize{0};
    uint32_t sendBufferSize{0};
    uint32_t maxMessageSize{0};
    uint32_t maxChunkCount{0};
  };

  /// Post-negotiation limits, populated after handshake completes.
  ua::connection_protocol::NegotiatedLimits mNegotiatedLimits;

  /// Whether this connection is ECC-only (Hello buffers < 8192).
  std::atomic<bool> mEccOnly{false};

  std::optional<boost::asio::strand<boost::asio::any_io_executor>> mStrand;
  const shared_ptr<TransportConnection> mConnection;
  // True while the chunk last handed to the transport was an intermediate one ('C'), so the next
  // chunk continues that message; strand-only (send_message_chunk runs on mStrand).
  bool mSendingContinuation{false};
  std::string mEndpointUrl;
  std::string mServerUri;
  EndpointUrlValidator mEndpointUrlValidator;
  ReverseHelloValidator mReverseHelloValidator;
  std::optional<detail::ReverseHelloMessage> mReverseHelloMessage;
  ua::connection_protocol::MessageChunkReceivedCallback mMessageChunkReceivedCallback;
  ua::connection_protocol::ErrorCallback mErrorCallback;
  // Set by set_callbacks(..., delegateFatalClose = true): mErrorCallback sends the CloseSecureChannel a
  // fatal error calls for, so the protocol leaves a writable transport open for it (strand-owned).
  bool mDelegateFatalClose{false};
  CloseObserver mCloseObserver;

  /// Client fatal-close state (strand-owned). `mFatalClosing`: a fatal error left the transport writable
  /// for the SecureChannel's CloseSecureChannel, so reads have stopped and the next failure closes at
  /// once. `mTransportClosed`: the transport close has been requested, so a later request is a no-op.
  /// `mFatalCloseKeepAlive` holds this protocol from close_after_pending_writes until the transport has
  /// closed, since the channel releases it; the fallback timer bounds that wait.
  bool mFatalClosing{false};
  bool mTransportClosed{false};
  /// Set by a close after pending writes: the read its transport close aborts is that close, not a failure.
  bool mClosingAfterWrites{false};
  StatusCode mFatalCloseStatus;
  std::string mFatalCloseDescription;
  Timer mFatalCloseTimer;
  std::chrono::milliseconds mFatalCloseTimeout{defaultFatalCloseTimeout};
  shared_ptr<ConnectionProtocol> mFatalCloseKeepAlive;

  /// Inbound read-pump backpressure state (strand-owned). `mReadsPaused` inhibits the next header
  /// re-arm; `mHeaderRxDeferred` records that a header read was withheld while paused so `resume_reads`
  /// can arm it. See `configure_for_header_rx` / `pause_reads` / `resume_reads`.
  bool mReadsPaused{false};
  bool mHeaderRxDeferred{false};

  Timer mMessageReadTimer;
  std::chrono::milliseconds mMessageReadTimeout{10'000};
  boost::asio::any_io_executor mExecutor;
  Logger mLogger;

  /// Per-flow handshake state. `mHandshakeFlow != nullptr` is the canonical
  /// "handshake in progress" predicate. Allocated in `initialise`, reset by
  /// `complete_handshake` / `fail_handshake`.
  struct HandshakeFlow;
  std::unique_ptr<HandshakeFlow> mHandshakeFlow;

  ConnectionProtocol(ConnectionProtocolRole role, weak_ptr<ConnectionProtocolDependencies> dependencies,
    shared_ptr<TransportConnection> connection, bool reverseConnect,
    ua::connection_protocol::ErrorCallback errorCallback, std::string endpointUrl,
    EndpointUrlValidator endpointUrlValidator, std::string serverUri,
    ReverseHelloValidator reverseHelloValidator, CloseObserver closeObserver);

  void initialise(boost::asio::any_io_executor executor, std::chrono::seconds timeout,
    std::chrono::milliseconds messageReadTimeout, ConnectionCompleteCallback connectionCompleteCallback);

public:
  /// Probes the peer of this connection (see TransportConnection::peer_state); @ref
  /// TransportConnection::PeerState::Open when there is no transport. For a connection with no read armed;
  /// the reverse-connect listener probes the connections it has queued.
  TransportConnection::PeerState peer_state() const;

private:
  /// Whether the transport can still carry a message when a fatal error is detected. A failed read or
  /// write, a transport error and the server's ERR leave nothing a client could send its
  /// CloseSecureChannel on.
  enum class TransportState
  {
    Writable,
    Failed
  };

  /// Report a fatal error and close: a server sends ERR first, a client that delegated the close
  /// (set_callbacks) is left a writable transport for its CloseSecureChannel when @p transport allows.
  /// @p description is the ERR Reason a server sends, so it must be fixed, server-authored text; when it is
  /// empty the Reason is the specification's description of @p status (ua::description). Text that came
  /// from the transport or an exception (an OS error string, a decoder's message) never goes here: the
  /// caller puts it in @p status's ErrorDetail, which the error sink and the log receive (review B1-10).
  /// @p transport matters to a client only: after a failed read or write, or the server's ERR, no
  /// CloseSecureChannel can be sent.
  void send_error_to_secure_channel_and_close(
    StatusCode status, string_view description, TransportState transport = TransportState::Writable);
  void notify_close_observer(StatusCode status, string_view description);

  /// Fire the error sink, at most once over the protocol's life.
  void fire_error_sink(StatusCode status, string_view description, FatalCloseDisposition disposition);

  // Client fatal close (see set_callbacks, delegateFatalClose).
  void begin_fatal_close(StatusCode status, string_view description);
  void arm_fatal_close_timer();
  void close_transport_after_fatal_error();
  /// close_async with CloseMode::AfterPendingWrites, on the strand.
  void close_after_writes_on_strand(std::function<void(VoidResult)> done);
  void on_transport_closed_after_writes();

  // Server handshake
  void send_reverse_hello();
  void on_hello_received(StatusCode, string_view, std::vector<byte>&& buffer);
  void on_hello_decoded(StatusCode, string_view, std::vector<byte>&& buffer);
  void send_acknowledge();

  // Client handshake
  void on_reverse_hello_received(StatusCode, string_view, std::vector<byte>&& buffer);
  void on_reverse_hello_decoded(StatusCode, string_view, std::vector<byte>&& buffer);
  void send_hello();
  void on_acknowledge_received(StatusCode, string_view, std::vector<byte>&& buffer);
  void on_acknowledge_decoded(StatusCode, string_view, std::vector<byte>&& buffer);

  // Handshake completion points (single fire site for success / failure).
  void complete_handshake();
  void fail_handshake(StatusCode status, std::string description);

  /// Schedule an async read of (messageSize - headerSize) bytes into the given buffer at offset
  /// headerSize. The handshake header is preserved at buffer[0..headerSize]; on completion the
  /// full message (header + body) is delivered to onComplete on the strand. Used by the
  /// *_expected handlers to await the message body without racing on bytes_available_to_read().
  void await_handshake_body(std::vector<byte>&& buffer,
    void (ConnectionProtocol::*onComplete)(StatusCode, string_view, std::vector<byte>&&), const char* opName);

  /// Build NegotiatedLimits from the completed handshake. Must be called after
  /// Hello and ACK values are known.
  ua::connection_protocol::NegotiatedLimits build_negotiated_limits() const;

  void configure_for_header_rx();

  void check_header_and_configure_for_message_rx(std::vector<byte>&& buffer);

  void process_message(std::vector<byte>&& buffer);

  void send_error_and_close(StatusCode status, string_view description);
};

}  // namespace ua

#endif  // !UA_CONNECTION_PROTOCOL_H
