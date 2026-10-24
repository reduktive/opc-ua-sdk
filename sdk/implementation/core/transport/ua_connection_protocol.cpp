// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_connection_protocol.h"

#include "ua_connection_protocol_limits.h"
#include "ua_log_exception.h"
#include "ua_error_detail.h"
#include "ua_logger.h"
#include "ua_on_strand.h"
#include "ua_reverse_hello.h"
#include "ua_tcp_transport_connection.h"
#include "ua_structure_factory.h"
#include "ua_memory_stream.h"
#include "ua_binary_codec.h"
#include "ua_application_configuration.h"
#include "ua_to_result.h"
#include "ua_error_chain.h"
#include "ua_status_to_string.h"

#include "fmt/format.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/io_context_strand.hpp>
#include <boost/asio/strand.hpp>

namespace ua
{

namespace
{

/// Moves internal text (a transport error, an exception message) out of the wire Reason and into the
/// status's ErrorDetail, where the error sink and the log still have it: the ERR then carries the
/// specification's description of the status instead (send_error_to_secure_channel_and_close).
StatusCode wire_safe(StatusCode status, std::string_view internalText)
{
  if (status.is_good() || internalText.empty())
  {
    return status;
  }
  return annotate(
    VoidResult{std::move(status)}, "ConnectionFailure", std::string{internalText}, "ConnectionProtocol")
    .status_code();
}

// The handshake messages (HEL, RHE, ERR) carry strings of at most maxUrlSize bytes by the protocol
// grammar, so their decoders run under that bound instead of the process-wide limits: a forged
// length prefix costs at most that allocation before it is refused. Without it the String decoder
// reserved the claimed length up to the BYTE-STRING limit (16 MiB by default; the string limit is
// checked after the bytes are read), so both limits are lowered. One over the URL limit, so a URL
// exactly one byte too long still reaches the explicit URL check and is refused with that check's
// own status.
EncodingLimits handshake_decode_limits(EncodingLimits limits)
{
  limits.maxStringLength = ua::connection_protocol::maxUrlSize + 1;
  limits.maxByteStringLength = ua::connection_protocol::maxUrlSize + 1;
  return limits;
}

constexpr std::size_t maxErrReasonBytes = 4096;
// An ERR body: the Error field, the Reason's length prefix and at most maxErrReasonBytes of Reason.
constexpr std::size_t maxErrBodyBytes = (2 * sizeof(std::uint32_t)) + maxErrReasonBytes;

// Locks the dependencies and returns its executor. create() always locks and
// checks the same weak_ptr before constructing the protocol, so this lock is
// guaranteed to succeed; check() enforces that invariant defensively.
boost::asio::any_io_executor lock_executor(const weak_ptr<ConnectionProtocolDependencies>& dependencies)
{
  auto deps = dependencies.lock();
  check(deps);
  return deps->executor();
}

// Returns the engaged strand by reference. mStrand is constructed engaged in the
// constructor's member-init list and is never disengaged for the object's
// lifetime, so this guard never fires in practice; it makes the always-engaged
// invariant explicit to readers and to static analysis at every dispatch site.
boost::asio::strand<boost::asio::any_io_executor>& engaged_strand(
  std::optional<boost::asio::strand<boost::asio::any_io_executor>>& strand)
{
  if (!strand.has_value())
  {
    throw_empty_optional_check(Status::BadInvalidArgument);
  }
  return *strand;
}

// Part 6 section 7.1.2.5: the ERR Reason parameter shall not be more than 4096 bytes; a Client shall ignore a
// Reason longer than this. Returns @p reason unchanged if within the cap, else an empty string (the
// status code is still surfaced; only the over-long reason is dropped). CL-TCP-013.
String ignore_oversized_err_reason(String reason)
{
  if (reason.size() > maxErrReasonBytes)
  {
    return String{};
  }
  return reason;
}

/// An ERR frame's Error field is peer-supplied. Part 6 section 7.1.2.5 defines ERR as the
/// notification of a fatal error, so a value that is not Bad is malformed: report it as a
/// communication error rather than forwarding a Good status into an error path.
StatusCode sanitise_err_status(uint32_t errorCode)
{
  const StatusCode status{errorCode};
  return status.is_bad() ? status : StatusCode{Status::BadCommunicationError};
}

// Part 6 section 7.1.2.5 binds the sender too: preserve the Reason prefix while capping its encoded
// byte length so a useful diagnostic is not replaced by a dropped ERR frame.
String truncate_err_reason(string_view reason)
{
  return String{reason.substr(0, maxErrReasonBytes)};
}
}  // namespace

struct ConnectionProtocol::HandshakeFlow
{
  enum class Step
  {
    AwaitingReverseHello,  // client + reverseConnect, prior to RHE arrival
    AwaitingHello,  // server, prior to HEL arrival
    AwaitingAcknowledge,  // client, after HEL sent, prior to ACK arrival
  };
  Step step{Step::AwaitingHello};
  HelloValues remoteHello;
  Timer deadlineTimer;
  ConnectionCompleteCallback onComplete;
};

asio::ip::tcp::endpoint ConnectionProtocol::get_local_endpoint() const
{
  return mConnection->get_local_endpoint();
}

void ConnectionProtocol::send_message_chunk(std::vector<byte>&& messageChunk)
{
  async::post_borrowing(this,
    engaged_strand(mStrand),
    mLogger,
    [mc = std::move(messageChunk)](ConnectionProtocol& self) mutable
    {
      try
      {
        // send_message_chunk is only valid post-handshake. If the handshake is
        // still in flight, this is a programmer error.
        check_true(!self.mHandshakeFlow);

        // Part 6, 7.1.2.4 / 6.7.3: If a message exceeds MaxMessageSize, report an error.
        const auto maxSize = self.mNegotiatedLimits.sendMaxMessageSize;
        if (maxSize > 0 && mc.size() > maxSize)
        {
          // A CloseSecureChannel can follow only a refused chunk that is a whole message: after an
          // intermediate chunk already written, or before the rest of this one, it would land inside
          // another message's chunk sequence.
          const bool refusedWholeMessage =
            !self.mSendingContinuation && mc.size() > 3 && static_cast<char>(mc[3]) != 'C';
          self.send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTooLarge},
            "Message exceeds MaxMessageSize",
            refusedWholeMessage ? TransportState::Writable : TransportState::Failed);
          return;
        }

        // The transport's send budget is applied per MESSAGE (see TransportConnection::async_write):
        // a chunk starts a message unless the previous chunk was intermediate ('C', Part 6 6.7.2.2).
        const bool startsMessage = !self.mSendingContinuation;
        self.mSendingContinuation = mc.size() > 3 && static_cast<char>(mc[3]) == 'C';
        self.mConnection->async_write(std::move(mc), startsMessage);
      }
      catch (...)
      {
        log_exception(self.mLogger, "ConnectionProtocol::send_message_chunk", std::current_exception());
        self.mConnection->close_async();
      }
    })();
}

void ConnectionProtocol::pause_reads()
{
  async::post_borrowing(
    this, engaged_strand(mStrand), mLogger, [](ConnectionProtocol& self) { self.mReadsPaused = true; })();
}

void ConnectionProtocol::resume_reads()
{
  async::post_borrowing(this,
    engaged_strand(mStrand),
    mLogger,
    [](ConnectionProtocol& self)
    {
      self.mReadsPaused = false;
      if (self.mHeaderRxDeferred)
      {
        self.mHeaderRxDeferred = false;
        try
        {
          self.configure_for_header_rx();
        }
        catch (...)
        {
          log_exception(self.mLogger, "ConnectionProtocol::resume_reads", std::current_exception());
          self.mConnection->close_async();
        }
      }
    })();
}

void ConnectionProtocol::send_error(StatusCode status, string_view description)
{
  const std::string desc{description};

  async::post_borrowing(this,
    engaged_strand(mStrand),
    mLogger,
    [status, desc](ConnectionProtocol& self)
    {
      try
      {
        self.send_error_and_close(status, desc);
      }
      catch (...)
      {
        log_exception(self.mLogger, "ConnectionProtocol::send_error", std::current_exception());
        self.mConnection->close_async();
      }
    })();
}

void ConnectionProtocol::close_async(
  std::function<void(VoidResult)> callback, TransportConnection::CloseMode mode)
{
  // The completion-owning post_borrowing below delivers `callback` on its GONE path - self destroyed
  // before the strand turn runs, which is the common case during an RST teardown/reconnect. There the
  // helper calls `callback(goneResult)` unconditionally, and std::function::operator() throws
  // std::bad_function_call when empty. A fire-and-forget close (the defaulted `callback == {}`) would
  // therefore throw on the gone path - caught by `guarded` and logged as a "guarded async continuation"
  // bad_function_call, with the close completion silently lost. Normalize the fire-and-forget case to an
  // explicit no-op completion (per the async design: fire-and-forget uses `[](VoidResult){}`, never an
  // empty std::function), so the gone path fires a real, empty-safe callable.
  if (!callback)
  {
    // The caller explicitly selected fire-and-forget close and has no use for the result.
    callback = [](VoidResult) {
    };
  }
  if (mode == TransportConnection::CloseMode::AfterPendingWrites)
  {
    // Owning post: the protocol must outlive the chunks submitted before this call even if the caller lets
    // go of it at once - a borrowing post would drop them with the protocol.
    async::post_owning(this,
      engaged_strand(mStrand),
      mLogger,
      [callback = std::move(callback)](ConnectionProtocol& self) mutable
      { self.close_after_writes_on_strand(std::move(callback)); })();
    return;
  }
  async::post_borrowing(this,
    engaged_strand(mStrand),
    mLogger,
    std::move(callback),
    VoidResult{},  // gone-path result: close on a dead CP is effectively closed -> Good (never a rich
                   // error, so the fire-and-forget no-op above discards nothing; revisit if this ever
                   // carries a bad status).
    [](ConnectionProtocol& self, std::function<void(VoidResult)> done)
    {
      if (self.mHandshakeFlow)
      {
        self.mHandshakeFlow->deadlineTimer.cancel();
      }
      self.mMessageReadTimer.cancel();
      // An explicit close ends a fatal close too: the transport is closed now, not after its writes.
      self.mFatalCloseTimer.cancel();
      self.mTransportClosed = true;
      const auto keepAlive = std::move(self.mFatalCloseKeepAlive);

      // Synthesize a terminal error callback if neither completion nor error
      // has fired yet. This guarantees user-side teardown (e.g. the listener's
      // cpHolder cycle break) runs deterministically - without relying on a
      // pending read/write to discover the close via EOF.
      try
      {
        if (self.mHandshakeFlow)
        {
          self.fail_handshake(StatusCode{Status::BadShutdown}, "Connection protocol closed");
        }
        else
        {
          self.fire_error_sink(StatusCode{Status::BadShutdown},
            "Connection protocol closed",
            FatalCloseDisposition::TransportClosed);
        }
        self.notify_close_observer(StatusCode{Status::BadShutdown}, "Connection protocol closed");
      }
      catch (...)
      {
        log_exception(
          self.mLogger, "ConnectionProtocol::close_async terminal callback", std::current_exception());
      }

      try
      {
        // Hand off to the underlying transport, which provides drain
        // confirmation (its callback fires after cancellation handlers run).
        // close_async takes the callback by value: if it throws before taking
        // ownership the argument is constructed (and moved-from) outside the
        // callee, so we cannot rely on `done` in the catch path. Hand the
        // callee a copy and keep the original for the deterministic fallback,
        // clearing it only once the handoff is known to have succeeded.
        self.mConnection->close_async(done);
        done = nullptr;
      }
      catch (...)
      {
        log_exception(self.mLogger, "ConnectionProtocol::close_async", std::current_exception());
        if (done)
          done(VoidResult{});
      }
    })();
}

void ConnectionProtocol::complete_handshake()
{
  // Pre-condition: on strand. If the flow is gone we have already terminated;
  // the call is idempotent.
  if (!mHandshakeFlow)
  {
    return;
  }

  // Move-out -> reset -> fire (the completion point pattern). Capture
  // anything needed by the user callback into locals before resetting the
  // flow, so re-entrant close_async from inside onComplete sees the
  // post-handshake shape.
  auto onComplete = std::exchange(mHandshakeFlow->onComplete, {});
  auto reverseHelloMsg = mReverseHelloMessage;
  auto negotiatedLimits = mNegotiatedLimits;
  mHandshakeFlow.reset();

  // Keep mErrorCallback live until set_callbacks replaces it. Clearing it here
  // (as commit 5a05181 did, regressing 0a25d5f) creates a window where a
  // post-handshake error before the user's set_callbacks post lands on the
  // strand is silently dropped - single-fire is still guaranteed by std::exchange
  // in fail_handshake / close_async, so re-firing the original sink is harmless.
  if (onComplete)
  {
    onComplete(StatusCode{Status::Good}, shared_from_this(), negotiatedLimits, reverseHelloMsg);
  }
}

void ConnectionProtocol::fail_handshake(StatusCode status, std::string description)
{
  // Pre-condition: on strand. If the flow has already terminated, drain any
  // remaining error sink so close_async still produces a single terminal
  // delivery without duplicating success.
  if (!mHandshakeFlow)
  {
    fire_error_sink(status, description, FatalCloseDisposition::TransportClosed);
    notify_close_observer(status, description);
    return;
  }

  // Pre-flip contract preserved: connection-complete callback fires ONLY on
  // success - discard it on failure rather than re-firing with bad status.
  // The terminal-error sink (mErrorCallback) is the failure-side delivery.
  // Cancel the deadline before resetting so a late-firing timer cannot
  // re-enter through send_error_to_secure_channel_and_close.
  mHandshakeFlow->onComplete = {};
  mHandshakeFlow->deadlineTimer.cancel();
  mHandshakeFlow.reset();

  fire_error_sink(status, description, FatalCloseDisposition::TransportClosed);
  notify_close_observer(status, description);
}

void ConnectionProtocol::fire_error_sink(
  StatusCode status, string_view description, FatalCloseDisposition disposition)
{
  // Taken as it fires, so the protocol reports one terminal error over its whole life.
  if (auto sink = std::exchange(mErrorCallback, {}))
  {
    sink(status, description, disposition);
  }
}

void ConnectionProtocol::notify_close_observer(StatusCode status, string_view description)
{
  if (auto observer = std::exchange(mCloseObserver, {}))
  {
    observer(status, description);
  }
}

void ConnectionProtocol::set_callbacks(
  ua::connection_protocol::MessageChunkReceivedCallback messageChunkReceivedCallback,
  ua::connection_protocol::ErrorCallback errorCallback, bool delegateFatalClose)
{
  async::post_borrowing(this,
    engaged_strand(mStrand),
    mLogger,
    [messageChunkReceivedCallback, errorCallback, delegateFatalClose](ConnectionProtocol& self)
    {
      try
      {
        self.mMessageChunkReceivedCallback = messageChunkReceivedCallback;
        self.mErrorCallback = errorCallback;
        self.mDelegateFatalClose = delegateFatalClose;

        auto weak = self.weak_from_this();

        self.mConnection->register_write_callback(
          [weak](StatusCode status, string_view description)
          {
            auto connection = weak.lock();
            if (connection)
            {
              async::post_borrowing(connection.get(),
                *connection->mStrand,
                connection->mLogger,
                [status, errDesc = std::string{description}](ConnectionProtocol& cp)
                {
                  try
                  {
                    if (status.is_bad())
                    {
                      cp.send_error_to_secure_channel_and_close(
                        wire_safe(status, errDesc), {}, TransportState::Failed);
                    }
                  }
                  catch (...)
                  {
                    log_exception(cp.mLogger, "ConnectionProtocol write callback", std::current_exception());
                    cp.mConnection->close_async();
                  }
                })();
            }
          });

        self.configure_for_header_rx();
      }
      catch (...)
      {
        log_exception(self.mLogger, "ConnectionProtocol::set_callbacks", std::current_exception());
        self.mConnection->close_async();
      }
    })();
}

shared_ptr<ConnectionProtocol> ConnectionProtocol::create(ConnectionProtocolRole role,
  weak_ptr<ConnectionProtocolDependencies> dependencies, shared_ptr<TransportConnection> connection,
  bool reverseConnect, std::chrono::seconds timeout, ConnectionCompleteCallback connectionCompleteCallback,
  ua::connection_protocol::ErrorCallback errorCallback, std::string endpointUrl,
  EndpointUrlValidator endpointUrlValidator, std::chrono::milliseconds messageReadTimeout,
  std::string serverUri, ReverseHelloValidator reverseHelloValidator, CloseObserver closeObserver,
  std::chrono::milliseconds fatalCloseTimeout)
{
  class Wrapper : public ConnectionProtocol
  {
  public:
    Wrapper(ConnectionProtocolRole role, weak_ptr<ConnectionProtocolDependencies> dependencies,
      shared_ptr<TransportConnection> connection, bool reverseConnect,
      ua::connection_protocol::ErrorCallback errorCallback, std::string endpointUrl,
      EndpointUrlValidator endpointUrlValidator, std::string serverUri,
      ReverseHelloValidator reverseHelloValidator, CloseObserver closeObserver)
      : ConnectionProtocol(role, dependencies, connection, reverseConnect, errorCallback,
          std::move(endpointUrl), std::move(endpointUrlValidator), std::move(serverUri),
          std::move(reverseHelloValidator), std::move(closeObserver))
    {}
  };

  auto cp = make_shared<Wrapper>(role,
    dependencies,
    connection,
    reverseConnect,
    errorCallback,
    std::move(endpointUrl),
    std::move(endpointUrlValidator),
    std::move(serverUri),
    std::move(reverseHelloValidator),
    std::move(closeObserver));

  cp->mFatalCloseTimeout = fatalCloseTimeout;
  auto deps = dependencies.lock();
  check(deps);
  cp->initialise(deps->executor(), timeout, messageReadTimeout, std::move(connectionCompleteCallback));
  return cp;
}

ConnectionProtocol::ConnectionProtocol(ConnectionProtocolRole role,
  weak_ptr<ConnectionProtocolDependencies> dependencies, shared_ptr<TransportConnection> connection,
  bool reverseConnect, ua::connection_protocol::ErrorCallback errorCallback, std::string endpointUrl,
  EndpointUrlValidator endpointUrlValidator, std::string serverUri,
  ReverseHelloValidator reverseHelloValidator, CloseObserver closeObserver)
  : mId(Guid::create_and_generate()), mRole(role), mReverseConnect(reverseConnect),
    mDependencies(dependencies),
    mStrand(std::in_place, boost::asio::make_strand(lock_executor(dependencies))), mConnection(connection),
    mEndpointUrl(std::move(endpointUrl)), mServerUri(std::move(serverUri)),
    mEndpointUrlValidator(std::move(endpointUrlValidator)),
    mReverseHelloValidator(std::move(reverseHelloValidator)), mErrorCallback(std::move(errorCallback)),
    mCloseObserver(std::move(closeObserver))
{
  // mStrand is constructed engaged in the member-init list (above) so its
  // executor is bound before any continuation can post to it; it is never
  // disengaged for the lifetime of the object. The remaining dependency-derived
  // members are populated here; deps is guaranteed live because create() locks
  // and checks it before constructing this object.
  auto deps = mDependencies.lock();
  check(deps);

  mConfigLimits = deps->connection_protocol_limits();

  mExecutor = deps->executor();
  mLogger = deps->logger().with_category("transport");
}

ConnectionProtocol::~ConnectionProtocol() = default;

TransportConnection::PeerState ConnectionProtocol::peer_state() const
{
  return mConnection ? mConnection->peer_state() : TransportConnection::PeerState::Open;
}

void ConnectionProtocol::send_error_to_secure_channel_and_close(
  StatusCode status, string_view description, TransportState transport)
{
  if (mRole == ConnectionProtocolRole::Server)
  {
    // Part 6 7.1.5: server SHALL send an Error Message on fatal errors.
    // send_error_and_close writes ERR frame, then closes on write completion. The description IS the
    // Reason on the wire, so it is fixed, server-authored text by contract; a caller holding transport or
    // exception text puts it in the status's ErrorDetail (wire_safe below) and passes none, and the wire
    // then carries the specification's description of the status (review B1-10, owner decision 2).
    try
    {
      const std::string_view wireReason =
        description.empty() ? ::ua::description(status.as_status()) : description;
      mLogger.debug({{"status", to_string(status.as_status())}, {"reason", wireReason}},
        "Fatal connection error; sending ERR");
      send_error_and_close(status, wireReason);
    }
    catch (...)
    {
      log_exception(
        mLogger, "ConnectionProtocol::send_error_to_secure_channel_and_close", std::current_exception());
      mConnection->close_async();
    }
  }
  else if (mFatalClosing)
  {
    // The fatal error that began this close was reported once. A later failure (the CloseSecureChannel
    // write failing, the read the close aborted) only closes the transport now.
    close_transport_after_fatal_error();
    return;
  }
  else if (!mHandshakeFlow && mDelegateFatalClose && mErrorCallback && transport == TransportState::Writable)
  {
    // Part 6 7.1.5: "If a Client encounters a fatal error, it shall report the error to the application
    // and send a CloseSecureChannel Message." That message is a secured UASC message (6.7.2.2-6.7.2.4:
    // SecureChannelId, TokenId, sequence header; signed with the current token, Part 4 5.5.3.1), so only
    // the SecureChannel can build it. Stop reading, keep the transport writable for it, and report with
    // the disposition that says so; the channel closes (close_after_pending_writes / close_async) or
    // the fallback timer does.
    begin_fatal_close(status, description);
    fire_error_sink(status, description, FatalCloseDisposition::AwaitingClose);
    return;
  }
  else
  {
    // No CloseSecureChannel can be sent: during the handshake no SecureChannel exists, and after a
    // failed read or write or the server's ERR the socket cannot carry one (Part 6 7.1.4, 7.1.5). A
    // caller that did not delegate the close (set_callbacks without delegateFatalClose) is closed here
    // too. Report and close without writing.
    mTransportClosed = true;
    try
    {
      mConnection->close_async();
    }
    catch (...)
    {
      log_exception(
        mLogger, "ConnectionProtocol::send_error_to_secure_channel_and_close", std::current_exception());
    }
  }
  // Route through the single failure completion point so both the success-completion
  // (mHandshakeFlow->onComplete) and the terminal-error sink (mErrorCallback) are
  // fired exactly once, and any pending handshake state is reset before user
  // callbacks observe the terminal status.
  fail_handshake(status, std::string{description});
}

void ConnectionProtocol::await_handshake_body(std::vector<byte>&& buffer,
  void (ConnectionProtocol::*onComplete)(StatusCode, string_view, std::vector<byte>&&), const char* opName)
{
  // The 8-byte header has been read into buffer[0..headerSize]; buffer has already been resized
  // to the full message length. async_read fills the remaining body bytes at offset headerSize and
  // delivers the complete message to onComplete on the strand. This avoids racing on
  // bytes_available_to_read(): the body bytes may not have arrived yet - e.g. on Windows, TCP
  // can deliver the header before the body is in the receive buffer.
  auto me = weak_from_this();
  mConnection->register_read_callback(
    [me, onComplete, opName](StatusCode status, string_view errorDescription, std::vector<byte>&& buf)
    {
      auto lockedCp = me.lock();
      if (!lockedCp)
        return;

      async::post_borrowing(lockedCp.get(),
        *lockedCp->mStrand,
        lockedCp->mLogger,
        [onComplete, opName, status, errDesc = std::string{errorDescription}, b = std::move(buf)](
          ConnectionProtocol& cp) mutable
        {
          try
          {
            (cp.*onComplete)(status, errDesc, std::move(b));
          }
          catch (const UaException& exception)
          {
            // A malformed body (a length prefix past the end of the frame, a value cut short) is a
            // protocol failure: report it through the single terminal path so the peer gets an ERR
            // (server role) and the error sink and close observer fire, rather than a bare close.
            log_exception(cp.mLogger, opName, std::current_exception());
            cp.send_error_to_secure_channel_and_close(
              wire_safe(exception.status_code(), exception.what()), {});
          }
          catch (...)
          {
            // Any other failure takes the same terminal path (ERR, error sink, close observer).
            log_exception(cp.mLogger, opName, std::current_exception());
            cp.send_error_to_secure_channel_and_close(
              wire_safe(::ua::exception_to_status_code(std::current_exception()), opName), {});
          }
        })();
    });

  mConnection->async_read(std::move(buffer), ua::connection_protocol::headerSize);
}

void ConnectionProtocol::send_reverse_hello()
{
  detail::ReverseHelloMessage msg;
  msg.serverUri = mServerUri;
  msg.endpointUrl = mEndpointUrl;

  auto validationStatus = detail::validate_reverse_hello_fields(msg);
  if (validationStatus.is_bad())
  {
    send_error_to_secure_channel_and_close(validationStatus, "ReverseHello fields invalid");
    return;
  }

  auto encoded = detail::encode_reverse_hello(msg);

  mLogger.debug({{"server_uri", mServerUri}, {"endpoint_url", mEndpointUrl}}, "Sending RHE");

  auto me = this->weak_from_this();

  mConnection->register_write_callback(
    [me](StatusCode status, string_view description)
    {
      auto lockedCp = me.lock();
      if (!lockedCp)
        return;

      async::post_borrowing(lockedCp.get(),
        *lockedCp->mStrand,
        lockedCp->mLogger,
        [status, errDesc = std::string{description}](ConnectionProtocol& cp)
        {
          try
          {
            if (status.is_bad())
            {
              cp.send_error_to_secure_channel_and_close(wire_safe(status, errDesc), {});
              return;
            }

            // RHE sent - now wait for HEL from the client.
            auto readWeak = cp.weak_from_this();
            cp.mConnection->register_read_callback(
              [readWeak](StatusCode readStatus, string_view errorDescription, std::vector<byte>&& buf)
              {
                auto conn = readWeak.lock();
                if (!conn)
                  return;

                async::post_borrowing(conn.get(),
                  *conn->mStrand,
                  conn->mLogger,
                  [readStatus, errDesc = std::string{errorDescription}, b = std::move(buf)](
                    ConnectionProtocol& innerCp) mutable
                  {
                    try
                    {
                      innerCp.on_hello_received(readStatus, errDesc, std::move(b));
                    }
                    catch (...)
                    {
                      log_exception(innerCp.mLogger,
                        "ConnectionProtocol::on_hello_received (after RHE)",
                        std::current_exception());
                      innerCp.mConnection->close_async();
                    }
                  })();
              });

            std::vector<byte> header;
            header.resize(ua::connection_protocol::headerSize);
            cp.mConnection->async_read(std::move(header));
          }
          catch (...)
          {
            log_exception(
              cp.mLogger, "ConnectionProtocol::send_reverse_hello callback", std::current_exception());
            cp.mConnection->close_async();
          }
        })();
    });

  mConnection->async_write(std::move(encoded));
}

void ConnectionProtocol::on_hello_received(StatusCode status, string_view, std::vector<byte>&& buffer)
{
  // Step guard. Null flow = post-termination stale callback (drop silently).
  // Wrong step while flow alive = dispatch invariant violated (fail loudly,
  // same handling as every other "shouldn't happen" check in this handler).
  if (!mHandshakeFlow)
  {
    return;
  }
  if (mHandshakeFlow->step != HandshakeFlow::Step::AwaitingHello)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "on_hello_received reached in unexpected step");
    return;
  }

  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = deps->encoding_limits();

  if (status.is_bad())
  {
    mLogger.warning({{"incoming_status", fmt::format("0x{:08x}", status.as_uint32())}},
      "on_hello_received: read completed with bad status");
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpInternalError}, "");
    return;
  }

  if (buffer.size() != ua::connection_protocol::headerSize)
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid}, "");
    return;
  }

  std::array<byte, ua::connection_protocol::messageTypeSize> helloMessageType{
    std::byte{'H'}, std::byte{'E'}, std::byte{'L'}};
  const span<byte> messageType{buffer.data(), ua::connection_protocol::messageTypeSize};

  if (!std::ranges::equal(messageType, helloMessageType))
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid}, "");
    return;
  }

  // The 4th byte (IsFinal/ChunkType) is not validated at the Connection Protocol layer.
  // Per Part 6 Section 7.1.2.2, the Connection Protocol only verifies MessageType and MessageSize
  // for SecureChannel messages (MSG, OPN, CLO). The IsFinal byte ('F', 'C', 'A') is interpreted
  // by the Secure Channel layer.

  const span<byte> messageSizeBytes{&buffer[4], sizeof(uint32_t)};

  uint32_t messageSize{0};
  {
    memory_stream_device::ExternalReadOnly streamDevice{messageSizeBytes};
    MemoryStream stream{streamDevice};
    UaBinaryDecoder decoder(StructureResolver{}, stream, limits);
    auto depth = limits.stack_depth();
    decoder.decode(depth, messageSize);
  }

  if (messageSize <= ua::connection_protocol::headerSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "Message size is invalid");
    return;
  }

  // HEL is bounded by the protocol grammar (header + 5 uint32 fields + EndpointUrl string with
  // max length maxUrlSize). Use maxReverseHelloSize as a generous upper bound covering both
  // shapes; an exact-shape constant would not be worth introducing.
  if (messageSize > ua::connection_protocol::maxReverseHelloSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTypeInvalid}, "HEL message size exceeds maximum");
    return;
  }

  // Grow the buffer to the full message size and await the body bytes asynchronously.
  buffer.resize(messageSize);
  await_handshake_body(
    std::move(buffer), &ConnectionProtocol::on_hello_decoded, "ConnectionProtocol::on_hello_decoded");
}

void ConnectionProtocol::on_hello_decoded(StatusCode status, string_view, std::vector<byte>&& buffer)
{
  if (!mHandshakeFlow)
  {
    return;
  }
  if (mHandshakeFlow->step != HandshakeFlow::Step::AwaitingHello)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "on_hello_decoded reached in unexpected step");
    return;
  }

  if (status.is_bad())
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpInternalError}, "");
    return;
  }

  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = handshake_decode_limits(deps->encoding_limits());

  // Decode the body starting after the header.
  const span<byte> body{
    buffer.data() + ua::connection_protocol::headerSize, buffer.size() - ua::connection_protocol::headerSize};
  memory_stream_device::ExternalReadOnly streamDevice{body};
  MemoryStream stream{streamDevice};
  UaBinaryDecoder decoder(StructureResolver{}, stream, limits);

  uint32_t protocolVersion{};
  auto depth = limits.stack_depth();
  decoder.decode(depth, protocolVersion);
  // Part 6 7.1.2.3 Table 66: "If the Server supports the requested version or a lower version it shall
  // return the version it will use in the Acknowledge Message. The ProtocolVersion for this version of the
  // standard is 0." Version 0 is lower than any requested version, so no Hello is refused for its version:
  // the Acknowledge carries 0 and the requested version is kept for the OpenSecureChannel check (6.7.4).
  mNegotiatedLimits.helloProtocolVersion = protocolVersion;

  auto& remoteHello = mHandshakeFlow->remoteHello;
  decoder.decode(depth, remoteHello.receiveBufferSize);
  decoder.decode(depth, remoteHello.sendBufferSize);
  decoder.decode(depth, remoteHello.maxMessageSize);
  decoder.decode(depth, remoteHello.maxChunkCount);

  // Part 6 7.1.2.3 Table 66: "The encoded value shall be less than 4 096 bytes. Servers shall return a
  // Bad_TcpEndpointUrlInvalid Error Message and close the connection if the length exceeds 4 096". The
  // encoded value is the four-byte length prefix plus the bytes, as for the ReverseHello fields
  // (validate_reverse_hello_fields), so one rule governs both handshake messages; a length prefix past the
  // decode limit is the same refusal.
  String endpointUrl;
  try
  {
    decoder.decode(depth, endpointUrl);
  }
  catch (const UaException& exception)
  {
    if (exception.status() != Status::BadEncodingLimitsExceeded)
    {
      throw;
    }
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpEndpointUrlInvalid}, "EndpointUrl exceeds the maximum size");
    return;
  }

  if (sizeof(int32_t) + endpointUrl.size() >= ua::connection_protocol::maxUrlSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpEndpointUrlInvalid}, "EndpointUrl exceeds the maximum size");
    return;
  }

  if (mEndpointUrlValidator && !mEndpointUrlValidator(std::string_view{endpointUrl}))
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpEndpointUrlInvalid},
      fmt::format("EndpointUrl is not recognized: {}", std::string_view{endpointUrl}));
    return;
  }

  mLogger.debug({{"endpoint_url", std::string_view{endpointUrl}},
                  {"receive_buffer_size", int64_t(remoteHello.receiveBufferSize)},
                  {"send_buffer_size", int64_t(remoteHello.sendBufferSize)},
                  {"max_message_size", int64_t(remoteHello.maxMessageSize)},
                  {"max_chunk_count", int64_t(remoteHello.maxChunkCount)}},
    "HEL received");

  if (mHandshakeFlow->deadlineTimer)
  {
    mHandshakeFlow->deadlineTimer.cancel();
  }

  // Validate Hello buffer sizes against absolute minimum (1024).
  if (remoteHello.receiveBufferSize < ua::connection_protocol::eccMinBufferSize ||
      remoteHello.sendBufferSize < ua::connection_protocol::eccMinBufferSize)
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid},
      "Client buffer sizes are below the absolute minimum (1024)");
    return;
  }

  // Mark connection as ECC-only if client's buffers are below the non-ECC minimum.
  if (remoteHello.receiveBufferSize < ua::connection_protocol::nonEccMinBufferSize ||
      remoteHello.sendBufferSize < ua::connection_protocol::nonEccMinBufferSize)
  {
    mEccOnly.store(true, std::memory_order_relaxed);
  }

  // Compute ACK buffer sizes: clamp to the smaller of local config and client's Hello values.
  const uint32_t ackReceiveBufferSize = std::min(mConfigLimits.maxBufferSize, remoteHello.sendBufferSize);
  const uint32_t ackSendBufferSize = std::min(mConfigLimits.maxBufferSize, remoteHello.receiveBufferSize);

  // Part 6 section 7.1.2.4 Table 67: each ACK buffer is at least 8192 when the peer's opposite HEL field
  // is at least 8192, or at least 1024 otherwise. A local maximum below that floor makes a
  // conforming ACK impossible; refuse rather than advertising unsupported capacity or an illegal
  // sub-minimum value.
  const uint32_t requiredAckReceiveBufferSize =
    remoteHello.sendBufferSize >= ua::connection_protocol::nonEccMinBufferSize
      ? ua::connection_protocol::nonEccMinBufferSize
      : ua::connection_protocol::eccMinBufferSize;
  if (ackReceiveBufferSize < requiredAckReceiveBufferSize)
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid},
      "Server receive buffer size is below the ACK minimum required by the client Hello");
    return;
  }

  const uint32_t requiredAckSendBufferSize =
    remoteHello.receiveBufferSize >= ua::connection_protocol::nonEccMinBufferSize
      ? ua::connection_protocol::nonEccMinBufferSize
      : ua::connection_protocol::eccMinBufferSize;
  if (ackSendBufferSize < requiredAckSendBufferSize)
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid},
      "Server send buffer size is below the ACK minimum required by the client Hello");
    return;
  }

  // Build NegotiatedLimits (server perspective).
  mNegotiatedLimits.sendBufferSize = ackSendBufferSize;
  mNegotiatedLimits.receiveBufferSize = ackReceiveBufferSize;
  mNegotiatedLimits.sendMaxMessageSize = remoteHello.maxMessageSize;
  mNegotiatedLimits.sendMaxChunkCount = remoteHello.maxChunkCount;
  mNegotiatedLimits.recvMaxMessageSize = mConfigLimits.maxMessageSize;
  mNegotiatedLimits.recvMaxChunkCount = mConfigLimits.maxChunkCount;

  mLogger.debug({{"send_buffer_size", int64_t(mNegotiatedLimits.sendBufferSize)},
                  {"receive_buffer_size", int64_t(mNegotiatedLimits.receiveBufferSize)},
                  {"ecc_only", mEccOnly.load(std::memory_order_relaxed)}},
    "Buffer sizes negotiated");

  send_acknowledge();
}

void ConnectionProtocol::send_acknowledge()
{
  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = deps->encoding_limits();

  memory_stream_device::Dynamic streamDevice{ua::connection_protocol::acknowledgeSize, true};

  MemoryStream stream{streamDevice};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  const StackDepth limit = limits.stack_depth();
  encoder.encode(limit, uint8_t{'A'});
  encoder.encode(limit, uint8_t{'C'});
  encoder.encode(limit, uint8_t{'K'});
  encoder.encode(limit, uint8_t{'F'});
  encoder.encode(limit, numeric_cast<uint32_t>(streamDevice.get_capacity()));
  encoder.encode(limit, uint32_t{0});
  encoder.encode(limit, mNegotiatedLimits.receiveBufferSize);
  encoder.encode(limit, mNegotiatedLimits.sendBufferSize);
  encoder.encode(limit, mConfigLimits.maxMessageSize);
  encoder.encode(limit, mConfigLimits.maxChunkCount);

  auto me = this->weak_from_this();

  mConnection->register_write_callback(
    [me](StatusCode status, string_view description)
    {
      auto connection = me.lock();
      if (!connection)
        return;

      async::post_borrowing(connection.get(),
        *connection->mStrand,
        connection->mLogger,
        [status, errDesc = std::string{description}](ConnectionProtocol& cp)
        {
          try
          {
            if (status.is_bad())
            {
              cp.send_error_to_secure_channel_and_close(wire_safe(status, errDesc), {});
            }
            else
            {
              cp.mLogger.info("Connection established");
              cp.complete_handshake();
            }
          }
          catch (...)
          {
            log_exception(
              cp.mLogger, "ConnectionProtocol::send_acknowledge callback", std::current_exception());
            cp.mConnection->close_async();
          }
        })();
    });

  mConnection->async_write(streamDevice.move_storage_out());
}

void ConnectionProtocol::on_reverse_hello_received(StatusCode status, string_view, std::vector<byte>&& buffer)
{
  if (!mHandshakeFlow)
  {
    return;
  }
  if (mHandshakeFlow->step != HandshakeFlow::Step::AwaitingReverseHello)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "on_reverse_hello_received reached in unexpected step");
    return;
  }

  if (status.is_bad())
  {
    mLogger.warning({{"incoming_status", fmt::format("0x{:08x}", status.as_uint32())}},
      "on_reverse_hello_received: read completed with bad status");
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpInternalError}, "");
    return;
  }

  if (buffer.size() != ua::connection_protocol::headerSize)
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid}, "");
    return;
  }

  std::array<byte, ua::connection_protocol::messageTypeSize> rheMessageType{
    std::byte{'R'}, std::byte{'H'}, std::byte{'E'}};
  const span<byte> messageType{buffer.data(), ua::connection_protocol::messageTypeSize};

  if (!std::ranges::equal(messageType, rheMessageType))
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTypeInvalid}, "Expected RHE message");
    return;
  }

  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = deps->encoding_limits();

  const span<byte> messageSizeBytes{&buffer[4], sizeof(uint32_t)};
  uint32_t messageSize{0};
  {
    memory_stream_device::ExternalReadOnly streamDevice{messageSizeBytes};
    MemoryStream stream{streamDevice};
    UaBinaryDecoder decoder(StructureResolver{}, stream, limits);
    auto depth = limits.stack_depth();
    decoder.decode(depth, messageSize);
  }

  if (messageSize <= ua::connection_protocol::headerSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "RHE message size is invalid");
    return;
  }

  if (messageSize > ua::connection_protocol::maxReverseHelloSize)
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpInternalError}, "RHE message too large");
    return;
  }

  // Grow the buffer to the full message size and await the body bytes asynchronously.
  buffer.resize(messageSize);
  await_handshake_body(std::move(buffer),
    &ConnectionProtocol::on_reverse_hello_decoded,
    "ConnectionProtocol::on_reverse_hello_decoded");
}

void ConnectionProtocol::on_reverse_hello_decoded(StatusCode status, string_view, std::vector<byte>&& buffer)
{
  if (!mHandshakeFlow)
  {
    return;
  }
  if (mHandshakeFlow->step != HandshakeFlow::Step::AwaitingReverseHello)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "on_reverse_hello_decoded reached in unexpected step");
    return;
  }

  if (status.is_bad())
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpInternalError}, "");
    return;
  }

  // decode_reverse_hello consumes the full message (header + body).
  auto decodeResult = detail::decode_reverse_hello(buffer);
  if (!decodeResult)
  {
    send_error_to_secure_channel_and_close(decodeResult.status_code(), "Failed to decode ReverseHello");
    return;
  }

  auto& msg = decodeResult.value();

  mLogger.debug({{"server_uri", msg.serverUri}, {"endpoint_url", msg.endpointUrl}}, "RHE received");

  // Validate via the application-provided callback (C1, C2).
  if (mReverseHelloValidator && !mReverseHelloValidator(msg))
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpEndpointUrlInvalid}, "ReverseHello rejected by validator");
    return;
  }

  if (mHandshakeFlow && mHandshakeFlow->deadlineTimer)
  {
    mHandshakeFlow->deadlineTimer.cancel();
  }

  // Store the RHE message for the completion callback.
  mReverseHelloMessage = msg;

  // Spec C3: echo the EndpointUrl from RHE back in the Hello message.
  mEndpointUrl = msg.endpointUrl;

  // Proceed with normal Client handshake: send HEL, wait for ACK.
  send_hello();
}

void ConnectionProtocol::send_hello()
{
  // Phase transition: after the HEL write completes, the next continuation
  // is on_acknowledge_received. Advance step before issuing the async write
  // so the read-callback's step guard sees the expected value.
  if (mHandshakeFlow)
  {
    mHandshakeFlow->step = HandshakeFlow::Step::AwaitingAcknowledge;
  }

  // Part 6, 7.1.2.3: the EndpointUrl's encoded value (length prefix plus bytes) shall be less than 4096
  // bytes.
  if (sizeof(int32_t) + mEndpointUrl.size() >= ua::connection_protocol::maxUrlSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpEndpointUrlInvalid}, "EndpointUrl exceeds maximum size");
    return;
  }

  // Part 6, 7.1.2.3: a client shall never propose a Receive/SendBufferSize below the protocol minimum.
  // A misconfigured sub-minimum buffer (e.g. an embedded default below 8192, or an accidental tiny
  // value) would otherwise be put on the wire verbatim and rejected by any compliant server. Clamp the
  // configured proposal up to the non-ECC minimum (8192): a proposal at or above 8192 is valid for every
  // server, ECC and non-ECC alike. Persist the clamp into mConfigLimits so the subsequent ACK validation
  // (which bounds the peer's reply by mConfigLimits.mMaxBufferSize) uses the same effective proposal.
  mConfigLimits.maxBufferSize =
    std::max(mConfigLimits.maxBufferSize, ua::connection_protocol::nonEccMinBufferSize);

  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = deps->encoding_limits();

  memory_stream_device::Dynamic streamDevice{ua::connection_protocol::maxUrlSize + 128, true};

  MemoryStream stream{streamDevice};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);

  const StackDepth limit = limits.stack_depth();
  encoder.encode(limit, uint8_t{'H'});
  encoder.encode(limit, uint8_t{'E'});
  encoder.encode(limit, uint8_t{'L'});
  encoder.encode(limit, uint8_t{'F'});

  const size_t sizePosition = stream.get_position();
  encoder.encode(limit, uint32_t{0});  // placeholder for message size

  encoder.encode(limit, uint32_t{0});  // protocolVersion
  encoder.encode(limit, mConfigLimits.maxBufferSize);  // ReceiveBufferSize
  encoder.encode(limit, mConfigLimits.maxBufferSize);  // SendBufferSize
  encoder.encode(limit, mConfigLimits.maxMessageSize);
  encoder.encode(limit, mConfigLimits.maxChunkCount);

  const String endpointUrlStr{mEndpointUrl};
  encoder.encode(limit, endpointUrlStr);

  // Write the actual message size.
  const auto messageSize = numeric_cast<uint32_t>(stream.get_position());
  stream.seek_from_start(sizePosition);
  encoder.encode(limit, messageSize);

  auto buffer = streamDevice.move_storage_out();
  buffer.resize(messageSize);

  mLogger.debug({{"endpoint_url", std::string_view{mEndpointUrl}}}, "Sending HEL");

  auto me = this->weak_from_this();

  mConnection->register_write_callback(
    [me](StatusCode status, string_view description)
    {
      auto lockedCp = me.lock();
      if (!lockedCp)
        return;

      async::post_borrowing(lockedCp.get(),
        *lockedCp->mStrand,
        lockedCp->mLogger,
        [status, errDesc = std::string{description}](ConnectionProtocol& cp)
        {
          try
          {
            if (status.is_bad())
            {
              cp.send_error_to_secure_channel_and_close(wire_safe(status, errDesc), {});
              return;
            }

            // HEL sent successfully - now wait for ACK header.
            auto readWeak = cp.weak_from_this();
            cp.mConnection->register_read_callback(
              [readWeak](StatusCode readStatus, string_view errorDescription, std::vector<byte>&& buf)
              {
                auto conn = readWeak.lock();
                if (!conn)
                  return;

                async::post_borrowing(conn.get(),
                  *conn->mStrand,
                  conn->mLogger,
                  [readStatus, errDesc = std::string{errorDescription}, b = std::move(buf)](
                    ConnectionProtocol& innerCp) mutable
                  {
                    try
                    {
                      innerCp.on_acknowledge_received(readStatus, errDesc, std::move(b));
                    }
                    catch (const UaException& exception)
                    {
                      log_exception(innerCp.mLogger,
                        "ConnectionProtocol::on_acknowledge_received",
                        std::current_exception());
                      innerCp.send_error_to_secure_channel_and_close(
                        wire_safe(exception.status_code(), exception.what()), {});
                    }
                    catch (...)
                    {
                      log_exception(innerCp.mLogger,
                        "ConnectionProtocol::on_acknowledge_received",
                        std::current_exception());
                      innerCp.mConnection->close_async();
                    }
                  })();
              });

            std::vector<byte> header;
            header.resize(ua::connection_protocol::headerSize);
            cp.mConnection->async_read(std::move(header));
          }
          catch (...)
          {
            log_exception(cp.mLogger, "ConnectionProtocol::send_hello callback", std::current_exception());
            cp.mConnection->close_async();
          }
        })();
    });

  mConnection->async_write(std::move(buffer));
}

void ConnectionProtocol::on_acknowledge_received(StatusCode status, string_view, std::vector<byte>&& buffer)
{
  if (!mHandshakeFlow)
  {
    return;
  }
  if (mHandshakeFlow->step != HandshakeFlow::Step::AwaitingAcknowledge)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "on_acknowledge_received reached in unexpected step");
    return;
  }

  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = deps->encoding_limits();

  if (status.is_bad())
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpInternalError}, "");
    return;
  }

  if (buffer.size() != ua::connection_protocol::headerSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "Invalid ACK header size");
    return;
  }

  const span<byte> messageType{buffer.data(), ua::connection_protocol::messageTypeSize};

  // Check for ERR frame from server.
  std::array<byte, ua::connection_protocol::messageTypeSize> errMessageType{
    std::byte{'E'}, std::byte{'R'}, std::byte{'R'}};
  if (std::ranges::equal(messageType, errMessageType))
  {
    // Read the ERR body to extract the status code and reason.
    const span<byte> messageSizeBytes{&buffer[4], sizeof(uint32_t)};
    uint32_t messageSize{0};
    {
      memory_stream_device::ExternalReadOnly streamDevice{messageSizeBytes};
      MemoryStream stream{streamDevice};
      UaBinaryDecoder decoder(StructureResolver{}, stream, limits);
      auto depth = limits.stack_depth();
      decoder.decode(depth, messageSize);
    }

    // Bounded as in the post-handshake ERR path: at most the Error, the Reason length and 4096 bytes.
    const size_t readSize =
      messageSize > ua::connection_protocol::headerSize
        ? std::min<size_t>(messageSize - ua::connection_protocol::headerSize, maxErrBodyBytes)
        : 0;
    if (readSize > 0 && mConnection->bytes_available_to_read() >= readSize)
    {
      std::vector<byte> errBody;
      errBody.resize(readSize);
      auto readStatus = mConnection->read(errBody);
      if (readStatus.is_good() && errBody.size() >= sizeof(uint32_t))
      {
        memory_stream_device::ExternalReadOnly streamDevice{errBody};
        MemoryStream stream{streamDevice};
        // The handshake limits: a forged Reason length must not reserve up to the general String limit.
        const auto errLimits = handshake_decode_limits(limits);
        UaBinaryDecoder decoder(StructureResolver{}, stream, errLimits);
        auto depth = errLimits.stack_depth();

        uint32_t errorCode{0};
        decoder.decode(depth, errorCode);

        String reason;
        try
        {
          decoder.decode(depth, reason);
        }
        catch (const UaException&)
        {
          reason = {};  // a Reason cut short does not hide the peer's Error status
        }
        reason = ignore_oversized_err_reason(std::move(reason));

        mLogger.warning(
          {{"status", fmt::format("0x{:08x}", errorCode)}}, "Server sent ERR: {}", std::string_view{reason});

        // ERR is the peer's fatal-error notification and its Error field is peer-supplied: a value
        // whose severity is not Bad must still surface as an error, or a Good status would reach the
        // Result<T> error constructors (invariant: non-Good) and lose the completion.
        send_error_to_secure_channel_and_close(sanitise_err_status(errorCode), std::string_view{reason});
        return;
      }
    }

    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadCommunicationError}, "Server sent ERR frame");
    return;
  }

  // Must be ACK.
  std::array<byte, ua::connection_protocol::messageTypeSize> ackMessageType{
    std::byte{'A'}, std::byte{'C'}, std::byte{'K'}};
  if (!std::ranges::equal(messageType, ackMessageType))
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTypeInvalid}, "Expected ACK message");
    return;
  }

  // Reserved byte must be 'F'.
  if (static_cast<uint8_t>(buffer[3]) != static_cast<uint8_t>('F'))
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTypeInvalid}, "Invalid reserved byte in ACK");
    return;
  }

  const span<byte> messageSizeBytes{&buffer[4], sizeof(uint32_t)};

  uint32_t messageSize{0};
  {
    memory_stream_device::ExternalReadOnly streamDevice{messageSizeBytes};
    MemoryStream stream{streamDevice};
    UaBinaryDecoder decoder(StructureResolver{}, stream, limits);
    auto depth = limits.stack_depth();
    decoder.decode(depth, messageSize);
  }

  if (messageSize <= ua::connection_protocol::headerSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "ACK message size is invalid");
    return;
  }

  // ACK is a fixed-size message: bound the body size before allocating.
  if (messageSize > ua::connection_protocol::acknowledgeSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "ACK message size exceeds maximum");
    return;
  }

  // Grow the buffer to the full message size and await the body bytes asynchronously.
  buffer.resize(messageSize);
  await_handshake_body(std::move(buffer),
    &ConnectionProtocol::on_acknowledge_decoded,
    "ConnectionProtocol::on_acknowledge_decoded");
}

void ConnectionProtocol::on_acknowledge_decoded(StatusCode status, string_view, std::vector<byte>&& buffer)
{
  if (!mHandshakeFlow)
  {
    return;
  }
  if (mHandshakeFlow->step != HandshakeFlow::Step::AwaitingAcknowledge)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpInternalError}, "on_acknowledge_decoded reached in unexpected step");
    return;
  }

  if (status.is_bad())
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpInternalError}, "");
    return;
  }

  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = deps->encoding_limits();

  // Decode the body starting after the header.
  const span<byte> body{
    buffer.data() + ua::connection_protocol::headerSize, buffer.size() - ua::connection_protocol::headerSize};
  memory_stream_device::ExternalReadOnly streamDevice{body};
  MemoryStream stream{streamDevice};
  UaBinaryDecoder decoder(StructureResolver{}, stream, limits);

  uint32_t protocolVersion{};
  auto depth = limits.stack_depth();
  decoder.decode(depth, protocolVersion);

  // Part 6, 7.1.2.4: If the ACK protocol version is not supported, the client shall report an error.
  // The SDK currently supports protocol version 0 only.
  if (protocolVersion != 0)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadProtocolVersionUnsupported}, "Unsupported protocol version in ACK");
    return;
  }

  uint32_t ackReceiveBufferSize{0};
  uint32_t ackSendBufferSize{0};
  uint32_t ackMaxMessageSize{0};
  uint32_t ackMaxChunkCount{0};

  decoder.decode(depth, ackReceiveBufferSize);
  decoder.decode(depth, ackSendBufferSize);
  decoder.decode(depth, ackMaxMessageSize);
  decoder.decode(depth, ackMaxChunkCount);

  mLogger.debug({{"ack_receive_buffer_size", int64_t(ackReceiveBufferSize)},
                  {"ack_send_buffer_size", int64_t(ackSendBufferSize)},
                  {"ack_max_message_size", int64_t(ackMaxMessageSize)},
                  {"ack_max_chunk_count", int64_t(ackMaxChunkCount)}},
    "ACK received");

  if (mHandshakeFlow && mHandshakeFlow->deadlineTimer)
  {
    mHandshakeFlow->deadlineTimer.cancel();
  }

  // Validate: ACK buffer sizes shall not exceed what we sent in Hello.
  if (ackReceiveBufferSize > mConfigLimits.maxBufferSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTypeInvalid}, "ACK ReceiveBufferSize exceeds Hello SendBufferSize");
    return;
  }
  if (ackSendBufferSize > mConfigLimits.maxBufferSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTypeInvalid}, "ACK SendBufferSize exceeds Hello ReceiveBufferSize");
    return;
  }

  // Validate: ACK buffer sizes meet minimum.
  if (ackReceiveBufferSize < ua::connection_protocol::eccMinBufferSize ||
      ackSendBufferSize < ua::connection_protocol::eccMinBufferSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTypeInvalid}, "ACK buffer sizes are below the absolute minimum (1024)");
    return;
  }

  // Build NegotiatedLimits (client perspective).
  mNegotiatedLimits.sendBufferSize = ackReceiveBufferSize;  // peer can receive this much
  mNegotiatedLimits.receiveBufferSize = ackSendBufferSize;  // peer will send this much
  mNegotiatedLimits.sendMaxMessageSize = ackMaxMessageSize;  // peer's constraint on my requests
  mNegotiatedLimits.sendMaxChunkCount = ackMaxChunkCount;  // peer's constraint on my request chunks
  mNegotiatedLimits.recvMaxMessageSize = mConfigLimits.maxMessageSize;  // my constraint on responses
  mNegotiatedLimits.recvMaxChunkCount = mConfigLimits.maxChunkCount;  // my constraint on response chunks

  mLogger.debug({{"send_buffer_size", int64_t(mNegotiatedLimits.sendBufferSize)},
                  {"receive_buffer_size", int64_t(mNegotiatedLimits.receiveBufferSize)}},
    "Buffer sizes negotiated");

  mLogger.info("Connection established");
  complete_handshake();
}

void ConnectionProtocol::configure_for_header_rx()
{
  // After a fatal error nothing more is read: the channel is closing (Part 6 7.1.4).
  if (mFatalClosing)
  {
    return;
  }

  // Backpressure: while reads are paused (the SecureChannel's incoming-chunk queue is at its depth
  // cap), do not re-arm the header read. Record that one is owed so resume_reads can arm it once the
  // queue drains. Runs on the strand, like every caller of this method.
  if (mReadsPaused)
  {
    mHeaderRxDeferred = true;
    return;
  }

  auto me = weak_from_this();

  // No read timer here: waiting for the *next* message header is an idle wait. A channel that is
  // legitimately idle (e.g. a Session deliberately stalled to test its own timeout, Part 4 5.6.2)
  // must stay open until its SecurityToken lifetime or Session timeout governs it - the transport
  // must not tear it down. The per-message read timeout is armed only once a message is in flight
  // (header received, body pending) in check_header_and_configure_for_message_rx.

  mConnection->register_read_callback(
    [me](StatusCode status, string_view errorDescription, std::vector<byte>&& buffer)
    {
      auto lockedCp = me.lock();
      if (!lockedCp)
        return;

      async::post_borrowing(lockedCp.get(),
        *lockedCp->mStrand,
        lockedCp->mLogger,
        [status, errDesc = std::string{errorDescription}, buf = std::move(buffer)](
          ConnectionProtocol& cp) mutable
        {
          try
          {
            if (status.is_bad())
            {
              // The read a close after pending writes aborts is that close: its completion reports it, and
              // nothing (no Error message) can be written to the closed transport.
              if (cp.mClosingAfterWrites)
                return;
              cp.send_error_to_secure_channel_and_close(
                wire_safe(status, errDesc), {}, TransportState::Failed);
            }
            else
            {
              cp.check_header_and_configure_for_message_rx(std::move(buf));
            }
          }
          catch (const UaException& exception)
          {
            log_exception(
              cp.mLogger, "ConnectionProtocol::configure_for_header_rx", std::current_exception());
            cp.send_error_to_secure_channel_and_close(
              wire_safe(exception.status_code(), exception.what()), {});
          }
          catch (...)
          {
            log_exception(
              cp.mLogger, "ConnectionProtocol::configure_for_header_rx", std::current_exception());
            cp.mConnection->close_async();
          }
        })();
    });

  std::vector<byte> header;
  header.resize(ua::connection_protocol::headerSize);
  mConnection->async_read(std::move(header));
}

void ConnectionProtocol::check_header_and_configure_for_message_rx(std::vector<byte>&& buffer)
{
  if (mFatalClosing)
  {
    return;
  }

  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = deps->encoding_limits();

  if (buffer.size() != ua::connection_protocol::headerSize)
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid}, "");
    return;
  }

  std::array<byte, ua::connection_protocol::messageTypeSize> msgMessageType{
    std::byte{'M'}, std::byte{'S'}, std::byte{'G'}};
  std::array<byte, ua::connection_protocol::messageTypeSize> opnMessageType{
    std::byte{'O'}, std::byte{'P'}, std::byte{'N'}};
  std::array<byte, ua::connection_protocol::messageTypeSize> cloMessageType{
    std::byte{'C'}, std::byte{'L'}, std::byte{'O'}};

  const span<byte> messageType{buffer.data(), ua::connection_protocol::messageTypeSize};

  // Handle ERR frames from the server during message exchange (post-HEL/ACK).
  std::array<byte, ua::connection_protocol::messageTypeSize> errMessageType{
    std::byte{'E'}, std::byte{'R'}, std::byte{'R'}};
  if (std::ranges::equal(messageType, errMessageType) && mRole == ConnectionProtocolRole::Server)
  {
    // Part 6 7.1.5 defines ERR as the Server's notification to the Client; a client's ERR is a Message
    // type the Server does not accept (Table 70, Bad_TcpMessageTypeInvalid). Its body is not read, so
    // neither its size nor its Reason reaches the server (group L, review B1-10).
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid}, "");
    return;
  }
  if (std::ranges::equal(messageType, errMessageType))
  {
    // Parse the ERR body to extract status code and reason.
    const span<byte> messageSizeBytes{&buffer[4], sizeof(uint32_t)};
    uint32_t messageSize{0};
    {
      memory_stream_device::ExternalReadOnly sizeDevice{messageSizeBytes};
      MemoryStream sizeStream{sizeDevice};
      UaBinaryDecoder sizeDecoder(StructureResolver{}, sizeStream, limits);
      auto depth = limits.stack_depth();
      sizeDecoder.decode(depth, messageSize);
    }

    const size_t bodySize = messageSize > ua::connection_protocol::headerSize
                              ? messageSize - ua::connection_protocol::headerSize
                              : 0;

    // At most the Error field, the Reason's length and 4096 Reason bytes are read: a larger claim must not
    // size the synchronous read by whatever the socket holds. A Reason longer than that fails to decode
    // from the prefix and is ignored, the Error kept (Part 6 7.1.2.5).
    const size_t readSize = std::min(bodySize, maxErrBodyBytes);
    if (bodySize > 0 && readSize <= mConnection->bytes_available_to_read())
    {
      std::vector<byte> errBody;
      errBody.resize(readSize);
      auto readStatus = mConnection->read(errBody);
      if (readStatus.is_good() && errBody.size() >= sizeof(uint32_t))
      {
        memory_stream_device::ExternalReadOnly bodyDevice{errBody};
        MemoryStream bodyStream{bodyDevice};
        const auto errLimits = handshake_decode_limits(limits);
        UaBinaryDecoder bodyDecoder(StructureResolver{}, bodyStream, errLimits);
        auto depth = errLimits.stack_depth();

        uint32_t errorCode{0};
        bodyDecoder.decode(depth, errorCode);
        String reason;
        try
        {
          bodyDecoder.decode(depth, reason);
        }
        catch (const UaException&)
        {
          reason = {};  // a Reason cut short does not hide the peer's Error status
        }
        reason = ignore_oversized_err_reason(std::move(reason));

        mLogger.warning(
          {{"status", fmt::format("0x{:08x}", errorCode)}}, "Server sent ERR: {}", std::string_view{reason});

        // ERR is the peer's fatal-error notification and its Error field is peer-supplied: a value
        // whose severity is not Bad must still surface as an error, or a Good status would reach the
        // Result<T> error constructors (invariant: non-Good) and lose the completion. The server closes
        // the socket after its ERR (Part 6 7.1.5), so no CloseSecureChannel follows it.
        send_error_to_secure_channel_and_close(
          sanitise_err_status(errorCode), std::string_view{reason}, TransportState::Failed);
        return;
      }
    }

    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadCommunicationError}, "Server sent ERR frame", TransportState::Failed);
    return;
  }

  if (!std::ranges::equal(messageType, msgMessageType) && !std::ranges::equal(messageType, opnMessageType) &&
      !std::ranges::equal(messageType, cloMessageType))
  {
    send_error_to_secure_channel_and_close(StatusCode{Status::BadTcpMessageTypeInvalid}, "");
    return;
  }

  // The 4th byte (IsFinal/ChunkType) is not validated at the Connection Protocol layer.
  // Per Part 6 Section 7.1.2.2, the Connection Protocol only verifies MessageType and MessageSize
  // for SecureChannel messages (MSG, OPN, CLO). The IsFinal byte ('F', 'C', 'A') is interpreted
  // by the Secure Channel layer.

  const span<byte> messageSizeBytes{&buffer[4], sizeof(uint32_t)};

  uint32_t messageSize{0};
  {
    memory_stream_device::ExternalReadOnly streamDevice{messageSizeBytes};
    MemoryStream stream{streamDevice};
    UaBinaryDecoder decoder(StructureResolver{}, stream, limits);
    auto depth = limits.stack_depth();
    decoder.decode(depth, messageSize);
  }

  if (messageSize <= ua::connection_protocol::headerSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTypeInvalid}, "Message size is invalid");
    return;
  }

  // Connection Protocol must enforce the negotiated ReceiveBufferSize before passing chunks to UASC.
  if (messageSize > mNegotiatedLimits.receiveBufferSize)
  {
    send_error_to_secure_channel_and_close(
      StatusCode{Status::BadTcpMessageTooLarge}, "Message size exceeds negotiated ReceiveBufferSize");
    return;
  }

  buffer.resize(messageSize);

  auto me = weak_from_this();

  mConnection->register_read_callback(
    [me](StatusCode status, string_view errorDescription, std::vector<byte>&& readBuffer)
    {
      auto lockedCp = me.lock();
      if (!lockedCp)
        return;

      async::post_borrowing(lockedCp.get(),
        *lockedCp->mStrand,
        lockedCp->mLogger,
        [status, errDesc = std::string{errorDescription}, buf = std::move(readBuffer)](
          ConnectionProtocol& cp) mutable
        {
          try
          {
            // Cancel the per-message read timer - full message arrived.
            cp.mMessageReadTimer.cancel();

            if (status.is_bad())
            {
              if (cp.mClosingAfterWrites)
                return;  // the close after pending writes aborted this read; its completion reports it.
              cp.send_error_to_secure_channel_and_close(
                wire_safe(status, errDesc), {}, TransportState::Failed);
            }
            else if (!cp.mFatalClosing)
            {
              cp.mMessageChunkReceivedCallback(status, std::move(buf));
              cp.configure_for_header_rx();
            }
          }
          catch (...)
          {
            log_exception(cp.mLogger,
              "ConnectionProtocol::check_header_and_configure_for_message_rx",
              std::current_exception());
            cp.mConnection->close_async();
          }
        })();
    });

  // A message is now in flight (header received, body pending). Arm the per-message read timer so a
  // peer that announces a MessageSize but never delivers the body cannot block the connection
  // indefinitely. Cancelled when the full body arrives (above); deliberately not armed during the
  // idle inter-message wait so legitimately idle channels survive (see configure_for_header_rx).
  {
    auto meTimer = weak_from_this();
    mMessageReadTimer = Timer::schedule_after(engaged_strand(mStrand),
      mMessageReadTimeout,
      [meTimer](boost::system::error_code ec)
      {
        if (ec)
          return;
        auto cp = meTimer.lock();
        if (!cp)
          return;
        cp->mLogger.warning("Message read timeout");
        cp->send_error_to_secure_channel_and_close(StatusCode{Status::BadTimeout}, "Message read timeout");
      });
  }

  mConnection->async_read(std::move(buffer), ua::connection_protocol::headerSize);
}

void ConnectionProtocol::send_error_and_close(StatusCode status, string_view description)
{
  auto deps = mDependencies.lock();
  check(deps);
  const auto limits = deps->encoding_limits();

  memory_stream_device::Dynamic streamDevice{
    ua::connection_protocol::headerSize + (2 * sizeof(uint32_t)) + maxErrReasonBytes, true};

  MemoryStream stream{streamDevice};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  const StackDepth limit = limits.stack_depth();
  encoder.encode(limit, uint8_t{'E'});
  encoder.encode(limit, uint8_t{'R'});
  encoder.encode(limit, uint8_t{'R'});
  encoder.encode(limit, uint8_t{'F'});

  const size_t sizePosition = stream.get_position();
  encoder.encode(limit, uint32_t{0});

  encoder.encode(limit, status.as_uint32());

  const String reason = truncate_err_reason(description);
  encoder.encode(limit, reason);

  stream.seek_from_start(sizePosition);
  const size_t messageSize = stream.get_length();
  encoder.encode(limit, numeric_cast<uint32_t>(messageSize));

  auto buffer = streamDevice.move_storage_out();
  buffer.resize(messageSize);

  auto me = this->weak_from_this();

  mConnection->register_write_callback(
    [me](StatusCode writeStatus, string_view writeDescription)
    {
      UA_UNUSED(writeStatus);
      UA_UNUSED(writeDescription);

      auto lockedCp = me.lock();
      if (!lockedCp)
        return;

      async::post_borrowing(lockedCp.get(),
        *lockedCp->mStrand,
        lockedCp->mLogger,
        [](ConnectionProtocol& cp)
        {
          try
          {
            cp.close_async();
          }
          catch (...)
          {
            log_exception(
              cp.mLogger, "ConnectionProtocol::send_error_and_close callback", std::current_exception());
          }
        })();
    });

  mConnection->async_write(std::move(buffer));
}

void ConnectionProtocol::begin_fatal_close(StatusCode status, string_view description)
{
  // Cost: nothing on the normal path beyond one flag test where a read is re-armed; the transport
  // already knows whether writes are queued, so no per-write count is kept. The fatal path arms one
  // timer, and the SecureChannel signs (and encrypts) one small CloseSecureChannel body.
  mFatalClosing = true;
  mFatalCloseStatus = status;
  mFatalCloseDescription = std::string{description};
  mMessageReadTimer.cancel();
  arm_fatal_close_timer();
}

void ConnectionProtocol::arm_fatal_close_timer()
{
  if (mFatalCloseTimer)
  {
    return;
  }
  mFatalCloseTimer = Timer::schedule_after(engaged_strand(mStrand),
    mFatalCloseTimeout,
    [me = weak_from_this()](boost::system::error_code ec)
    {
      if (ec)
      {
        return;
      }
      auto cp = me.lock();
      if (!cp)
      {
        return;
      }
      cp->mLogger.warning(
        "CloseSecureChannel not written in time after a fatal error; closing the transport");
      cp->close_transport_after_fatal_error();
    });
}

void ConnectionProtocol::begin_close_after_channel_error()
{
  async::post_borrowing(this,
    engaged_strand(mStrand),
    mLogger,
    [](ConnectionProtocol& self)
    {
      if (self.mTransportClosed || self.mFatalClosing)
      {
        return;
      }
      self.mErrorCallback = {};
      self.begin_fatal_close(
        StatusCode{Status::BadSecureChannelClosed}, "SecureChannel closing after a fatal error it detected");
    })();
}

void ConnectionProtocol::close_after_writes_on_strand(std::function<void(VoidResult)> done)
{
  // Writes are waited for only on an established connection whose transport is still open; a close during
  // the handshake, or of a transport already closed, is the immediate close.
  if (mHandshakeFlow || mTransportClosed)
  {
    close_async(std::move(done));
    return;
  }
  mMessageReadTimer.cancel();
  mFatalCloseTimer.cancel();
  mTransportClosed = true;
  mClosingAfterWrites = true;
  // The protocol owns the transport and the transport's write handlers do not: keep the protocol alive until
  // the transport has closed, and bound the wait with the fallback timer, whose expiry closes the transport
  // at once (close_transport_after_fatal_error). The terminal error sink and the close observer fire when the
  // transport HAS closed: a channel told earlier would tear down and close it at once, cutting off the
  // writes.
  if (!mFatalClosing)
  {
    // A fatal close already in progress keeps its own status for the close observer.
    mFatalCloseStatus = StatusCode{Status::BadShutdown};
    mFatalCloseDescription = "Connection protocol closed";
  }
  arm_fatal_close_timer();
  mFatalCloseKeepAlive = shared_from_this();
  const auto reportClosed = [](ConnectionProtocol& cp)
  {
    try
    {
      // The status recorded for this close: an orderly close's BadShutdown, or the status of a fatal close
      // that was already in progress.
      cp.fire_error_sink(
        cp.mFatalCloseStatus, cp.mFatalCloseDescription, FatalCloseDisposition::TransportClosed);
      cp.notify_close_observer(cp.mFatalCloseStatus, cp.mFatalCloseDescription);
    }
    catch (...)
    {
      log_exception(
        cp.mLogger, "ConnectionProtocol::close_after_writes terminal callback", std::current_exception());
    }
  };
  try
  {
    mConnection->close_async(async::post_borrowing(this,
                               engaged_strand(mStrand),
                               mLogger,
                               [done, reportClosed](ConnectionProtocol& cp, VoidResult result) mutable
                               {
                                 const auto releasedKeepAlive = std::move(cp.mFatalCloseKeepAlive);
                                 cp.mFatalCloseTimer.cancel();
                                 reportClosed(cp);
                                 done(std::move(result));
                               }),
      TransportConnection::CloseMode::AfterPendingWrites);
  }
  catch (...)
  {
    log_exception(mLogger, "ConnectionProtocol::close_after_writes", std::current_exception());
    close_transport_after_fatal_error();
    reportClosed(*this);
    done(VoidResult{});
  }
}

void ConnectionProtocol::close_after_pending_writes()
{
  // Owning post: the SecureChannel releases its reference straight after this call, and the transport
  // must outlive the CloseSecureChannel chunk still queued on it.
  async::post_owning(this,
    engaged_strand(mStrand),
    mLogger,
    [](ConnectionProtocol& self)
    {
      try
      {
        if (self.mTransportClosed)
        {
          return;
        }
        // The channel reported the failure itself; nothing further is reported from here.
        self.mErrorCallback = {};
        if (!self.mFatalClosing)
        {
          self.begin_fatal_close(
            StatusCode{Status::BadSecureChannelClosed}, "SecureChannel closed after a fatal error");
        }
        self.mTransportClosed = true;
        self.mFatalCloseKeepAlive = self.shared_from_this();
        self.mConnection->close_async(
          async::post_borrowing(&self,
            engaged_strand(self.mStrand),
            self.mLogger,
            [](ConnectionProtocol& cp, VoidResult) { cp.on_transport_closed_after_writes(); }),
          TransportConnection::CloseMode::AfterPendingWrites);
      }
      catch (...)
      {
        log_exception(
          self.mLogger, "ConnectionProtocol::close_after_pending_writes", std::current_exception());
        self.close_transport_after_fatal_error();
      }
    })();
}

void ConnectionProtocol::close_transport_after_fatal_error()
{
  // Released when this returns: the caller holds its own reference for the duration of the call.
  const auto keepAlive = std::move(mFatalCloseKeepAlive);
  mFatalCloseTimer.cancel();
  mTransportClosed = true;
  try
  {
    // Closes at once, and completes an AfterPendingWrites close still waiting on the queue.
    mConnection->close_async();
  }
  catch (...)
  {
    log_exception(mLogger, "ConnectionProtocol::close_transport_after_fatal_error", std::current_exception());
  }
  notify_close_observer(mFatalCloseStatus, mFatalCloseDescription);
}

void ConnectionProtocol::on_transport_closed_after_writes()
{
  const auto keepAlive = std::move(mFatalCloseKeepAlive);
  mFatalCloseTimer.cancel();
  notify_close_observer(mFatalCloseStatus, mFatalCloseDescription);
}

void ConnectionProtocol::initialise(boost::asio::any_io_executor /*executor*/, std::chrono::seconds timeout,
  std::chrono::milliseconds messageReadTimeout, ConnectionCompleteCallback connectionCompleteCallback)
{
  mMessageReadTimeout = messageReadTimeout;

  // Allocate the per-handshake flow state. mHandshakeFlow != nullptr is the
  // canonical "handshake in progress" predicate.
  mHandshakeFlow = std::make_unique<HandshakeFlow>();
  mHandshakeFlow->onComplete = std::move(connectionCompleteCallback);
  if (mRole == ConnectionProtocolRole::Server)
  {
    // Forward and reverse-connect servers both await Hello next (reverse-connect after the RHE send).
    mHandshakeFlow->step = HandshakeFlow::Step::AwaitingHello;
  }
  else if (mRole == ConnectionProtocolRole::Client && mReverseConnect)
  {
    mHandshakeFlow->step = HandshakeFlow::Step::AwaitingReverseHello;
  }
  else
  {
    mHandshakeFlow->step = HandshakeFlow::Step::AwaitingAcknowledge;  // after HEL send
  }

  auto me = this->weak_from_this();

  // A non-positive timeout disables the connection-establishment deadline. Arming a
  // zero-delay timer here is actively unsafe: the timer can fire on the io_context thread
  // (running the strand) the instant it is armed, while this initialise() is still executing
  // on the *calling* thread - its notifier would touch this half-constructed CP concurrently.
  // Production config validation forbids a non-positive ConnectionProtocolTimeout
  // (ua_application_configuration.cpp), so this only guards degenerate/internal callers.
  if (timeout > std::chrono::seconds{0})
  {
    mHandshakeFlow->deadlineTimer = Timer::schedule_after(engaged_strand(mStrand),
      timeout,
      [me](boost::system::error_code ec)
      {
        if (ec)
        {
          return;
        }
        auto cp = me.lock();
        if (cp)
        {
          cp->mLogger.warning("Connection timeout");
          cp->send_error_to_secure_channel_and_close(StatusCode{Status::BadTimeout}, "");
        }
      });
  }

  mConnection->register_error_callback(
    [me](StatusCode status, string_view description)
    {
      auto lockedCp = me.lock();
      if (!lockedCp)
        return;

      async::post_borrowing(lockedCp.get(),
        *lockedCp->mStrand,
        lockedCp->mLogger,
        [status, errDesc = std::string{description}](ConnectionProtocol& cp)
        {
          try
          {
            cp.send_error_to_secure_channel_and_close(wire_safe(status, errDesc), {}, TransportState::Failed);
          }
          catch (...)
          {
            log_exception(cp.mLogger, "ConnectionProtocol error callback", std::current_exception());
            cp.mConnection->close_async();
          }
        })();
    });

  if (mRole == ConnectionProtocolRole::Server && mReverseConnect)
  {
    // Server + reverse connect: send RHE first, then wait for HEL.
    async::post_borrowing(this,
      engaged_strand(mStrand),
      mLogger,
      [](ConnectionProtocol& cp)
      {
        try
        {
          cp.send_reverse_hello();
        }
        catch (...)
        {
          log_exception(cp.mLogger, "ConnectionProtocol::send_reverse_hello", std::current_exception());
          cp.mConnection->close_async();
        }
      })();
  }
  else if (mRole == ConnectionProtocolRole::Server)
  {
    // Server + normal: wait for HEL.
    mConnection->register_read_callback(
      [me](StatusCode status, string_view errorDescription, std::vector<byte>&& buffer)
      {
        auto lockedCp = me.lock();
        if (!lockedCp)
          return;

        async::post_borrowing(lockedCp.get(),
          *lockedCp->mStrand,
          lockedCp->mLogger,
          [status, errDesc = std::string{errorDescription}, buf = std::move(buffer)](
            ConnectionProtocol& cp) mutable
          {
            try
            {
              cp.on_hello_received(status, errDesc, std::move(buf));
            }
            catch (...)
            {
              log_exception(cp.mLogger, "ConnectionProtocol::on_hello_received", std::current_exception());
              cp.mConnection->close_async();
            }
          })();
      });

    std::vector<byte> header;
    header.resize(ua::connection_protocol::headerSize);
    mConnection->async_read(std::move(header));
  }
  else if (mRole == ConnectionProtocolRole::Client && mReverseConnect)
  {
    // Client + reverse connect: wait for RHE first, then send HEL.
    mConnection->register_read_callback(
      [me](StatusCode status, string_view errorDescription, std::vector<byte>&& buffer)
      {
        auto lockedCp = me.lock();
        if (!lockedCp)
          return;

        async::post_borrowing(lockedCp.get(),
          *lockedCp->mStrand,
          lockedCp->mLogger,
          [status, errDesc = std::string{errorDescription}, buf = std::move(buffer)](
            ConnectionProtocol& cp) mutable
          {
            try
            {
              cp.on_reverse_hello_received(status, errDesc, std::move(buf));
            }
            catch (...)
            {
              log_exception(
                cp.mLogger, "ConnectionProtocol::on_reverse_hello_received", std::current_exception());
              cp.mConnection->close_async();
            }
          })();
      });

    std::vector<byte> header;
    header.resize(ua::connection_protocol::headerSize);
    mConnection->async_read(std::move(header));
  }
  else
  {
    // Client + normal: send HEL, then wait for ACK.
    async::post_borrowing(this,
      engaged_strand(mStrand),
      mLogger,
      [](ConnectionProtocol& cp)
      {
        try
        {
          cp.send_hello();
        }
        catch (...)
        {
          log_exception(cp.mLogger, "ConnectionProtocol::send_hello", std::current_exception());
          cp.mConnection->close_async();
        }
      })();
  }
}

}  // namespace ua
