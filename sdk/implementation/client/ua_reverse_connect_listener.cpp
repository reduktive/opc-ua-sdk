// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// ReverseConnectListener - strand-serialized component that accepts incoming reverse
// connections from OPC UA Servers.
//
// Lifecycle: create() -> start() -> [accept/handshake/queue/dispatch] -> stop_async()
//
// Listens on a TCP port. When a Server connects, creates a ConnectionProtocol
// in Client+ReverseConnect mode, validates the ReverseHello against the
// configured ExpectedServers, and either dispatches to a waiting consumer
// or queues the ready connection for later consumption.

#include "ua_reverse_connect_listener.h"
#include "ua_reverse_connect_admission.h"

#include "ua_connection_protocol.h"
#include "ua_error_detail.h"
#include "ua_log_exception.h"
#include "ua_on_strand.h"
#include "ua_tcp_transport_acceptor.h"
#include "ua_tcp_transport_connection.h"
#include "ua_to_result.h"

#include "fmt/format.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <utility>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>

namespace ua::client
{

// ---------------------------------------------------------------------------
// Construction / factory
// ---------------------------------------------------------------------------

ReverseConnectListener::ReverseConnectListener(boost::asio::any_io_executor executor,
  std::weak_ptr<ua::ConnectionProtocolDependencies> connectionProtocolDeps,
  ReverseConnectListenerConfig config, ua::Logger logger)
  : mExecutor(std::move(executor)), mConnectionProtocolDeps(std::move(connectionProtocolDeps)),
    mConfig(std::move(config)), mStrand(boost::asio::make_strand(mExecutor)), mLogger(std::move(logger))
{}

ReverseConnectListener::~ReverseConnectListener() = default;

std::shared_ptr<ReverseConnectListener> ReverseConnectListener::create(boost::asio::any_io_executor executor,
  std::weak_ptr<ua::ConnectionProtocolDependencies> connectionProtocolDeps,
  ReverseConnectListenerConfig config, ua::Logger logger, size_t writeQueueDepthCap,
  size_t writeQueueBytesCap)
{
  auto listener = std::shared_ptr<ReverseConnectListener>(new ReverseConnectListener(
    std::move(executor), std::move(connectionProtocolDeps), std::move(config), std::move(logger)));
  listener->mWriteQueueDepthCap = writeQueueDepthCap;
  listener->mWriteQueueBytesCap = writeQueueBytesCap;
  listener->initialise();
  return listener;
}

void ReverseConnectListener::initialise()
{
  mLogger = mLogger.with_category("reverse_connect_listener");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void ReverseConnectListener::start(std::function<void(VoidResult)> completionHandler)
{
  if (!completionHandler)
  {
    completionHandler = [](VoidResult) {
    };
  }
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    VoidResult{ua::Status::BadShutdown},
    [](ReverseConnectListener& self, std::function<void(VoidResult)> callback)
    {
      // CL-RC-007: the admission bounds must admit at least one handshake, or nothing could ever connect.
      if (self.mConfig.maxPendingHandshakes == 0 || self.mConfig.maxPendingHandshakesPerAddress == 0)
      {
        self.mLogger.error({}, "Invalid reverse-connect configuration: a pending-handshake bound of zero");
        if (callback)
        {
          callback(VoidResult{ua::Status::BadInvalidArgument,
            ua::ErrorDetail::build("InvalidPendingHandshakeBound",
              "maxPendingHandshakes and maxPendingHandshakesPerAddress must be at least 1",
              "ReverseConnectListener")});
        }
        return;
      }

      self.mRunning = true;

      // Parse bind address "host:port".
      const auto& address = self.mConfig.bind.address;
      auto colonPos = address.rfind(':');
      if (colonPos == std::string::npos)
      {
        self.mLogger.error({{"address", address}}, "Invalid bind address: missing port separator");
        if (callback)
        {
          callback(VoidResult{ua::Status::BadInvalidArgument,
            ua::ErrorDetail::build(
              "InvalidBindAddress", "Missing port separator in bind address", "ReverseConnectListener")
              .context(ua::ContextKeys::endpointAddress, address)});
        }
        return;
      }

      auto host = address.substr(0, colonPos);
      uint16_t port{0};
      try
      {
        auto portValue = std::stoul(address.substr(colonPos + 1));
        if (portValue > 65535)
        {
          throw std::out_of_range("port value exceeds 65535");
        }
        port = numeric_cast<uint16_t>(portValue);
      }
      catch (const std::exception& ex)
      {
        self.mLogger.error({{"address", address}, {"error", ex.what()}}, "Invalid port in bind address");
        if (callback)
        {
          callback(VoidResult{ua::Status::BadInvalidArgument,
            ua::ErrorDetail::build(
              "InvalidBindAddress", "Invalid port in bind address", "ReverseConnectListener")
              .context(ua::ContextKeys::endpointAddress, address)
              .context(ua::ContextKeys::endpointPort, address.substr(colonPos + 1))});
        }
        return;
      }

      boost::system::error_code addressError;
      auto addr = boost::asio::ip::make_address(host, addressError);
      if (addressError)
      {
        self.mLogger.error(
          {{"address", address}, {"error", addressError.message()}}, "Failed to parse bind address");
        if (callback)
        {
          callback(VoidResult{ua::Status::BadInvalidArgument,
            ua::ErrorDetail::build(
              "InvalidBindAddress", "Failed to parse bind address", "ReverseConnectListener")
              .context(ua::ContextKeys::endpointAddress, host)});
        }
        return;
      }

      const boost::asio::ip::tcp::endpoint endpoint{addr, port};

      auto weakSelf = self.weak_from_this();
      // The acceptor binds inside create(), so this is where a taken port or an address this
      // host does not own is discovered. Catch it: an exception escaping this posted handler
      // would abandon `callback` entirely, leaving a caller that asked for completion waiting
      // forever rather than being told the listener never came up.
      try
      {
        self.mAcceptor = ua::TcpTransportAcceptor::create(
          self.mExecutor,
          endpoint,
          [weakSelf](ua::StatusCode status,
            ua::string_view errorDescription,
            std::shared_ptr<ua::TcpTransportConnection>
              connection)
          {
            auto listener = weakSelf.lock();
            if (!listener)
              return;

            ua::async::post_borrowing(listener.get(),
              listener->mStrand,
              listener->mLogger,
              [status, errorDesc = std::string{errorDescription}, connection = std::move(connection)](
                ReverseConnectListener& postSelf) mutable
              { postSelf.on_tcp_accepted(status, errorDesc, std::move(connection)); })();
          },
          self.mLogger,
          self.mWriteQueueDepthCap,
          self.mWriteQueueBytesCap);
      }
      catch (...)
      {
        auto status = ua::exception_to_status_code(std::current_exception());
        self.mRunning = false;
        self.mLogger.error({{"address", address}}, "Reverse connect listener failed to bind");
        if (callback)
          callback(VoidResult{status});
        return;
      }

      self.mLogger.info({{"address", address}}, "Reverse connect listener started");

      if (callback)
        callback(VoidResult{});
    })();
}

void ReverseConnectListener::stop_async(std::function<void(ua::VoidResult)> completionHandler)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    ua::VoidResult{},
    [](ReverseConnectListener& self, std::function<void(ua::VoidResult)> callback)
    {
      if (!self.mRunning)
      {
        if (callback)
          callback(ua::VoidResult{});
        return;
      }

      self.mRunning = false;
      self.mLogger.info({}, "Stopping reverse connect listener");

      // Move all in-flight resources out of the listener so any late strand
      // work (e.g. a posted on_tcp_accepted that races stop_async) sees empty
      // containers and is a no-op.
      auto acceptor = std::exchange(self.mAcceptor, {});
      auto handshakes = std::exchange(self.mPendingHandshakes, {});
      auto queued = std::exchange(self.mQueuedConnections, {});
      auto waiters = std::exchange(self.mWaiters, {});

      // Fail waiters synchronously - no async work to drain.
      for (auto& waiter : waiters)
      {
        waiter.timeoutTimer.cancel();
        auto cb = std::move(waiter.callback);
        if (cb)
        {
          cb(QueuedConnectionResult{ua::Status::BadShutdown,
            ua::ErrorDetail::build("ListenerStopped",
              "Reverse connect listener stopped while waiting for connection",
              "ReverseConnectListener")
              .context(ua::ContextKeys::endpointUrl, waiter.endpointUrl)});
        }
      }
      for (auto& q : queued)
      {
        q.idleTimer.cancel();
      }

      // Drain all close paths before signalling completion.
      const std::size_t closeCount = (acceptor ? 1u : 0u) + handshakes.size() + queued.size();

      if (closeCount == 0)
      {
        if (callback)
          callback(ua::VoidResult{});
        return;
      }

      auto remaining = std::make_shared<std::atomic<std::size_t>>(closeCount);
      auto finalCallback = std::make_shared<std::function<void(ua::VoidResult)>>(std::move(callback));
      auto onOneDone = [remaining, finalCallback, strand = self.mStrand, logger = self.mLogger](
                         ua::VoidResult)
      {
        if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
        {
          boost::asio::post(strand,
            ua::async::guarded(logger,
              [finalCallback]()
              {
                if (*finalCallback)
                  (*finalCallback)(ua::VoidResult{});
              }));
        }
      };

      if (acceptor)
      {
        // Capture `acceptor` into the callback so it stays alive until drained.
        acceptor->close_async([acceptor, onOneDone](ua::VoidResult r) mutable { onOneDone(std::move(r)); });
      }
      for (const auto& handshake : handshakes)
      {
        auto h = handshake.connection;  // copy strong ref into callback capture
        h->close_async([h, onOneDone](ua::VoidResult r) mutable { onOneDone(std::move(r)); });
      }
      for (const auto& q : queued)
      {
        auto conn = q.connection;  // copy strong ref into callback capture
        if (!conn)
        {
          onOneDone(ua::VoidResult{});  // nothing to close
          continue;
        }
        conn->close_async([conn, onOneDone](ua::VoidResult r) mutable { onOneDone(std::move(r)); });
      }
    })();
}

void ReverseConnectListener::consume_connection(
  std::string endpointUrl, std::chrono::seconds timeout, ConsumeConnectionCallback completionHandler)
{
  auto goneResult = QueuedConnectionResult{ua::Status::BadShutdown,
    ua::ErrorDetail::build(
      "ListenerGone", "Reverse connect listener no longer exists", "ReverseConnectListener")
      .context(ua::ContextKeys::endpointUrl, endpointUrl)};
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::move(goneResult),
    [endpointUrl = std::move(endpointUrl), timeout](
      ReverseConnectListener& self, ConsumeConnectionCallback callback) mutable
    {
      if (!self.mRunning)
      {
        if (callback)
        {
          callback(QueuedConnectionResult{ua::Status::BadShutdown,
            ua::ErrorDetail::build(
              "ListenerNotRunning", "Reverse connect listener is not running", "ReverseConnectListener")
              .context(ua::ContextKeys::endpointUrl, endpointUrl)});
        }
        return;
      }

      // Search for a matching queued connection, among the live ones only.
      self.drop_closed_queued_connections();
      for (auto it = self.mQueuedConnections.begin(); it != self.mQueuedConnections.end(); ++it)
      {
        if (it->reverseHello.endpointUrl == endpointUrl)
        {
          auto queued = std::move(*it);
          self.mQueuedConnections.erase(it);
          queued.idleTimer.cancel();

          self.mLogger.debug({{"endpoint_url", endpointUrl}}, "Dispatching queued connection to consumer");

          if (callback)
          {
            callback(QueuedConnectionResult{std::move(queued)});
          }
          return;
        }
      }

      // No match found - create a waiter.

      auto weakSelf = self.weak_from_this();

      auto waiterId = self.mNextWaiterId++;

      // Capture the endpoint URL for logging in the timer closure.
      auto waiterEndpoint = endpointUrl;

      auto timer = Timer::schedule_after(self.mStrand,
        timeout,
        [weakSelf, waiterId, waiterEndpoint](boost::system::error_code errorCode)
        {
          if (errorCode)
            return;

          auto listener = weakSelf.lock();
          if (!listener)
            return;

          // Find and remove the waiter by unique ID (already on strand).
          // IMPORTANT: Copy all needed data and the callback BEFORE erasing the waiter,
          // because erasing destroys the Timer, which calls cancel(), which sets
          // mNotifier = nullptr - destroying this lambda's captures while we're executing.
          for (auto it = listener->mWaiters.begin(); it != listener->mWaiters.end(); ++it)
          {
            if (it->id == waiterId)
            {
              auto cb = std::move(it->callback);
              auto endpoint = std::move(it->endpointUrl);
              listener->mWaiters.erase(it);

              listener->mLogger.debug(
                {{"endpoint_url", endpoint}}, "Waiter timed out waiting for reverse connection");

              if (cb)
              {
                cb(QueuedConnectionResult{ua::Status::BadTimeout,
                  ua::ErrorDetail::build(
                    "WaiterTimeout", "Timed out waiting for reverse connection", "ReverseConnectListener")
                    .context(ua::ContextKeys::endpointUrl, endpoint)});
              }
              return;
            }
          }
        });

      self.mWaiters.push_back(ConnectionWaiter{
        .id = waiterId,
        .endpointUrl = std::move(endpointUrl),
        .callback = std::move(callback),
        .timeoutTimer = std::move(timer),
      });

      self.mLogger.debug({{"endpoint_url", waiterEndpoint}}, "Waiter registered for reverse connection");
    })();
}

bool ReverseConnectListener::matches_endpoint(const std::string& endpointUrl) const
{
  for (const auto& expected : mConfig.expectedServers)
  {
    if (expected.endpointUrls.empty())
    {
      // Any endpoint from this server is accepted.
      return true;
    }
    for (const auto& url : expected.endpointUrls)
    {
      if (url == endpointUrl)
      {
        return true;
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Internal: TCP accept handling (all on strand)
// ---------------------------------------------------------------------------

void ReverseConnectListener::on_tcp_accepted(ua::StatusCode status, ua::string_view errorDescription,
  std::shared_ptr<ua::TcpTransportConnection> connection)
{
  if (!mRunning)
  {
    if (connection)
    {
      // Drain via close_async so this late-arriving socket doesn't keep the
      // io_context alive past pool stop. The shared_ptr capture in the
      // callback keeps the connection alive until drained.
      const auto& conn = connection;
      conn->close_async([conn](ua::VoidResult) mutable {});
    }
    return;
  }

  if (status.is_bad())
  {
    mLogger.warning(
      {{"status", fmt::format("0x{:08x}", status.as_uint32())}, {"error", std::string{errorDescription}}},
      "TCP accept failed");
    return;
  }

  auto deps = mConnectionProtocolDeps.lock();
  if (!deps)
  {
    mLogger.warning({}, "Connection protocol dependencies no longer available");
    if (connection)
    {
      connection->close_async();
    }
    return;
  }

  // CL-RC-007: bound the handshakes in flight, in total and per remote address, BEFORE any handshake state
  // is allocated for this socket. The pending list is the count; a socket refused here is closed at once.
  const std::string remoteAddress = connection ? connection->get_remote_endpoint().address().to_string() : "";
  if (!detail::admit_pending_handshake(mPendingHandshakes,
        remoteAddress,
        mConfig.maxPendingHandshakes,
        mConfig.maxPendingHandshakesPerAddress))
  {
    mLogger.warning({{"address", remoteAddress},
                      {"pending", std::to_string(mPendingHandshakes.size())},
                      {"max_pending", std::to_string(mConfig.maxPendingHandshakes)},
                      {"max_pending_per_address", std::to_string(mConfig.maxPendingHandshakesPerAddress)}},
      "Reverse connection refused at accept: too many handshakes in flight");
    connection->close_async();
    return;
  }

  auto me = weak_from_this();

  struct HandshakeState
  {
    // WEAK, and that is the whole point: the ConnectionProtocol owns both callbacks below, and both
    // callbacks own this state, so a strong pointer here closes the ring CP -> callback -> state -> CP.
    // A ring only an invocation can open is a leak whenever the terminal callback never arrives - which
    // is exactly what happens when the executor is stopped with handlers still queued, or when the
    // listener is dropped without a stop. `connection` is only ever read to say WHICH handshake failed,
    // so it never needed to own anything.
    std::weak_ptr<ua::ConnectionProtocol> connection;
    std::optional<std::string> endpointUrl;
  };

  auto handshakeState = std::make_shared<HandshakeState>();

  auto reverseHelloValidator = [me, handshakeState](const ua::detail::ReverseHelloMessage& msg) -> bool
  {
    auto self = me.lock();
    if (!self)
      return false;
    const bool accepted = self->validate_reverse_hello(msg);
    if (accepted)
    {
      // The validator and terminal error callback are serialized by this
      // ConnectionProtocol's strand, so this per-handshake state needs no lock.
      handshakeState->endpointUrl = msg.endpointUrl;
    }
    return accepted;
  };

  // A shared holder so the error callback can identify which handshake failed. It holds the
  // ConnectionProtocol weakly (see HandshakeState), so no invocation is needed to keep the two objects
  // from pinning each other; `mPendingHandshakes` is the one strong owner of a handshake in flight.
  auto completionCallback = [me, handshakeState](ua::StatusCode completionStatus,
                              std::shared_ptr<ua::ConnectionProtocol>
                                cp,
                              ua::connection_protocol::NegotiatedLimits negotiatedLimits,
                              std::optional<ua::detail::ReverseHelloMessage>
                                reverseHello) mutable
  {
    auto self = me.lock();
    if (!self)
      return;

    ua::async::post_borrowing(self.get(),
      self->mStrand,
      self->mLogger,
      [completionStatus, cp = std::move(cp), negotiatedLimits, reverseHello = std::move(reverseHello)](
        ReverseConnectListener& inner) mutable
      {
        inner.on_handshake_complete(
          completionStatus, std::move(cp), negotiatedLimits, std::move(reverseHello));
      })();
  };

  auto errorCallback = [me, handshakeState](ua::StatusCode errorStatus,
                         ua::string_view description,
                         ua::FatalCloseDisposition) mutable
  {
    // Locked, not observed as a raw pointer: the post below crosses onto the listener's strand, and the
    // identity it carries has to still name a live object when it lands there.
    auto failedCp = handshakeState->connection.lock();
    auto endpointUrl = handshakeState->endpointUrl;
    auto self = me.lock();
    if (!self)
      return;

    auto descStr = std::string{description};
    ua::async::post_borrowing(self.get(),
      self->mStrand,
      self->mLogger,
      [errorStatus,
        descStr = std::move(descStr),
        failedCp = std::move(failedCp),
        endpointUrl = std::move(endpointUrl)](ReverseConnectListener& inner)
      { inner.on_handshake_error(errorStatus, descStr, failedCp.get(), std::move(endpointUrl)); })();
  };

  auto cp = ua::ConnectionProtocol::create(ua::ConnectionProtocolRole::Client,
    mConnectionProtocolDeps,
    std::move(connection),
    /*reverseConnect=*/true,
    mConfig.initialMessageTimeout,
    std::move(completionCallback),
    std::move(errorCallback),
    /*endpointUrl=*/{},
    /*endpointUrlValidator=*/{},
    /*messageReadTimeout=*/std::chrono::milliseconds{10'000},
    /*serverUri=*/{},
    std::move(reverseHelloValidator));

  handshakeState->connection = cp;
  mPendingHandshakes.push_back(detail::PendingHandshake{std::move(cp), remoteAddress});
}

void ReverseConnectListener::on_handshake_complete(ua::StatusCode status,
  std::shared_ptr<ua::ConnectionProtocol> connection,
  ua::connection_protocol::NegotiatedLimits negotiatedLimits,
  std::optional<ua::detail::ReverseHelloMessage> reverseHello)
{
  // Remove from pending handshakes, keeping the address the server connected from.
  std::string remoteAddress;
  auto it = std::find_if(mPendingHandshakes.begin(),
    mPendingHandshakes.end(),
    [&connection](const detail::PendingHandshake& handshake) { return handshake.connection == connection; });
  if (it != mPendingHandshakes.end())
  {
    remoteAddress = std::move(it->remoteAddress);
    mPendingHandshakes.erase(it);
  }

  if (status.is_bad())
  {
    mLogger.warning({{"status", fmt::format("0x{:08x}", status.as_uint32())}}, "Connection handshake failed");
    return;
  }

  if (!reverseHello)
  {
    mLogger.warning({}, "Handshake completed without ReverseHello - unexpected for reverse connect");
    if (connection)
    {
      connection->close_async();
    }
    return;
  }

  mLogger.debug({{"server_uri", reverseHello->serverUri}, {"endpoint_url", reverseHello->endpointUrl}},
    "Reverse connection handshake complete");

  enqueue_or_dispatch(QueuedConnection{
    .connection = std::move(connection),
    .negotiatedLimits = negotiatedLimits,
    .reverseHello = std::move(*reverseHello),
    .idleTimer = {},
    .remoteAddress = std::move(remoteAddress),
  });
}

void ReverseConnectListener::on_handshake_error(ua::StatusCode status, ua::string_view description,
  ua::ConnectionProtocol* failedHandshake, std::optional<std::string> endpointUrl)
{
  // Remove from pending handshakes.
  auto iter = std::find_if(mPendingHandshakes.begin(),
    mPendingHandshakes.end(),
    [failedHandshake](const detail::PendingHandshake& handshake)
    { return handshake.connection.get() == failedHandshake; });
  const bool wasPending = iter != mPendingHandshakes.end();
  if (wasPending)
  {
    mPendingHandshakes.erase(iter);
  }

  // BadShutdown is the synthesised terminal callback driven by close_async
  // during teardown (or after a queued connection is dispatched/evicted) -
  // not a real handshake failure. Log at debug to avoid noisy "error during
  // handshake" lines on the normal stop path.
  const bool isShutdownTerminal = (status == StatusCode{ua::Status::BadShutdown});
  if (isShutdownTerminal || !wasPending)
  {
    mLogger.debug(
      {{"status", fmt::format("0x{:08x}", status.as_uint32())}, {"error", std::string{description}}},
      "Connection protocol terminal callback (post-handshake or shutdown)");
  }
  else
  {
    mLogger.warning(
      {{"status", fmt::format("0x{:08x}", status.as_uint32())}, {"error", std::string{description}}},
      "Connection protocol error during handshake");
    report_handshake_error_to_waiters(status, description, endpointUrl);
  }
}

void ReverseConnectListener::report_handshake_error_to_waiters(
  ua::StatusCode status, ua::string_view description, const std::optional<std::string>& endpointUrl)
{
  for (auto iter = mWaiters.begin(); iter != mWaiters.end();)
  {
    if (endpointUrl && iter->endpointUrl != *endpointUrl)
    {
      ++iter;
      continue;
    }

    auto callback = std::move(iter->callback);
    auto waiterEndpoint = std::move(iter->endpointUrl);
    iter->timeoutTimer.cancel();
    iter = mWaiters.erase(iter);

    if (callback)
    {
      callback(QueuedConnectionResult{status,
        ua::ErrorDetail::build(
          "ReverseConnectHandshakeError", "Reverse connect handshake failed", "ReverseConnectListener")
          .context(ua::ContextKeys::endpointUrl, waiterEndpoint)
          .context(ua::ContextKeys::errorMessage, std::string{description})});
    }
  }
}

bool ReverseConnectListener::validate_reverse_hello(const ua::detail::ReverseHelloMessage& msg)
{
  for (const auto& expected : mConfig.expectedServers)
  {
    if (expected.serverUri != msg.serverUri)
      continue;

    // Server URI matches. Check endpoint URL.
    if (expected.endpointUrls.empty())
    {
      // Accept any endpoint from this server.
      mLogger.debug({{"server_uri", msg.serverUri}, {"endpoint_url", msg.endpointUrl}},
        "ReverseHello accepted (any endpoint allowed)");
      return true;
    }

    for (const auto& url : expected.endpointUrls)
    {
      if (url == msg.endpointUrl)
      {
        mLogger.debug(
          {{"server_uri", msg.serverUri}, {"endpoint_url", msg.endpointUrl}}, "ReverseHello accepted");
        return true;
      }
    }
  }

  mLogger.warning({{"server_uri", msg.serverUri}, {"endpoint_url", msg.endpointUrl}},
    "ReverseHello rejected: no matching expected server");
  return false;
}

void ReverseConnectListener::drop_closed_queued_connections()
{
  // A queued connection has no read armed, so its server's close is noticed only by asking the transport.
  // Dead entries would otherwise hold queue slots (and be handed to consumers) until their idle timers,
  // locking out the server's live reconnections now that a full queue refuses the newcomer (panel L round
  // 4). Cost: one non-blocking peek per queued connection, at most maxQueuedConnections, per enqueue and
  // per consume.
  for (auto it = mQueuedConnections.begin(); it != mQueuedConnections.end();)
  {
    // After its Acknowledge a server sends nothing until the client's OpenSecureChannel (Part 6 7.1.3), so
    // bytes waiting on a queued connection can only be an ERR the server wrote before closing it (its
    // first-OPN timeout does exactly that) or garbage: either way the connection is unusable, and the
    // close behind those bytes cannot be seen until they are read (panel L round 5).
    if (it->connection && it->connection->peer_state() != TransportConnection::PeerState::Open)
    {
      mLogger.debug(
        {{"endpoint_url", it->reverseHello.endpointUrl}}, "Queued connection closed by its server");
      it->idleTimer.cancel();
      it->connection->close_async();
      it = mQueuedConnections.erase(it);
    }
    else
    {
      ++it;
    }
  }
}

void ReverseConnectListener::enqueue_or_dispatch(QueuedConnection connection)
{
  // Check for a waiting consumer.
  for (auto it = mWaiters.begin(); it != mWaiters.end(); ++it)
  {
    if (it->endpointUrl == connection.reverseHello.endpointUrl)
    {
      auto waiter = std::move(*it);
      mWaiters.erase(it);
      dispatch_to_waiter(waiter, std::move(connection));
      return;
    }
  }

  drop_closed_queued_connections();

  // Enforce the queue bounds by refusing the NEW connection: evicting the oldest let any peer whose
  // ReverseHello passes the validator (public strings) displace a legitimate server's queued connection.
  // The queue is also bounded per address with the per-address handshake bound, so one address cannot
  // fill it (group L, review B1-10). A refused server reconnects (Part 6 7.1.3). Cost: one pass over at
  // most maxQueuedConnections entries per enqueue.
  const auto fromSameAddress = static_cast<std::size_t>(std::count_if(mQueuedConnections.begin(),
    mQueuedConnections.end(),
    [&connection](const QueuedConnection& queued)
    { return queued.remoteAddress == connection.remoteAddress; }));
  if (mQueuedConnections.size() >= mConfig.maxQueuedConnections ||
      fromSameAddress >= mConfig.maxPendingHandshakesPerAddress)
  {
    mLogger.warning({{"address", connection.remoteAddress},
                      {"endpoint_url", connection.reverseHello.endpointUrl},
                      {"queued", std::to_string(mQueuedConnections.size())},
                      {"queued_from_address", std::to_string(fromSameAddress)}},
      "Reverse connection refused: the queue of unclaimed connections is at its bound");
    if (connection.connection)
    {
      connection.connection->close_async();
    }
    return;
  }

  // Set up an idle timer (60s default). It removes this connection, found by identity: several queued
  // connections can share an EndpointUrl.
  static constexpr auto idleTimeout = std::chrono::seconds{60};

  auto me = weak_from_this();
  auto endpointUrl = connection.reverseHello.endpointUrl;
  const ua::ConnectionProtocol* const queuedConnection = connection.connection.get();

  connection.idleTimer = Timer::schedule_after(mStrand,
    idleTimeout,
    [me, endpointUrl, queuedConnection](boost::system::error_code errorCode)
    {
      if (errorCode)
        return;

      auto self = me.lock();
      if (!self)
        return;

      for (auto it = self->mQueuedConnections.begin(); it != self->mQueuedConnections.end(); ++it)
      {
        if (it->connection.get() == queuedConnection && it->reverseHello.endpointUrl == endpointUrl)
        {
          auto url = endpointUrl;  // copy before erase destroys timer captures
          if (it->connection)
          {
            it->connection->close_async();
          }
          self->mQueuedConnections.erase(it);
          self->mLogger.debug({{"endpoint_url", url}}, "Idle queued connection removed");
          return;
        }
      }
    });

  mLogger.debug(
    {{"endpoint_url", endpointUrl}, {"queue_size", mQueuedConnections.size() + 1}}, "Connection queued");

  mQueuedConnections.push_back(std::move(connection));
}

void ReverseConnectListener::dispatch_to_waiter(ConnectionWaiter& waiter, QueuedConnection connection)
{
  waiter.timeoutTimer.cancel();

  mLogger.debug({{"endpoint_url", waiter.endpointUrl}}, "Dispatching connection to waiter");

  auto cb = std::move(waiter.callback);
  if (cb)
  {
    cb(QueuedConnectionResult{std::move(connection)});
  }
}

}  // namespace ua::client
