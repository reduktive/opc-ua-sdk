// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// ReverseConnectListener - strand-serialized component that manages outbound reverse
// connections to a single Client endpoint.
//
// Lifecycle: create() -> start() -> [connects/reconnects/periodic] -> stop_async()
//
// Connects to the Client's reverse-connect listener, performs the HEL/ACK
// handshake (with ReverseHello), and delivers the ready ConnectionProtocol
// to the ServerImpl via the dependencies callback.

#include "ua_server_reverse_connect_listener.h"

#include "ua_connection_protocol.h"
#include "ua_error_detail.h"
#include "ua_log_exception.h"
#include "ua_on_strand.h"
#include "ua_resolver.h"
#include "ua_tcp_transport_connection.h"
#include "ua_tcp_transport_connector.h"
#include "ua_to_result.h"
#include "ua_url_parser.h"

#include "fmt/format.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <utility>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>

namespace ua::server
{

// ---------------------------------------------------------------------------
// Construction helpers
// ---------------------------------------------------------------------------
//
// These take the LIVE dependencies, not the weak_ptr. create() locks once and fails closed, so a
// null pointer cannot reach here and there is nothing to re-check.
//
// They previously took the weak_ptr and guarded the dereference with assert(), which compiles out
// under NDEBUG - so every shipped build dereferenced unguarded, and the only configuration that
// failed safely was the one nobody ships.

boost::asio::strand<boost::asio::any_io_executor> ReverseConnectListener::init_strand(
  const std::shared_ptr<ReverseConnectListenerDependencies>& live)
{
  return boost::asio::make_strand(live->executor());
}

Logger ReverseConnectListener::init_logger(const std::shared_ptr<ReverseConnectListenerDependencies>& live)
{
  return live->logger();
}

// ---------------------------------------------------------------------------
// Construction / factory
// ---------------------------------------------------------------------------

ReverseConnectListener::ReverseConnectListener(std::weak_ptr<ReverseConnectListenerDependencies> dependencies,
  const std::shared_ptr<ReverseConnectListenerDependencies>& live, ServerConfig::ReverseConnectTarget target)
  : mDependencies(std::move(dependencies)), mTarget(std::move(target)), mStrand(init_strand(live)),
    mLogger(init_logger(live))
{}

ReverseConnectListener::~ReverseConnectListener() = default;

std::shared_ptr<ReverseConnectListener> ReverseConnectListener::create(
  std::weak_ptr<ReverseConnectListenerDependencies> dependencies, ServerConfig::ReverseConnectTarget target)
{
  auto live = dependencies.lock();
  if (!live)
  {
    // Fail closed: the strand and logger are built from the dependencies, so there is no listener
    // to construct without them.
    return nullptr;
  }

  auto manager = std::shared_ptr<ReverseConnectListener>(
    new ReverseConnectListener(std::move(dependencies), live, std::move(target)));
  manager->initialise();
  return manager;
}

void ReverseConnectListener::initialise()
{
  mLogger = mLogger.with_category("reverse_connect");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void ReverseConnectListener::start()
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [](ReverseConnectListener& self)
    {
      self.mRunning = true;

      const bool missingClientApplicationUri = self.mTarget.clientApplicationUri.empty();
      const bool missingServerEndpointUrl = self.mTarget.serverEndpointUrl.empty();
      if (missingClientApplicationUri || missingServerEndpointUrl)
      {
        auto dependencies = self.mDependencies.lock();
        if (dependencies)
        {
          std::shared_ptr<const ErrorDetail> detail =
            ErrorDetail::build("ReverseConnectTargetIncomplete",
              "Reverse-connect target is missing administrator-supplied identity or endpoint data",
              "ReverseConnectListener")
              .context(ua::ContextKeys::listenerName, self.mTarget.name)
              .context(ua::ContextKeys::fieldName,
                missingClientApplicationUri ? "clientApplicationUri" : "serverEndpointUrl");
          dependencies->on_reverse_connect_error(
            VoidResult{StatusCode{Status::BadInvalidArgument, std::move(detail)}});
        }
        return;
      }

      self.mLogger.info({{"target", self.mTarget.name}, {"client_url", self.mTarget.clientEndpointUrl}},
        "Starting reverse connect manager");

      self.connect_one();
      self.schedule_periodic_connect();
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
      self.mLogger.info({{"target", self.mTarget.name}}, "Stopping reverse connect manager");

      // Cancel timers synchronously - they hold no async work.
      self.mReconnectTimer.cancel();
      self.mPeriodicTimer.cancel();

      // Move resources out so any late strand work sees empty containers.
      auto handshakes = std::exchange(self.mPendingHandshakes, {});
      auto connectors = std::exchange(self.mPendingConnectors, {});

      const std::size_t closeCount = handshakes.size() + connectors.size();
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

      for (const auto& handshake : handshakes)
      {
        auto h = handshake;  // copy strong ref into callback capture
        h->close_async([h, onOneDone](ua::VoidResult r) mutable { onOneDone(std::move(r)); });
      }
      // Pending connectors hold a real socket while async_connect is in flight
      // and a self-cycle via connectorHolder that only breaks when the connect
      // handler runs. Cancel each via close_async so the cycle resolves and the
      // socket drains before stop_async signals completion.
      for (const auto& connector : connectors)
      {
        auto c = connector;  // copy strong ref into callback capture
        c->close_async([c, onOneDone](ua::VoidResult r) mutable { onOneDone(std::move(r)); });
      }
    })();
}

// ---------------------------------------------------------------------------
// Internal: connection lifecycle (all on strand)
// ---------------------------------------------------------------------------

bool ReverseConnectListener::is_at_pending_limit() const
{
  if (mTarget.maxPendingSockets == 0)
    return false;  // no limit

  auto pending = mPendingConnectors.size() + mPendingHandshakes.size();
  return pending >= mTarget.maxPendingSockets;
}

void ReverseConnectListener::connect_one()
{
  if (!mRunning)
    return;

  if (is_at_pending_limit())
  {
    mLogger.debug({{"target", mTarget.name},
                    {"pending_connectors", mPendingConnectors.size()},
                    {"pending_handshakes", mPendingHandshakes.size()},
                    {"limit", mTarget.maxPendingSockets}},
      "Pending socket limit reached, deferring connect");
    return;
  }

  // Parse the client endpoint URL.
  auto parsed = ua::transport::parse_opc_tcp_url(mTarget.clientEndpointUrl, "ReverseConnectListener");
  if (!parsed)
  {
    mLogger.error(
      {{"target", mTarget.name}, {"url", mTarget.clientEndpointUrl}}, "Failed to parse client endpoint URL");
    auto deps = mDependencies.lock();
    if (deps)
    {
      deps->on_reverse_connect_error(VoidResult{parsed.status_code(), parsed.shared_detail()});
    }
    return;
  }

  auto hostname = std::move(parsed.value().hostname);
  auto port = parsed.value().port;

  // Resolve hostname -> TCP endpoint(s).
  auto deps = mDependencies.lock();
  if (!deps)
    return;

  auto me = weak_from_this();

  // Try parsing as an IP address first to avoid async DNS resolution.
  boost::system::error_code addressEc;
  auto address = boost::asio::ip::make_address(hostname, addressEc);
  if (addressEc)
  {
    // Hostname is not a literal IP - use DNS resolution.
    auto resolver = ua::Resolver::create(deps->executor(), deps->connection_protocol_timeout());
    auto hostnamePtr = std::make_shared<std::string>(std::move(hostname));
    resolver->resolve_endpoints_async(*hostnamePtr,
      port,
      std::nullopt,
      [me, resolver, hostnamePtr](ua::EndpointListResult resolveResult) mutable
      {
        auto self = me.lock();
        if (!self)
          return;
        ua::async::post_borrowing(self.get(),
          self->mStrand,
          self->mLogger,
          [resolveResult = std::move(resolveResult)](ReverseConnectListener& self2) mutable
          {
            if (!self2.mRunning)
              return;
            if (!resolveResult || resolveResult.value().empty())
            {
              self2.mLogger.warning(
                {{"target", self2.mTarget.name}}, "DNS resolution failed for client endpoint");
              self2.schedule_reconnect();
              return;
            }
            self2.tcp_connect(resolveResult.value().front());
          })();
      });
    return;
  }

  // Direct IP address - skip DNS, connect immediately.
  tcp_connect(boost::asio::ip::tcp::endpoint{address, port});
}

void ReverseConnectListener::tcp_connect(boost::asio::ip::tcp::endpoint endpoint)
{
  auto deps = mDependencies.lock();
  if (!deps)
    return;

  mLogger.debug({{"target", mTarget.name},
                  {"endpoint", endpoint.address().to_string()},
                  {"port", uint64_t(endpoint.port())}},
    "TCP connecting");

  auto me = weak_from_this();
  // Weak, NOT strong: the connector stores this callback, and the callback
  // captures connectorHolder, so a strong connectorHolder -> connector edge
  // would form a self-cycle (connector -> callback -> connectorHolder ->
  // connector) that only breaks if the connect handler runs. A connector still
  // pending when the listener is destroyed (no clean stop_async drain) would
  // then leak. Holding the connector weakly here keeps mPendingConnectors the
  // sole owner, so dropping it frees the connector regardless of teardown path.
  auto connectorHolder = std::make_shared<std::weak_ptr<ua::TcpTransportConnector>>();
  auto connector = ua::TcpTransportConnector::create(
    deps->executor(),
    endpoint,
    [me, connectorHolder](ua::StatusCode status,
      ua::string_view errorDescription,
      std::shared_ptr<ua::TcpTransportConnection>
        connection)
    {
      auto self = me.lock();
      if (!self)
        return;

      // Access connectorHolder only on the strand: the write at the bottom of
      // tcp_connect (*connectorHolder = connector) also runs on the strand, so
      // dispatching here serialises the two and avoids a data race on the
      // inner shared_ptr.
      ua::async::post_borrowing(self.get(),
        self->mStrand,
        self->mLogger,
        [status, errorDesc = std::string{errorDescription}, conn = std::move(connection), connectorHolder](
          ReverseConnectListener& self2) mutable
        {
          // Keep the connector alive across on_tcp_connected (which matches it
          // by raw pointer). It is normally still owned by mPendingConnectors
          // here; lock() yields null only if it was already torn down, in which
          // case there is nothing to complete.
          auto connectorStrong = connectorHolder->lock();
          if (!connectorStrong)
            return;
          self2.on_tcp_connected(status, errorDesc, std::move(conn), connectorStrong.get());
        })();
    },
    mLogger,
    deps->write_queue_depth_cap(),
    deps->write_queue_bytes_cap());

  *connectorHolder = connector;
  mPendingConnectors.push_back(std::move(connector));
}

void ReverseConnectListener::on_tcp_connected(ua::StatusCode status, ua::string_view errorDescription,
  std::shared_ptr<ua::TcpTransportConnection> connection, ua::TcpTransportConnector* completedConnector)
{
  // Remove the specific connector that completed.
  auto connIt = std::find_if(mPendingConnectors.begin(),
    mPendingConnectors.end(),
    [completedConnector](const auto& c) { return c.get() == completedConnector; });
  if (connIt != mPendingConnectors.end())
  {
    mPendingConnectors.erase(connIt);
  }

  if (!mRunning)
    return;

  if (!status.is_good())
  {
    mLogger.warning(
      {{"target", mTarget.name}, {"status", ua::to_string(status)}, {"error", std::string{errorDescription}}},
      "TCP connect to client failed");

    auto deps = mDependencies.lock();
    if (deps)
    {
      deps->on_reverse_connect_error(VoidResult{status,
        ErrorDetail::build(
          "TcpConnectFailed", "TCP connect to client endpoint failed", "ReverseConnectListener")
          .context(ua::ContextKeys::endpointUrl, mTarget.clientEndpointUrl)
          .context(ua::ContextKeys::listenerName, mTarget.name)
          .detail(std::string{errorDescription})});
    }

    schedule_reconnect();
    return;
  }

  auto deps = mDependencies.lock();
  if (!deps)
    return;

  // The outbound socket is up. This is the reverse-connect analogue of accepting an inbound
  // connection, and it precedes the ReverseHello handshake - a target that reports opened but never
  // reports a channel established is one whose handshake or allow-list check is failing.
  if (connection)
  {
    const auto endpoint = connection->get_remote_endpoint();
    const auto host = endpoint.address().to_string();
    deps->on_reverse_connect_opened(endpoint.address().is_v6() ? fmt::format("[{}]:{}", host, endpoint.port())
                                                               : fmt::format("{}:{}", host, endpoint.port()));
  }

  // The ConnectionProtocol constructor locks connection_protocol_dependencies()
  // and throws BadInvalidArgument if it has expired. That weak_ptr can
  // legitimately expire during server teardown while this connect-completion
  // handler is in flight - a normal shutdown race, not a programming error.
  // Detect it here and drop the connection gracefully, rather than letting the
  // constructor throw: this function runs as a strand-posted asio handler, so an
  // escaping exception would unwind out of io_context::run() and terminate the
  // process. (The forward-connect path is guarded equivalently by the try/catch
  // in ServerImpl's acceptor callback.) Note this only manifests when the TCP
  // connect actually succeeds - i.e. when something is listening on the target
  // endpoint (a real reverse-connect client, or port contention) - which is why
  // it surfaces under real network conditions but not when the target is down.
  if (!deps->connection_protocol_dependencies().lock())
  {
    mLogger.debug({{"target", mTarget.name}},
      "Reverse connection established but server is shutting down; dropping connection");
    if (connection)
    {
      connection->close_async();
    }
    return;
  }

  // Start the HEL/ACK handshake with ReverseHello.
  auto me = weak_from_this();

  // Holder lets the error callback identify which handshake failed without taking
  // ownership of the CP. The inner pointer is a weak_ptr, so the callback closures
  // do not extend the CP's lifetime - mPendingHandshakes is the sole strong owner.
  // This means destruction of the manager (which drops mPendingHandshakes) is
  // sufficient to tear down the CP, even on paths where neither callback fires
  // (e.g. stop_reverse_connect_sync, where the manager is destroyed via member
  // destruction before its strand-posted stop_async lambda runs).
  auto cpHolder = std::make_shared<std::weak_ptr<ua::ConnectionProtocol>>();
  auto handedOff = std::make_shared<std::atomic_bool>(false);

  auto connectionComplete = [me, cpHolder, handedOff](ua::StatusCode handshakeStatus,
                              std::shared_ptr<ua::ConnectionProtocol>
                                connectionProtocol,
                              ua::connection_protocol::NegotiatedLimits negotiatedLimits,
                              std::optional<ua::detail::ReverseHelloMessage>
                                reverseHello) mutable
  {
    if (handshakeStatus.is_good())
      handedOff->store(true, std::memory_order_release);
    // This callback fires on the CP's OWN strand (a different thread). cpHolder is touched here AND on
    // the RCL strand (`*cpHolder = ...` in on_tcp_connected), so defer all cpHolder access to the
    // RCL strand to serialise it (the inner weak_ptr is not atomic).
    auto self = me.lock();
    if (!self)
      return;

    ua::async::post_borrowing(self.get(),
      self->mStrand,
      self->mLogger,
      [cpHolder,
        handshakeStatus,
        connectionProtocol = std::move(connectionProtocol),
        negotiatedLimits,
        reverseHello = std::move(reverseHello)](ReverseConnectListener& self2) mutable
      {
        cpHolder->reset();  // on the RCL strand
        self2.on_handshake_complete(
          handshakeStatus, std::move(connectionProtocol), negotiatedLimits, std::move(reverseHello));
      })();
  };

  auto closeObserver = [me, handedOff](ua::StatusCode, ua::string_view)
  {
    if (!handedOff->load(std::memory_order_acquire))
      return;
    auto self = me.lock();
    if (!self)
      return;
    ua::async::post_borrowing(self.get(),
      self->mStrand,
      self->mLogger,
      [](ReverseConnectListener& listener) { listener.schedule_reconnect(); })();
  };

  auto errorCallback =
    [me, cpHolder](ua::StatusCode errorStatus, ua::string_view description, ua::FatalCloseDisposition) mutable
  {
    // This callback fires on the CP's OWN strand (a different thread). Defer ALL cpHolder access to the
    // RCL strand to serialise it with the `*cpHolder = ...` write in on_tcp_connected (the inner
    // weak_ptr is not atomic): extract the failed-CP pointer for identification and clear the holder
    // inside the strand continuation, not here.
    auto self = me.lock();
    if (!self)
      return;

    auto descStr = std::string{description};
    ua::async::post_borrowing(self.get(),
      self->mStrand,
      self->mLogger,
      [cpHolder, errorStatus, descStr = std::move(descStr)](ReverseConnectListener& self2)
      {
        // Promote the weak_ptr only long enough to extract the raw pointer for handshake
        // identification in on_connection_protocol_error (which compares by pointer).
        auto failedCpStrong = cpHolder->lock();
        auto* failedCp = failedCpStrong.get();
        cpHolder->reset();
        self2.on_connection_protocol_error(errorStatus, descStr, failedCp);
      })();
  };

  // Defence-in-depth: no exception may escape this strand-posted asio handler
  // (it would unwind out of io_context::run() and terminate the process). The
  // expired-dependency race is handled gracefully above; this catch is a
  // backstop for any other construction failure.
  std::shared_ptr<ua::ConnectionProtocol> connectionProtocol;
  try
  {
    connectionProtocol = ua::ConnectionProtocol::create(ua::ConnectionProtocolRole::Server,
      deps->connection_protocol_dependencies(),
      std::move(connection),
      /*reverseConnect=*/true,
      deps->connection_protocol_timeout(),
      std::move(connectionComplete),
      std::move(errorCallback),
      mTarget.serverEndpointUrl,
      /*endpointUrlValidator=*/{},
      deps->connection_protocol_message_read_timeout(),
      deps->server_uri(),
      /*reverseHelloValidator=*/{},
      std::move(closeObserver));
  }
  catch (...)
  {
    log_exception(mLogger, "ReverseConnectListener::on_tcp_connected", std::current_exception());
    schedule_reconnect();
    return;
  }

  *cpHolder = connectionProtocol;  // weak_ptr<CP> = shared_ptr<CP>; no ownership transfer
  mPendingHandshakes.push_back(std::move(connectionProtocol));
}

void ReverseConnectListener::on_handshake_complete(ua::StatusCode status,
  std::shared_ptr<ua::ConnectionProtocol> connectionProtocol,
  ua::connection_protocol::NegotiatedLimits negotiatedLimits,
  std::optional<ua::detail::ReverseHelloMessage> /*reverseHello*/)
{
  // Remove from pending handshakes.
  auto iter = std::find(mPendingHandshakes.begin(), mPendingHandshakes.end(), connectionProtocol);
  if (iter != mPendingHandshakes.end())
  {
    mPendingHandshakes.erase(iter);
  }

  if (!mRunning)
    return;

  if (!status.is_good())
  {
    mLogger.warning(
      {{"target", mTarget.name}, {"status", ua::to_string(status)}}, "Reverse connect handshake failed");
    schedule_reconnect();
    return;
  }

  // Reset backoff on successful handshake.
  mCurrentBackoff = sMinBackoff;

  mLogger.info({{"target", mTarget.name}}, "Reverse connect handshake completed successfully");

  // Deliver the ready connection to the server.
  auto deps = mDependencies.lock();
  if (deps)
  {
    deps->on_reverse_connection_ready(std::move(connectionProtocol), negotiatedLimits);
  }

  // Create a spare connection (spec S4).
  connect_one();
}

void ReverseConnectListener::on_connection_protocol_error(
  ua::StatusCode status, ua::string_view description, ua::ConnectionProtocol* failedHandshake)
{
  // Remove from pending handshakes.
  auto iter = std::find_if(mPendingHandshakes.begin(),
    mPendingHandshakes.end(),
    [failedHandshake](const auto& cp) { return cp.get() == failedHandshake; });
  if (iter != mPendingHandshakes.end())
  {
    mPendingHandshakes.erase(iter);
  }

  if (!mRunning)
    return;

  mLogger.warning(
    {{"target", mTarget.name}, {"status", ua::to_string(status)}, {"description", std::string{description}}},
    "Connection protocol error on reverse connection");

  auto deps = mDependencies.lock();
  if (deps)
  {
    const bool transportClosed = status.as_status() == Status::BadTcpInternalError;
    std::shared_ptr<const ErrorDetail> detail =
      transportClosed
        ? ErrorDetail::build("ReverseHandshakeTransportClosed",
            "Reverse connection transport closed during handshake",
            "ReverseConnectListener")
            .context(ua::ContextKeys::endpointUrl, mTarget.clientEndpointUrl)
            .context(ua::ContextKeys::listenerName, mTarget.name)
            .detail(std::string{description})
            .cause(status)
        : ErrorDetail::build(
            "ReverseHandshakeRejected", "Reverse connection handshake was rejected", "ReverseConnectListener")
            .context(ua::ContextKeys::endpointUrl, mTarget.clientEndpointUrl)
            .context(ua::ContextKeys::listenerName, mTarget.name)
            .detail(std::string{description})
            .cause(status);
    deps->on_reverse_connect_error(VoidResult{StatusCode{status.as_status(), std::move(detail)}});
  }

  schedule_reconnect();
}

// ---------------------------------------------------------------------------
// Internal: timers (all on strand)
// ---------------------------------------------------------------------------

void ReverseConnectListener::schedule_reconnect()
{
  if (!mRunning)
    return;

  auto deps = mDependencies.lock();
  if (!deps)
    return;

  mLogger.debug({{"target", mTarget.name}, {"backoff_seconds", mCurrentBackoff.count()}},
    "Scheduling reconnect with backoff");

  auto me = weak_from_this();
  mReconnectTimer = ua::Timer::schedule_after(mStrand,
    mCurrentBackoff,
    [me](boost::system::error_code errorCode)
    {
      if (errorCode)
        return;

      auto self = me.lock();
      if (!self || !self->mRunning)
        return;

      self->connect_one();
    });

  // Exponential backoff: double, capped at kMaxBackoff.
  mCurrentBackoff = std::min(mCurrentBackoff * 2, sMaxBackoff);
}

void ReverseConnectListener::schedule_periodic_connect()
{
  if (!mRunning)
    return;

  if (mTarget.periodicConnectInterval.count() <= 0)
    return;

  auto deps = mDependencies.lock();
  if (!deps)
    return;

  auto me = weak_from_this();
  mPeriodicTimer = ua::Timer::schedule_after(mStrand,
    mTarget.periodicConnectInterval,
    [me](boost::system::error_code errorCode)
    {
      if (errorCode)
        return;

      auto self = me.lock();
      if (!self || !self->mRunning)
        return;

      self->connect_one();
      self->schedule_periodic_connect();
    });
}

}  // namespace ua::server
