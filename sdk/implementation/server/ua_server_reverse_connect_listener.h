// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_REVERSE_CONNECT_LISTENER_H
#define UA_SERVER_REVERSE_CONNECT_LISTENER_H

#include "ua_connection_protocol.h"
#include "ua_connection_protocol_limits.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_result.h"
#include "ua_reverse_hello.h"
#include "ua_server_configuration.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>
#include "ua_timer.h"

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ua
{
class TcpTransportConnection;
class TcpTransportConnector;
}  // namespace ua

namespace ua::test_helpers
{
class ReverseConnectListenerTestAccess;
}

namespace ua::server
{

/// Dependencies injected into ReverseConnectListener.
class ReverseConnectListenerDependencies
{
public:
  ReverseConnectListenerDependencies() = default;
  ReverseConnectListenerDependencies(const ReverseConnectListenerDependencies&) = delete;
  ReverseConnectListenerDependencies& operator=(const ReverseConnectListenerDependencies&) = delete;
  ReverseConnectListenerDependencies(ReverseConnectListenerDependencies&&) = delete;
  ReverseConnectListenerDependencies& operator=(ReverseConnectListenerDependencies&&) = delete;
  virtual ~ReverseConnectListenerDependencies() = default;
  virtual boost::asio::any_io_executor executor() = 0;
  virtual ua::Logger logger() = 0;
  virtual std::string server_uri() = 0;
  virtual std::weak_ptr<ua::ConnectionProtocolDependencies> connection_protocol_dependencies() = 0;
  virtual ua::connection_protocol::Limits connection_protocol_limits() = 0;
  virtual std::chrono::seconds connection_protocol_timeout() = 0;
  virtual std::chrono::milliseconds connection_protocol_message_read_timeout() = 0;
  /// Pending-write queue cap applied to the outbound reverse connection (memory backstop if the
  /// remote stops draining the socket). See ServerConfig::ResourceLimits.
  virtual size_t write_queue_depth_cap() = 0;
  /// Pending-write byte budget applied to the outbound reverse connection (same reference).
  virtual size_t write_queue_bytes_cap() = 0;
  virtual void on_reverse_connection_ready(std::shared_ptr<ua::ConnectionProtocol> connection,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits) = 0;
  virtual void on_reverse_connect_error(ua::VoidResult error) = 0;

  /// The outbound socket to the client's listener is up (before the ReverseHello handshake).
  /// Raises `ServerObserver::on_reverse_connect_opened`; the target name is supplied by the
  /// implementer, which owns it.
  /// @param remoteAddress Address of the client this target connected to.
  virtual void on_reverse_connect_opened(const std::string& remoteAddress) = 0;

  /// A reverse connection has closed, for any reason.
  /// Raises `ServerObserver::on_reverse_connect_closed`.
  /// @param remoteAddress Address of the client the connection was to.
  /// @param reason        Status describing why it closed.
  virtual void on_reverse_connect_closed(const std::string& remoteAddress, ua::StatusCode reason) = 0;
};

/// Manages outbound reverse connections to a single Client endpoint.
/// One instance per ReverseConnectTarget.
class ReverseConnectListener : public std::enable_shared_from_this<ReverseConnectListener>
{
public:
  ReverseConnectListener() = delete;
  ReverseConnectListener(const ReverseConnectListener&) = delete;
  ReverseConnectListener(ReverseConnectListener&&) noexcept = delete;
  ReverseConnectListener& operator=(const ReverseConnectListener&) = delete;
  ReverseConnectListener& operator=(ReverseConnectListener&&) noexcept = delete;
  ~ReverseConnectListener();

  /// Creates a listener, or returns null if the dependencies have already expired.
  ///
  /// Construction needs the dependencies alive: the strand and logger are built from them. The
  /// weak_ptr is locked ONCE here and the live pointer handed to the constructor, so no later
  /// step has to re-check it. A null return is the only failure mode.
  ///
  /// @param dependencies Dependency adapter; retained weakly for the async callback path.
  /// @param target Reverse-connect target configuration.
  /// @return The listener, or null when @p dependencies has expired.
  [[nodiscard]] static std::shared_ptr<ReverseConnectListener> create(
    std::weak_ptr<ReverseConnectListenerDependencies> dependencies,
    ServerConfig::ReverseConnectTarget target);

  /// Start connecting. Must be called after create().
  void start();

  /// Stop all connections and timers. Callback fires when fully stopped.
  void stop_async(std::function<void(ua::VoidResult)> callback);

private:
  friend class ::ua::test_helpers::ReverseConnectListenerTestAccess;

  /// @param dependencies Retained weakly for the async path.
  /// @param live The same dependencies, locked by create() and guaranteed non-null. Used only to
  ///        build the strand and logger; not retained.
  /// @param target Reverse-connect target configuration.
  ReverseConnectListener(std::weak_ptr<ReverseConnectListenerDependencies> dependencies,
    const std::shared_ptr<ReverseConnectListenerDependencies>& live,
    ServerConfig::ReverseConnectTarget target);

  void initialise();

  // boost::asio::strand<boost::asio::any_io_executor>-serialized internal methods
  void connect_one();
  void on_tcp_connected(ua::StatusCode status, ua::string_view errorDescription,
    std::shared_ptr<ua::TcpTransportConnection> connection, ua::TcpTransportConnector* completedConnector);
  void on_handshake_complete(ua::StatusCode status,
    std::shared_ptr<ua::ConnectionProtocol> connectionProtocol,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits,
    std::optional<ua::detail::ReverseHelloMessage> reverseHello);
  void on_connection_protocol_error(
    ua::StatusCode status, ua::string_view description, ua::ConnectionProtocol* failedHandshake);
  void tcp_connect(boost::asio::ip::tcp::endpoint endpoint);
  void schedule_reconnect();
  void schedule_periodic_connect();

  bool is_at_pending_limit() const;

  static boost::asio::strand<boost::asio::any_io_executor> init_strand(
    const std::shared_ptr<ReverseConnectListenerDependencies>& live);
  static ua::Logger init_logger(const std::shared_ptr<ReverseConnectListenerDependencies>& live);

  const std::weak_ptr<ReverseConnectListenerDependencies> mDependencies;
  const ServerConfig::ReverseConnectTarget mTarget;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  ua::Logger mLogger;
  bool mRunning{false};

  // Pending connections (TCP connectors and CP handshakes in progress)
  std::vector<std::shared_ptr<ua::TcpTransportConnector>> mPendingConnectors;
  std::vector<std::shared_ptr<ua::ConnectionProtocol>> mPendingHandshakes;

  // Timers
  ua::Timer mReconnectTimer;
  ua::Timer mPeriodicTimer;

  // Backoff state for reconnection
  std::chrono::seconds mCurrentBackoff{1};
  static constexpr std::chrono::seconds sMinBackoff{1};
  static constexpr std::chrono::seconds sMaxBackoff{30};
};

}  // namespace ua::server

#endif  // UA_SERVER_REVERSE_CONNECT_LISTENER_H
