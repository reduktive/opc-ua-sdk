// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REVERSE_CONNECT_LISTENER_H
#define UA_REVERSE_CONNECT_LISTENER_H

#include "ua_connection_protocol.h"
#include "ua_result.h"
#include "ua_connection_protocol_limits.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_reverse_connect_config.h"
#include "ua_reverse_connect_admission.h"
#include "ua_reverse_hello.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/dispatch.hpp>
#include "ua_tcp_transport_connection.h"
#include "ua_timer.h"

#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ua
{
class TcpTransportAcceptor;
class TcpTransportConnection;
}  // namespace ua

namespace ua::test_helpers
{
class ReverseConnectListenerTestAccess;
}

namespace ua::client
{

/// A validated, ready reverse connection waiting to be consumed by open_channel.
struct QueuedConnection
{
  std::shared_ptr<ua::ConnectionProtocol> connection;
  ua::connection_protocol::NegotiatedLimits negotiatedLimits;
  ua::detail::ReverseHelloMessage reverseHello;
  ua::Timer idleTimer;
  /// The address the server connected from, for the per-address queue bound.
  std::string remoteAddress;
};

/// Result type for consume_connection.
using QueuedConnectionResult = ua::Result<QueuedConnection>;

using ConsumeConnectionCallback = std::function<void(QueuedConnectionResult)>;

/// Accepts incoming TCP connections from Servers performing reverse connect.
/// One instance per ReverseConnectListenerConfig.
class ReverseConnectListener : public std::enable_shared_from_this<ReverseConnectListener>
{
public:
  ReverseConnectListener() = delete;
  ReverseConnectListener(const ReverseConnectListener&) = delete;
  ReverseConnectListener(ReverseConnectListener&&) noexcept = delete;
  ReverseConnectListener& operator=(const ReverseConnectListener&) = delete;
  ReverseConnectListener& operator=(ReverseConnectListener&&) noexcept = delete;
  ~ReverseConnectListener();

  static std::shared_ptr<ReverseConnectListener> create(boost::asio::any_io_executor executor,
    std::weak_ptr<ua::ConnectionProtocolDependencies> connectionProtocolDeps,
    ReverseConnectListenerConfig config, ua::Logger logger = {}, size_t writeQueueDepthCap = 4096,
    size_t writeQueueBytesCap = ua::TcpTransportConnection::defaultWriteQueueBytesCap);

  /// Start accepting connections. Optional callback fires once the acceptor is bound
  /// (or on bind failure).
  void start(std::function<void(VoidResult)> callback = nullptr);

  /// Stop accepting and clean up all state. Callback fires when fully stopped.
  void stop_async(std::function<void(ua::VoidResult)> callback);

  /// Request a reverse connection matching the given endpointUrl.
  /// If a matching queued connection exists, callback fires immediately (from strand).
  /// Otherwise, the request is queued as a waiter with timeout.
  void consume_connection(
    std::string endpointUrl, std::chrono::seconds timeout, ConsumeConnectionCallback callback);

  /// Check if this listener has an ExpectedServer matching the given endpoint URL.
  /// Thread-safe: reads only const config data.
  bool matches_endpoint(const std::string& endpointUrl) const;

private:
  friend class ::ua::test_helpers::ReverseConnectListenerTestAccess;

  /// A waiter registered by open_channel for a reverse connection.
  struct ConnectionWaiter
  {
    uint64_t id{0};
    std::string endpointUrl;
    ConsumeConnectionCallback callback;
    ua::Timer timeoutTimer;
  };

  ReverseConnectListener(boost::asio::any_io_executor executor,
    std::weak_ptr<ua::ConnectionProtocolDependencies> connectionProtocolDeps,
    ReverseConnectListenerConfig config, ua::Logger logger);

  void initialise();

  // boost::asio::strand<boost::asio::any_io_executor>-serialized internals
  void on_tcp_accepted(ua::StatusCode status, ua::string_view errorDescription,
    std::shared_ptr<ua::TcpTransportConnection> connection);
  void on_handshake_complete(ua::StatusCode status, std::shared_ptr<ua::ConnectionProtocol> connection,
    ua::connection_protocol::NegotiatedLimits negotiatedLimits,
    std::optional<ua::detail::ReverseHelloMessage> reverseHello);
  void on_handshake_error(ua::StatusCode status, ua::string_view description,
    ua::ConnectionProtocol* failedHandshake, std::optional<std::string> endpointUrl);
  void report_handshake_error_to_waiters(
    ua::StatusCode status, ua::string_view description, const std::optional<std::string>& endpointUrl);
  // Removes the queued connections whose server has closed them (a non-blocking probe of each).
  void drop_closed_queued_connections();
  void enqueue_or_dispatch(QueuedConnection connection);
  void dispatch_to_waiter(ConnectionWaiter& waiter, QueuedConnection connection);

  // Thread-safe: reads only const-after-init mConfig and mLogger. Called from ConnectionProtocol's strand.
  bool validate_reverse_hello(const ua::detail::ReverseHelloMessage& msg);

  const boost::asio::any_io_executor mExecutor;
  const std::weak_ptr<ua::ConnectionProtocolDependencies> mConnectionProtocolDeps;
  const ReverseConnectListenerConfig mConfig;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  ua::Logger mLogger;
  bool mRunning{false};

  std::shared_ptr<ua::TcpTransportAcceptor> mAcceptor;
  size_t mWriteQueueDepthCap{4096};  // applied to each accepted reverse connection
  size_t mWriteQueueBytesCap{ua::TcpTransportConnection::defaultWriteQueueBytesCap};
  std::vector<detail::PendingHandshake> mPendingHandshakes;  // the one strong owner of a handshake in flight
  std::deque<QueuedConnection> mQueuedConnections;
  std::vector<ConnectionWaiter> mWaiters;
  uint64_t mNextWaiterId{0};
};

}  // namespace ua::client

#endif  // UA_REVERSE_CONNECT_LISTENER_H
