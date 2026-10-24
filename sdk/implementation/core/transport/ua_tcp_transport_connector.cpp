// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <tuple>

#include <boost/asio/connect.hpp>
#include <boost/lexical_cast.hpp>

#include <fmt/format.h>

#include "ua_on_strand.h"
#include "ua_tcp_transport_connector.h"
#include "ua_to_result.h"
#include "ua_log_exception.h"

namespace ua
{
StatusCode connect_failure_status(const boost::system::error_code& ec)
{
  namespace errc = boost::system::errc;
  if (ec == errc::connection_refused || ec == errc::host_unreachable || ec == errc::network_unreachable ||
      ec == errc::network_down || ec == boost::asio::error::host_not_found ||
      ec == boost::asio::error::host_not_found_try_again)
  {
    // The peer (or the path to it) refused or could not be reached: the connection was rejected
    // rather than mishandled.
    return ua::StatusCode{ua::Status::BadConnectionRejected};
  }
  if (ec == errc::timed_out || ec == boost::asio::error::timed_out)
  {
    return ua::StatusCode{ua::Status::BadTimeout};
  }
  return ua::StatusCode{ua::Status::BadTcpInternalError};
}

shared_ptr<TcpTransportConnector> TcpTransportConnector::create(boost::asio::any_io_executor executor,
  asio::ip::tcp::endpoint ipEndpoint, ConnectedCallback connectedCallback, Logger logger,
  size_t writeQueueDepthCap, size_t writeQueueBytesCap)
{
  return create(executor,
    std::vector<asio::ip::tcp::endpoint>{ipEndpoint},
    std::move(connectedCallback),
    std::move(logger),
    writeQueueDepthCap,
    writeQueueBytesCap);
}

shared_ptr<TcpTransportConnector> TcpTransportConnector::create(boost::asio::any_io_executor executor,
  std::vector<asio::ip::tcp::endpoint> ipEndpoints, ConnectedCallback connectedCallback, Logger logger,
  size_t writeQueueDepthCap, size_t writeQueueBytesCap)
{
  class Wrapper : public TcpTransportConnector
  {
  public:
    Wrapper(boost::asio::any_io_executor executor, ConnectedCallback connectedCallback, Logger logger,
      size_t writeQueueDepthCap, size_t writeQueueBytesCap)
      : TcpTransportConnector(
          executor, connectedCallback, std::move(logger), writeQueueDepthCap, writeQueueBytesCap)
    {}
  };

  auto connector = make_shared<Wrapper>(
    executor, connectedCallback, std::move(logger), writeQueueDepthCap, writeQueueBytesCap);
  connector->initialise(std::move(ipEndpoints));
  return connector;
}

TcpTransportConnector::TcpTransportConnector(boost::asio::any_io_executor executor,
  ConnectedCallback connectedCallback, Logger logger, size_t writeQueueDepthCap, size_t writeQueueBytesCap)
  : mLogger(std::move(logger)), mConnectedCallback(connectedCallback),
    mStrand(boost::asio::make_strand(executor)), mSocket(mStrand), mWriteQueueDepthCap(writeQueueDepthCap),
    mWriteQueueBytesCap(writeQueueBytesCap), mExecutor(mStrand)
{}

void TcpTransportConnector::close_async(std::function<void(VoidResult)> callback)
{
  // Posting onto the connector's executor lets callers invoke close_async safely
  // from any thread without re-entering mMutex on the calling thread. The owning
  // post keeps the connector alive across the hop so it can close its own socket.
  // mExecutor is used rather than mSocket.get_executor() because a successful
  // connect moves mSocket away, leaving it in a moved-from state.
  ua::async::post_owning(this,
    mExecutor,
    mLogger,
    [callback = std::move(callback)](TcpTransportConnector& self) mutable
    {
      {
        const Lock lk(self.mMutex);
        boost::system::error_code ec;
        // Best-effort close on the teardown path: the non-throwing overload is chosen so close
        // never throws. A close error (e.g. the socket is already gone) is not actionable here,
        // so the returned error_code is deliberately discarded.
        std::ignore = self.mSocket.close(ec);

        // socket.close() above queued an operation_aborted completion for any
        // in-flight async_connect. Defer the user callback until that has run
        // so callers observe the connect as resolved by the time their close
        // completes. The connect completion handler drains
        // mPendingCloseCallbacks under this same mutex.
        if (self.mConnectInFlight)
        {
          self.mPendingCloseCallbacks.push_back(std::move(callback));
          return;
        }
      }
      // No connect in flight - fire the callback inline, outside the lock.
      if (callback)
        callback(VoidResult{});
    })();
}

void TcpTransportConnector::initialise(std::vector<asio::ip::tcp::endpoint> ipEndpoints)
{
  auto me = this->weak_from_this();

  try
  {
    const Lock lk(mMutex);
    mConnectInFlight = true;
    mIpEndpoints = std::move(ipEndpoints);

    asio::async_connect(mSocket,
      mIpEndpoints,
      [me](boost::system::error_code ec, const asio::ip::tcp::endpoint&)
      {
        auto connector = me.lock();
        if (connector)
        {
          std::vector<std::function<void(VoidResult)>> pendingCloseCallbacks;
          StatusCode status{Status::Good};
          std::string errorMsg;
          std::shared_ptr<TcpTransportConnection> transport;
          {
            // The connect stays "in flight" until the user's callback has returned, so a close_async
            // issued meanwhile (from another thread, or from the callback itself) is deferred and fired
            // after it - close_async callers see the connect as resolved first.
            const Lock connectLock(connector->mMutex);

            if (ec != boost::system::errc::success)
            {
              status = connect_failure_status(ec);
              errorMsg = utils::boost_error_to_string(ec);
            }
            else
            {
              transport = TcpTransportConnection::create(std::move(connector->mSocket),
                connector->mLogger,
                connector->mWriteQueueDepthCap,
                connector->mWriteQueueBytesCap);
            }
          }
          if (status.is_bad())
          {
            connector->mLogger.warning({{"error", std::string_view{errorMsg}}}, "TCP connect failed");
          }
          // The user's callback runs outside the lock (it may call back into this connector, for example
          // close_async) and cannot throw out of this Asio handler, which would end the process (group L,
          // review B1-10). mConnectedCallback is set at construction and never changed.
          try
          {
            connector->mConnectedCallback(status, errorMsg, std::move(transport));
          }
          catch (...)
          {
            log_exception(
              connector->mLogger, "TcpTransportConnector connected callback", std::current_exception());
          }
          {
            const Lock connectLock(connector->mMutex);
            connector->mConnectInFlight = false;
            pendingCloseCallbacks = std::move(connector->mPendingCloseCallbacks);
          }
          // Drain ordering: connect callback fired above; deferred close
          // callbacks fire after, so close_async callers see the connect as
          // resolved first.
          for (const auto& cb : pendingCloseCallbacks)
          {
            if (!cb)
              continue;
            try
            {
              cb(VoidResult{});
            }
            catch (...)
            {
              log_exception(
                connector->mLogger, "TcpTransportConnector close callback", std::current_exception());
            }
          }
        }
      });
  }
  catch (...)
  {
    // async_connect threw before queuing the completion handler, so the
    // handler will never run and never reset mConnectInFlight. Reset it here
    // so a later close_async fires inline instead of deferring forever.
    {
      const Lock lk(mMutex);
      mConnectInFlight = false;
    }
    auto result = ua::exception_to_status_code(std::current_exception());
    mLogger.warning(
      {{"status", fmt::format("0x{:08x}", result.as_uint32())}}, "TCP connect failed with exception");
    mConnectedCallback(result, "", nullptr);
  }
}

}  // namespace ua
