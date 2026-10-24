// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <array>
#include <tuple>
#include <utility>

#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include "ua_error_detail.h"
#include "ua_on_strand.h"
#include "ua_tcp_transport_connection.h"

#include <fmt/format.h>

namespace ua
{

void TcpTransportConnection::register_error_callback(ErrorCallback /*callback*/)
{
  // Deliberately not using async_wait(wait_error) - it conflicts with async_read/async_write
  // on the same socket (cancels pending operations on some platforms). Socket errors are
  // already reported through the read/write completion handlers.
}

void TcpTransportConnection::register_read_callback(ReadCompleteCallback callback)
{
  const Lock lock{mMutex};
  mReadCompleteCallback = std::move(callback);
}

void TcpTransportConnection::register_write_callback(WriteCompleteCallback callback)
{
  const Lock lock{mMutex};
  mWriteCompleteCallback = std::move(callback);
}

void TcpTransportConnection::async_read(std::vector<byte>&& buffer, size_t offset)
{
  const Lock lock{mMutex};

  if (offset >= buffer.size())
  {
    throw UaException{Status::BadInvalidArgument,
      ua::ErrorDetail::build(
        "InvalidMessageSize", "Read offset out of range for buffer", "TcpTransportConnection")
        .context(ua::ContextKeys::offset, std::to_string(offset))
        .context(ua::ContextKeys::sizeActual, std::to_string(buffer.size()))};
  }

  if (!mReadBuffer.empty())
  {
    throw UaException{Status::BadInvalidState,
      make_error_detail("TransportError",
        "Cannot start async_read while a read operation is already in progress",
        "TcpTransportConnection")};
  }

  const span<byte> destination{&buffer[offset], buffer.size() - offset};

  mReadBuffer = std::move(buffer);
  auto me = this->weak_from_this();

  asio::async_read(mSocket,
    asio::buffer(destination.data(), destination.size()),
    [me, destination](boost::system::error_code ec, std::size_t bytesRead)
    {
      auto tc = me.lock();
      if (tc)
      {
        std::vector<byte> readBuffer;
        ReadCompleteCallback readCompleteCallback;
        std::vector<std::function<void(VoidResult)>> pendingCloseCallbacks;
        {
          const Lock lk(tc->mMutex);
          readBuffer = std::move(tc->mReadBuffer);
          tc->mReadBuffer.clear();
          readCompleteCallback = tc->mReadCompleteCallback;
          // If close was deferred and no write is still in flight, take ownership
          // of the deferred close callbacks so we can fire them after the user's
          // read callback below - preserving drain-before-callback ordering.
          if (tc->mActiveWriteBuffers.empty())
            pendingCloseCallbacks = std::move(tc->mPendingCloseCallbacks);
        }

        StatusCode status;
        std::string statusDescription;
        if ((ec != boost::system::errc::success) || (bytesRead != destination.size()))
        {
          status = Status::BadTcpInternalError;
          statusDescription = utils::boost_error_to_string(ec);
          // Use cached endpoints - mSocket.{local,remote}_endpoint() would race
          // with the close() inside close_async (only the close path holds
          // mMutex; the endpoints were captured once at construction).
          const std::string remoteStr =
            tc->mRemoteEndpoint
              ? fmt::format("{}:{}", tc->mRemoteEndpoint->address().to_string(), tc->mRemoteEndpoint->port())
              : std::string{"(unknown)"};
          const std::string localStr =
            tc->mLocalEndpoint
              ? fmt::format("{}:{}", tc->mLocalEndpoint->address().to_string(), tc->mLocalEndpoint->port())
              : std::string{"(unknown)"};
          // Distinguish partial-read-with-success (asio composed-op early-break) from a real ec
          // error so we can root-cause the rare case where it fires.
          if (ec == boost::system::errc::success)
          {
            tc->mLogger.warning({{"bytes_read", fmt::format("{}", bytesRead)},
                                  {"expected", fmt::format("{}", destination.size())},
                                  {"local", std::string_view{localStr}},
                                  {"remote", std::string_view{remoteStr}}},
              "TCP read short-completed with ec=success");
          }
          else
          {
            tc->mLogger.warning({{"error", std::string_view{statusDescription}},
                                  {"bytes_read", fmt::format("{}", bytesRead)},
                                  {"expected", fmt::format("{}", destination.size())},
                                  {"local", std::string_view{localStr}},
                                  {"remote", std::string_view{remoteStr}}},
              "TCP read error");
          }
        }

        readCompleteCallback(status, statusDescription, std::move(readBuffer));

        // Drain ordering: read callback fired above; deferred close callbacks
        // fire after, so close_async callers see the read as resolved first.
        for (const auto& cb : pendingCloseCallbacks)
          if (cb)
            cb(VoidResult{});
      }
    });
}

StatusCode TcpTransportConnection::read(std::vector<byte>& buffer, size_t offset)
{
  const Lock lock{mMutex};

  if (offset >= buffer.size())
  {
    throw UaException{Status::BadInvalidArgument,
      ua::ErrorDetail::build(
        "InvalidMessageSize", "Read offset out of range for buffer", "TcpTransportConnection")
        .context(ua::ContextKeys::offset, std::to_string(offset))
        .context(ua::ContextKeys::sizeActual, std::to_string(buffer.size()))};
  }

  if (!mReadBuffer.empty())
  {
    throw UaException{Status::BadInvalidState,
      make_error_detail("TransportError",
        "Cannot start synchronous read while a read operation is already in progress",
        "TcpTransportConnection")};
  }

  const span<byte> destination{&buffer[offset], buffer.size() - offset};

  boost::system::error_code ec;
  auto bytesRead = asio::read(mSocket, asio::buffer(destination.data(), destination.size()), ec);
  if (ec.failed() || (bytesRead != destination.size()))
  {
    return StatusCode{Status::BadInternalError};
  }
  else
  {
    return StatusCode{Status::Good};
  }
}

void TcpTransportConnection::async_write(std::vector<byte>&& buffer)
{
  async_write(std::move(buffer), /*startsMessage*/ true);
}

void TcpTransportConnection::async_write(std::vector<byte>&& buffer, bool startsMessage)
{
  WriteCompleteCallback overflowCallback;
  const char* refusal = nullptr;
  {
    const Lock lock{mMutex};

    // Fail closed if the peer is not draining the socket: dropping the buffer and reporting an error
    // is safer than letting mPendingWriteBuffers grow without bound. Capture the callback to invoke
    // after releasing the lock (callback-safety: never invoke a user callback while holding a mutex).
    // Two bounds, both O(1): the buffer count, and the bytes queued plus in flight (the count alone
    // lets a peer hold depth x chunk size, unbounded by anything it does not choose). Both are
    // applied at a message's FIRST chunk: a message that was admitted is queued whole, so a peer that
    // merely reads slowly is never cut off mid-message, and the bound is the cap plus one message.
    if (startsMessage)
    {
      mDroppingMessage = false;
    }
    else if (mDroppingMessage)
    {
      // A continuation chunk of the message whose first chunk was refused: dropped with it, so the
      // peer never sees a message tail and the refused message holds no memory.
      return;
    }
    if (startsMessage && mPendingWriteBuffers.size() >= mWriteQueueDepthCap)
    {
      overflowCallback = mWriteCompleteCallback;
      mDroppingMessage = true;
      refusal = "Pending-write queue depth cap reached";
      mLogger.warning({{"cap", fmt::format("{}", mWriteQueueDepthCap)}},
        "Pending-write queue depth cap reached; dropping outgoing message");
    }
    else if (startsMessage && mQueuedWriteBytes >= mWriteQueueBytesCap)
    {
      overflowCallback = mWriteCompleteCallback;
      mDroppingMessage = true;
      refusal = "Pending-write byte budget reached";
      mLogger.warning({{"cap", fmt::format("{}", mWriteQueueBytesCap)},
                        {"queued", fmt::format("{}", mQueuedWriteBytes)},
                        {"size", fmt::format("{}", buffer.size())}},
        "Pending-write byte budget reached; dropping outgoing message");
    }
    else
    {
      mQueuedWriteBytes += buffer.size();
      mPendingWriteBuffers.push(std::move(buffer));
      if (mActiveWriteBuffers.empty())
      {
        write();
      }
    }
  }

  if (overflowCallback)
  {
    overflowCallback(StatusCode{Status::BadTcpNotEnoughResources}, refusal);
  }
}

void TcpTransportConnection::write()
{
  size_t bytesToWrite{0};

  while (!mPendingWriteBuffers.empty())
  {
    auto buffer = std::move(mPendingWriteBuffers.front());
    mPendingWriteBuffers.pop();

    bytesToWrite += buffer.size();
    mActiveWriteBuffers.push_back(std::move(buffer));
    mActiveAsioWriteBuffers.push_back(asio::buffer(mActiveWriteBuffers.back()));
  }

  if (bytesToWrite == 0)
  {
    return;
  }

  auto me = this->weak_from_this();

  asio::async_write(mSocket,
    mActiveAsioWriteBuffers,
    [me, bytesToWrite](boost::system::error_code ec, std::size_t bytesWritten)
    {
      auto tc = me.lock();
      if (!tc)
        return;

      WriteCompleteCallback writeCompleteCallback;
      bool noDataRemainingToWrite{false};
      std::string bufferSizes;
      size_t bufferCount{0};
      bool socketOpen{false};
      std::vector<std::function<void(VoidResult)>> pendingCloseCallbacks;
      std::vector<std::function<void(VoidResult)>> closeAfterWritesCallbacks;

      {
        const Lock lk(tc->mMutex);

        if (bytesWritten != bytesToWrite)
        {
          bufferCount = tc->mActiveAsioWriteBuffers.size();
          for (const auto& b : tc->mActiveAsioWriteBuffers)
          {
            if (!bufferSizes.empty())
              bufferSizes += ',';
            bufferSizes += fmt::format("{}", b.size());
          }
          socketOpen = tc->mSocket.is_open();
        }

        tc->mActiveWriteBuffers.clear();
        tc->mActiveAsioWriteBuffers.clear();
        // The batch just handed to the socket no longer counts against the byte budget, whatever
        // the outcome: on error the connection is closing and nothing further is queued.
        tc->mQueuedWriteBytes -= std::min(tc->mQueuedWriteBytes, bytesToWrite);

        // Drain any queued buffers and submit the next asio::async_write under the same
        // lock that just cleared mActive*. This closes the window in which a concurrent
        // async_write() caller would otherwise observe mActiveWriteBuffers empty and
        // submit a second asio::async_write - asio forbids concurrent writes on a socket.
        tc->write();

        // mActiveWriteBuffers is non-empty iff write() just submitted the next operation.
        noDataRemainingToWrite = tc->mActiveWriteBuffers.empty();
        writeCompleteCallback = tc->mWriteCompleteCallback;

        // If close was deferred and no other write is queued and no read is in
        // flight, take ownership of the deferred close callbacks so we can fire
        // them after the user's write callback below.
        if (noDataRemainingToWrite && tc->mReadBuffer.empty())
          pendingCloseCallbacks = std::move(tc->mPendingCloseCallbacks);

        // The queue has drained: an AfterPendingWrites close waiting on it closes now.
        if (noDataRemainingToWrite)
          closeAfterWritesCallbacks = std::exchange(tc->mCloseAfterWritesCallbacks, {});
      }

      StatusCode status;
      std::string statusDescription;
      if ((ec != boost::system::errc::success) || (bytesWritten != bytesToWrite))
      {
        status = Status::BadTcpInternalError;
        statusDescription = utils::boost_error_to_string(ec);
        if (ec == boost::system::errc::success)
        {
          tc->mLogger.warning(
            {{"bytes_written", fmt::format("{}", bytesWritten)},
              {"expected", fmt::format("{}", bytesToWrite)},
              {"buffer_count", fmt::format("{}", bufferCount)},
              {"buffer_sizes", std::string_view{bufferSizes}},
              {"socket_open", socketOpen ? std::string_view{"true"} : std::string_view{"false"}}},
            "TCP write byte count mismatch with ec=success");
        }
        else
        {
          tc->mLogger.warning({{"error", std::string_view{statusDescription}}}, "TCP write error");
        }
      }

      if (noDataRemainingToWrite)
      {
        writeCompleteCallback(status, statusDescription);
      }

      // Drain ordering: write callback fired above; deferred close callbacks
      // fire after, so close_async callers see the write as resolved first.
      for (const auto& cb : pendingCloseCallbacks)
        if (cb)
          cb(VoidResult{});

      if (!closeAfterWritesCallbacks.empty())
      {
        tc->close_async(
          [callbacks = std::move(closeAfterWritesCallbacks)](VoidResult result)
          {
            for (const auto& cb : callbacks)
              if (cb)
                cb(result);
          });
      }
    });
}

void TcpTransportConnection::close_async(std::function<void(VoidResult)> callback, CloseMode mode)
{
  if (mode == CloseMode::AfterPendingWrites)
  {
    const Lock lock{mMutex};
    // A write queued or in flight has a completion still to take mMutex, and the one that leaves
    // nothing queued closes (see write()). Otherwise nothing is left to wait for.
    if (!mActiveWriteBuffers.empty() || !mPendingWriteBuffers.empty())
    {
      mCloseAfterWritesCallbacks.push_back(std::move(callback));
      return;
    }
  }
  // Posting onto the socket's executor lets callers invoke close_async safely
  // from any thread, including from inside a read/write completion handler,
  // without re-entering mMutex on the calling thread. Strong self-capture
  // (post_owning) keeps the connection alive across the hop.
  ua::async::post_owning(this,
    mSocket.get_executor(),
    mLogger,
    [callback = std::move(callback)](TcpTransportConnection& self) mutable
    {
      std::function<void(VoidResult)> inlineCallback;
      // An AfterPendingWrites close still waiting on the queue is overtaken by this close.
      std::vector<std::function<void(VoidResult)>> overtaken;
      {
        const Lock lock{self.mMutex};
        overtaken = std::exchange(self.mCloseAfterWritesCallbacks, {});
        boost::system::error_code ec;
        // Best-effort close on the teardown path: the non-throwing overload is chosen so close
        // never throws. A close error (e.g. the socket is already gone) is not actionable here,
        // so the returned error_code is deliberately discarded.
        std::ignore = self.mSocket.close(ec);

        // socket.close() above queued operation_aborted completions for any
        // in-flight async_read/async_write. Defer the user callback until
        // those have run so callers observe all in-flight reads/writes as
        // resolved by the time their close completes. The completion handler
        // for the last in-flight op drains mPendingCloseCallbacks under this
        // same mutex and fires them after invoking its own user callback.
        const bool readInFlight = !self.mReadBuffer.empty();
        const bool writeInFlight = !self.mActiveWriteBuffers.empty();
        if (readInFlight || writeInFlight)
        {
          self.mPendingCloseCallbacks.push_back(std::move(callback));
          for (auto& cb : overtaken)
            self.mPendingCloseCallbacks.push_back(std::move(cb));
          overtaken.clear();
        }
        else
          inlineCallback = std::move(callback);
      }
      // Fire outside the lock (never invoke a user callback while holding the
      // mutex). Only the inline branch above populates inlineCallback, so the
      // moved-from capture is never read here.
      if (inlineCallback)
        inlineCallback(VoidResult{});
      for (const auto& cb : overtaken)
        if (cb)
          cb(VoidResult{});
    })();
}

shared_ptr<TcpTransportConnection> TcpTransportConnection::create(
  asio::ip::tcp::socket&& socket, Logger logger, size_t writeQueueDepthCap, size_t writeQueueBytesCap)
{
  class Wrapper : public TcpTransportConnection
  {
  public:
    Wrapper(
      asio::ip::tcp::socket&& socket, Logger logger, size_t writeQueueDepthCap, size_t writeQueueBytesCap)
      : TcpTransportConnection(std::move(socket), std::move(logger), writeQueueDepthCap, writeQueueBytesCap)
    {}
  };

  auto conn =
    make_shared<Wrapper>(std::move(socket), std::move(logger), writeQueueDepthCap, writeQueueBytesCap);

  // Log the remote endpoint at debug level after creation. Use the cached
  // value captured by the constructor - accessing mSocket here would conflict
  // with later strand-serialized close_async() calls under TSan.
  const auto& remoteEndpoint = conn->mRemoteEndpoint;
  if (conn->mLogger.is_enabled(LogLevel::Debug) && remoteEndpoint)
  {
    conn->mLogger.debug(
      {{"remote", fmt::format("{}:{}", remoteEndpoint->address().to_string(), remoteEndpoint->port())}},
      "TCP connection established");
  }

  return conn;
}

namespace
{

std::optional<asio::ip::tcp::endpoint> capture_local_endpoint(const asio::ip::tcp::socket& s)
{
  boost::system::error_code ec;
  auto ep = s.local_endpoint(ec);
  if (ec)
    return std::nullopt;
  return ep;
}

std::optional<asio::ip::tcp::endpoint> capture_remote_endpoint(const asio::ip::tcp::socket& s)
{
  boost::system::error_code ec;
  auto ep = s.remote_endpoint(ec);
  if (ec)
    return std::nullopt;
  return ep;
}

}  // namespace

TcpTransportConnection::TcpTransportConnection(
  asio::ip::tcp::socket&& socket, Logger logger, size_t writeQueueDepthCap, size_t writeQueueBytesCap)
  : mLogger(std::move(logger)), mSocket(std::move(socket)), mLocalEndpoint(capture_local_endpoint(mSocket)),
    mRemoteEndpoint(capture_remote_endpoint(mSocket)),
    mWriteQueueDepthCap(writeQueueDepthCap < 1 ? 1 : writeQueueDepthCap),
    mWriteQueueBytesCap(writeQueueBytesCap < 1 ? 1 : writeQueueBytesCap)
{}

asio::ip::tcp::endpoint TcpTransportConnection::get_local_endpoint() const
{
  return mLocalEndpoint.value_or(asio::ip::tcp::endpoint{});
}

asio::ip::tcp::endpoint TcpTransportConnection::get_remote_endpoint() const
{
  return mRemoteEndpoint.value_or(asio::ip::tcp::endpoint{});
}

size_t TcpTransportConnection::bytes_available_to_read() const
{
  const Lock lock{mMutex};
  return mSocket.available();
}

TransportConnection::PeerState TcpTransportConnection::peer_state() const
{
  // Peek one byte in non-blocking mode and restore the mode: end of stream or a reset means the peer has
  // closed; "would block" means it is open with nothing sent; a byte means data is waiting. Nothing is
  // consumed. Cost: one system call.
  const Lock lock{mMutex};
  auto& socket = const_cast<asio::ip::tcp::socket&>(mSocket);
  if (!socket.is_open())
  {
    return PeerState::Closed;
  }
  boost::system::error_code ec;
  const bool wasNonBlocking = socket.non_blocking();
  socket.non_blocking(true, ec);
  if (ec)
  {
    // Cannot peek: report only what the receive buffer holds, as a transport that cannot detect a close.
    boost::system::error_code availableError;
    const auto available = socket.available(availableError);
    return !availableError && available > 0 ? PeerState::DataWaiting : PeerState::Open;
  }
  std::array<char, 1> probe{};
  std::ignore = socket.receive(asio::buffer(probe), asio::socket_base::message_peek, ec);
  boost::system::error_code restoreError;
  socket.non_blocking(wasNonBlocking, restoreError);
  if (!ec)
  {
    return PeerState::DataWaiting;
  }
  if (ec == asio::error::would_block || ec == asio::error::try_again || ec == asio::error::interrupted)
  {
    return PeerState::Open;
  }
  return PeerState::Closed;
}

TcpTransportConnection::~TcpTransportConnection()
{
  const Lock lock{mMutex};
  boost::system::error_code ec;
  // Best-effort close in the destructor: the non-throwing overload is chosen so destruction
  // never throws. A close error at teardown is not actionable, so the returned error_code is
  // deliberately discarded.
  std::ignore = mSocket.close(ec);
}

}  // namespace ua
