// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <algorithm>
#include <chrono>
#include <tuple>

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/lexical_cast.hpp>

#include "ua_on_strand.h"
#include "ua_tcp_transport_acceptor.h"
#include "ua_tcp_transport_connection.h"

namespace ua
{

shared_ptr<TcpTransportAcceptor> TcpTransportAcceptor::create(boost::asio::any_io_executor executor,
  asio::ip::tcp::endpoint ipEndpoint, NewConnectionCallback newConnectionCallback, Logger logger,
  size_t writeQueueDepthCap, size_t writeQueueBytesCap)
{
  class Wrapper : public TcpTransportAcceptor
  {
  public:
    Wrapper(boost::asio::any_io_executor executor, asio::ip::tcp::endpoint ipEndpoint,
      NewConnectionCallback newConnectionCallback, Logger logger, size_t writeQueueDepthCap,
      size_t writeQueueBytesCap)
      : TcpTransportAcceptor(executor, ipEndpoint, newConnectionCallback, std::move(logger),
          writeQueueDepthCap, writeQueueBytesCap)
    {}
  };

  auto acceptor = make_shared<Wrapper>(
    executor, ipEndpoint, newConnectionCallback, std::move(logger), writeQueueDepthCap, writeQueueBytesCap);
  acceptor->initialise();
  return acceptor;
}

TcpTransportAcceptor::TcpTransportAcceptor(boost::asio::any_io_executor executor,
  asio::ip::tcp::endpoint ipEndpoint, NewConnectionCallback newConnectionCallback, Logger logger,
  size_t writeQueueDepthCap, size_t writeQueueBytesCap)
  : mLogger(std::move(logger)), mNewConnectionCallback(newConnectionCallback), mAcceptor(executor),
    mEndpoint(ipEndpoint), mSocket(executor), mWriteQueueDepthCap(writeQueueDepthCap),
    mWriteQueueBytesCap(writeQueueBytesCap), mExecutor(executor)
{}

void TcpTransportAcceptor::initialise()
{
  // Binding is where a deployment mistake surfaces - a port already taken, an address this host
  // does not own. Asio's throwing overloads raise boost::system::system_error, which the generic
  // conversion turns into a bare BadInternalError: a status that reads as an SDK defect rather
  // than an operator-fixable one. Take the error_code overloads instead so the failure carries
  // the address it was attempted on and the operating system's reason, and so the symbolic code
  // names which step failed (open vs bind vs listen) without needing a separate context key.
  boost::system::error_code ec;
  const char* code = "ListenerOpenFailed";
  mAcceptor.open(mEndpoint.protocol(), ec);
  if (!ec)
  {
    mAcceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
  }
  if (!ec)
  {
    code = "ListenerBindFailed";
    mAcceptor.bind(mEndpoint, ec);
  }
  if (!ec)
  {
    code = "ListenerListenFailed";
    mAcceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
  }
  if (ec)
  {
    throw UaException{Status::BadResourceUnavailable,
      ErrorDetail::build(code, "could not acquire the listening socket", "TcpTransportAcceptor")
        .context(ua::ContextKeys::endpointAddress, mEndpoint.address().to_string())
        .context(ua::ContextKeys::endpointPort, mEndpoint.port())
        .context(ua::ContextKeys::errorMessage, ec.message())};
  }

  // Capture the bound endpoint now, while we are still single-threaded (before
  // the accept loop or any close can touch mAcceptor), so get_local_endpoint()
  // can read it lock-free.
  mBoundEndpoint = mAcceptor.local_endpoint();

  async_accept();
}

std::chrono::milliseconds TcpTransportAcceptor::accept_retry_delay(unsigned consecutiveFailures) noexcept
{
  if (consecutiveFailures == 0)
  {
    return std::chrono::milliseconds{0};
  }
  constexpr unsigned maxDoublings = 6;  // 100 ms << 6 = 6.4 s, clamped to the 5 s ceiling
  const unsigned doublings = std::min(consecutiveFailures - 1, maxDoublings);
  const auto delay = std::chrono::milliseconds{100} * (1u << doublings);
  return std::min(delay, std::chrono::milliseconds{5000});
}

bool TcpTransportAcceptor::accept_failure_backs_off(const boost::system::error_code& ec) noexcept
{
  namespace errc = boost::system::errc;
  return ec == errc::too_many_files_open || ec == errc::too_many_files_open_in_system ||
         ec == errc::no_buffer_space || ec == errc::not_enough_memory;
}

unsigned TcpTransportAcceptor::consecutive_accept_failures_for_tests() const
{
  const Lock lock{mMutex};
  return mConsecutiveAcceptFailures;
}

void TcpTransportAcceptor::set_accept_outcome_injector_for_tests(AcceptOutcomeInjector injector)
{
  const Lock lock{mMutex};
  mAcceptOutcomeInjectorForTests = std::move(injector);
}

void TcpTransportAcceptor::async_accept_after(std::chrono::milliseconds delay)
{
  auto me = this->weak_from_this();
  const Lock lock{mMutex};
  if (mClosed)
    return;

  mRetryTimer = Timer::schedule_after(mExecutor,
    delay,
    [me](boost::system::error_code ec)
    {
      if (ec == boost::asio::error::operation_aborted)
        return;
      if (auto acceptor = me.lock())
        acceptor->async_accept();
    });
}

void TcpTransportAcceptor::async_accept()
{
  auto me = this->weak_from_this();

  // Arm the accept under mMutex so it is serialized against close_async's
  // mAcceptor.close(): two threads must never touch mAcceptor concurrently
  // (asio acceptors are not thread-safe). Once closed, do not re-arm.
  const Lock lock{mMutex};
  if (mClosed)
    return;

  // Each connection's socket gets a strand of its own. asio::async_read and asio::async_write re-issue
  // their partial reads and writes from their own completion handlers, which run on the socket's
  // executor and take no SDK lock; close_async posts the close() to that same executor. On the pool
  // executor the two could run on different threads at once, and a socket is not safe for concurrent
  // use. On a strand every completion of the socket and its close() are serialized.
  mSocket = asio::ip::tcp::socket{boost::asio::make_strand(mExecutor)};
  mAcceptor.async_accept(mSocket,
    [me](boost::system::error_code ec) mutable
    {
      auto acceptor = me.lock();
      if (!acceptor)
        return;

      // operation_aborted means the acceptor was closed - stop the accept chain.
      if (ec == boost::asio::error::operation_aborted)
        return;

      StatusCode status{Status::Good};
      std::string errorMsg;
      shared_ptr<TcpTransportConnection> connection;
      std::chrono::milliseconds retryDelay{0};
      {
        const Lock acceptorLock{acceptor->mMutex};

        // Closed while this completion was in flight: drop the just-accepted
        // socket without delivering it, honouring the close_async contract that
        // no new-connection callback fires once the acceptor is closed.
        if (acceptor->mClosed)
          return;

        if (acceptor->mAcceptOutcomeInjectorForTests)
        {
          ec = acceptor->mAcceptOutcomeInjectorForTests(ec);
          if (ec)
          {
            // The injected failure stands in for an accept that produced no socket.
            boost::system::error_code ignored;
            std::ignore = acceptor->mSocket.close(ignored);
          }
        }

        if (ec != boost::system::errc::success)
        {
          errorMsg = utils::boost_error_to_string(ec);
          if (accept_failure_backs_off(ec))
          {
            ++acceptor->mConsecutiveAcceptFailures;
            retryDelay = accept_retry_delay(acceptor->mConsecutiveAcceptFailures);
          }
          acceptor->mLogger.warning(
            {{"error", std::string_view{errorMsg}},
              {"consecutive_failures", uint64_t(acceptor->mConsecutiveAcceptFailures)},
              {"retry_ms", uint64_t(retryDelay.count())}},
            "TCP accept failed");
          status = StatusCode{Status::BadTcpInternalError};
        }
        else
        {
          acceptor->mConsecutiveAcceptFailures = 0;
          connection = TcpTransportConnection::create(std::move(acceptor->mSocket),
            acceptor->mLogger,
            acceptor->mWriteQueueDepthCap,
            acceptor->mWriteQueueBytesCap);
        }
      }

      // Invoke the user callback outside the lock (callback-safety golden rule).
      acceptor->mNewConnectionCallback(status, errorMsg, connection);

      // Re-arm; arming re-takes mMutex and is a no-op once the acceptor is closed. A failed accept
      // re-arms through the backoff timer (see accept_retry_delay) instead of immediately.
      if (retryDelay.count() > 0)
        acceptor->async_accept_after(retryDelay);
      else
        acceptor->async_accept();
    });
}

void TcpTransportAcceptor::close_async(std::function<void(VoidResult)> completionHandler)
{
  // The inner completion-owning post_borrowing below delivers `completionHandler` on its GONE path
  // (the acceptor destroyed before the inner strand turn) via an UNCONDITIONAL `completion(goneResult)`
  // in the helper. std::function::operator() throws std::bad_function_call when empty, so a fire-and-
  // forget close (the defaulted `completionHandler == {}`, e.g. ServerImpl shutdown) would throw on the
  // gone path - caught by `guarded` and logged as a swallowed "guarded async continuation". The
  // alive-path handler already guards with `if (callback)`; the gone path lives inside the helper and
  // cannot, so normalize the fire-and-forget case to an explicit no-op completion (per the async design:
  // fire-and-forget uses `[](VoidResult){}`, never an empty std::function) to keep the gone path safe.
  if (!completionHandler)
  {
    // The caller explicitly selected fire-and-forget close and has no use for the result.
    completionHandler = [](VoidResult) {
    };
  }
  // Post close to the acceptor's executor so it runs after any accept callback
  // already in flight on the same executor. The actual close() and the
  // mClosed flip run under mMutex, serialized against the accept loop's
  // mAcceptor.async_accept() re-arm - two threads must never touch mAcceptor
  // concurrently (asio acceptors are not thread-safe; the unserialized variant
  // crashed in epoll_reactor::deregister_descriptor). The mMutex guard also
  // makes close idempotent: a second close_async finds mClosed already set.
  //
  // Strong self-capture (post_owning) keeps the acceptor alive across the hop so
  // the close still runs if the caller has dropped its last reference.
  ua::async::post_owning(this,
    mExecutor,
    mLogger,
    [pendingCompletion = std::move(completionHandler)](TcpTransportAcceptor& self) mutable
    {
      {
        const Lock lock{self.mMutex};
        if (!self.mClosed)
        {
          self.mClosed = true;
          self.mRetryTimer.cancel();
          boost::system::error_code ec;
          // Best-effort close on the shutdown path: the non-throwing overload is chosen so teardown
          // never throws. A close error (e.g. the acceptor is already closed) is not actionable here,
          // so the returned error_code is deliberately discarded.
          std::ignore = self.mAcceptor.close(ec);
        }
      }

      // close() above cancels the in-flight async_accept; its operation_aborted
      // completion is now queued on this executor. Re-post so that cancellation
      // has a chance to run before we fire `callback`. Strict ordering holds on
      // a single-threaded executor; under a multi-threaded pool the abort
      // handler may still run concurrently, but it is a no-op (operation_aborted
      // is filtered) and touches nothing, so shutdown semantics still hold. This
      // second hop owns the user callback and must fire it exactly once, so it is
      // a completion-owning post: if the acceptor is gone by the time the strand
      // turn runs the completion still fires with a good VoidResult.
      ua::async::post_borrowing(&self,
        self.mExecutor,
        self.mLogger,
        std::move(pendingCompletion),
        VoidResult{},
        [](TcpTransportAcceptor&, std::function<void(VoidResult)> callback)
        {
          if (callback)
            callback(VoidResult{});
        })();
    })();
}

asio::ip::tcp::endpoint TcpTransportAcceptor::get_local_endpoint() const
{
  // mBoundEndpoint is set once in initialise() before the acceptor is shared, so
  // it is immutable here - no lock needed, and no race against mAcceptor.close().
  return mBoundEndpoint;
}

}  // namespace ua
