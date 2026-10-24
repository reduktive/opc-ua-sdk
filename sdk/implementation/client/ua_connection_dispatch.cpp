// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_connection_dispatch.h"

#include "ua_on_strand.h"
#include "ua_status.h"

#include <boost/asio/strand.hpp>

#include <utility>

namespace ua::client::detail
{

std::shared_ptr<ConnectionDispatch> ConnectionDispatch::create(boost::asio::any_io_executor executor,
  bool queueOnReconnect, std::optional<std::size_t> pendingQueueLimit,
  std::chrono::steady_clock::duration maxQueueAge, ua::Logger logger)
{
  return std::shared_ptr<ConnectionDispatch>(new ConnectionDispatch(
    std::move(executor), queueOnReconnect, pendingQueueLimit, maxQueueAge, std::move(logger)));
}

ConnectionDispatch::ConnectionDispatch(boost::asio::any_io_executor executor, bool queueOnReconnect,
  std::optional<std::size_t> pendingQueueLimit, std::chrono::steady_clock::duration maxQueueAge,
  ua::Logger logger)
  : mExecutor(std::move(executor)), mStrand(boost::asio::make_strand(mExecutor)), mLogger(std::move(logger)),
    mQueueOnReconnect(queueOnReconnect), mQueue(pendingQueueLimit, maxQueueAge)
{
  publish_info();
}

void ConnectionDispatch::route(PendingRequest request)
{
  switch (mState)
  {
  case DispatchState::Active:
    if (request.dispatch)
    {
      request.dispatch();  // session is up - run the op now
    }
    break;
  case DispatchState::Reconnecting:
    if (mQueueOnReconnect)
    {
      mQueue.enqueue(std::move(request));  // hold until the reconnect reaches Active
      publish_info();
    }
    else if (request.fail)
    {
      request.fail(ua::Status::BadSessionNotActivated);  // fail-fast (queueOnReconnect = false)
    }
    break;
  case DispatchState::Failed:
  case DispatchState::Closed:
    if (request.fail)
    {
      request.fail(ua::Status::BadConnectionClosed);
    }
    break;
  }
}

void ConnectionDispatch::submit_async(PendingRequest request) noexcept
{
  // The op owes a callback (dispatch or fail), and PendingRequest is move-only-ish, so share it so both
  // the alive (route) and gone (fail) paths of post_borrowing_or_else can consume the one instance.
  auto shared = std::make_shared<PendingRequest>(std::move(request));
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [shared](ConnectionDispatch& self) { self.route(std::move(*shared)); },
    [shared]()
    {
      if (shared->fail)
      {
        shared->fail(ua::Status::BadConnectionClosed);  // Connection gone - the op cannot run
      }
    })();
}

void ConnectionDispatch::notify_reconnecting_async() noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [](ConnectionDispatch& self)
    {
      if (self.mState == DispatchState::Active)
      {
        self.mState = DispatchState::Reconnecting;
        self.publish_info();
      }
    },
    []() {})();
}

void ConnectionDispatch::notify_active_async() noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [](ConnectionDispatch& self)
    {
      if (self.mState == DispatchState::Failed || self.mState == DispatchState::Closed)
      {
        return;  // terminal - a stray notify cannot resurrect the Connection
      }
      self.mState = DispatchState::Active;
      self.publish_info();
      self.mQueue.flush(std::chrono::steady_clock::now());  // FIFO dispatch; stale entries age out
      self.publish_info();  // pending count changed
    },
    []() {})();
}

void ConnectionDispatch::notify_failed_async(ua::StatusCode terminal) noexcept
{
  ua::async::post_borrowing_or_else(
    this,
    mStrand,
    mLogger,
    [terminal](ConnectionDispatch& self)
    {
      if (self.mState == DispatchState::Closed)
      {
        return;  // already terminal via close
      }
      self.mState = DispatchState::Failed;
      self.mQueue.drain(terminal);
      self.publish_info();
    },
    []() {})();
}

void ConnectionDispatch::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    ua::VoidResult{},  // already gone -> effectively closed -> Good
    [](ConnectionDispatch& self, std::function<void(ua::VoidResult)> completion)
    {
      if (self.mState != DispatchState::Closed)
      {
        self.mState = DispatchState::Closed;
        self.mQueue.drain(ua::Status::BadConnectionClosed);
        self.publish_info();
      }
      // Deliver Good on the executor (not the strand).
      ua::async::post_borrowing(&self,
        self.mExecutor,
        self.mLogger,
        std::move(completion),
        ua::VoidResult{},
        [](ConnectionDispatch&, std::function<void(ua::VoidResult)> cb) { cb(ua::VoidResult{}); })();
    })();
}

void ConnectionDispatch::publish_info()
{
  mInfoSnapshot.store(std::make_shared<const DispatchInfo>(DispatchInfo{mState, mQueue.size()}));
}

std::shared_ptr<const DispatchInfo> ConnectionDispatch::info() const noexcept
{
  return mInfoSnapshot.load();
}

}  // namespace ua::client::detail
