// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_transport_connection.h"

#include "ua_exceptions.h"

#include <utility>

namespace ua::test_helpers
{

void FakeTransportConnection::register_error_callback(ErrorCallback callback)
{
  std::lock_guard<std::mutex> lk(mMutex);
  mErrorCallback = std::move(callback);
}

void FakeTransportConnection::register_read_callback(ReadCompleteCallback callback)
{
  std::lock_guard<std::mutex> lk(mMutex);
  mReadCallback = std::move(callback);
}

void FakeTransportConnection::register_write_callback(WriteCompleteCallback callback)
{
  std::lock_guard<std::mutex> lk(mMutex);
  mWriteCallback = std::move(callback);
}

asio::ip::tcp::endpoint FakeTransportConnection::get_local_endpoint() const
{
  return {};
}

void FakeTransportConnection::enqueue_read_exact(std::vector<byte> bytes)
{
  ReadCompleteCallback cb;
  DeferredRead deferred;
  bool hasDeferred = false;

  {
    std::lock_guard<std::mutex> lk(mMutex);

    if (mDeferredRead)
    {
      // A read is waiting - complete it immediately.
      cb = mReadCallback;
      deferred = std::move(*mDeferredRead);
      mDeferredRead.reset();
      hasDeferred = true;
    }
    else
    {
      PendingRead pr;
      pr.status = StatusCode{Status::Good};
      pr.bytes = std::move(bytes);
      mPendingReads.push(std::move(pr));
    }
  }

  if (hasDeferred && cb)
  {
    check_true(deferred.offset <= deferred.buffer.size());
    const auto needed = deferred.buffer.size() - deferred.offset;
    check_true(bytes.size() == needed);
    std::ranges::copy(bytes, deferred.buffer.begin() + static_cast<std::ptrdiff_t>(deferred.offset));
    cb(StatusCode{Status::Good}, "", std::move(deferred.buffer));
  }
}

void FakeTransportConnection::enqueue_read_error(StatusCode status, std::string description)
{
  ReadCompleteCallback cb;
  DeferredRead deferred;
  bool hasDeferred = false;

  {
    std::lock_guard<std::mutex> lk(mMutex);

    if (mDeferredRead)
    {
      cb = mReadCallback;
      deferred = std::move(*mDeferredRead);
      mDeferredRead.reset();
      hasDeferred = true;
    }
    else
    {
      PendingRead pr;
      pr.status = status;
      pr.description = std::move(description);
      mPendingReads.push(std::move(pr));
    }
  }

  if (hasDeferred && cb)
  {
    cb(status, description, std::move(deferred.buffer));
  }
}

void FakeTransportConnection::enqueue_hello_message(std::vector<byte> helloMessage)
{
  check_true(helloMessage.size() >= ua::connection_protocol::headerSize);
  std::vector<byte> header{helloMessage.begin(), helloMessage.begin() + ua::connection_protocol::headerSize};
  std::vector<byte> remainder{helloMessage.begin() + ua::connection_protocol::headerSize, helloMessage.end()};

  // The header is delivered via an async read; the body is then fetched by the connection protocol
  // via a second `async_read(buffer, headerSize)` call (new partial-receipt-safe path) or by a
  // legacy `bytes_available_to_read()` + sync `read()` call (still used for ERR body decoding).
  // Populate both delivery channels so either reader sees the body.
  std::lock_guard<std::mutex> lk(mMutex);
  PendingRead headerPending;
  headerPending.status = StatusCode{Status::Good};
  headerPending.bytes = std::move(header);
  mPendingReads.push(std::move(headerPending));

  if (!remainder.empty())
  {
    PendingRead bodyPending;
    bodyPending.status = StatusCode{Status::Good};
    bodyPending.bytes = remainder;
    mPendingReads.push(std::move(bodyPending));
  }

  mHelloRemainder = std::move(remainder);
  mHelloRemainderAvailable = true;
}

void FakeTransportConnection::async_read(std::vector<byte>&& buffer, size_t offset)
{
  ReadCompleteCallback cb;
  PendingRead pr;

  {
    std::lock_guard<std::mutex> lk(mMutex);
    cb = mReadCallback;
    check(cb);

    if (mPendingReads.empty())
    {
      if (mStallReads)
      {
        // Stall mode: don't call the callback - the read stays pending forever.
        // This simulates a connection waiting for data that never arrives.
        return;
      }

      // No data available yet - defer the read until data is enqueued.
      mDeferredRead = DeferredRead{std::move(buffer), offset};
      return;
    }

    pr = std::move(mPendingReads.front());
    mPendingReads.pop();
  }

  if (pr.status.is_bad())
  {
    cb(pr.status, pr.description, std::move(buffer));
    return;
  }

  check_true(offset <= buffer.size());
  const auto needed = buffer.size() - offset;
  check_true(pr.bytes.size() == needed);

  std::ranges::copy(pr.bytes, buffer.begin() + static_cast<std::ptrdiff_t>(offset));
  cb(StatusCode{Status::Good}, "", std::move(buffer));
}

void FakeTransportConnection::set_peer_state(PeerState state)
{
  std::lock_guard<std::mutex> lk(mMutex);
  mPeerState = state;
}

ua::TransportConnection::PeerState FakeTransportConnection::peer_state() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  if (mPeerState != PeerState::Open)
  {
    return mPeerState;
  }
  return mHelloRemainderAvailable && !mHelloRemainder.empty() ? PeerState::DataWaiting : PeerState::Open;
}

std::vector<size_t> FakeTransportConnection::sync_read_sizes() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  return mSyncReadSizes;
}

size_t FakeTransportConnection::bytes_available_to_read() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  if (!mHelloRemainderAvailable)
  {
    return 0;
  }
  return mHelloRemainder.size();
}

StatusCode FakeTransportConnection::read(std::vector<byte>& buffer, size_t offset)
{
  std::lock_guard<std::mutex> lk(mMutex);
  if (!mHelloRemainderAvailable)
  {
    return StatusCode{Status::BadNoData};
  }
  check_true(offset <= buffer.size());
  const auto needed = buffer.size() - offset;
  // A reader may take a prefix of what is buffered (the ERR body read is bounded by the ERR grammar); the
  // rest stays readable. Each read's size is recorded for tests that bound it.
  check_true(needed <= mHelloRemainder.size());
  std::copy_n(mHelloRemainder.begin(), needed, buffer.begin() + static_cast<std::ptrdiff_t>(offset));
  mHelloRemainder.erase(
    mHelloRemainder.begin(), mHelloRemainder.begin() + static_cast<std::ptrdiff_t>(needed));
  mHelloRemainderAvailable = !mHelloRemainder.empty();
  mSyncReadSizes.push_back(needed);
  return StatusCode{Status::Good};
}

void FakeTransportConnection::async_write(std::vector<byte>&& buffer)
{
  async_write(std::move(buffer), /*startsMessage*/ true);
}

std::vector<bool> FakeTransportConnection::write_message_starts() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  return mWriteMessageStarts;
}

void FakeTransportConnection::async_write(std::vector<byte>&& buffer, bool startsMessage)
{
  WriteCompleteCallback cb;
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mWrites.push_back(buffer);
    mWriteMessageStarts.push_back(startsMessage);
    if (mHoldWrites)
    {
      ++mHeldWrites;
    }
    else
    {
      cb = mWriteCallback;
    }
  }
  mCv.notify_all();
  if (cb)
  {
    cb(StatusCode{Status::Good}, "");
  }
}

void FakeTransportConnection::close_async(std::function<void(VoidResult)> callback, CloseMode mode)
{
  if (mode == CloseMode::AfterPendingWrites)
  {
    std::lock_guard<std::mutex> lk(mMutex);
    ++mCloseAfterWritesCount;
    if (mHeldWrites > 0)
    {
      mCloseAfterWritesCallbacks.push_back(std::move(callback));
      return;
    }
  }
  std::vector<std::function<void(VoidResult)>> overtaken;
  {
    std::lock_guard<std::mutex> lk(mMutex);
    ++mCloseCount;
    if (!mWritesAtFirstClose)
    {
      mWritesAtFirstClose = mWrites.size();
    }
    overtaken = std::exchange(mCloseAfterWritesCallbacks, {});
  }
  mCv.notify_all();
  if (callback)
    callback(VoidResult{});
  for (auto& cb : overtaken)
    if (cb)
      cb(VoidResult{});
}

void FakeTransportConnection::hold_writes()
{
  std::lock_guard<std::mutex> lk(mMutex);
  mHoldWrites = true;
}

void FakeTransportConnection::complete_held_writes()
{
  WriteCompleteCallback cb;
  std::vector<std::function<void(VoidResult)>> closeAfterWrites;
  {
    std::lock_guard<std::mutex> lk(mMutex);
    mHoldWrites = false;
    if (mHeldWrites == 0)
    {
      return;
    }
    mHeldWrites = 0;
    cb = mWriteCallback;
    closeAfterWrites = std::exchange(mCloseAfterWritesCallbacks, {});
  }
  if (cb)
  {
    cb(StatusCode{Status::Good}, "");
  }
  for (auto& closeCallback : closeAfterWrites)
  {
    close_async(std::move(closeCallback));
  }
}

std::optional<size_t> FakeTransportConnection::writes_at_first_close() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  return mWritesAtFirstClose;
}

size_t FakeTransportConnection::close_after_writes_count() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  return mCloseAfterWritesCount;
}

bool FakeTransportConnection::wait_for_write_count(size_t n, std::chrono::milliseconds timeout)
{
  std::unique_lock<std::mutex> lk(mMutex);
  return mCv.wait_for(lk, timeout, [&]() { return mWrites.size() >= n; });
}

std::vector<std::vector<byte>> FakeTransportConnection::writes() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  return mWrites;
}

bool FakeTransportConnection::closed() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  return mCloseCount != 0;
}

size_t FakeTransportConnection::close_count() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  return mCloseCount;
}

void FakeTransportConnection::stall_reads()
{
  std::lock_guard<std::mutex> lk(mMutex);
  mStallReads = true;
}

bool FakeTransportConnection::has_stalled_read() const
{
  std::lock_guard<std::mutex> lk(mMutex);
  return mStallReads;
}

bool FakeTransportConnection::wait_for_close(std::chrono::milliseconds timeout)
{
  std::unique_lock<std::mutex> lk(mMutex);
  return mCv.wait_for(lk, timeout, [&]() { return mCloseCount != 0; });
}

}  // namespace ua::test_helpers
