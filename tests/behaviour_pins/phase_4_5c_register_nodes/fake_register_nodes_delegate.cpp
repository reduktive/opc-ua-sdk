// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_register_nodes_delegate.h"

#include "ua_error_detail.h"

namespace ua::test::behaviour_pins::phase_4_5c
{

std::shared_ptr<FakeRegisterNodesNamespace> FakeRegisterNodesNamespace::create(
  ua::string_view uri, boost::asio::any_io_executor ex, bool deferred)
{
  // Use a private inheritance trick: shared_from_this requires construction
  // through std::shared_ptr. Subclass to expose the protected constructor.
  struct Wrapper : public FakeRegisterNodesNamespace
  {
    Wrapper(ua::string_view uri, boost::asio::any_io_executor ex, bool deferred)
      : FakeRegisterNodesNamespace(uri, std::move(ex), deferred)
    {}
  };

  auto self = std::make_shared<Wrapper>(uri, std::move(ex), deferred);
  if (deferred)
  {
    self->start_worker();
  }
  return self;
}

FakeRegisterNodesNamespace::FakeRegisterNodesNamespace(
  ua::string_view uri, boost::asio::any_io_executor ex, bool deferred)
  : ua::default_ns::Namespace(uri, std::move(ex)), mDeferred(deferred)
{}

FakeRegisterNodesNamespace::~FakeRegisterNodesNamespace()
{
  stop_worker();
}

void FakeRegisterNodesNamespace::start_worker()
{
  mWorker = std::thread([this]() { this->worker_loop(); });
  mWorkerId = mWorker.get_id();
}

void FakeRegisterNodesNamespace::stop_worker()
{
  if (!mWorker.joinable())
  {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mShutdown = true;
  }
  mCv.notify_all();
  mWorker.join();
}

void FakeRegisterNodesNamespace::worker_loop()
{
  while (true)
  {
    std::function<void()> next;
    {
      std::unique_lock<std::mutex> lock(mMutex);
      mCv.wait(lock, [this] { return mShutdown || !mPending.empty(); });
      if (mShutdown && mPending.empty())
      {
        return;
      }
      next = std::move(mPending.front());
      mPending.pop_front();
    }
    // Run the parked callback OUTSIDE the lock (golden rule: never invoke a
    // user callback while holding a mutex).
    if (next)
    {
      next();
    }
    // Notify any drain_pending_via_worker() waiters that the queue shrank.
    mCv.notify_all();
  }
}

std::shared_ptr<ua::NamespaceRegisterNodesDelegate>
  FakeRegisterNodesNamespace::register_nodes_delegate() noexcept
{
  return std::dynamic_pointer_cast<NamespaceRegisterNodesDelegate>(shared_from_this());
}

void FakeRegisterNodesNamespace::register_nodes_async(
  const Context&, std::vector<Item> items, RegisterCompleteCallback callback) noexcept
{
  ua::BatchResult<ua::NodeId> response;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    for (const auto& item : items)
    {
      mObservedItems.push_back(item.nodeId);
    }
    if (!mNextRegisterResponses.empty())
    {
      response = std::move(mNextRegisterResponses.front());
      mNextRegisterResponses.pop_front();
    }
    else
    {
      // Default: identity-mapped batch (echo each input).
      response.batchStatus = ua::VoidResult{};
      response.items.reserve(items.size());
      for (auto& it : items)
      {
        response.items.push_back(std::move(it.nodeId));
      }
    }
  }

  if (mDeferred)
  {
    auto cb = std::move(callback);
    auto resp = std::move(response);
    std::lock_guard<std::mutex> lock(mMutex);
    mPending.emplace_back([cb = std::move(cb), resp = std::move(resp)]() mutable { cb(std::move(resp)); });
    mCv.notify_one();
  }
  else
  {
    callback(std::move(response));
  }
}

void FakeRegisterNodesNamespace::unregister_nodes_async(
  const Context&, std::vector<Item> items, UnregisterCompleteCallback callback) noexcept
{
  ua::VoidResult response;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    for (const auto& item : items)
    {
      mObservedItems.push_back(item.nodeId);
    }
    if (!mNextUnregisterResponses.empty())
    {
      response = std::move(mNextUnregisterResponses.front());
      mNextUnregisterResponses.pop_front();
    }
  }

  if (mDeferred)
  {
    auto cb = std::move(callback);
    auto resp = std::move(response);
    std::lock_guard<std::mutex> lock(mMutex);
    mPending.emplace_back([cb = std::move(cb), resp = std::move(resp)]() mutable { cb(std::move(resp)); });
    mCv.notify_one();
  }
  else
  {
    callback(std::move(response));
  }
}

void FakeRegisterNodesNamespace::push_register_response(ua::BatchResult<ua::NodeId> response)
{
  std::lock_guard<std::mutex> lock(mMutex);
  mNextRegisterResponses.push_back(std::move(response));
}

void FakeRegisterNodesNamespace::push_unregister_response(ua::VoidResult response)
{
  std::lock_guard<std::mutex> lock(mMutex);
  mNextUnregisterResponses.push_back(std::move(response));
}

size_t FakeRegisterNodesNamespace::pending_call_count() const
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mPending.size();
}

void FakeRegisterNodesNamespace::drain_pending_via_worker()
{
  // The worker thread autonomously consumes mPending and notifies mCv on each
  // pop. Wait until the queue is empty. This is deterministic - no timed
  // sleeps, no polling.
  std::unique_lock<std::mutex> lock(mMutex);
  mCv.wait(lock, [this] { return mPending.empty(); });
}

std::thread::id FakeRegisterNodesNamespace::worker_thread_id() const
{
  return mWorkerId;
}

std::vector<ua::NodeId> FakeRegisterNodesNamespace::register_call_items() const
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mObservedItems;
}

}  // namespace ua::test::behaviour_pins::phase_4_5c
