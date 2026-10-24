// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_history_delegate.h"

#include <utility>

#include "ua_data_value.h"
#include "ua_status_code.h"

namespace ua::test::behaviour_pins::phase_4_5e
{
namespace
{

/// A staged historical value carrying both timestamps.
///
/// Part 11 section 6.5.3.2 obliges the Server to answer `Bad_TimestampNotSupported` for an operation whose
/// Node cannot supply the requested TimestampsToReturn, and the pins request `Both`. A staged
/// DataValue left with two empty timestamp optionals is therefore not a historian's answer at all -
/// it is a Node that supplies neither, and the Server refusing it is the Server obeying the clause.
/// The pins above are about per-operation status independence and HistoryData wrapping, so their
/// staged data has to be well-formed enough to reach the behaviour they pin.
DataValue staged_value(std::int32_t value)
{
  DataValue dv;
  dv.value() = value;
  const auto now = DateTime::now();
  dv.source_timestamp() = now;
  dv.server_timestamp() = now;
  return dv;
}

}  // namespace

FakeHistoryDelegate::FakeHistoryDelegate(Mode mode) : mMode(mode)
{
  if (mMode == Mode::Deferred)
  {
    mWorker.emplace([this] { worker_loop(); });
    mWorkerId = mWorker->get_id();
  }
}

FakeHistoryDelegate::~FakeHistoryDelegate()
{
  {
    std::lock_guard<std::mutex> lock(mMutex);
    mShuttingDown = true;
  }
  mCv.notify_all();
  if (mWorker && mWorker->joinable())
  {
    mWorker->join();
  }
}

// ----- Configuration -----

void FakeHistoryDelegate::stage_read_raw_per_item_success()
{
  std::lock_guard<std::mutex> lock(mMutex);
  StagedReadRaw staged;
  staged.kind = StagedReadRawKind::PerItemSuccess;
  mStagedReadRaw = staged;
}

void FakeHistoryDelegate::stage_read_raw_batch_failure(StatusCode status)
{
  std::lock_guard<std::mutex> lock(mMutex);
  StagedReadRaw staged;
  staged.kind = StagedReadRawKind::BatchFailure;
  staged.status = status;
  mStagedReadRaw = staged;
}

void FakeHistoryDelegate::stage_read_raw_per_item_statuses(std::vector<StatusCode> perItemStatuses)
{
  std::lock_guard<std::mutex> lock(mMutex);
  StagedReadRaw staged;
  staged.kind = StagedReadRawKind::PerItemStatuses;
  staged.perItemStatuses = std::move(perItemStatuses);
  mStagedReadRaw = staged;
}

void FakeHistoryDelegate::stage_update_data_per_item_success()
{
  std::lock_guard<std::mutex> lock(mMutex);
  mStagedUpdateData = StagedUpdate{StagedUpdateKind::PerItemSuccess, StatusCode{Status::Good}};
}

void FakeHistoryDelegate::stage_update_data_batch_failure(StatusCode status)
{
  std::lock_guard<std::mutex> lock(mMutex);
  mStagedUpdateData = StagedUpdate{StagedUpdateKind::BatchFailure, status};
}

void FakeHistoryDelegate::stage_delete_raw_batch_failure(StatusCode status)
{
  std::lock_guard<std::mutex> lock(mMutex);
  mStagedDeleteRaw = StagedUpdate{StagedUpdateKind::BatchFailure, status};
}

// ----- Mode-only helpers (deferred) -----

bool FakeHistoryDelegate::drive_next_pending()
{
  PendingFn fn;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    if (mPending.empty())
    {
      return false;
    }
    fn = std::move(mPending.front());
    mPending.pop();
  }
  // The deferred-mode contract is "the next continuation runs on a thread
  // that is NOT the strand's thread." We hand the lambda to the worker so it
  // fires from the dedicated worker thread.
  if (mMode == Mode::Deferred)
  {
    {
      std::lock_guard<std::mutex> lock(mMutex);
      mReady.push(std::move(fn));
    }
    mCv.notify_all();
    return true;
  }
  // Inline-mode "drive" - caller's thread runs the callback. Only used in
  // tests that switched a delegate to deferred mid-run; not exercised in this
  // pin corpus.
  fn();
  return true;
}

size_t FakeHistoryDelegate::pending_call_count()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mPending.size();
}

std::future<void> FakeHistoryDelegate::when_parked()
{
  std::lock_guard<std::mutex> lock(mMutex);
  std::promise<void> promise;
  std::future<void> future = promise.get_future();
  if (!mPending.empty())
  {
    promise.set_value();  // already parked - satisfy immediately
  }
  else
  {
    mParkWaiters.push_back(std::move(promise));  // armed; park_or_run will satisfy it
  }
  return future;
}

std::thread::id FakeHistoryDelegate::worker_thread_id() const
{
  return mWorkerId;
}

// ----- Observation -----

size_t FakeHistoryDelegate::read_raw_call_count()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mReadRawCalls;
}

size_t FakeHistoryDelegate::update_data_call_count()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mUpdateDataCalls;
}

size_t FakeHistoryDelegate::delete_raw_call_count()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mDeleteRawCalls;
}

size_t FakeHistoryDelegate::delete_at_time_call_count()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mDeleteAtTimeCalls;
}

size_t FakeHistoryDelegate::delete_events_call_count()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mDeleteEventsCalls;
}

std::vector<ReadRawCall> FakeHistoryDelegate::read_raw_calls()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mReadRawCallLog;
}

std::vector<UpdateDataCall> FakeHistoryDelegate::update_data_calls()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mUpdateDataCallLog;
}

std::vector<DeleteRawCall> FakeHistoryDelegate::delete_raw_calls()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mDeleteRawCallLog;
}

std::shared_ptr<std::atomic_bool> FakeHistoryDelegate::last_seen_cancelled_flag()
{
  std::lock_guard<std::mutex> lock(mMutex);
  return mLastCancelled;
}

// ----- Internals -----

void FakeHistoryDelegate::park_or_run(PendingFn fn)
{
  if (mMode == Mode::Inline)
  {
    fn();
    return;
  }
  std::lock_guard<std::mutex> lock(mMutex);
  mPending.push(std::move(fn));
  // Wake any main-thread waiter blocked in when_parked() (replaces the busy-spin poll).
  for (std::promise<void>& waiter : mParkWaiters)
  {
    waiter.set_value();
  }
  mParkWaiters.clear();
}

void FakeHistoryDelegate::worker_loop()
{
  for (;;)
  {
    PendingFn fn;
    {
      std::unique_lock<std::mutex> lock(mMutex);
      mCv.wait(lock, [this] { return mShuttingDown || !mReady.empty(); });
      if (mShuttingDown && mReady.empty())
      {
        return;
      }
      // Only fire pending items that drive_next_pending() has explicitly
      // re-queued (i.e. test has asked for completion). In deferred mode the
      // initial parked items wait for an explicit drive_next_pending() call.
      if (mReady.empty())
      {
        continue;
      }
      fn = std::move(mReady.front());
      mReady.pop();
    }
    // Run on the worker thread.
    fn();
  }
}

// ----- NamespaceHistoryDelegate overrides -----

void FakeHistoryDelegate::read_raw_async(
  const ReadContext& context, std::vector<ReadRawItem> items, ReadRawCallback callback) noexcept
{
  std::optional<StagedReadRaw> staged;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mReadRawCalls;
    ReadRawCall log;
    log.items = items;
    log.context = context;
    mReadRawCallLog.push_back(std::move(log));
    mLastCancelled = context.cancelled;
    staged = mStagedReadRaw;
    mStagedReadRaw.reset();
  }

  if (!staged)
  {
    // Default: defer to base (BadHistoryOperationUnsupported per item).
    NamespaceHistoryDelegate::read_raw_async(context, std::move(items), std::move(callback));
    return;
  }

  auto run = [staged = *staged, items = std::move(items), callback = std::move(callback)]() mutable
  {
    BatchResult<ReadRawItemResult> batch;
    switch (staged.kind)
    {
    case StagedReadRawKind::BatchFailure:
      batch.batchStatus = VoidResult{staged.status};
      break;
    case StagedReadRawKind::PerItemSuccess:
      batch.items.reserve(items.size());
      for (const auto& item : items)
      {
        HistoryReadRawSuccess success;
        success.values.push_back(staged_value(static_cast<int32_t>(item.index)));
        batch.items.emplace_back(std::move(success));
      }
      break;
    case StagedReadRawKind::PerItemStatuses:
      batch.items.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        StatusCode s =
          i < staged.perItemStatuses.size() ? staged.perItemStatuses[i] : StatusCode{Status::Good};
        if (s.is_bad())
        {
          batch.items.emplace_back(ReadRawItemResult{s});
        }
        else
        {
          HistoryReadRawSuccess success;
          success.values.push_back(staged_value(static_cast<int32_t>(items[i].index)));
          batch.items.emplace_back(std::move(success));
        }
      }
      break;
    }
    callback(std::move(batch));
  };

  park_or_run(std::move(run));
}

void FakeHistoryDelegate::update_data_async(
  const UpdateContext& context, std::vector<UpdateDataItem> items, UpdateDataCallback callback) noexcept
{
  std::optional<StagedUpdate> staged;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mUpdateDataCalls;
    UpdateDataCall log;
    log.items = items;
    log.context = context;
    mUpdateDataCallLog.push_back(std::move(log));
    mLastCancelled = context.cancelled;
    staged = mStagedUpdateData;
    mStagedUpdateData.reset();
  }

  if (!staged)
  {
    NamespaceHistoryDelegate::update_data_async(context, std::move(items), std::move(callback));
    return;
  }

  auto run = [staged = *staged, items = std::move(items), callback = std::move(callback)]() mutable
  {
    BatchResult<UpdateDataItemResult> batch;
    if (staged.kind == StagedUpdateKind::BatchFailure)
    {
      batch.batchStatus = VoidResult{staged.status};
    }
    else
    {
      batch.items.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        HistoryUpdateSuccess success;
        batch.items.emplace_back(std::move(success));
      }
    }
    callback(std::move(batch));
  };

  park_or_run(std::move(run));
}

void FakeHistoryDelegate::delete_raw_async(
  const UpdateContext& context, std::vector<DeleteRawItem> items, DeleteRawCallback callback) noexcept
{
  std::optional<StagedUpdate> staged;
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mDeleteRawCalls;
    DeleteRawCall log;
    log.items = items;
    log.context = context;
    mDeleteRawCallLog.push_back(std::move(log));
    mLastCancelled = context.cancelled;
    staged = mStagedDeleteRaw;
    mStagedDeleteRaw.reset();
  }

  if (!staged)
  {
    NamespaceHistoryDelegate::delete_raw_async(context, std::move(items), std::move(callback));
    return;
  }

  auto run = [staged = *staged, items = std::move(items), callback = std::move(callback)]() mutable
  {
    BatchResult<DeleteItemResult> batch;
    if (staged.kind == StagedUpdateKind::BatchFailure)
    {
      batch.batchStatus = VoidResult{staged.status};
    }
    else
    {
      batch.items.reserve(items.size());
      for (size_t i = 0; i < items.size(); ++i)
      {
        HistoryUpdateSuccess success;
        batch.items.emplace_back(std::move(success));
      }
    }
    callback(std::move(batch));
  };

  park_or_run(std::move(run));
}

void FakeHistoryDelegate::delete_at_time_async(
  const UpdateContext& context, std::vector<DeleteAtTimeItem> items, DeleteAtTimeCallback callback) noexcept
{
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mDeleteAtTimeCalls;
    mLastCancelled = context.cancelled;
  }
  // Default base: per-item BadHistoryOperationUnsupported.
  NamespaceHistoryDelegate::delete_at_time_async(context, std::move(items), std::move(callback));
}

void FakeHistoryDelegate::delete_events_async(
  const UpdateContext& context, std::vector<DeleteEventsItem> items, DeleteEventsCallback callback) noexcept
{
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mDeleteEventsCalls;
    mLastCancelled = context.cancelled;
  }
  NamespaceHistoryDelegate::delete_events_async(context, std::move(items), std::move(callback));
}

// ----- HistoryPinNamespace -----

HistoryPinNamespace::HistoryPinNamespace(std::string_view uri, boost::asio::any_io_executor executor)
  : ua::default_ns::Namespace(uri, std::move(executor))
{}

void HistoryPinNamespace::set_delegate(std::shared_ptr<FakeHistoryDelegate> delegate)
{
  mDelegate = std::move(delegate);
}

std::shared_ptr<ua::NamespaceHistoryDelegate> HistoryPinNamespace::history_delegate() noexcept
{
  return mDelegate;
}

}  // namespace ua::test::behaviour_pins::phase_4_5e
