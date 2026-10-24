// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "monitoring_recording_namespace.h"
#include "per_item_join.h"

#include "ua_exceptions.h"
#include "ua_node.h"

#include <boost/asio/post.hpp>

#include <utility>

namespace ua::test
{

namespace
{

/// How deep this thread is inside a create_monitoring_async call or answer of a MonitoringRecordingNamespace.
thread_local int gCreateAnswerDepth = 0;

/// Marks this thread as inside a create_monitoring_async call or answer for its lifetime.
struct InsideCreate
{
  InsideCreate()
  {
    ++gCreateAnswerDepth;
  }

  ~InsideCreate()
  {
    --gCreateAnswerDepth;
  }

  InsideCreate(const InsideCreate&) = delete;
  InsideCreate& operator=(const InsideCreate&) = delete;
};

}  // namespace

struct MonitoringRecordingNamespace::ValueReadHold
{
  mutable std::mutex mutex;
  bool hold{false};
  std::vector<std::function<void()>> parked;
};

std::shared_ptr<MonitoringRecordingNamespace> MonitoringRecordingNamespace::create(
  string_view uri, boost::asio::any_io_executor executor, MonitoringHandle firstHandle)
{
  return std::shared_ptr<MonitoringRecordingNamespace>(
    new MonitoringRecordingNamespace(uri, std::move(executor), firstHandle));
}

MonitoringRecordingNamespace::MonitoringRecordingNamespace(
  string_view uri, boost::asio::any_io_executor executor, MonitoringHandle firstHandle)
  : default_ns::Namespace(uri, executor), mNextHandle(firstHandle), mExecutor(std::move(executor)),
    mValueReadHold(std::make_shared<ValueReadHold>())
{}

void MonitoringRecordingNamespace::hold_value_reads()
{
  const std::lock_guard lock{mValueReadHold->mutex};
  mValueReadHold->hold = true;
}

std::size_t MonitoringRecordingNamespace::held_value_reads() const
{
  const std::lock_guard lock{mValueReadHold->mutex};
  return mValueReadHold->parked.size();
}

void MonitoringRecordingNamespace::release_value_reads()
{
  std::vector<std::function<void()>> parked;
  {
    const std::lock_guard lock{mValueReadHold->mutex};
    mValueReadHold->hold = false;
    parked.swap(mValueReadHold->parked);
  }
  for (auto& answer : parked)
  {
    boost::asio::post(mExecutor, std::move(answer));
  }
}

void MonitoringRecordingNamespace::read_values_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
  std::function<void(BatchResult<DataValueResult>)> complete)
{
  auto join = std::make_shared<test::PerItemJoin<DataValueResult>>(items.size(), std::move(complete));
  for (std::size_t index = 0; index < items.size(); ++index)
  {
    const ValueReadItem one[]{items[index]};
    default_ns::Namespace::read_values_async(request,
      caller,
      one,
      maxAge,
      setSourceTimestamp,
      [hold = mValueReadHold, join, index](BatchResult<DataValueResult> read)
      {
        auto shared = std::make_shared<DataValueResult>(test::only_item(std::move(read)));
        std::function<void()> answer = [join, index, shared]
        {
          join->answer(index, std::move(*shared));
        };
        {
          const std::lock_guard lock{hold->mutex};
          if (hold->hold)
          {
            hold->parked.push_back(std::move(answer));
            return;
          }
        }
        answer();
      });
  }
  join->started();
}

void MonitoringRecordingNamespace::answer_creates(CreateAnswer how, StatusCode thrown)
{
  const std::lock_guard lock{mMutex};
  mCreateAnswer = how;
  mThrown = std::move(thrown);
}

void MonitoringRecordingNamespace::issue_next(std::vector<MonitoringHandle> handles)
{
  const std::lock_guard lock{mMutex};
  mScriptedHandles.insert(mScriptedHandles.end(), handles.begin(), handles.end());
}

void MonitoringRecordingNamespace::answer_next_create_items(std::vector<std::optional<StatusCode>> results)
{
  const std::lock_guard lock{mMutex};
  mScriptedCreateItems.insert(mScriptedCreateItems.end(), results.begin(), results.end());
}

void MonitoringRecordingNamespace::answer_next_modify_items(std::vector<std::optional<StatusCode>> results)
{
  const std::lock_guard lock{mMutex};
  mScriptedModifyItems.insert(mScriptedModifyItems.end(), results.begin(), results.end());
}

std::size_t MonitoringRecordingNamespace::create_calls() const
{
  const std::lock_guard lock{mMutex};
  return mCreateCalls;
}

std::vector<std::vector<LocaleId>> MonitoringRecordingNamespace::create_locales() const
{
  const std::lock_guard lock{mMutex};
  return mCreateLocales;
}

std::vector<std::vector<LocaleId>> MonitoringRecordingNamespace::modify_locales() const
{
  const std::lock_guard lock{mMutex};
  return mModifyLocales;
}

std::size_t MonitoringRecordingNamespace::held_create_answers() const
{
  const std::lock_guard lock{mMutex};
  return mHeldCreateAnswers.size();
}

void MonitoringRecordingNamespace::release_create_answers()
{
  std::vector<std::function<void()>> held;
  {
    const std::lock_guard lock{mMutex};
    held.swap(mHeldCreateAnswers);
  }
  for (auto& answer : held)
  {
    answer();
  }
}

void MonitoringRecordingNamespace::hold_delete_answers()
{
  const std::lock_guard lock{mMutex};
  mHoldDeleteAnswers = true;
}

std::size_t MonitoringRecordingNamespace::held_delete_answers() const
{
  const std::lock_guard lock{mMutex};
  return mHeldDeleteAnswers.size();
}

void MonitoringRecordingNamespace::release_delete_answers()
{
  std::vector<std::function<void()>> held;
  {
    const std::lock_guard lock{mMutex};
    mHoldDeleteAnswers = false;
    held.swap(mHeldDeleteAnswers);
  }
  for (auto& answer : held)
  {
    answer();
  }
}

void MonitoringRecordingNamespace::fail_deletes(StatusCode batchStatus)
{
  const std::lock_guard lock{mMutex};
  mDeleteFailure = std::move(batchStatus);
}

void MonitoringRecordingNamespace::throw_from_deletes(StatusCode status)
{
  const std::lock_guard lock{mMutex};
  mDeleteThrow = std::move(status);
}

std::vector<MonitoringHandle> MonitoringRecordingNamespace::issued_handles() const
{
  const std::lock_guard lock{mMutex};
  return mIssued;
}

std::vector<std::vector<MonitoringHandle>> MonitoringRecordingNamespace::delete_calls() const
{
  const std::lock_guard lock{mMutex};
  return mDeleteCalls;
}

std::vector<MonitoringHandle> MonitoringRecordingNamespace::released_handles() const
{
  const std::lock_guard lock{mMutex};
  std::vector<MonitoringHandle> released;
  for (const auto& call : mDeleteCalls)
  {
    released.insert(released.end(), call.begin(), call.end());
  }
  return released;
}

bool MonitoringRecordingNamespace::deleted_inside_a_create_answer() const
{
  const std::lock_guard lock{mMutex};
  return mDeletedInsideCreateAnswer;
}

BatchResult<MonitoringCreateItemResult> MonitoringRecordingNamespace::issue_locked(std::size_t count)
{
  BatchResult<MonitoringCreateItemResult> answer;
  for (std::size_t i = 0; i < count; ++i)
  {
    if (!mScriptedCreateItems.empty())
    {
      auto scripted = std::move(mScriptedCreateItems.front());
      mScriptedCreateItems.pop_front();
      if (scripted)
      {
        answer.items.emplace_back(MonitoringCreateItemResult{std::move(*scripted)});
        continue;
      }
    }
    MonitoringHandle handle = 0;
    if (!mScriptedHandles.empty())
    {
      handle = mScriptedHandles.front();
      mScriptedHandles.pop_front();
    }
    else
    {
      handle = mNextHandle++;
    }
    mIssued.push_back(handle);
    answer.items.emplace_back(MonitoringCreateSuccess{handle, 0});
  }
  return answer;
}

void MonitoringRecordingNamespace::deliver_create(
  const CreateMonitoringCallback& callback, BatchResult<MonitoringCreateItemResult> answer)
{
  const InsideCreate inside;
  callback(std::move(answer));
}

void MonitoringRecordingNamespace::create_monitoring_async(const RequestInfo& request,
  const CallerInfo* /*caller*/, std::span<const MonitoringCreateItem> items,
  std::function<void(BatchResult<MonitoringCreateItemResult>)> complete)
{
  const CreateMonitoringCallback callback = std::move(complete);
  const InsideCreate inside;
  CreateAnswer how{};
  StatusCode thrown;
  BatchResult<MonitoringCreateItemResult> first;
  BatchResult<MonitoringCreateItemResult> second;
  {
    const std::lock_guard lock{mMutex};
    ++mCreateCalls;
    mCreateLocales.push_back(request.locales);
    how = mCreateAnswer;
    thrown = mThrown;
    switch (how)
    {
    case CreateAnswer::Throw:
      break;
    case CreateAnswer::OmitLast:
      first = issue_locked(items.empty() ? 0 : items.size() - 1);
      break;
    case CreateAnswer::IssueTwice:
      first = issue_locked(items.size());
      second = issue_locked(items.size());
      break;
    case CreateAnswer::Hold:
    {
      auto answer = std::make_shared<BatchResult<MonitoringCreateItemResult>>(issue_locked(items.size()));
      mHeldCreateAnswers.push_back([callback, answer]() { deliver_create(callback, std::move(*answer)); });
      return;
    }
    default:
      first = issue_locked(items.size());
      break;
    }
  }
  switch (how)
  {
  case CreateAnswer::Throw:
    throw UaException(thrown);
  case CreateAnswer::IssueThenThrow:
    deliver_create(callback, std::move(first));
    throw UaException(thrown);
  case CreateAnswer::IssueTwice:
    deliver_create(callback, std::move(first));
    deliver_create(callback, std::move(second));
    return;
  default:
    deliver_create(callback, std::move(first));
    return;
  }
}

void MonitoringRecordingNamespace::delete_monitoring_async(const RequestInfo& /*request*/,
  std::span<const MonitoringHandle> handles, std::function<void(BatchResult<VoidResult>)> callback)
{
  std::optional<StatusCode> failure;
  std::optional<StatusCode> toThrow;
  {
    const std::lock_guard lock{mMutex};
    mDeleteCalls.emplace_back(handles.begin(), handles.end());
    if (gCreateAnswerDepth > 0)
    {
      mDeletedInsideCreateAnswer = true;
    }
    failure = mDeleteFailure;
    toThrow = mDeleteThrow;
  }
  if (toThrow)
  {
    throw UaException(*toThrow);
  }
  BatchResult<VoidResult> answer;
  if (failure)
  {
    answer.batchStatus = VoidResult{*failure};
  }
  else
  {
    answer.items.resize(handles.size());
  }
  {
    const std::lock_guard lock{mMutex};
    if (mHoldDeleteAnswers)
    {
      auto held = std::make_shared<BatchResult<VoidResult>>(std::move(answer));
      mHeldDeleteAnswers.push_back([callback, held]() { callback(std::move(*held)); });
      return;
    }
  }
  callback(std::move(answer));
}

void MonitoringRecordingNamespace::modify_monitoring_async(const RequestInfo& request,
  std::span<const MonitoringModifyItem> items,
  std::function<void(BatchResult<MonitoringModifyItemResult>)> callback)
{
  BatchResult<MonitoringModifyItemResult> answer;
  {
    const std::lock_guard lock{mMutex};
    mModifyLocales.push_back(request.locales);
    for (const auto& item : items)
    {
      if (!mScriptedModifyItems.empty())
      {
        auto scripted = std::move(mScriptedModifyItems.front());
        mScriptedModifyItems.pop_front();
        if (scripted)
        {
          answer.items.emplace_back(MonitoringModifyItemResult{std::move(*scripted)});
          continue;
        }
      }
      answer.items.emplace_back(MonitoringModifySuccess{item.samplingInterval});
    }
  }
  callback(std::move(answer));
}

}  // namespace ua::test
