// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "register_nodes_recording_namespace.h"

#include <algorithm>
#include <utility>

namespace ua::test
{

namespace
{

/// How deep this thread is inside a register call or answer of a RegisterNodesRecordingNamespace.
thread_local int gRegisterDepth = 0;

struct InsideRegister
{
  InsideRegister()
  {
    ++gRegisterDepth;
  }

  ~InsideRegister()
  {
    --gRegisterDepth;
  }

  InsideRegister(const InsideRegister&) = delete;
  InsideRegister& operator=(const InsideRegister&) = delete;
};

}  // namespace

std::shared_ptr<RegisterNodesRecordingNamespace> RegisterNodesRecordingNamespace::create(
  string_view uri, boost::asio::any_io_executor executor)
{
  return std::shared_ptr<RegisterNodesRecordingNamespace>(
    new RegisterNodesRecordingNamespace(uri, std::move(executor)));
}

RegisterNodesRecordingNamespace::RegisterNodesRecordingNamespace(
  string_view uri, boost::asio::any_io_executor executor)
  : default_ns::Namespace(uri, std::move(executor))
{}

shared_ptr<NamespaceRegisterNodesDelegate> RegisterNodesRecordingNamespace::register_nodes_delegate() noexcept
{
  return std::static_pointer_cast<NamespaceRegisterNodesDelegate>(
    std::enable_shared_from_this<RegisterNodesRecordingNamespace>::shared_from_this());
}

void RegisterNodesRecordingNamespace::answer_registers(RegisterAnswer how)
{
  const std::lock_guard lock{mMutex};
  mRegisterAnswer = how;
}

void RegisterNodesRecordingNamespace::alias_next(std::vector<NodeId> nodeIds)
{
  const std::lock_guard lock{mMutex};
  mAliases.insert(mAliases.end(), nodeIds.begin(), nodeIds.end());
}

std::size_t RegisterNodesRecordingNamespace::register_calls() const
{
  const std::lock_guard lock{mMutex};
  return mRegisterCalls;
}

std::size_t RegisterNodesRecordingNamespace::held_register_answers() const
{
  const std::lock_guard lock{mMutex};
  return mHeldAnswers.size();
}

void RegisterNodesRecordingNamespace::release_register_answers()
{
  std::vector<std::function<void()>> held;
  {
    const std::lock_guard lock{mMutex};
    held.swap(mHeldAnswers);
  }
  for (auto& answer : held)
  {
    answer();
  }
}

void RegisterNodesRecordingNamespace::answer_kept_calls_again()
{
  std::vector<std::pair<std::vector<Item>, RegisterCompleteCallback>> kept;
  std::vector<BatchResult<NodeId>> answers;
  {
    const std::lock_guard lock{mMutex};
    kept.swap(mKeptCalls);
    for (const auto& [items, callback] : kept)
    {
      answers.push_back(answer_locked(items, 0));
    }
  }
  for (std::size_t i = 0; i < kept.size(); ++i)
  {
    deliver(kept[i].second, std::move(answers[i]));
  }
}

void RegisterNodesRecordingNamespace::answer_batch_status(StatusCode status)
{
  const std::lock_guard lock{mMutex};
  mBatchStatus = std::move(status);
}

void RegisterNodesRecordingNamespace::answer_unregisters(StatusCode status)
{
  const std::lock_guard lock{mMutex};
  mUnregisterAnswer = std::move(status);
}

std::vector<NodeId> RegisterNodesRecordingNamespace::returned() const
{
  const std::lock_guard lock{mMutex};
  return mReturned;
}

std::vector<std::vector<NodeId>> RegisterNodesRecordingNamespace::unregister_calls() const
{
  const std::lock_guard lock{mMutex};
  return mUnregisterCalls;
}

std::vector<NodeId> RegisterNodesRecordingNamespace::unregistered() const
{
  const std::lock_guard lock{mMutex};
  std::vector<NodeId> all;
  for (const auto& call : mUnregisterCalls)
  {
    all.insert(all.end(), call.begin(), call.end());
  }
  return all;
}

std::size_t RegisterNodesRecordingNamespace::unregistered_count(const NodeId& nodeId) const
{
  const auto all = unregistered();
  return static_cast<std::size_t>(std::count(all.begin(), all.end(), nodeId));
}

bool RegisterNodesRecordingNamespace::unregistered_inside_a_register_answer() const
{
  const std::lock_guard lock{mMutex};
  return mUnregisteredInsideAnswer;
}

BatchResult<NodeId> RegisterNodesRecordingNamespace::answer_locked(
  const std::vector<Item>& items, std::size_t extra)
{
  BatchResult<NodeId> answer;
  for (std::size_t i = 0; i < items.size() + extra; ++i)
  {
    NodeId returnedId;
    if (!mAliases.empty())
    {
      returnedId = mAliases.front();
      mAliases.pop_front();
    }
    else
    {
      returnedId = items[std::min(i, items.size() - 1)].nodeId;
    }
    mReturned.push_back(returnedId);
    answer.items.push_back(std::move(returnedId));
  }
  if (!mBatchStatus.is_good())
  {
    answer.batchStatus = VoidResult{mBatchStatus};
  }
  return answer;
}

void RegisterNodesRecordingNamespace::deliver(
  const RegisterCompleteCallback& callback, BatchResult<NodeId> answer)
{
  const InsideRegister inside;
  callback(std::move(answer));
}

void RegisterNodesRecordingNamespace::register_nodes_async(
  const Context& /*context*/, std::vector<Item> items, RegisterCompleteCallback callback) noexcept
{
  const InsideRegister inside;
  RegisterAnswer how{};
  BatchResult<NodeId> first;
  BatchResult<NodeId> second;
  {
    const std::lock_guard lock{mMutex};
    ++mRegisterCalls;
    how = mRegisterAnswer;
    switch (how)
    {
    case RegisterAnswer::Hold:
    {
      auto answer = std::make_shared<BatchResult<NodeId>>(answer_locked(items, 0));
      mHeldAnswers.push_back([callback, answer]() { deliver(callback, std::move(*answer)); });
      return;
    }
    case RegisterAnswer::Twice:
      first = answer_locked(items, 0);
      second = answer_locked(items, 0);
      break;
    case RegisterAnswer::NowAndKeep:
      first = answer_locked(items, 0);
      mKeptCalls.emplace_back(items, callback);
      break;
    case RegisterAnswer::OneTooMany:
      first = answer_locked(items, 1);
      break;
    default:
      first = answer_locked(items, 0);
      break;
    }
  }
  deliver(callback, std::move(first));
  if (how == RegisterAnswer::Twice)
  {
    deliver(callback, std::move(second));
  }
}

void RegisterNodesRecordingNamespace::unregister_nodes_async(
  const Context& /*context*/, std::vector<Item> items, UnregisterCompleteCallback callback) noexcept
{
  StatusCode answer;
  {
    const std::lock_guard lock{mMutex};
    std::vector<NodeId> call;
    for (const auto& item : items)
    {
      call.push_back(item.nodeId);
    }
    mUnregisterCalls.push_back(std::move(call));
    if (gRegisterDepth > 0)
    {
      mUnregisteredInsideAnswer = true;
    }
    answer = mUnregisterAnswer;
  }
  callback(answer.is_good() ? VoidResult{} : VoidResult{answer});
}

}  // namespace ua::test
