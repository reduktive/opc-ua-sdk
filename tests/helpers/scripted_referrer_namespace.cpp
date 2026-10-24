// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "scripted_referrer_namespace.h"

#include "ua_node.h"

#include <boost/asio/post.hpp>

#include <cstddef>
#include <iterator>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace ua::test
{

namespace
{

/// The answers to one batched call, which arrive in any order and from any thread: the call completes once,
/// with one answer per item in item order and every versioned Node reported, when the last has arrived. A
/// second answer for an item is dropped.
template<typename Item>
class Answers
{
public:
  using Complete = std::function<void(BatchResult<Item>, std::vector<VersionedNode>)>;

  Answers(std::size_t count, Complete complete)
    : mAnswers(count), mRemaining(count), mComplete(std::move(complete))
  {}

  void answer(std::size_t index, Item item, std::vector<VersionedNode> versioned)
  {
    {
      const std::lock_guard lock{mMutex};
      if (mAnswers[index].has_value())
      {
        return;
      }
      mAnswers[index] = std::move(item);
      mVersioned.insert(mVersioned.end(),
        std::make_move_iterator(versioned.begin()),
        std::make_move_iterator(versioned.end()));
      if (--mRemaining != 0)
      {
        return;
      }
    }
    BatchResult<Item> batch;
    batch.items.reserve(mAnswers.size());
    for (auto& answered : mAnswers)
    {
      batch.items.push_back(std::move(*answered));
    }
    mComplete(std::move(batch), std::move(mVersioned));
  }

private:
  std::mutex mMutex;
  std::vector<std::optional<Item>> mAnswers;
  std::vector<VersionedNode> mVersioned;
  std::size_t mRemaining;
  Complete mComplete;
};

/// The answer for item @p index of a batch, which was asked for that item alone or with others.
template<typename Item>
Item item_answer(BatchResult<Item>& answered, std::size_t index)
{
  if (answered.batchStatus.is_bad())
  {
    return Item{answered.batchStatus.status_code()};
  }
  if (index >= answered.items.size())
  {
    return Item{StatusCode{Status::BadInternalError}};
  }
  return std::move(answered.items[index]);
}

/// Posts a removal's answer, or parks it while the script holds removals at @p referrer; counts it once
/// @p callback has returned.
void deliver(const std::shared_ptr<ScriptedReferrerNamespace::Script>& script,
  const boost::asio::any_io_executor& executor, const NodeId& referrer,
  std::function<void(VoidResult)> callback, VoidResult result)
{
  std::function<void()> answer =
    [script, referrer, callback = std::move(callback), result = std::move(result)]() mutable
  {
    callback(std::move(result));
    const std::lock_guard lock{script->mutex};
    ++script->answeredRemovals[referrer];
  };
  {
    const std::lock_guard lock{script->mutex};
    if (script->heldRemovals.contains(referrer))
    {
      script->parkedRemovals.push_back(std::move(answer));
      return;
    }
  }
  boost::asio::post(executor, std::move(answer));
}

}  // namespace

std::shared_ptr<ScriptedReferrerNamespace> ScriptedReferrerNamespace::create(
  string_view uri, boost::asio::any_io_executor executor)
{
  auto created =
    std::shared_ptr<ScriptedReferrerNamespace>(new ScriptedReferrerNamespace(uri, std::move(executor)));
  created->mSelf = created;
  return created;
}

ScriptedReferrerNamespace::ScriptedReferrerNamespace(string_view uri, boost::asio::any_io_executor executor)
  : default_ns::Namespace(uri, executor), mExecutor(std::move(executor))
{}

void ScriptedReferrerNamespace::fail_lookups(const NodeId& nodeId, StatusCode status)
{
  const std::lock_guard lock{mMutex};
  mLookupFailures.insert_or_assign(nodeId, std::move(status));
}

void ScriptedReferrerNamespace::answer_removals(const NodeId& referrer, StatusCode status)
{
  const std::lock_guard lock{mScript->mutex};
  mScript->removalAnswers.insert_or_assign(referrer, std::move(status));
}

void ScriptedReferrerNamespace::hold_removals(const NodeId& referrer)
{
  const std::lock_guard lock{mScript->mutex};
  mScript->heldRemovals.insert(referrer);
}

std::size_t ScriptedReferrerNamespace::held_removals() const
{
  const std::lock_guard lock{mScript->mutex};
  return mScript->parkedRemovals.size();
}

void ScriptedReferrerNamespace::release_removals()
{
  std::vector<std::function<void()>> parked;
  {
    const std::lock_guard lock{mScript->mutex};
    mScript->heldRemovals.clear();
    parked.swap(mScript->parkedRemovals);
  }
  for (auto& answer : parked)
  {
    boost::asio::post(mExecutor, std::move(answer));
  }
}

std::size_t ScriptedReferrerNamespace::answered_removals(const NodeId& referrer) const
{
  const std::lock_guard lock{mScript->mutex};
  const auto found = mScript->answeredRemovals.find(referrer);
  return found == mScript->answeredRemovals.end() ? 0u : found->second;
}

void ScriptedReferrerNamespace::refuse_deletes(const NodeId& nodeId, StatusCode status)
{
  const std::lock_guard lock{mMutex};
  mDeleteRefusals.insert_or_assign(nodeId, std::move(status));
}

void ScriptedReferrerNamespace::hold_deletes(const NodeId& nodeId)
{
  const std::lock_guard lock{mMutex};
  mHeldDeletes.insert(nodeId);
}

std::size_t ScriptedReferrerNamespace::held_deletes() const
{
  const std::lock_guard lock{mMutex};
  return mParkedDeletes.size();
}

void ScriptedReferrerNamespace::release_deletes()
{
  std::vector<std::function<void()>> parked;
  {
    const std::lock_guard lock{mMutex};
    mHeldDeletes.clear();
    parked.swap(mParkedDeletes);
  }
  for (auto& answer : parked)
  {
    boost::asio::post(mExecutor, std::move(answer));
  }
}

void ScriptedReferrerNamespace::release_everything()
{
  release_deletes();
  release_removals();
}

void ScriptedReferrerNamespace::remove_references_async(const RequestInfo& request,
  std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  if (changes.empty())
  {
    complete(BatchResult<VoidResult>{}, std::vector<VersionedNode>{});
    return;
  }
  auto answers = std::make_shared<Answers<VoidResult>>(changes.size(), std::move(complete));
  // The changes the default namespace removes, with their places in the batch.
  std::vector<ReferenceChange> removed;
  std::vector<std::size_t> places;
  for (std::size_t index = 0; index < changes.size(); ++index)
  {
    const ReferenceChange& change = changes[index];
    // A referrer whose lookup fails answers with the lookup's status, at once and uncounted.
    const NodeResult referrer = resolve_here(change.source);
    if (referrer.is_bad())
    {
      answers->answer(index, VoidResult{referrer.status_code()}, {});
      continue;
    }
    std::optional<StatusCode> scripted;
    {
      const std::lock_guard lock{mScript->mutex};
      if (const auto found = mScript->removalAnswers.find(change.source);
          found != mScript->removalAnswers.end())
      {
        scripted = found->second;
      }
    }
    if (scripted)
    {
      deliver(
        mScript,
        mExecutor,
        change.source,
        [answers, index](VoidResult result) { answers->answer(index, std::move(result), {}); },
        VoidResult{*scripted});
      continue;
    }
    removed.push_back(change);
    places.push_back(index);
  }
  if (removed.empty())
  {
    return;
  }
  default_ns::Namespace::remove_references_async(request,
    removed,
    [answers, places, removed, script = mScript, executor = mExecutor](
      BatchResult<VoidResult> answered, std::vector<VersionedNode> versioned) mutable
    {
      for (std::size_t k = 0; k < places.size(); ++k)
      {
        // The versioned Nodes travel with the first answer; the batch reports them once.
        std::vector<VersionedNode> reported = k == 0 ? std::move(versioned) : std::vector<VersionedNode>{};
        deliver(
          script,
          executor,
          removed[k].source,
          [answers, place = places[k], reported = std::move(reported)](VoidResult result) mutable
          { answers->answer(place, std::move(result), std::move(reported)); },
          item_answer(answered, k));
      }
    });
}

void ScriptedReferrerNamespace::delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes,
  ReferenceHalves halves,
  std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete)
{
  if (nodes.empty())
  {
    complete(BatchResult<DeleteNodeResult>{}, std::vector<VersionedNode>{});
    return;
  }
  auto answers = std::make_shared<Answers<DeleteNodeResult>>(nodes.size(), std::move(complete));
  for (std::size_t index = 0; index < nodes.size(); ++index)
  {
    const NodeId nodeId = nodes[index];
    std::function<void()> answer;
    {
      const std::lock_guard lock{mMutex};
      if (const auto refused = mDeleteRefusals.find(nodeId); refused != mDeleteRefusals.end())
      {
        answer = [answers, index, status = refused->second]()
        {
          answers->answer(index, DeleteNodeResult{status}, {});
        };
      }
      else
      {
        // A held delete runs after this call has returned, so it keeps its own copy of the request.
        answer = [weakSelf = mSelf, request, nodeId, halves, answers, index]()
        {
          auto self = weakSelf.lock();
          if (!self)
          {
            answers->answer(index, DeleteNodeResult{StatusCode{Status::BadShutdown}}, {});
            return;
          }
          const NodeId one[]{nodeId};
          self->default_ns::Namespace::delete_nodes_async(request,
            one,
            halves,
            [answers, index](BatchResult<DeleteNodeResult> deleted, std::vector<VersionedNode> versioned)
            { answers->answer(index, item_answer(deleted, 0), std::move(versioned)); });
        };
      }
      if (mHeldDeletes.contains(nodeId))
      {
        mParkedDeletes.push_back(std::move(answer));
        continue;
      }
    }
    answer();
  }
}

NodeResult ScriptedReferrerNamespace::resolve_here(const NodeId& nodeId)
{
  {
    const std::lock_guard lock{mMutex};
    if (const auto failed = mLookupFailures.find(nodeId); failed != mLookupFailures.end())
    {
      return NodeResult{failed->second};
    }
  }
  return default_ns::Namespace::resolve_here(nodeId);
}

}  // namespace ua::test
