// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "every_node_in_view_namespace.h"

#include "ua_node.h"
#include "ua_node_class.h"

#include <cstddef>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace ua::test
{

namespace
{

/// The answers to one view_contains_async call, which arrive in any order and from any thread: the call
/// completes once, with one answer per candidate in candidate order, when the last has arrived. A second
/// answer for a candidate is dropped.
class MembershipAnswers
{
public:
  MembershipAnswers(std::size_t count, std::function<void(BatchResult<BoolResult>)> complete)
    : mAnswers(count), mRemaining(count), mComplete(std::move(complete))
  {}

  void answer(std::size_t index, BoolResult result)
  {
    {
      const std::lock_guard lock{mMutex};
      if (mAnswers[index].has_value())
      {
        return;
      }
      mAnswers[index] = std::move(result);
      if (--mRemaining != 0)
      {
        return;
      }
    }
    BatchResult<BoolResult> batch;
    batch.items.reserve(mAnswers.size());
    for (auto& answered : mAnswers)
    {
      batch.items.push_back(std::move(*answered));
    }
    mComplete(std::move(batch));
  }

private:
  std::mutex mMutex;
  std::vector<std::optional<BoolResult>> mAnswers;
  std::size_t mRemaining;
  std::function<void(BatchResult<BoolResult>)> mComplete;
};

}  // namespace

std::shared_ptr<EveryNodeInViewNamespace> EveryNodeInViewNamespace::create(
  string_view uri, boost::asio::any_io_executor executor, MembershipAnswer answer)
{
  // A synchronous answer is a deferred one given at once; an empty one is true for every NodeId.
  DeferredMembershipAnswer atOnce = [answer = std::move(answer)](
                                      const NodeId& nodeId, std::function<void(BoolResult)> callback)
  {
    BoolResult result{true};
    if (answer)
    {
      try
      {
        result = answer(nodeId);
      }
      catch (...)
      {
        result = BoolResult{StatusCode{Status::BadInternalError}};
      }
    }
    callback(std::move(result));
  };
  return create_deferred(uri, std::move(executor), std::move(atOnce));
}

std::shared_ptr<EveryNodeInViewNamespace> EveryNodeInViewNamespace::create_deferred(
  string_view uri, boost::asio::any_io_executor executor, DeferredMembershipAnswer answer)
{
  return std::shared_ptr<EveryNodeInViewNamespace>(
    new EveryNodeInViewNamespace(uri, std::move(executor), std::move(answer)));
}

EveryNodeInViewNamespace::EveryNodeInViewNamespace(
  string_view uri, boost::asio::any_io_executor executor, DeferredMembershipAnswer answer)
  : default_ns::Namespace(uri, std::move(executor)),
    mAnswer(std::make_shared<const DeferredMembershipAnswer>(std::move(answer)))
{}

void EveryNodeInViewNamespace::view_contains_async(const RequestInfo& request, const NodeId& view,
  std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete)
{
  bool ownView = false;
  try
  {
    const NodeResult resolved = resolve_here(view);
    ownView = resolved.is_good() && resolved.value() != nullptr &&
              resolved.value()->attributes().node_class() == NodeClass::View;
  }
  catch (...)
  {
    BatchResult<BoolResult> failed;
    failed.batchStatus = VoidResult{StatusCode{Status::BadInternalError}};
    complete(std::move(failed));
    return;
  }
  if (!ownView)
  {
    default_ns::Namespace::view_contains_async(request, view, nodes, std::move(complete));
    return;
  }
  if (nodes.empty())
  {
    complete(BatchResult<BoolResult>{});
    return;
  }
  auto answers = std::make_shared<MembershipAnswers>(nodes.size(), std::move(complete));
  for (std::size_t index = 0; index < nodes.size(); ++index)
  {
    const ExpandedNodeId& candidate = nodes[index];
    if (!candidate.is_local() || !candidate.namespace_uri().empty())
    {
      answers->answer(index, BoolResult{false});
      continue;
    }
    std::function<void(BoolResult)> callback = [answers, index](BoolResult contained)
    {
      answers->answer(index, std::move(contained));
    };
    // The answer gets a copy, so a question it fails to take is still answered.
    try
    {
      (*mAnswer)(candidate.node_id(), callback);
    }
    catch (...)
    {
      callback(BoolResult{StatusCode{Status::BadInternalError}});
    }
  }
}

}  // namespace ua::test
