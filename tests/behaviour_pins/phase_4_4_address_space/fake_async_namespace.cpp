// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_async_namespace.h"

#include <cstdio>
#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "per_item_join.h"

#include "ua_attribute_id.h"
#include "ua_error_detail.h"
#include "ua_status_code.h"

namespace ua::test::behaviour_pins
{
namespace
{

std::shared_ptr<const ErrorDetail> missing_canned_detail(std::string_view opName)
{
  return make_error_detail("FakeMissingCannedResult",
    std::string{"FakeAsyncNamespace::"} + std::string{opName} + " has no canned result staged",
    "FakeAsyncNamespace");
}

NodeResult missing_canned_node_result(std::string_view opName)
{
  return NodeResult{StatusCode{Status::BadInternalError}, missing_canned_detail(opName)};
}

DeleteNodeResult missing_canned_delete_result()
{
  return DeleteNodeResult{StatusCode{Status::BadInternalError},
    make_error_detail("FakeMissingCannedResult",
      "FakeAsyncNamespace::delete_nodes_async has no canned result staged",
      "FakeAsyncNamespace")};
}

template<typename T>
BatchResult<T> missing_canned_batch_result(std::string_view opName, std::size_t itemCount)
{
  BatchResult<T> result;
  result.batchStatus = VoidResult{StatusCode{Status::BadInternalError},
    make_error_detail("FakeMissingCannedResult",
      std::string{"FakeAsyncNamespace::"} + std::string{opName} + " has no canned result staged",
      "FakeAsyncNamespace")};
  result.items.reserve(itemCount);
  for (std::size_t i = 0; i < itemCount; ++i)
  {
    result.items.emplace_back(StatusCode{Status::BadInternalError});
  }
  return result;
}

/// The front of @p queue, removed; a BadInternalError flagging the missing canned result when it is empty.
template<typename Answer>
Answer take_front(std::deque<Answer>& queue, std::string_view opName)
{
  if (queue.empty())
  {
    return Answer{StatusCode{Status::BadInternalError}, missing_canned_detail(opName)};
  }
  Answer front = std::move(queue.front());
  queue.pop_front();
  return front;
}

}  // namespace

std::shared_ptr<FakeAsyncNamespace> FakeAsyncNamespace::create(std::string uri)
{
  // Wrapper exposes the protected ctor to make_shared.
  struct Wrapper : public FakeAsyncNamespace
  {
    explicit Wrapper(std::string u) : FakeAsyncNamespace(std::move(u))
    {}
  };

  auto fake = std::make_shared<Wrapper>(std::move(uri));
  fake->mWorker = std::thread(&FakeAsyncNamespace::worker_loop, fake.get());
  fake->mWorkerThreadId = fake->mWorker.get_id();
  return fake;
}

FakeAsyncNamespace::FakeAsyncNamespace(std::string uri) : mUri(std::move(uri))
{}

FakeAsyncNamespace::~FakeAsyncNamespace()
{
  {
    std::lock_guard lock(mMutex);
    mShutdown = true;
  }
  mCond.notify_all();
  if (mWorker.joinable())
  {
    // Self-join would EDEADLK. This happens when a parked-callback's destruct
    // chain unwinds the last shared_ptr<AddressSpaceImpl> ref from this very
    // worker thread, cascading into NamespaceArray -> fake destruction.
    // The fix is at the *call site*: tests that drive deferred fakes through a
    // multi-step flow must call `wait_idle()` after the final user callback
    // fires so the destruct cascade completes while the fixture still holds
    // an AddressSpace ref. The runtime detects the violation here and aborts
    // with a clear message rather than deadlocking silently.
    if (std::this_thread::get_id() == mWorkerThreadId)
    {
      std::fprintf(stderr,
        "[fake_async_namespace] FATAL: ~FakeAsyncNamespace ran on its own worker "
        "thread (uri=%s). This means a parked-callback chain held the last "
        "shared_ptr to a transitive owner (e.g. AddressSpaceImpl) and the "
        "destruct cascade reached the fake on the worker. Call "
        "fake->wait_idle() in the test before TearDown to drain the worker "
        "while the fixture still owns the transitive refs.\n",
        mUri.c_str());
      std::abort();
    }
    mWorker.join();
  }
}

void FakeAsyncNamespace::worker_loop()
{
  while (true)
  {
    std::function<void()> fire;
    {
      std::unique_lock lock(mMutex);
      mCond.wait(lock, [this] { return mShutdown || mReleasedCount > 0; });
      if (mShutdown && mReleasedCount == 0)
      {
        return;
      }
      // mReleasedCount > 0 implies mParked is non-empty (invariant maintained
      // by complete_pending() / complete_all_pending()).
      fire = std::move(mParked.front());
      mParked.pop_front();
      --mReleasedCount;
      mWorkerBusy = true;
    }
    // Fire callback off-lock per the callback-safety golden rule. Continuations may
    // re-enter the fake (e.g. AddressSpace's external-ref cleanup loop) and
    // would otherwise deadlock on mMutex.
    try
    {
      fire();
    }
    catch (...)
    {
      // Defensive: a thrown user callback shouldn't terminate the worker.
    }
    // Explicitly destroy the captured callback chain BEFORE we mark the
    // worker idle. This is the destruct boundary - if the chain held the
    // last shared_ptr to a transitive owner (e.g. AddressSpaceImpl), the
    // cascade runs here while wait_idle() is still blocking the test
    // thread, so the fixture's owning ref keeps the transitive owner alive
    // and prevents fake destruction on the worker. See class comment on
    // wait_idle().
    fire = nullptr;
    {
      std::lock_guard lock(mMutex);
      mWorkerBusy = false;
    }
    mIdleCond.notify_all();
  }
}

void FakeAsyncNamespace::park_locked(std::function<void()> fire)
{
  // Caller holds mMutex.
  mParked.push_back(std::move(fire));
}

// --- Deferral controls ----------------------------------------------------

void FakeAsyncNamespace::set_find_node_deferred(bool deferred)
{
  std::lock_guard lock(mMutex);
  mFindNodeDeferred = deferred;
}

void FakeAsyncNamespace::set_create_node_deferred(bool deferred)
{
  std::lock_guard lock(mMutex);
  mCreateNodeDeferred = deferred;
}

void FakeAsyncNamespace::set_delete_node_deferred(bool deferred)
{
  std::lock_guard lock(mMutex);
  mDeleteNodeDeferred = deferred;
}

void FakeAsyncNamespace::set_create_monitoring_deferred(bool deferred)
{
  std::lock_guard lock(mMutex);
  mCreateMonitoringDeferred = deferred;
}

void FakeAsyncNamespace::set_delete_monitoring_deferred(bool deferred)
{
  std::lock_guard lock(mMutex);
  mDeleteMonitoringDeferred = deferred;
}

void FakeAsyncNamespace::set_modify_monitoring_deferred(bool deferred)
{
  std::lock_guard lock(mMutex);
  mModifyMonitoringDeferred = deferred;
}

// --- Per-op canned results ------------------------------------------------

void FakeAsyncNamespace::set_next_find_node_result(NodeResult result)
{
  std::lock_guard lock(mMutex);
  mNextFindNodeResults.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_create_node_result(NodeResult result)
{
  std::lock_guard lock(mMutex);
  mNextCreateNodeResults.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_delete_node_result(DeleteNodeResult result)
{
  std::lock_guard lock(mMutex);
  mNextDeleteNodeResults.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_create_monitoring_result(BatchResult<MonitoringCreateItemResult> result)
{
  std::lock_guard lock(mMutex);
  mNextCreateMonitoringResults.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_delete_monitoring_result(BatchResult<VoidResult> result)
{
  std::lock_guard lock(mMutex);
  mNextDeleteMonitoringResults.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_modify_monitoring_result(BatchResult<MonitoringModifyItemResult> result)
{
  std::lock_guard lock(mMutex);
  mNextModifyMonitoringResults.push_back(std::move(result));
}

void FakeAsyncNamespace::hold(const NodeId& nodeId, std::shared_ptr<Node> node)
{
  std::lock_guard lock(mMutex);
  mHeld[nodeId] = std::move(node);
}

// --- Per-NodeId canned answers --------------------------------------------

void FakeAsyncNamespace::set_next_get_references(const NodeId& nodeId, NodeAccessor::ReferencesResult result)
{
  NodeReferencesResult answer =
    result.is_good() ? NodeReferencesResult{NodeReferences{std::move(result).value(), ByteString{}}}
                     : NodeReferencesResult{result.status_code()};
  std::lock_guard lock(mMutex);
  mNodeScripts[nodeId].references.push_back(std::move(answer));
}

void FakeAsyncNamespace::set_next_get_references_page(
  const NodeId& nodeId, NodeAccessor::ReferencesPageResult result)
{
  NodeReferencesResult answer = NodeReferencesResult{StatusCode{Status::BadInternalError}};
  if (result.is_good())
  {
    NodeAccessor::ReferencePage page = std::move(result).value();
    answer =
      NodeReferencesResult{NodeReferences{std::move(page.references), std::move(page.continuationToken)}};
  }
  else
  {
    answer = NodeReferencesResult{result.status_code()};
  }
  std::lock_guard lock(mMutex);
  mNodeScripts[nodeId].references.push_back(std::move(answer));
}

void FakeAsyncNamespace::set_next_add_reference(const NodeId& source, VoidResult result)
{
  std::lock_guard lock(mMutex);
  mNodeScripts[source].addReference.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_remove_reference(const NodeId& source, VoidResult result)
{
  std::lock_guard lock(mMutex);
  mNodeScripts[source].removeReference.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_call(const NodeId& method, CallResult result)
{
  std::lock_guard lock(mMutex);
  mNodeScripts[method].call.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_read_value(const NodeId& nodeId, DataValueResult result)
{
  std::lock_guard lock(mMutex);
  mNodeScripts[nodeId].readValue.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_write_value(const NodeId& nodeId, VoidResult result)
{
  std::lock_guard lock(mMutex);
  mNodeScripts[nodeId].writeValue.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_is_node_in_view(const NodeId& view, BoolResult result)
{
  std::lock_guard lock(mMutex);
  mNodeScripts[view].isNodeInView.push_back(std::move(result));
}

void FakeAsyncNamespace::set_next_add_node_to_view(const NodeId& view, VoidResult result)
{
  std::lock_guard lock(mMutex);
  mNodeScripts[view].addNodeToView.push_back(std::move(result));
}

// --- Pending-call introspection ------------------------------------------

std::size_t FakeAsyncNamespace::pending_call_count() const
{
  std::lock_guard lock(mMutex);
  return mParked.size() - mReleasedCount;
}

bool FakeAsyncNamespace::wait_for_pending(std::size_t n, std::chrono::milliseconds timeout) const
{
  // Spin with short sleeps. Most pin uses set n in single digits.
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (true)
  {
    {
      std::lock_guard lock(mMutex);
      if (mParked.size() - mReleasedCount >= n)
      {
        return true;
      }
    }
    if (std::chrono::steady_clock::now() >= deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }
}

void FakeAsyncNamespace::complete_pending()
{
  {
    std::lock_guard lock(mMutex);
    if (mParked.size() <= mReleasedCount)
    {
      throw std::runtime_error(
        "FakeAsyncNamespace::complete_pending called with no parked callback awaiting release");
    }
    ++mReleasedCount;
  }
  mCond.notify_one();
}

std::size_t FakeAsyncNamespace::complete_all_pending()
{
  std::size_t released = 0;
  {
    std::lock_guard lock(mMutex);
    released = mParked.size() - mReleasedCount;
    mReleasedCount = mParked.size();
  }
  mCond.notify_all();
  return released;
}

void FakeAsyncNamespace::wait_idle() const
{
  std::unique_lock lock(mMutex);
  // "Idle" = worker is back in its mCond.wait(), having completed the
  // post-fire destructor cascade. mParked.empty() catches the case where
  // a previous fire() parked further work via re-entry; mReleasedCount==0
  // ensures we don't return while the worker still has greenlit work to
  // pick up.
  mIdleCond.wait(lock, [this] { return !mWorkerBusy && mParked.empty() && mReleasedCount == 0; });
}

std::thread::id FakeAsyncNamespace::worker_thread_id() const noexcept
{
  return mWorkerThreadId;
}

std::vector<FakeAsyncNamespace::RecordedCall> FakeAsyncNamespace::recorded_calls() const
{
  std::lock_guard lock(mMutex);
  return mRecordedCalls;
}

// --- Recorded operations on a Node ------------------------------------------

template<typename Recorded>
std::vector<Recorded> FakeAsyncNamespace::recorded_of(
  const NodeId& nodeId, std::vector<Recorded> NodeScript::*recorded) const
{
  std::lock_guard lock(mMutex);
  const auto found = mNodeScripts.find(nodeId);
  return found == mNodeScripts.end() ? std::vector<Recorded>{} : found->second.*recorded;
}

std::size_t FakeAsyncNamespace::recorded_get_references_count(const NodeId& nodeId) const
{
  return recorded_of(nodeId, &NodeScript::referenceQueries).size();
}

std::vector<FakeAsyncNamespace::GetReferencesPageCall> FakeAsyncNamespace::recorded_get_references_page_calls(
  const NodeId& nodeId) const
{
  return recorded_of(nodeId, &NodeScript::referenceQueries);
}

std::vector<FakeAsyncNamespace::AddReferenceCall> FakeAsyncNamespace::recorded_add_reference_calls(
  const NodeId& source) const
{
  return recorded_of(source, &NodeScript::addReferenceCalls);
}

std::vector<FakeAsyncNamespace::RemoveReferenceCall> FakeAsyncNamespace::recorded_remove_reference_calls(
  const NodeId& source) const
{
  return recorded_of(source, &NodeScript::removeReferenceCalls);
}

std::vector<FakeAsyncNamespace::CallCall> FakeAsyncNamespace::recorded_call_calls(const NodeId& method) const
{
  return recorded_of(method, &NodeScript::callCalls);
}

std::vector<FakeAsyncNamespace::ReadValueCall> FakeAsyncNamespace::recorded_read_value_calls(
  const NodeId& nodeId) const
{
  return recorded_of(nodeId, &NodeScript::readValueCalls);
}

std::vector<FakeAsyncNamespace::WriteValueCall> FakeAsyncNamespace::recorded_write_value_calls(
  const NodeId& nodeId) const
{
  return recorded_of(nodeId, &NodeScript::writeValueCalls);
}

std::vector<FakeAsyncNamespace::IsNodeInViewCall> FakeAsyncNamespace::recorded_is_node_in_view_calls(
  const NodeId& view) const
{
  return recorded_of(view, &NodeScript::isNodeInViewCalls);
}

std::vector<FakeAsyncNamespace::AddNodeToViewCall> FakeAsyncNamespace::recorded_add_node_to_view_calls(
  const NodeId& view) const
{
  return recorded_of(view, &NodeScript::addNodeToViewCalls);
}

// --- Namespace virtuals --------------------------------------------------

String FakeAsyncNamespace::uri() const
{
  return String{mUri};
}

void FakeAsyncNamespace::find_nodes_async(const RequestInfo& /*request*/, std::span<const NodeId> nodeIds,
  std::optional<Duration> /*maxAge*/, std::function<void(BatchResult<NodeResult>)> complete)
{
  // Records and parks each id separately; resolve_each completes the batch once every parked entry has been
  // released.
  resolve_each(nodeIds,
    std::move(complete),
    [this](const NodeId& nodeId, std::function<void(NodeResult)> done)
    { resolve_one(nodeId, std::move(done)); });
}

void FakeAsyncNamespace::resolve_one(const NodeId& nodeId, std::function<void(NodeResult)> callback)
{
  bool deferred;
  std::optional<NodeResult> cannedResult;
  {
    std::lock_guard lock(mMutex);
    mRecordedCalls.push_back(RecordedCall{Op::FindNode, nodeId, NodeClass::Unspecified, 0});
    deferred = mFindNodeDeferred;
    if (const auto held = mHeld.find(nodeId); held != mHeld.end())
    {
      cannedResult.emplace(held->second);
    }
    else if (mNextFindNodeResults.empty())
    {
      cannedResult.emplace(missing_canned_node_result("find_nodes_async"));
    }
    else
    {
      cannedResult.emplace(std::move(mNextFindNodeResults.front()));
      mNextFindNodeResults.pop_front();
    }
  }

  if (!deferred)
  {
    callback(std::move(*cannedResult));
    return;
  }

  std::lock_guard lock(mMutex);
  park_locked([callback = std::move(callback), value = std::move(*cannedResult)]() mutable
    { callback(std::move(value)); });
}

void FakeAsyncNamespace::create_nodes_async(const RequestInfo& /*request*/,
  std::span<const NodeCreation> nodes, std::function<void(BatchResult<NodeResult>)> complete)
{
  auto join = std::make_shared<test::PerItemJoin<NodeResult>>(nodes.size(), std::move(complete));
  for (std::size_t index = 0; index < nodes.size(); ++index)
  {
    create_one(nodes[index], [join, index](NodeResult created) { join->answer(index, std::move(created)); });
  }
  join->started();
}

void FakeAsyncNamespace::create_one(const NodeCreation& creation, std::function<void(NodeResult)> callback)
{
  bool deferred;
  std::optional<NodeResult> cannedResult;
  {
    std::lock_guard lock(mMutex);
    mRecordedCalls.push_back(RecordedCall{Op::CreateNode, creation.nodeId, creation.nodeClass, 0});
    deferred = mCreateNodeDeferred;
    if (mNextCreateNodeResults.empty())
    {
      cannedResult.emplace(missing_canned_node_result("create_nodes_async"));
    }
    else
    {
      cannedResult.emplace(std::move(mNextCreateNodeResults.front()));
      mNextCreateNodeResults.pop_front();
    }
  }

  if (!deferred)
  {
    callback(std::move(*cannedResult));
    return;
  }

  std::lock_guard lock(mMutex);
  park_locked([callback = std::move(callback), value = std::move(*cannedResult)]() mutable
    { callback(std::move(value)); });
}

void FakeAsyncNamespace::delete_nodes_async(const RequestInfo& /*request*/, std::span<const NodeId> nodes,
  ReferenceHalves /*halves*/,
  std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete)
{
  auto join = std::make_shared<test::PerItemJoin<DeleteNodeResult>>(nodes.size(),
    [complete = std::move(complete)](BatchResult<DeleteNodeResult> deleted)
    { complete(std::move(deleted), std::vector<VersionedNode>{}); });
  for (std::size_t index = 0; index < nodes.size(); ++index)
  {
    delete_one(
      nodes[index], [join, index](DeleteNodeResult deleted) { join->answer(index, std::move(deleted)); });
  }
  join->started();
}

void FakeAsyncNamespace::delete_one(const NodeId& nodeId, std::function<void(DeleteNodeResult)> callback)
{
  bool deferred;
  std::optional<DeleteNodeResult> cannedResult;
  {
    std::lock_guard lock(mMutex);
    mRecordedCalls.push_back(RecordedCall{Op::DeleteNode, nodeId, NodeClass::Unspecified, 0});
    deferred = mDeleteNodeDeferred;
    if (mNextDeleteNodeResults.empty())
    {
      cannedResult.emplace(missing_canned_delete_result());
    }
    else
    {
      cannedResult.emplace(std::move(mNextDeleteNodeResults.front()));
      mNextDeleteNodeResults.pop_front();
    }
  }

  if (!deferred)
  {
    callback(std::move(*cannedResult));
    return;
  }

  std::lock_guard lock(mMutex);
  park_locked([callback = std::move(callback), value = std::move(*cannedResult)]() mutable
    { callback(std::move(value)); });
}

void FakeAsyncNamespace::create_monitoring_async(const RequestInfo& /*request*/, const CallerInfo* /*caller*/,
  std::span<const MonitoringCreateItem> items,
  std::function<void(BatchResult<MonitoringCreateItemResult>)> complete)
{
  bool deferred;
  BatchResult<MonitoringCreateItemResult> cannedResult;
  {
    std::lock_guard lock(mMutex);
    mRecordedCalls.push_back(
      RecordedCall{Op::CreateMonitoring, NodeId{}, NodeClass::Unspecified, items.size()});
    deferred = mCreateMonitoringDeferred;
    if (mNextCreateMonitoringResults.empty())
    {
      cannedResult =
        missing_canned_batch_result<MonitoringCreateItemResult>("create_monitoring_async", items.size());
    }
    else
    {
      cannedResult = std::move(mNextCreateMonitoringResults.front());
      mNextCreateMonitoringResults.pop_front();
    }
  }

  if (!deferred)
  {
    complete(std::move(cannedResult));
    return;
  }

  std::lock_guard lock(mMutex);
  park_locked([complete = std::move(complete), value = std::move(cannedResult)]() mutable
    { complete(std::move(value)); });
}

void FakeAsyncNamespace::delete_monitoring_async(const RequestInfo& /*request*/,
  std::span<const MonitoringHandle> handles, std::function<void(BatchResult<VoidResult>)> complete)
{
  bool deferred;
  BatchResult<VoidResult> cannedResult;
  {
    std::lock_guard lock(mMutex);
    mRecordedCalls.push_back(
      RecordedCall{Op::DeleteMonitoring, NodeId{}, NodeClass::Unspecified, handles.size()});
    deferred = mDeleteMonitoringDeferred;
    if (mNextDeleteMonitoringResults.empty())
    {
      cannedResult = missing_canned_batch_result<VoidResult>("delete_monitoring_async", handles.size());
    }
    else
    {
      cannedResult = std::move(mNextDeleteMonitoringResults.front());
      mNextDeleteMonitoringResults.pop_front();
    }
  }

  if (!deferred)
  {
    complete(std::move(cannedResult));
    return;
  }

  std::lock_guard lock(mMutex);
  park_locked([complete = std::move(complete), value = std::move(cannedResult)]() mutable
    { complete(std::move(value)); });
}

void FakeAsyncNamespace::modify_monitoring_async(const RequestInfo& /*request*/,
  std::span<const MonitoringModifyItem> items,
  std::function<void(BatchResult<MonitoringModifyItemResult>)> complete)
{
  bool deferred;
  BatchResult<MonitoringModifyItemResult> cannedResult;
  {
    std::lock_guard lock(mMutex);
    mRecordedCalls.push_back(
      RecordedCall{Op::ModifyMonitoring, NodeId{}, NodeClass::Unspecified, items.size()});
    deferred = mModifyMonitoringDeferred;
    if (mNextModifyMonitoringResults.empty())
    {
      cannedResult =
        missing_canned_batch_result<MonitoringModifyItemResult>("modify_monitoring_async", items.size());
    }
    else
    {
      cannedResult = std::move(mNextModifyMonitoringResults.front());
      mNextModifyMonitoringResults.pop_front();
    }
  }

  if (!deferred)
  {
    complete(std::move(cannedResult));
    return;
  }

  std::lock_guard lock(mMutex);
  park_locked([complete = std::move(complete), value = std::move(cannedResult)]() mutable
    { complete(std::move(value)); });
}

// --- Operations on a Node: inline, per NodeId -------------------------------

void FakeAsyncNamespace::read_references_async(const RequestInfo& /*request*/,
  std::span<const ReferenceQuery> queries, std::function<void(BatchResult<NodeReferencesResult>)> complete)
{
  BatchResult<NodeReferencesResult> answer;
  answer.items.reserve(queries.size());
  {
    std::lock_guard lock(mMutex);
    for (const auto& query : queries)
    {
      NodeScript& script = mNodeScripts[query.nodeId];
      script.referenceQueries.push_back(GetReferencesPageCall{query.maxReferences, query.resumeToken});
      answer.items.push_back(take_front(script.references, "read_references_async"));
    }
  }
  complete(std::move(answer));
}

void FakeAsyncNamespace::read_values_async(const RequestInfo& /*request*/, const CallerInfo* /*caller*/,
  std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
  std::function<void(BatchResult<DataValueResult>)> complete)
{
  BatchResult<DataValueResult> answer;
  answer.items.reserve(items.size());
  {
    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      NodeScript& script = mNodeScripts[item.value.node_id()];
      script.readValueCalls.push_back(ReadValueCall{maxAge, setSourceTimestamp, item.value});
      answer.items.push_back(take_front(script.readValue, "read_values_async"));
    }
  }
  complete(std::move(answer));
}

void FakeAsyncNamespace::write_async(const RequestInfo& /*request*/, const CallerInfo* /*caller*/,
  std::span<const ValueWriteItem> items,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  BatchResult<VoidResult> answer;
  answer.items.reserve(items.size());
  {
    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      if (static_cast<AttributeId>(item.value.attribute_id()) != AttributeId::Value)
      {
        answer.items.emplace_back();
        continue;
      }
      NodeScript& script = mNodeScripts[item.value.node_id()];
      script.writeValueCalls.push_back(WriteValueCall{item.value});
      answer.items.push_back(take_front(script.writeValue, "write_async"));
    }
  }
  complete(std::move(answer), std::vector<VersionedNode>{});
}

void FakeAsyncNamespace::call_async(const RequestInfo& /*request*/, const CallerInfo* /*caller*/,
  std::span<const CallItem> items, std::function<void(BatchResult<std::optional<CallResult>>)> complete)
{
  BatchResult<std::optional<CallResult>> answer;
  answer.items.reserve(items.size());
  {
    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      const auto found = mNodeScripts.find(item.request.method_id());
      if (found == mNodeScripts.end() || found->second.call.empty())
      {
        answer.items.emplace_back(std::nullopt);
        continue;
      }
      found->second.callCalls.push_back(CallCall{item.request, item.context != nullptr});
      answer.items.emplace_back(take_front(found->second.call, "call_async"));
    }
  }
  complete(std::move(answer));
}

void FakeAsyncNamespace::view_contains_async(const RequestInfo& /*request*/, const NodeId& view,
  std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete)
{
  BatchResult<BoolResult> answer;
  answer.items.reserve(nodes.size());
  {
    std::lock_guard lock(mMutex);
    NodeScript& script = mNodeScripts[view];
    for (const auto& candidate : nodes)
    {
      script.isNodeInViewCalls.push_back(IsNodeInViewCall{candidate});
      answer.items.push_back(take_front(script.isNodeInView, "view_contains_async"));
    }
  }
  complete(std::move(answer));
}

void FakeAsyncNamespace::add_to_view_async(const RequestInfo& /*request*/, const NodeId& view,
  std::span<const NodeId> nodes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  BatchResult<VoidResult> answer;
  answer.items.reserve(nodes.size());
  {
    std::lock_guard lock(mMutex);
    NodeScript& script = mNodeScripts[view];
    for (const auto& added : nodes)
    {
      script.addNodeToViewCalls.push_back(AddNodeToViewCall{added});
      answer.items.push_back(take_front(script.addNodeToView, "add_to_view_async"));
    }
  }
  complete(std::move(answer), std::vector<VersionedNode>{});
}

template<typename Recorded>
void FakeAsyncNamespace::change_references(std::span<const ReferenceChange> changes,
  std::deque<VoidResult> NodeScript::*staged, std::vector<Recorded> NodeScript::*recorded,
  std::string_view opName, std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  BatchResult<VoidResult> answer;
  answer.items.reserve(changes.size());
  {
    std::lock_guard lock(mMutex);
    for (const auto& change : changes)
    {
      NodeScript& script = mNodeScripts[change.source];
      (script.*recorded).push_back(Recorded{change.referenceType, change.target, change.isForward});
      answer.items.push_back(take_front(script.*staged, opName));
    }
  }
  complete(std::move(answer), std::vector<VersionedNode>{});
}

void FakeAsyncNamespace::add_references_async(const RequestInfo& /*request*/,
  std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  change_references(changes,
    &NodeScript::addReference,
    &NodeScript::addReferenceCalls,
    "add_references_async",
    std::move(complete));
}

void FakeAsyncNamespace::remove_references_async(const RequestInfo& /*request*/,
  std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  change_references(changes,
    &NodeScript::removeReference,
    &NodeScript::removeReferenceCalls,
    "remove_references_async",
    std::move(complete));
}

}  // namespace ua::test::behaviour_pins
