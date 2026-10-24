// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "batch_recording_namespace.h"

#include "ua_namespace_context.h"
#include "ua_namespace_monitoring_support.h"
#include "ua_node.h"
#include "ua_node_description.h"
#include "ua_read_value_id.h"
#include "ua_reference.h"
#include "ua_reference_type_model.h"
#include "ua_write_value.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <atomic>
#include <iterator>
#include <charconv>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace ua::test
{

namespace
{

// The namespace whose recorded member is running on this thread and forwarding to its default; null when none
// is. A call into that namespace while it is set is made by the default member, not by the SDK.
thread_local const void* gForwardingFor = nullptr;

class ForwardingScope
{
public:
  explicit ForwardingScope(const void* owner) noexcept : mPrevious{gForwardingFor}
  {
    gForwardingFor = owner;
  }

  ~ForwardingScope()
  {
    gForwardingFor = mPrevious;
  }

  ForwardingScope(const ForwardingScope&) = delete;
  ForwardingScope& operator=(const ForwardingScope&) = delete;

private:
  const void* mPrevious;
};

// A completion runs outside the forwarding scope of the member that delivers it: what the SDK does from
// inside a completion is a new call, and is recorded.
template<typename... Args>
std::function<void(Args...)> outside_forwarding(std::function<void(Args...)> callback)
{
  if (!callback)
  {
    return callback;
  }
  return [callback = std::move(callback)](Args... args)
  {
    const ForwardingScope outside{nullptr};
    callback(std::forward<Args>(args)...);
  };
}

void fill_request(BatchRecordingNamespace::Call& call, const RequestInfo& request)
{
  call.hasRequest = true;
  call.deadline = request.deadline;
  call.answerBy = request.answerBy;
  call.cancelled = request.cancelled && request.cancelled->load();
}

void fill_caller(BatchRecordingNamespace::Call& call, const CallerInfo* caller)
{
  call.hasCaller = caller != nullptr;
  call.caller = caller;
  if (caller != nullptr)
  {
    call.identity = caller->identity;
    call.callerSessionId = caller->sessionId;
  }
}

// Runs a function when the scope it is declared in ends.
class AtReturn
{
public:
  explicit AtReturn(std::function<void()> action) : mAction{std::move(action)}
  {}

  ~AtReturn()
  {
    if (mAction)
    {
      mAction();
    }
  }

  AtReturn(const AtReturn&) = delete;
  AtReturn& operator=(const AtReturn&) = delete;

private:
  std::function<void()> mAction;
};

// The NodeId @p node describes, or nullopt when its Attributes cannot be read.
std::optional<NodeId> readable_node_id(const Node& node) noexcept
{
  try
  {
    const NodeDescription described = node.attributes();
    return described.node_id();
  }
  catch (...)
  {
    return std::nullopt;
  }
}

PermissionType every_permission()
{
  return PermissionType{uint32_t{0x0001ffff}};
}

// The resume token of a paged answer: the call that issued it and the offset the next page starts at.
constexpr std::string_view pageTokenPrefix{"page:"};

ByteString page_token(std::size_t sequence, std::size_t offset)
{
  const std::string text =
    std::string{pageTokenPrefix} + std::to_string(sequence) + ":" + std::to_string(offset);
  return ByteString{std::vector<uint8_t>(text.begin(), text.end())};
}

// The offset @p token names: 0 for no token, nullopt for a token this namespace did not issue.
std::optional<std::size_t> page_offset(const ByteString& token)
{
  if (token.empty())
  {
    return std::size_t{0};
  }
  const std::string text{reinterpret_cast<const char*>(token.data()), token.size()};
  const auto colon = text.rfind(':');
  if (!text.starts_with(pageTokenPrefix) || colon == std::string::npos || colon < pageTokenPrefix.size())
  {
    return std::nullopt;
  }
  std::size_t offset = 0;
  const char* first = text.data() + colon + 1;
  const char* last = text.data() + text.size();
  const auto parsed = std::from_chars(first, last, offset);
  if (parsed.ec != std::errc{} || parsed.ptr != last || first == last)
  {
    return std::nullopt;
  }
  return offset;
}

// A sink that passes every call on to the sink it replaces and then notes each sample and notice, so that a
// test which sees the note knows the replaced sink has been given it.
class ObservingSink final : public SampleSink
{
public:
  ObservingSink(
    std::shared_ptr<SampleSink> inner, std::function<void(BatchRecordingNamespace::Delivery)> note)
    : mInner(std::move(inner)), mNote(std::move(note))
  {}

  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    const auto given = samples;
    mInner->push(std::move(samples));
    for (const auto& [monitoredItemId, value] : given)
    {
      mNote(BatchRecordingNamespace::Delivery{
        .monitoredItemId = monitoredItemId, .sample = value, .notice = std::nullopt});
    }
  }

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override
  {
    mInner->invalidate(monitoredItemId, reason);
    mNote(BatchRecordingNamespace::Delivery{
      .monitoredItemId = monitoredItemId, .sample = std::nullopt, .notice = std::move(reason)});
  }

  void mark_semantics_changed(IntegerId monitoredItemId) override
  {
    mInner->mark_semantics_changed(monitoredItemId);
  }

  std::shared_ptr<const CallerInfo> caller() const override
  {
    return mInner->caller();
  }

  void detach() override
  {
    mInner->detach();
  }

private:
  std::shared_ptr<SampleSink> mInner;
  std::function<void(BatchRecordingNamespace::Delivery)> mNote;
};

// A completion that stores the answer in @p held until it is released, and delivers it when it arrives
// after the release.
template<typename Answer, typename Held>
std::function<void(Answer)> store_in(std::shared_ptr<Held> held)
{
  return [held = std::move(held)](Answer answer)
  {
    std::function<void(Answer)> deliver;
    {
      const std::lock_guard lock{held->mutex};
      if (!held->released)
      {
        held->answer = std::move(answer);
        return;
      }
      deliver = std::move(held->complete);
    }
    if (deliver)
    {
      deliver(std::move(answer));
    }
  };
}

// Releases each of @p held not yet released, in order, and returns how many it released.
template<typename Held>
std::size_t release_all(const std::vector<std::shared_ptr<Held>>& held)
{
  std::size_t released = 0;
  for (const auto& one : held)
  {
    decltype(one->answer) answer;
    decltype(one->complete) deliver;
    {
      const std::lock_guard lock{one->mutex};
      if (one->released)
      {
        continue;
      }
      one->released = true;
      ++released;
      if (!one->answer.has_value())
      {
        // Still running: its completion delivers it.
        continue;
      }
      answer = std::move(one->answer);
      one->answer.reset();
      deliver = std::move(one->complete);
    }
    if (deliver && answer.has_value())
    {
      deliver(std::move(*answer));
    }
  }
  return released;
}

}  // namespace

BatchRecordingNamespace::BatchRecordingNamespace(string_view uri, boost::asio::any_io_executor executor)
  : default_ns::Namespace(uri, executor), mExecutor{std::move(executor)}
{}

void BatchRecordingNamespace::page_without_end_of(std::vector<NodeId> nodeIds)
{
  const std::lock_guard lock{mMutex};
  mPageWithoutEndOf = std::move(nodeIds);
}

void BatchRecordingNamespace::decline_single_lookups(bool decline)
{
  const std::lock_guard lock{mMutex};
  mDeclineSingleLookups = decline;
}

void BatchRecordingNamespace::decline_immediate_permissions(bool decline)
{
  const std::lock_guard lock{mMutex};
  mDeclineImmediatePermissions = decline;
}

void BatchRecordingNamespace::grant(const NodeId& nodeId, PermissionType permissions)
{
  const std::lock_guard lock{mMutex};
  mGrants.insert_or_assign(nodeId, permissions);
}

void BatchRecordingNamespace::refuse_role_permissions_update(const NodeId& nodeId, StatusCode refusal)
{
  const std::lock_guard lock{mMutex};
  mRefusals.insert_or_assign(nodeId, std::move(refusal));
}

void BatchRecordingNamespace::set_history_delegate(shared_ptr<NamespaceHistoryDelegate> delegate)
{
  const std::lock_guard lock{mMutex};
  mHistoryDelegate = std::move(delegate);
}

void BatchRecordingNamespace::answer_whole_values(bool whole)
{
  const std::lock_guard lock{mMutex};
  mWholeValues = whole;
}

void BatchRecordingNamespace::fail_value_reads_of(const NodeId& nodeId, StatusCode failure)
{
  const std::lock_guard lock{mMutex};
  mFailedReads.insert_or_assign(nodeId, std::move(failure));
}

void BatchRecordingNamespace::hold_writes(bool hold)
{
  const std::lock_guard lock{mMutex};
  mHoldWrites = hold;
}

void BatchRecordingNamespace::fail_reference_changes_of(const NodeId& nodeId, StatusCode failure)
{
  const std::lock_guard lock{mMutex};
  mFailedReferenceChanges.insert_or_assign(nodeId, std::move(failure));
}

void BatchRecordingNamespace::change_references_scripted(const RequestInfo& request,
  std::span<const ReferenceChange> changes, bool add,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  std::map<NodeId, StatusCode> failures;
  {
    const std::lock_guard lock{mMutex};
    failures = mFailedReferenceChanges;
  }
  // As write_async's scripted failures: the scripted changes are answered with their status and not applied,
  // the others applied by the default, and the two sets of answers merged in change order.
  std::vector<std::optional<StatusCode>> scripted(changes.size());
  std::vector<ReferenceChange> applied;
  std::vector<std::size_t> appliedPositions;
  for (std::size_t i = 0; i < changes.size(); ++i)
  {
    if (const auto failure = failures.find(changes[i].source); failure != failures.end())
    {
      scripted[i] = failure->second;
    }
    else
    {
      applied.push_back(changes[i]);
      appliedPositions.push_back(i);
    }
  }
  auto forward = [this, &request, add](std::span<const ReferenceChange> items,
                   std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)>
                     answer)
  {
    const ForwardingScope scope{this};
    if (add)
    {
      default_ns::Namespace::add_references_async(request, items, std::move(answer));
    }
    else
    {
      default_ns::Namespace::remove_references_async(request, items, std::move(answer));
    }
  };
  if (applied.size() == changes.size())
  {
    forward(changes, outside_forwarding(std::move(complete)));
    return;
  }
  auto merge = [deliver = outside_forwarding(std::move(complete)),
                 scripted = std::move(scripted),
                 appliedPositions](BatchResult<VoidResult> answers, std::vector<VersionedNode> versioned)
  {
    BatchResult<VoidResult> merged;
    merged.batchStatus = answers.batchStatus;
    merged.items.resize(scripted.size());
    for (std::size_t i = 0; i < scripted.size(); ++i)
    {
      if (scripted[i])
      {
        merged.items[i] = VoidResult{*scripted[i]};
      }
    }
    for (std::size_t k = 0; k < appliedPositions.size(); ++k)
    {
      merged.items[appliedPositions[k]] =
        k < answers.items.size() ? std::move(answers.items[k]) : VoidResult{answers.batchStatus};
    }
    if (deliver)
    {
      deliver(std::move(merged), std::move(versioned));
    }
  };
  if (applied.empty())
  {
    merge(BatchResult<VoidResult>{}, {});
    return;
  }
  forward(applied, std::move(merge));
}

void BatchRecordingNamespace::fail_writes_of(const NodeId& nodeId, StatusCode failure)
{
  const std::lock_guard lock{mMutex};
  mFailedWrites.insert_or_assign(nodeId, std::move(failure));
}

void BatchRecordingNamespace::answer_view_membership(
  std::function<bool(const NodeId& view, const NodeId& candidate)> member)
{
  const std::lock_guard lock{mMutex};
  mViewMembership = std::move(member);
}

void BatchRecordingNamespace::accept_view_additions(bool accept)
{
  const std::lock_guard lock{mMutex};
  mAcceptViewAdditions = accept;
}

void BatchRecordingNamespace::answer_creations_without_node(bool answer)
{
  const std::lock_guard lock{mMutex};
  mAnswerCreationsWithoutNode = answer;
}

void BatchRecordingNamespace::apply_reference_hints(bool apply)
{
  const std::lock_guard lock{mMutex};
  mApplyReferenceHints = apply;
}

void BatchRecordingNamespace::page_references(std::size_t pageSize)
{
  const std::lock_guard lock{mMutex};
  mPageSize = pageSize;
}

void BatchRecordingNamespace::page_references_by_max_references(bool page)
{
  const std::lock_guard lock{mMutex};
  mPageByMaxReferences = page;
}

void BatchRecordingNamespace::answer_every_reference(bool every)
{
  const std::lock_guard lock{mMutex};
  mEveryReference = every;
}

void BatchRecordingNamespace::answer_lookup_of(const NodeId& nodeId, StatusCode answer,
  std::optional<StatusCode> batchStatus, std::optional<std::size_t> itemLimit)
{
  const std::lock_guard lock{mMutex};
  mLookupAnswers.insert_or_assign(nodeId, NodeResult{std::move(answer)});
  if (batchStatus)
    mLookupBatchStatuses.insert_or_assign(nodeId, std::move(*batchStatus));
  else
    mLookupBatchStatuses.erase(nodeId);
  if (itemLimit)
    mLookupItemLimits.insert_or_assign(nodeId, *itemLimit);
  else
    mLookupItemLimits.erase(nodeId);
}

void BatchRecordingNamespace::answer_lookup_of(const NodeId& nodeId, shared_ptr<Node> node,
  std::optional<StatusCode> batchStatus, std::optional<std::size_t> itemLimit)
{
  const std::lock_guard lock{mMutex};
  mLookupAnswers.insert_or_assign(nodeId, NodeResult{std::move(node)});
  if (batchStatus)
    mLookupBatchStatuses.insert_or_assign(nodeId, std::move(*batchStatus));
  else
    mLookupBatchStatuses.erase(nodeId);
  if (itemLimit)
    mLookupItemLimits.insert_or_assign(nodeId, *itemLimit);
  else
    mLookupItemLimits.erase(nodeId);
}

void BatchRecordingNamespace::answer_reference_query_of(
  const NodeId& nodeId, std::size_t nth, StatusCode answer)
{
  const std::lock_guard lock{mMutex};
  mReferenceQueryAnswers[nodeId].insert_or_assign(nth, std::move(answer));
}

void BatchRecordingNamespace::hold_reference_reads_of(std::vector<NodeId> nodeIds)
{
  const std::lock_guard lock{mMutex};
  mHoldReferenceReadsOf = std::move(nodeIds);
}

bool BatchRecordingNamespace::wait_for_held_reference_reads(
  std::size_t count, std::chrono::milliseconds limit)
{
  std::unique_lock lock{mMutex};
  return mHeldReferenceReadArrived.wait_for(
    lock, limit, [this, count] { return mHeldReferenceReads.size() >= count; });
}

std::size_t BatchRecordingNamespace::held_reference_read_count() const
{
  const std::lock_guard lock{mMutex};
  return mHeldReferenceReads.size();
}

RequestInfo BatchRecordingNamespace::held_reference_read_request(std::size_t index) const
{
  const std::lock_guard lock{mMutex};
  return mHeldReferenceReads.at(index).request;
}

std::size_t BatchRecordingNamespace::release_held_reference_reads()
{
  std::vector<HeldReferenceRead> released;
  {
    const std::lock_guard lock{mMutex};
    for (auto& held : mHeldReferenceReads)
    {
      if (held.released)
      {
        continue;
      }
      held.released = true;
      HeldReferenceRead copy;
      copy.request = held.request;
      copy.sequence = held.sequence;
      copy.queries = held.queries;
      copy.scripted = held.scripted;
      copy.complete = std::move(held.complete);
      released.push_back(std::move(copy));
    }
  }
  for (auto& held : released)
  {
    // The Nodes are looked up again, and kept until the read completes, rather than taken from the call
    // that was held: its caller holds them only until that call completes.
    auto nodes = std::make_shared<std::vector<shared_ptr<Node>>>();
    nodes->reserve(held.queries.size());
    {
      const ForwardingScope scope{this};
      for (const auto& query : held.queries)
      {
        auto found = default_ns::Namespace::find_node(query.nodeId, std::nullopt);
        if (!found.has_value() || !found->is_good() || found->value() == nullptr)
        {
          break;
        }
        nodes->push_back(std::move(found->value()));
      }
    }
    if (nodes->size() != held.queries.size())
    {
      BatchResult<NodeReferencesResult> unknown;
      unknown.items.assign(held.queries.size(), NodeReferencesResult{StatusCode{Status::BadNodeIdUnknown}});
      if (held.complete)
      {
        held.complete(std::move(unknown));
      }
      continue;
    }
    std::vector<ReferenceQuery> queries;
    queries.reserve(held.queries.size());
    for (std::size_t i = 0; i < held.queries.size(); ++i)
    {
      const auto& query = held.queries[i];
      queries.push_back(ReferenceQuery{*(*nodes)[i],
        query.nodeId,
        query.direction,
        query.referenceTypeHint,
        query.maxReferences,
        query.resumeToken});
    }
    answer_references(held.request,
      held.sequence,
      queries,
      std::move(held.scripted),
      [nodes, complete = std::move(held.complete)](BatchResult<NodeReferencesResult> answer)
      {
        if (complete)
        {
          complete(std::move(answer));
        }
      });
  }
  return released.size();
}

void BatchRecordingNamespace::hold_lookups_of(std::vector<NodeId> nodeIds)
{
  const std::lock_guard lock{mMutex};
  mHoldLookupsOf = std::move(nodeIds);
}

bool BatchRecordingNamespace::wait_for_held_lookups(std::size_t count, std::chrono::milliseconds limit)
{
  std::unique_lock lock{mMutex};
  return mHeldLookupArrived.wait_for(lock, limit, [this, count] { return mHeldLookupCount >= count; });
}

std::size_t BatchRecordingNamespace::release_held_lookups()
{
  std::vector<std::function<void()>> held;
  {
    const std::lock_guard lock{mMutex};
    held = std::move(mHeldLookups);
    mHeldLookups.clear();
  }
  for (auto& resume : held)
  {
    resume();
  }
  return held.size();
}

std::size_t BatchRecordingNamespace::discard_held_lookups()
{
  std::vector<std::function<void()>> held;
  {
    const std::lock_guard lock{mMutex};
    held = std::move(mHeldLookups);
    mHeldLookups.clear();
  }
  const auto discarded = held.size();
  // Destroyed here, uncalled and outside the lock: destroying a completion may end the work that owns it, and
  // that work may call this namespace.
  held.clear();
  return discarded;
}

bool BatchRecordingNamespace::holds_lookup_of(std::span<const NodeId> nodeIds) const
{
  if (forwarding())
  {
    return false;
  }
  const std::lock_guard lock{mMutex};
  return std::any_of(nodeIds.begin(),
    nodeIds.end(),
    [this](const NodeId& nodeId)
    { return std::find(mHoldLookupsOf.begin(), mHoldLookupsOf.end(), nodeId) != mHoldLookupsOf.end(); });
}

void BatchRecordingNamespace::hold_lookup(std::function<void()> resume)
{
  {
    const std::lock_guard lock{mMutex};
    mHeldLookups.push_back(std::move(resume));
    ++mHeldLookupCount;
  }
  mHeldLookupArrived.notify_all();
}

std::size_t BatchRecordingNamespace::release_held_writes()
{
  std::vector<HeldWrite> held;
  {
    const std::lock_guard lock{mMutex};
    mHoldWrites = false;
    held = std::move(mHeldWrites);
    mHeldWrites.clear();
  }
  for (auto& write : held)
  {
    const ForwardingScope scope{this};
    // The Nodes are looked up again, and kept until the write completes, rather than taken from the call
    // that was held: its caller holds them only until that call completes.
    auto nodes = std::make_shared<std::vector<shared_ptr<Node>>>();
    nodes->reserve(write.values.size());
    for (const auto& value : write.values)
    {
      auto found = default_ns::Namespace::find_node(NodeId{value.node_id()}, std::nullopt);
      if (!found.has_value() || !found->is_good() || found->value() == nullptr)
      {
        break;
      }
      nodes->push_back(std::move(found->value()));
    }
    if (nodes->size() != write.values.size())
    {
      BatchResult<VoidResult> unknown;
      unknown.items.assign(write.values.size(), VoidResult{StatusCode{Status::BadNodeIdUnknown}});
      write.complete(std::move(unknown), {});
      continue;
    }
    std::vector<ValueWriteItem> items;
    items.reserve(write.values.size());
    for (std::size_t i = 0; i < write.values.size(); ++i)
    {
      items.push_back(ValueWriteItem{*(*nodes)[i], write.values[i]});
    }
    default_ns::Namespace::write_async(write.request,
      write.caller.has_value() ? &*write.caller : nullptr,
      items,
      [nodes, complete = std::move(write.complete)](
        BatchResult<VoidResult> result, std::vector<VersionedNode> versioned)
      {
        if (complete)
        {
          complete(std::move(result), std::move(versioned));
        }
      });
  }
  return held.size();
}

std::vector<BatchRecordingNamespace::Call> BatchRecordingNamespace::calls() const
{
  const std::lock_guard lock{mMutex};
  return mCalls;
}

std::vector<BatchRecordingNamespace::Call> BatchRecordingNamespace::calls(Member member) const
{
  const std::lock_guard lock{mMutex};
  std::vector<Call> selected;
  std::copy_if(mCalls.begin(),
    mCalls.end(),
    std::back_inserter(selected),
    [member](const Call& call) { return call.member == member; });
  return selected;
}

std::size_t BatchRecordingNamespace::count(Member member) const
{
  const std::lock_guard lock{mMutex};
  return static_cast<std::size_t>(std::count_if(
    mCalls.begin(), mCalls.end(), [member](const Call& call) { return call.member == member; }));
}

void BatchRecordingNamespace::reset()
{
  const std::lock_guard lock{mMutex};
  mCalls.clear();
}

bool BatchRecordingNamespace::forwarding() const noexcept
{
  return gForwardingFor == static_cast<const void*>(this);
}

std::size_t BatchRecordingNamespace::record(Call call) const
{
  std::size_t sequence = 0;
  {
    const std::lock_guard lock{mMutex};
    call.sequence = ++mSequence;
    call.entered = std::chrono::steady_clock::now();
    mCalls.push_back(std::move(call));
    sequence = mSequence;
  }
  mRecorded.notify_all();
  return sequence;
}

bool BatchRecordingNamespace::wait_for_calls(
  Member member, std::size_t count, std::chrono::milliseconds limit) const
{
  std::unique_lock lock{mMutex};
  return mRecorded.wait_for(lock,
    limit,
    [this, member, count]
    {
      return static_cast<std::size_t>(std::count_if(
               mCalls.begin(), mCalls.end(), [member](const Call& call) { return call.member == member; })) >=
             count;
    });
}

void BatchRecordingNamespace::hold_value_reads_of(std::vector<NodeId> nodeIds)
{
  const std::lock_guard lock{mMutex};
  mHoldValueReadsOf = std::move(nodeIds);
}

bool BatchRecordingNamespace::wait_for_held_value_reads(std::size_t count, std::chrono::milliseconds limit)
{
  std::unique_lock lock{mMutex};
  return mHeldValueReadArrived.wait_for(
    lock, limit, [this, count] { return mHeldValueReads.size() >= count; });
}

std::size_t BatchRecordingNamespace::release_held_value_reads()
{
  std::vector<std::shared_ptr<HeldAnswer<BatchResult<DataValueResult>>>> held;
  {
    const std::lock_guard lock{mMutex};
    held = mHeldValueReads;
  }
  return release_all(held);
}

void BatchRecordingNamespace::hold_modify_answers(bool hold)
{
  const std::lock_guard lock{mMutex};
  mHoldModifyAnswers = hold;
}

bool BatchRecordingNamespace::wait_for_held_modify_answers(std::size_t count, std::chrono::milliseconds limit)
{
  std::unique_lock lock{mMutex};
  return mHeldModifyAnswerArrived.wait_for(
    lock, limit, [this, count] { return mHeldModifyAnswers.size() >= count; });
}

std::size_t BatchRecordingNamespace::release_held_modify_answers()
{
  std::vector<std::shared_ptr<HeldAnswer<BatchResult<MonitoringModifyItemResult>>>> held;
  {
    const std::lock_guard lock{mMutex};
    held = mHeldModifyAnswers;
  }
  return release_all(held);
}

void BatchRecordingNamespace::hold_permission_answers(bool hold)
{
  const std::lock_guard lock{mMutex};
  mHoldPermissionAnswers = hold;
}

bool BatchRecordingNamespace::wait_for_held_permission_answers(
  std::size_t count, std::chrono::milliseconds limit)
{
  std::unique_lock lock{mMutex};
  return mHeldPermissionAnswerArrived.wait_for(
    lock, limit, [this, count] { return mHeldPermissionAnswers.size() >= count; });
}

std::size_t BatchRecordingNamespace::release_held_permission_answers()
{
  std::vector<std::shared_ptr<HeldAnswer<EffectivePermissionsResult>>> held;
  {
    const std::lock_guard lock{mMutex};
    held = mHeldPermissionAnswers;
  }
  return release_all(held);
}

void BatchRecordingNamespace::fail_create_monitoring(StatusCode failure)
{
  const std::lock_guard lock{mMutex};
  if (failure.is_good())
  {
    mCreateMonitoringFailure.reset();
    return;
  }
  mCreateMonitoringFailure = std::move(failure);
}

void BatchRecordingNamespace::fail_create_monitoring_of(const NodeId& nodeId, StatusCode failure)
{
  const std::lock_guard lock{mMutex};
  mCreateMonitoringItemFailures.insert_or_assign(nodeId, std::move(failure));
}

EffectivePermissionsCallback BatchRecordingNamespace::held_permission_answer(
  EffectivePermissionsCallback callback)
{
  std::shared_ptr<HeldAnswer<EffectivePermissionsResult>> held;
  {
    const std::lock_guard lock{mMutex};
    if (!mHoldPermissionAnswers)
    {
      return callback;
    }
    held = std::make_shared<HeldAnswer<EffectivePermissionsResult>>();
    held->complete = outside_forwarding(std::move(callback));
    mHeldPermissionAnswers.push_back(held);
  }
  mHeldPermissionAnswerArrived.notify_all();
  return store_in<EffectivePermissionsResult>(held);
}

void BatchRecordingNamespace::observe_deliveries(bool observe)
{
  const std::lock_guard lock{mMutex};
  mObserveDeliveries = observe;
}

std::vector<BatchRecordingNamespace::Delivery> BatchRecordingNamespace::deliveries() const
{
  const std::lock_guard lock{mDeliveryLog->mutex};
  return mDeliveryLog->deliveries;
}

bool BatchRecordingNamespace::wait_for_delivery(
  IntegerId monitoredItemId, bool notice, std::chrono::milliseconds limit) const
{
  std::unique_lock lock{mDeliveryLog->mutex};
  return mDeliveryLog->arrived.wait_for(lock,
    limit,
    [this, monitoredItemId, notice]
    {
      return std::any_of(mDeliveryLog->deliveries.begin(),
        mDeliveryLog->deliveries.end(),
        [monitoredItemId, notice](const Delivery& delivery)
        {
          return delivery.monitoredItemId == monitoredItemId &&
                 (notice ? delivery.notice.has_value() : delivery.sample.has_value());
        });
    });
}

void BatchRecordingNamespace::report_change(
  const NodeId& nodeId, AttributeId attribute, const DataValue& value)
{
  context().monitoring().attribute_changed(nodeId, attribute, value);
}

std::vector<default_ns::NamespaceMonitoringSupport::CreateResult> BatchRecordingNamespace::create_sampled(
  std::span<const MonitoringCreateItem> items)
{
  using Helper = default_ns::NamespaceMonitoringSupport;
  std::vector<Helper::ResolvedMonitoringItem> resolved;
  resolved.reserve(items.size());
  for (const auto& item : items)
  {
    Helper::ResolvedMonitoringItem entry;
    entry.item = item;
    entry.item.node = default_ns::Namespace::find_node<Node>(item.nodeId);
    entry.delivery = Helper::Delivery::Sampled;
    resolved.push_back(std::move(entry));
  }
  return context().monitoring().create_monitoring(resolved);
}

void BatchRecordingNamespace::on_value_read(std::function<void(const Call&)> hook)
{
  const std::lock_guard lock{mMutex};
  mValueReadHook = std::move(hook);
}

std::vector<MonitoringCreateItem> BatchRecordingNamespace::observed_items(
  std::span<const MonitoringCreateItem> items)
{
  std::vector<MonitoringCreateItem> passed(items.begin(), items.end());
  const std::lock_guard lock{mMutex};
  if (!mObserveDeliveries)
  {
    return passed;
  }
  for (auto& item : passed)
  {
    if (!item.sink)
    {
      continue;
    }
    auto& observing = mObservingSinks[item.sink.get()];
    if (!observing)
    {
      observing = std::make_shared<ObservingSink>(item.sink,
        [log = mDeliveryLog](Delivery delivery)
        {
          {
            const std::lock_guard logLock{log->mutex};
            log->deliveries.push_back(std::move(delivery));
          }
          log->arrived.notify_all();
        });
    }
    item.sink = observing;
  }
  return passed;
}

void BatchRecordingNamespace::record_monitoring_create(
  std::span<const MonitoringCreateItem> items, const RequestInfo& request) const
{
  Call call;
  call.member = Member::CreateMonitoring;
  call.nodeIds.reserve(items.size());
  call.monitoredItemIds.reserve(items.size());
  call.monitoringItems.reserve(items.size());
  for (const auto& item : items)
  {
    call.nodeIds.push_back(item.nodeId);
    call.monitoredItemIds.push_back(item.monitoredItemId);
    // Without the Node and the sink, which the record must not keep alive.
    MonitoringCreateItem recorded = item;
    recorded.node.reset();
    recorded.sink.reset();
    call.monitoringItems.push_back(std::move(recorded));
  }
  fill_request(call, request);
  record(std::move(call));
}

std::optional<NodeResult> BatchRecordingNamespace::scripted_lookup(const NodeId& nodeId) const
{
  const std::lock_guard lock{mMutex};
  const auto scripted = mLookupAnswers.find(nodeId);
  if (scripted == mLookupAnswers.end())
  {
    return std::nullopt;
  }
  return scripted->second;
}

void BatchRecordingNamespace::note_answered_tokens(
  std::size_t sequence, const std::vector<ByteString>& tokens) const
{
  const std::lock_guard lock{mMutex};
  const auto recorded = std::find_if(
    mCalls.begin(), mCalls.end(), [sequence](const Call& call) { return call.sequence == sequence; });
  if (recorded == mCalls.end())
  {
    return;
  }
  for (std::size_t i = 0; i < tokens.size() && i < recorded->referenceQueries.size(); ++i)
  {
    recorded->referenceQueries[i].answeredToken = tokens[i];
  }
}

void BatchRecordingNamespace::note_answered_statuses(
  std::size_t sequence, const std::vector<std::optional<StatusCode>>& statuses) const
{
  const std::lock_guard lock{mMutex};
  const auto recorded = std::find_if(
    mCalls.begin(), mCalls.end(), [sequence](const Call& call) { return call.sequence == sequence; });
  if (recorded == mCalls.end())
  {
    return;
  }
  for (std::size_t i = 0; i < statuses.size() && i < recorded->referenceQueries.size(); ++i)
  {
    recorded->referenceQueries[i].answeredStatus = statuses[i];
  }
}

// --- Lookups
// -------------------------------------------------------------------------------------------------

void BatchRecordingNamespace::find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
  std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::BatchedLookup;
    call.nodeIds.assign(nodeIds.begin(), nodeIds.end());
    fill_request(call, request);
    call.maxAge = maxAge;
    record(std::move(call));
  }
  std::function<void(BatchResult<NodeResult>)> answer = outside_forwarding(std::move(complete));
  std::map<NodeId, NodeResult> scripted;
  std::optional<StatusCode> batchStatus;
  std::optional<std::size_t> itemLimit;
  {
    const std::lock_guard lock{mMutex};
    scripted = mLookupAnswers;
    for (const auto& nodeId : nodeIds)
    {
      if (const auto status = mLookupBatchStatuses.find(nodeId); status != mLookupBatchStatuses.end())
        batchStatus = status->second;
      if (const auto limit = mLookupItemLimits.find(nodeId); limit != mLookupItemLimits.end())
        itemLimit = itemLimit ? std::min(*itemLimit, limit->second) : limit->second;
    }
  }
  if ((!scripted.empty() || batchStatus || itemLimit) && answer)
  {
    // The default's answer, with each scripted lookup answer put in place of its item's.
    answer = [deliver = std::move(answer),
               named = std::vector<NodeId>(nodeIds.begin(), nodeIds.end()),
               scripted = std::move(scripted),
               batchStatus,
               itemLimit](BatchResult<NodeResult> result)
    {
      if (result.items.size() == named.size())
      {
        for (std::size_t i = 0; i < named.size(); ++i)
        {
          if (const auto found = scripted.find(named[i]); found != scripted.end())
          {
            result.items[i] = found->second;
          }
        }
      }
      if (batchStatus)
        result.batchStatus = VoidResult{*batchStatus};
      if (itemLimit && *itemLimit < result.items.size())
        result.items.erase(
          result.items.begin() + static_cast<std::ptrdiff_t>(*itemLimit), result.items.end());
      deliver(std::move(result));
    };
  }
  if (holds_lookup_of(nodeIds))
  {
    // Held: what the call is given that is valid only until it returns is copied.
    auto named = std::make_shared<std::vector<NodeId>>(nodeIds.begin(), nodeIds.end());
    hold_lookup(
      [this, named, request = RequestInfo{request}, maxAge, deliver = std::move(answer)]
      {
        const ForwardingScope scope{this};
        default_ns::Namespace::find_nodes_async(request,
          *named,
          maxAge,
          [named, deliver](BatchResult<NodeResult> result)
          {
            if (deliver)
            {
              deliver(std::move(result));
            }
          });
      });
    return;
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(answer));
}

std::optional<NodeResult> BatchRecordingNamespace::find_node(
  const NodeId& nodeId, std::optional<Duration> maxAge)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::SingleLookup;
    call.nodeIds.push_back(nodeId);
    call.maxAge = maxAge;
    record(std::move(call));
    const std::lock_guard lock{mMutex};
    if (mLookupBatchStatuses.contains(nodeId) || mLookupItemLimits.contains(nodeId))
      return std::nullopt;
  }
  if (auto scripted = scripted_lookup(nodeId))
  {
    return std::move(*scripted);
  }
  if (holds_lookup_of(std::span<const NodeId>{&nodeId, 1}))
  {
    return std::nullopt;
  }
  bool decline = false;
  {
    const std::lock_guard lock{mMutex};
    decline = mDeclineSingleLookups;
  }
  if (decline)
  {
    return std::nullopt;
  }
  const ForwardingScope scope{this};
  return default_ns::Namespace::find_node(nodeId, maxAge);
}

// --- Permissions
// ---------------------------------------------------------------------------------------------

std::optional<PermissionType> BatchRecordingNamespace::effective_permissions(
  const AccessIdentity& identity, const Node* node) const
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::ImmediatePermissionsOfNode;
    call.node = node;
    if (node != nullptr)
    {
      // A Node whose Attributes cannot be read is recorded without its NodeId; the default, which reads
      // them too, answers for it.
      if (auto nodeId = readable_node_id(*node))
      {
        call.nodeIds.push_back(std::move(*nodeId));
      }
    }
    record(std::move(call));
  }
  bool decline = false;
  {
    const std::lock_guard lock{mMutex};
    decline = mDeclineImmediatePermissions;
  }
  if (decline)
  {
    return std::nullopt;
  }
  const ForwardingScope scope{this};
  return default_ns::Namespace::effective_permissions(identity, node);
}

void BatchRecordingNamespace::effective_permissions_async(const RequestInfo& request,
  shared_ptr<const AccessIdentity> identity, std::optional<std::vector<NodeId>> nodes,
  EffectivePermissionsCallback callback)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::PermissionsAsyncForRequest;
    if (nodes)
    {
      call.nodeIds = *nodes;
    }
    fill_request(call, request);
    call.identity = identity;
    record(std::move(call));
    callback = held_permission_answer(std::move(callback));
  }

  bool answerHere = false;
  std::map<NodeId, PermissionType> grants;
  {
    const std::lock_guard lock{mMutex};
    answerHere = mDeclineImmediatePermissions;
    grants = mGrants;
  }
  if (!answerHere)
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::effective_permissions_async(
      request, std::move(identity), std::move(nodes), outside_forwarding(std::move(callback)));
    return;
  }

  // The immediate form declines, so this namespace answers here: the mask granted to each NodeId, every bit
  // for one given none, and every bit for the namespace subject.
  EffectivePermissionsResult result;
  if (!nodes)
  {
    result.items.emplace_back(every_permission());
  }
  else
  {
    result.items.reserve(nodes->size());
    for (const auto& nodeId : *nodes)
    {
      const auto granted = grants.find(nodeId);
      result.items.emplace_back(granted == grants.end() ? every_permission() : granted->second);
    }
  }
  if (callback)
  {
    callback(std::move(result));
  }
}

// --- Values, References, RolePermissions
// ---------------------------------------------------------------------

void BatchRecordingNamespace::read_values_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
  std::function<void(BatchResult<DataValueResult>)> complete)
{
  // Whether the call was answered by the time this member returns, noted on the recorded call then.
  auto answered = std::make_shared<std::atomic<bool>>(false);
  std::size_t sequence = 0;
  const AtReturn noteInline{[this, answered, &sequence]
    {
      if (sequence == 0)
      {
        return;
      }
      const std::lock_guard lock{mMutex};
      const auto recorded = std::find_if(
        mCalls.begin(), mCalls.end(), [sequence](const Call& call) { return call.sequence == sequence; });
      if (recorded != mCalls.end())
      {
        recorded->answeredInline = answered->load();
      }
    }};
  if (!forwarding())
  {
    Call call;
    call.member = Member::ReadValues;
    call.nodeIds.reserve(items.size());
    call.itemNodes.reserve(items.size());
    call.itemRanged.reserve(items.size());
    call.itemRanges.reserve(items.size());
    for (const auto& item : items)
    {
      call.nodeIds.push_back(NodeId{item.value.node_id()});
      call.itemNodes.push_back(&item.node);
      call.itemRanged.push_back(!item.value.index_range().empty());
      call.itemRanges.push_back(item.value.index_range());
    }
    fill_request(call, request);
    fill_caller(call, caller);
    call.maxAge = maxAge;
    sequence = record(std::move(call));
    complete = [answered, deliver = std::move(complete)](BatchResult<DataValueResult> result)
    {
      answered->store(true);
      if (deliver)
      {
        deliver(std::move(result));
      }
    };

    std::function<void(const Call&)> hook;
    std::optional<Call> recorded;
    {
      const std::lock_guard lock{mMutex};
      hook = mValueReadHook;
      if (hook)
      {
        const auto found = std::find_if(
          mCalls.begin(), mCalls.end(), [sequence](const Call& entry) { return entry.sequence == sequence; });
        if (found != mCalls.end())
        {
          recorded = *found;
        }
      }
    }
    if (hook && recorded)
    {
      hook(*recorded);
    }

    // Held: read now, as it otherwise would be, and the answer kept until it is released.
    std::shared_ptr<HeldAnswer<BatchResult<DataValueResult>>> held;
    {
      const std::lock_guard lock{mMutex};
      const bool hold = std::any_of(items.begin(),
        items.end(),
        [this](const ValueReadItem& item)
        {
          return std::find(mHoldValueReadsOf.begin(),
                   mHoldValueReadsOf.end(),
                   NodeId{item.value.node_id()}) != mHoldValueReadsOf.end();
        });
      if (hold)
      {
        held = std::make_shared<HeldAnswer<BatchResult<DataValueResult>>>();
        held->complete = std::move(complete);
        mHeldValueReads.push_back(held);
        mHeldValueReadRequests.push_back(request);
      }
    }
    if (held)
    {
      mHeldValueReadArrived.notify_all();
      complete = store_in<BatchResult<DataValueResult>>(held);
    }
  }

  bool whole = false;
  std::map<NodeId, StatusCode> failures;
  {
    const std::lock_guard lock{mMutex};
    whole = mWholeValues;
    failures = mFailedReads;
  }
  std::function<void(BatchResult<DataValueResult>)> answer = outside_forwarding(std::move(complete));
  if (!failures.empty())
  {
    // The answer otherwise given, with each scripted failure put in place of its item's.
    std::vector<NodeId> named;
    named.reserve(items.size());
    for (const auto& item : items)
    {
      named.push_back(NodeId{item.value.node_id()});
    }
    answer = [deliver = std::move(answer), named = std::move(named), failures = std::move(failures)](
               BatchResult<DataValueResult> result)
    {
      if (result.batchStatus.is_good() && result.items.size() == named.size())
      {
        for (std::size_t i = 0; i < named.size(); ++i)
        {
          if (const auto failure = failures.find(named[i]); failure != failures.end())
          {
            result.items[i] = DataValueResult{failure->second};
          }
        }
      }
      if (deliver)
      {
        deliver(std::move(result));
      }
    };
  }
  const ForwardingScope scope{this};
  if (!whole)
  {
    default_ns::Namespace::read_values_async(
      request, caller, items, maxAge, setSourceTimestamp, std::move(answer));
    return;
  }

  // Each item read without its IndexRange, so the default answers the whole Value. The copies live until
  // this returns, which is as long as the default may use an item's ReadValueId.
  std::vector<ReadValueId> unranged;
  unranged.reserve(items.size());
  for (const auto& item : items)
  {
    ReadValueId value{item.value};
    value.index_range() = NumericRange{};
    unranged.push_back(std::move(value));
  }
  std::vector<ValueReadItem> wholeItems;
  wholeItems.reserve(items.size());
  for (std::size_t i = 0; i < items.size(); ++i)
  {
    wholeItems.push_back(ValueReadItem{items[i].node, unranged[i]});
  }
  default_ns::Namespace::read_values_async(
    request, caller, wholeItems, maxAge, setSourceTimestamp, std::move(answer));
}

void BatchRecordingNamespace::write_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const ValueWriteItem> items,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::Write;
    call.nodeIds.reserve(items.size());
    call.itemNodes.reserve(items.size());
    for (const auto& item : items)
    {
      call.nodeIds.push_back(NodeId{item.value.node_id()});
      call.itemNodes.push_back(&item.node);
    }
    fill_request(call, request);
    fill_caller(call, caller);
    record(std::move(call));

    // Held: what is valid only until this returns is copied, and nothing is applied or answered.
    const std::lock_guard lock{mMutex};
    if (mHoldWrites)
    {
      HeldWrite held;
      held.request = request;
      if (caller != nullptr)
      {
        held.caller = *caller;
      }
      held.values.reserve(items.size());
      for (const auto& item : items)
      {
        held.values.push_back(item.value);
      }
      held.complete = outside_forwarding(std::move(complete));
      mHeldWrites.push_back(std::move(held));
      return;
    }
  }

  std::map<NodeId, StatusCode> failures;
  if (!forwarding())
  {
    const std::lock_guard lock{mMutex};
    failures = mFailedWrites;
  }
  // Each item with a scripted failure is answered with it and not applied; the others are applied by the
  // default, and the two sets of answers merged in item order.
  std::vector<std::optional<StatusCode>> scripted(items.size());
  std::vector<ValueWriteItem> applied;
  std::vector<std::size_t> appliedPositions;
  for (std::size_t i = 0; i < items.size(); ++i)
  {
    if (const auto failure = failures.find(NodeId{items[i].value.node_id()}); failure != failures.end())
    {
      scripted[i] = failure->second;
    }
    else
    {
      applied.push_back(items[i]);
      appliedPositions.push_back(i);
    }
  }
  if (applied.size() == items.size())
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::write_async(request, caller, items, outside_forwarding(std::move(complete)));
    return;
  }
  auto merge = [deliver = outside_forwarding(std::move(complete)),
                 scripted = std::move(scripted),
                 appliedPositions](BatchResult<VoidResult> answers, std::vector<VersionedNode> versioned)
  {
    BatchResult<VoidResult> merged;
    merged.batchStatus = answers.batchStatus;
    merged.items.resize(scripted.size());
    for (std::size_t i = 0; i < scripted.size(); ++i)
    {
      if (scripted[i])
      {
        merged.items[i] = VoidResult{*scripted[i]};
      }
    }
    for (std::size_t k = 0; k < appliedPositions.size(); ++k)
    {
      merged.items[appliedPositions[k]] =
        k < answers.items.size() ? std::move(answers.items[k]) : VoidResult{answers.batchStatus};
    }
    if (deliver)
    {
      deliver(std::move(merged), std::move(versioned));
    }
  };
  if (applied.empty())
  {
    merge(BatchResult<VoidResult>{}, {});
    return;
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::write_async(request, caller, applied, std::move(merge));
}

void BatchRecordingNamespace::read_references_async(const RequestInfo& request,
  std::span<const ReferenceQuery> queries, std::function<void(BatchResult<NodeReferencesResult>)> complete)
{
  std::size_t sequence = 0;
  std::vector<ReferenceQueryRecord> records;
  records.reserve(queries.size());
  for (const auto& query : queries)
  {
    records.push_back(ReferenceQueryRecord{.nodeId = query.nodeId,
      .direction = query.direction,
      .referenceTypeHint = query.referenceTypeHint,
      .maxReferences = query.maxReferences,
      .resumeToken = query.resumeToken,
      .answeredToken = {},
      .answeredStatus = std::nullopt});
  }
  const bool recorded = !forwarding();
  if (recorded)
  {
    Call call;
    call.member = Member::ReadReferences;
    call.nodeIds.reserve(queries.size());
    for (const auto& query : queries)
    {
      call.nodeIds.push_back(query.nodeId);
    }
    call.referenceQueries = records;
    fill_request(call, request);
    sequence = record(std::move(call));
  }

  // Each query's scripted answer, decided by its place among the queries naming its NodeId; and whether the
  // call is held.
  std::vector<std::optional<StatusCode>> scripted(queries.size());
  bool hold = false;
  {
    const std::lock_guard lock{mMutex};
    if (recorded)
    {
      for (std::size_t i = 0; i < queries.size(); ++i)
      {
        const std::size_t nth = ++mReferenceQueryCounts[queries[i].nodeId];
        if (const auto answers = mReferenceQueryAnswers.find(queries[i].nodeId);
            answers != mReferenceQueryAnswers.end())
        {
          if (const auto answer = answers->second.find(nth); answer != answers->second.end())
          {
            scripted[i] = answer->second;
          }
        }
      }
      hold = std::any_of(queries.begin(),
        queries.end(),
        [this](const ReferenceQuery& query)
        {
          return std::find(mHoldReferenceReadsOf.begin(), mHoldReferenceReadsOf.end(), query.nodeId) !=
                 mHoldReferenceReadsOf.end();
        });
    }
    if (hold)
    {
      HeldReferenceRead held;
      held.request = request;
      held.sequence = sequence;
      held.queries = std::move(records);
      held.scripted = std::move(scripted);
      held.complete = outside_forwarding(std::move(complete));
      mHeldReferenceReads.push_back(std::move(held));
    }
  }
  if (hold)
  {
    mHeldReferenceReadArrived.notify_all();
    return;
  }
  answer_references(request, sequence, queries, std::move(scripted), outside_forwarding(std::move(complete)));
}

void BatchRecordingNamespace::answer_references(const RequestInfo& request, std::size_t sequence,
  std::span<const ReferenceQuery> queries, std::vector<std::optional<StatusCode>> scripted,
  std::function<void(BatchResult<NodeReferencesResult>)> complete)
{
  bool applyHints = false;
  std::size_t pageSize = 0;
  bool pageByMaxReferences = false;
  bool every = false;
  std::vector<NodeId> endlessOf;
  {
    const std::lock_guard lock{mMutex};
    applyHints = mApplyReferenceHints;
    pageSize = mPageSize;
    pageByMaxReferences = mPageByMaxReferences;
    every = mEveryReference;
    endlessOf = mPageWithoutEndOf;
  }
  const bool anyScripted =
    std::any_of(scripted.begin(), scripted.end(), [](const auto& answer) { return answer.has_value(); });
  // The queries @ref page_without_end_of answers with no References and a fresh token.
  std::vector<bool> endless(queries.size(), false);
  for (std::size_t i = 0; i < queries.size(); ++i)
  {
    endless[i] = !scripted[i].has_value() &&
                 std::find(endlessOf.begin(), endlessOf.end(), queries[i].nodeId) != endlessOf.end();
  }
  const bool anyEndless = std::find(endless.begin(), endless.end(), true) != endless.end();
  if (!applyHints && pageSize == 0 && !pageByMaxReferences && !every && !anyScripted && !anyEndless)
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::read_references_async(request, queries, std::move(complete));
    return;
  }

  // Every Reference of each Node, read by the default without a limit or a token, then shaped here: the hint
  // applied, then the page cut from where the query's token says.
  std::vector<ReferenceQuery> whole;
  std::vector<std::vector<NodeId>> hints;
  std::vector<ByteString> resumeTokens;
  std::vector<std::size_t> pageSizes;
  whole.reserve(queries.size());
  hints.reserve(queries.size());
  resumeTokens.reserve(queries.size());
  pageSizes.reserve(queries.size());
  for (const auto& query : queries)
  {
    whole.push_back(ReferenceQuery{query.node, query.nodeId, query.direction, {}, 0, ByteString{}});
    hints.push_back(query.referenceTypeHint);
    resumeTokens.push_back(query.resumeToken);
    pageSizes.push_back(every ? 0 : (pageByMaxReferences ? query.maxReferences : pageSize));
  }
  const bool paging = !every && (pageByMaxReferences || pageSize > 0);
  auto shaped = [this,
                  sequence,
                  applyHints,
                  paging,
                  hints = std::move(hints),
                  resumeTokens = std::move(resumeTokens),
                  pageSizes = std::move(pageSizes),
                  scripted = std::move(scripted),
                  endless = std::move(endless),
                  anyEndless,
                  complete = std::move(complete)](BatchResult<NodeReferencesResult> read)
  {
    std::vector<ByteString> answeredTokens(resumeTokens.size());
    std::vector<std::optional<StatusCode>> answeredStatuses(resumeTokens.size());
    if (read.batchStatus.is_good() && read.items.size() == resumeTokens.size())
    {
      for (std::size_t i = 0; i < read.items.size(); ++i)
      {
        if (scripted[i].has_value())
        {
          read.items[i] = NodeReferencesResult{*scripted[i]};
          answeredStatuses[i] = *scripted[i];
          continue;
        }
        if (endless[i])
        {
          std::size_t issued = 0;
          {
            const std::lock_guard lock{mMutex};
            issued = ++mEndlessTokens;
          }
          const std::string text = "endless:" + std::to_string(issued);
          answeredTokens[i] = ByteString{std::vector<uint8_t>(text.begin(), text.end())};
          read.items[i] = NodeReferencesResult{NodeReferences{References{}, answeredTokens[i]}};
          continue;
        }
        if (!read.items[i].is_good())
        {
          continue;
        }
        std::vector<Reference> kept;
        for (const auto& reference : read.items[i].value().references)
        {
          if (!applyHints || reference_type_may_match_hint(reference.type_id(), hints[i]))
          {
            kept.push_back(reference);
          }
        }
        if (!paging)
        {
          read.items[i] = NodeReferencesResult{NodeReferences{References{std::move(kept)}, ByteString{}}};
          continue;
        }
        const auto offset = page_offset(resumeTokens[i]);
        if (!offset.has_value() || *offset > kept.size())
        {
          read.items[i] = NodeReferencesResult{StatusCode{Status::BadContinuationPointInvalid}};
          continue;
        }
        const std::size_t end =
          pageSizes[i] == 0 ? kept.size() : std::min(*offset + pageSizes[i], kept.size());
        std::vector<Reference> page(kept.begin() + static_cast<std::ptrdiff_t>(*offset),
          kept.begin() + static_cast<std::ptrdiff_t>(end));
        if (end < kept.size())
        {
          answeredTokens[i] = page_token(sequence, end);
        }
        read.items[i] = NodeReferencesResult{NodeReferences{References{std::move(page)}, answeredTokens[i]}};
      }
    }
    if ((paging || anyEndless) && sequence > 0)
    {
      note_answered_tokens(sequence, answeredTokens);
    }
    if (sequence > 0 && std::any_of(answeredStatuses.begin(),
                          answeredStatuses.end(),
                          [](const std::optional<StatusCode>& status) { return status.has_value(); }))
    {
      note_answered_statuses(sequence, answeredStatuses);
    }
    if (complete && anyEndless)
    {
      // Off the caller's stack, so that a caller that asks again from the completion does not recurse.
      boost::asio::post(
        mExecutor, [complete, read = std::move(read)]() mutable { complete(std::move(read)); });
      return;
    }
    if (complete)
    {
      complete(std::move(read));
    }
  };
  const ForwardingScope scope{this};
  default_ns::Namespace::read_references_async(request, whole, std::move(shaped));
}

void BatchRecordingNamespace::release_resume_token(ByteString token)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::ReleaseResumeToken;
    call.token = token;
    record(std::move(call));
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::release_resume_token(std::move(token));
}

void BatchRecordingNamespace::create_nodes_async(const RequestInfo& request,
  std::span<const NodeCreation> nodes, std::function<void(BatchResult<NodeResult>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::CreateNodes;
    for (const auto& creation : nodes)
    {
      call.nodeIds.push_back(creation.nodeId);
      call.creations.push_back(creation);
    }
    fill_request(call, request);
    record(std::move(call));
  }
  bool withoutNode = false;
  {
    const std::lock_guard lock{mMutex};
    withoutNode = mAnswerCreationsWithoutNode;
  }
  if (withoutNode)
  {
    BatchResult<NodeResult> answer;
    answer.items.assign(nodes.size(), NodeResult{shared_ptr<Node>{}});
    complete(std::move(answer));
    return;
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::create_nodes_async(request, nodes, outside_forwarding(std::move(complete)));
}

void BatchRecordingNamespace::delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes,
  ReferenceHalves halves,
  std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::DeleteNodes;
    call.nodeIds.assign(nodes.begin(), nodes.end());
    fill_request(call, request);
    record(std::move(call));
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::delete_nodes_async(request, nodes, halves, outside_forwarding(std::move(complete)));
}

void BatchRecordingNamespace::add_references_async(const RequestInfo& request,
  std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::AddReferences;
    for (const auto& change : changes)
    {
      call.nodeIds.push_back(change.source);
      call.referenceChanges.push_back(change);
    }
    fill_request(call, request);
    record(std::move(call));
  }
  if (forwarding())
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::add_references_async(request, changes, outside_forwarding(std::move(complete)));
    return;
  }
  change_references_scripted(request, changes, /*add=*/true, std::move(complete));
}

void BatchRecordingNamespace::remove_references_async(const RequestInfo& request,
  std::span<const ReferenceChange> changes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::RemoveReferences;
    for (const auto& change : changes)
    {
      call.nodeIds.push_back(change.source);
      call.referenceChanges.push_back(change);
    }
    fill_request(call, request);
    record(std::move(call));
  }
  if (forwarding())
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::remove_references_async(request, changes, outside_forwarding(std::move(complete)));
    return;
  }
  change_references_scripted(request, changes, /*add=*/false, std::move(complete));
}

void BatchRecordingNamespace::validate_role_permissions_updates_async(const RequestInfo& request,
  std::span<const RolePermissionsUpdate> updates, std::function<void(BatchResult<VoidResult>)> complete)
{
  std::vector<NodeId> named;
  named.reserve(updates.size());
  for (const auto& update : updates)
  {
    named.push_back(update.nodeId);
  }
  if (!forwarding())
  {
    Call call;
    call.member = Member::ValidateRolePermissionsUpdates;
    call.nodeIds = named;
    call.proposals.reserve(updates.size());
    for (const auto& update : updates)
    {
      call.proposals.push_back(update.proposed);
    }
    fill_request(call, request);
    record(std::move(call));
  }

  std::map<NodeId, StatusCode> refusals;
  {
    const std::lock_guard lock{mMutex};
    refusals = mRefusals;
  }
  // The default's answer, with each scripted refusal put in place of its update's item.
  auto scripted = [complete = outside_forwarding(std::move(complete)),
                    named = std::move(named),
                    refusals = std::move(refusals)](BatchResult<VoidResult> answer)
  {
    if (answer.batchStatus.is_good() && answer.items.size() == named.size())
    {
      for (std::size_t i = 0; i < named.size(); ++i)
      {
        if (const auto refusal = refusals.find(named[i]); refusal != refusals.end())
        {
          answer.items[i] = VoidResult{refusal->second};
        }
      }
    }
    if (complete)
    {
      complete(std::move(answer));
    }
  };
  const ForwardingScope scope{this};
  default_ns::Namespace::validate_role_permissions_updates_async(request, updates, std::move(scripted));
}

// --- Views
// ---------------------------------------------------------------------------------------------------

void BatchRecordingNamespace::view_contains_async(const RequestInfo& request, const NodeId& view,
  std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::ViewContains;
    call.view = view;
    call.candidates.assign(nodes.begin(), nodes.end());
    fill_request(call, request);
    record(std::move(call));
  }

  std::function<bool(const NodeId&, const NodeId&)> member;
  {
    const std::lock_guard lock{mMutex};
    member = mViewMembership;
  }
  if (!member)
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::view_contains_async(request, view, nodes, outside_forwarding(std::move(complete)));
    return;
  }

  BatchResult<BoolResult> answer;
  answer.items.reserve(nodes.size());
  for (const auto& candidate : nodes)
  {
    answer.items.emplace_back(member(view, candidate.node_id()));
  }
  if (complete)
  {
    complete(std::move(answer));
  }
}

void BatchRecordingNamespace::add_to_view_async(const RequestInfo& request, const NodeId& view,
  std::span<const NodeId> nodes,
  std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::AddToView;
    call.view = view;
    call.nodeIds.assign(nodes.begin(), nodes.end());
    fill_request(call, request);
    record(std::move(call));
  }

  bool accept = false;
  {
    const std::lock_guard lock{mMutex};
    accept = mAcceptViewAdditions;
  }
  if (!accept)
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::add_to_view_async(request, view, nodes, outside_forwarding(std::move(complete)));
    return;
  }

  BatchResult<VoidResult> answer;
  answer.items.assign(nodes.size(), VoidResult{});
  if (complete)
  {
    complete(std::move(answer), {});
  }
}

void BatchRecordingNamespace::call_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const CallItem> items, std::function<void(BatchResult<std::optional<CallResult>>)> complete)
{
  bool decline = false;
  bool held = false;
  Call offered;
  std::function<BatchResult<std::optional<CallResult>>(const Call&)> scriptedAnswer;
  if (!forwarding())
  {
    Call call;
    call.member = Member::Call;
    call.nodeIds.reserve(items.size());
    for (const auto& item : items)
    {
      call.nodeIds.push_back(item.request.object_id());
      call.methodRequests.push_back(item.request);
    }
    fill_request(call, request);
    fill_caller(call, caller);
    offered = call;
    offered.sequence = record(std::move(call));

    {
      const std::lock_guard lock{mMutex};
      decline = mDeclineCalls;
      scriptedAnswer = mCallAnswer;
      // Held: the request and the caller are copied, the items kept as given and read when released.
      if (mHoldCalls)
      {
        HeldCall heldCall;
        heldCall.request = request;
        if (caller != nullptr)
        {
          heldCall.caller = *caller;
        }
        // CallItem holds references, so it is copied one by one rather than assigned.
        heldCall.items.reserve(items.size());
        for (const auto& item : items)
        {
          heldCall.items.push_back(item);
        }
        heldCall.complete = outside_forwarding(std::move(complete));
        mHeldCalls.push_back(std::move(heldCall));
        held = true;
      }
    }
    if (held)
    {
      mHeldCallArrived.notify_all();
      return;
    }
  }
  if (decline)
  {
    BatchResult<std::optional<CallResult>> declined;
    declined.items.assign(items.size(), std::nullopt);
    outside_forwarding(std::move(complete))(std::move(declined));
    return;
  }
  if (scriptedAnswer)
  {
    auto answer = scriptedAnswer(offered);
    outside_forwarding(std::move(complete))(std::move(answer));
    return;
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::call_async(request, caller, items, outside_forwarding(std::move(complete)));
}

void BatchRecordingNamespace::decline_calls(bool decline)
{
  const std::lock_guard lock{mMutex};
  mDeclineCalls = decline;
}

void BatchRecordingNamespace::answer_calls(
  std::function<BatchResult<std::optional<CallResult>>(const Call&)> answer)
{
  const std::lock_guard lock{mMutex};
  mCallAnswer = std::move(answer);
}

void BatchRecordingNamespace::hold_calls(bool hold)
{
  const std::lock_guard lock{mMutex};
  mHoldCalls = hold;
}

bool BatchRecordingNamespace::wait_for_held_calls(std::size_t count, std::chrono::milliseconds limit)
{
  std::unique_lock lock{mMutex};
  return mHeldCallArrived.wait_for(lock, limit, [this, count] { return mHeldCalls.size() >= count; });
}

RequestInfo BatchRecordingNamespace::held_value_read_request(std::size_t index) const
{
  const std::lock_guard lock{mMutex};
  return index < mHeldValueReadRequests.size() ? mHeldValueReadRequests[index] : RequestInfo{};
}

RequestInfo BatchRecordingNamespace::held_write_request(std::size_t index) const
{
  const std::lock_guard lock{mMutex};
  return index < mHeldWrites.size() ? mHeldWrites[index].request : RequestInfo{};
}

RequestInfo BatchRecordingNamespace::held_call_request(std::size_t index) const
{
  const std::lock_guard lock{mMutex};
  return index < mHeldCalls.size() ? mHeldCalls[index].request : RequestInfo{};
}

std::size_t BatchRecordingNamespace::release_held_calls()
{
  struct Release
  {
    RequestInfo request;
    std::optional<CallerInfo> caller;
    std::vector<CallItem> items;
    std::function<void(BatchResult<std::optional<CallResult>>)> complete;
  };

  std::vector<Release> releases;
  {
    const std::lock_guard lock{mMutex};
    mHoldCalls = false;
    for (auto& held : mHeldCalls)
    {
      if (held.released)
      {
        continue;
      }
      held.released = true;
      releases.push_back(Release{held.request, held.caller, held.items, std::move(held.complete)});
      held.items.clear();
    }
  }
  for (auto& release : releases)
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::call_async(release.request,
      release.caller.has_value() ? &*release.caller : nullptr,
      release.items,
      std::move(release.complete));
  }
  return releases.size();
}

// --- Monitoring
// ----------------------------------------------------------------------------------------------

void BatchRecordingNamespace::create_monitoring_async(const RequestInfo& request, const CallerInfo* caller,
  std::span<const MonitoringCreateItem> items,
  std::function<void(BatchResult<MonitoringCreateItemResult>)> complete)
{
  if (forwarding())
  {
    default_ns::Namespace::create_monitoring_async(request, caller, items, std::move(complete));
    return;
  }
  record_monitoring_create(items, request);
  std::optional<StatusCode> batchFailure;
  std::map<NodeId, StatusCode> itemFailures;
  {
    const std::lock_guard lock{mMutex};
    batchFailure = mCreateMonitoringFailure;
    itemFailures = mCreateMonitoringItemFailures;
  }
  auto answer = outside_forwarding(std::move(complete));
  if (batchFailure)
  {
    BatchResult<MonitoringCreateItemResult> refused;
    refused.batchStatus = *batchFailure;
    if (answer)
    {
      answer(std::move(refused));
    }
    return;
  }

  // Scripted item failures answer in their places; the other items are registered as they otherwise would be.
  auto passed = observed_items(items);
  std::vector<std::optional<StatusCode>> failedAt(passed.size());
  std::vector<MonitoringCreateItem> registered;
  registered.reserve(passed.size());
  for (std::size_t k = 0; k < passed.size(); ++k)
  {
    const auto failure = itemFailures.find(passed[k].nodeId);
    if (failure != itemFailures.end())
    {
      failedAt[k] = failure->second;
      continue;
    }
    registered.push_back(std::move(passed[k]));
  }
  if (registered.size() == passed.size())
  {
    const ForwardingScope scope{this};
    default_ns::Namespace::create_monitoring_async(request, caller, registered, std::move(answer));
    return;
  }
  auto merge = [answer, failedAt, expected = registered.size()](
                 BatchResult<MonitoringCreateItemResult> created)
  {
    if (!answer)
    {
      return;
    }
    if (!created.batchStatus.is_good() || created.items.size() != expected)
    {
      answer(std::move(created));
      return;
    }
    BatchResult<MonitoringCreateItemResult> merged;
    merged.items.reserve(failedAt.size());
    std::size_t next = 0;
    for (const auto& failure : failedAt)
    {
      if (failure)
      {
        merged.items.emplace_back(*failure);
      }
      else
      {
        merged.items.push_back(std::move(created.items[next++]));
      }
    }
    answer(std::move(merged));
  };
  if (registered.empty())
  {
    merge(BatchResult<MonitoringCreateItemResult>{});
    return;
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::create_monitoring_async(request, caller, registered, std::move(merge));
}

void BatchRecordingNamespace::modify_monitoring_async(const RequestInfo& request,
  std::span<const MonitoringModifyItem> items,
  std::function<void(BatchResult<MonitoringModifyItemResult>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::ModifyMonitoring;
    for (const auto& item : items)
    {
      call.handles.push_back(item.handle);
    }
    fill_request(call, request);
    record(std::move(call));

    // Held: applied now, and the answer kept until it is released.
    std::shared_ptr<HeldAnswer<BatchResult<MonitoringModifyItemResult>>> held;
    {
      const std::lock_guard lock{mMutex};
      if (mHoldModifyAnswers)
      {
        held = std::make_shared<HeldAnswer<BatchResult<MonitoringModifyItemResult>>>();
        held->complete = outside_forwarding(std::move(complete));
        mHeldModifyAnswers.push_back(held);
      }
    }
    if (held)
    {
      mHeldModifyAnswerArrived.notify_all();
      const ForwardingScope scope{this};
      default_ns::Namespace::modify_monitoring_async(
        request, items, store_in<BatchResult<MonitoringModifyItemResult>>(held));
      return;
    }
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::modify_monitoring_async(request, items, outside_forwarding(std::move(complete)));
}

void BatchRecordingNamespace::delete_monitoring_async(const RequestInfo& request,
  std::span<const MonitoringHandle> handles, std::function<void(BatchResult<VoidResult>)> complete)
{
  if (!forwarding())
  {
    Call call;
    call.member = Member::DeleteMonitoring;
    call.handles.assign(handles.begin(), handles.end());
    fill_request(call, request);
    record(std::move(call));
  }
  const ForwardingScope scope{this};
  default_ns::Namespace::delete_monitoring_async(request, handles, outside_forwarding(std::move(complete)));
}

shared_ptr<NamespaceHistoryDelegate> BatchRecordingNamespace::history_delegate() noexcept
{
  const std::lock_guard lock{mMutex};
  return mHistoryDelegate;
}

}  // namespace ua::test
