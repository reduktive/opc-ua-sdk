// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_address_space_change_events.h"
#include "ua_namespace_items.h"
#include "ua_node_id.h"

#include "ua_result.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <unordered_map>
#include <vector>

namespace ua
{
class AddressSpaceImpl;
}

namespace ua::detail
{

/// The model changes of one operation, raised as one ModelChangeEvent when the operation has ended (NR-36
/// rules 4 and 5, NR-46, NR-55 rule 2).
///
/// An operation is a Write request, a delete with its cascade and the removals of the other halves, a NodeSet
/// import, an instantiation, a namespace's own report, or any other single route call. Each namespace call
/// the operation makes holds a @ref Call until its completion has run or been dropped, and records the
/// versioned Nodes it reported, with the verbs of the change the call made to each: an answer that arrives
/// after the operation's caller was answered is recorded too. The operation's driver calls @ref close once it
/// makes no further call. When the step is closed and no call is outstanding, the address space posts one
/// event to its executor (a GeneralModelChangeEvent listing the recorded Nodes, or a BaseModelChangeEvent
/// where @ref record_unspecified was called), then runs the closing caller's continuation; with nothing
/// recorded, the continuation runs at once and nothing is posted. A step its driver drops without closing (a
/// Write request withdrawn at its timeout) is closed when the last call holding it has ended, so that a late
/// answer is still raised (NR-46). Any thread.
class ModelChangeStep final : public std::enable_shared_from_this<ModelChangeStep>
{
public:
  /// One outstanding namespace call: the step raises nothing until it has ended. Held by the call's
  /// completion, which ends it when first called; a completion the namespace drops without calling ends it
  /// when destroyed.
  class Call
  {
  public:
    explicit Call(shared_ptr<ModelChangeStep> step) noexcept;
    Call(const Call&) = delete;
    Call& operator=(const Call&) = delete;
    Call(Call&&) = delete;
    Call& operator=(Call&&) = delete;
    ~Call();

    ModelChangeStep& step() const noexcept
    {
      return *mStep;
    }

    /// Ends the call; a second end does nothing.
    void end() noexcept;

    /// Whether the call has ended.
    bool ended() const noexcept
    {
      return mEnded.load(std::memory_order_acquire);
    }

  private:
    shared_ptr<ModelChangeStep> mStep;
    std::atomic<bool> mEnded{false};
  };

  /// A step that raises its event through @p addressSpace; nothing is raised once it is gone.
  static shared_ptr<ModelChangeStep> create(weak_ptr<AddressSpaceImpl> addressSpace);

  /// Opens one namespace call of the operation. Called before @ref close.
  shared_ptr<Call> call();

  /// Records each of @p nodes with the verbs (`ModelChangeStructureVerbMask`) of the change made to it; a
  /// Node recorded twice carries both sets of verbs. An empty `affectedType` is filled from @ref
  /// type_definition_sent. A Node with no verb is a change no verb names, as @ref record_unspecified.
  void record(std::span<const VersionedNode> nodes, uint8_t verbs) noexcept;

  /// Records each of @p nodes with the verbs @p verbsOf gives it.
  void record(
    std::span<const VersionedNode> nodes, const std::function<uint8_t(const NodeId&)>& verbsOf) noexcept;

  /// A change no verb names (a ValueRank or ArrayDimensions change, a NodeVersion a client wrote): the event
  /// is a BaseModelChangeEvent (Part 3 9.32.5, 9.32.7).
  void record_unspecified() noexcept;

  /// The TypeDefinition this operation gave @p node, a Node it created (NR-63 rule 3).
  void type_definition_sent(const NodeId& node, const NodeId& typeDefinition) noexcept;

  /// Ends the operation: no call is opened after this. @p done runs once, after the event has been raised, or
  /// at once when there is nothing to raise; the event is raised when the last outstanding call has ended.
  void close(std::function<void()> done) noexcept;

  explicit ModelChangeStep(weak_ptr<AddressSpaceImpl> addressSpace) noexcept;
  ModelChangeStep(const ModelChangeStep&) = delete;
  ModelChangeStep& operator=(const ModelChangeStep&) = delete;
  ModelChangeStep(ModelChangeStep&&) = delete;
  ModelChangeStep& operator=(ModelChangeStep&&) = delete;
  /// Raises what was recorded if the step was never closed.
  ~ModelChangeStep();

private:
  void call_ended() noexcept;
  /// Raises the event if the step is closed and no call is outstanding; called without the lock.
  void raise_if_done() noexcept;

  weak_ptr<AddressSpaceImpl> mAddressSpace;
  std::mutex mMutex;
  std::size_t mOutstanding{0};
  bool mClosed{false};
  bool mRaised{false};
  bool mUnspecified{false};
  std::vector<ModelChangeEntry> mEntries;
  std::unordered_map<NodeId, std::size_t> mEntryOf;
  std::unordered_map<NodeId, NodeId> mTypeDefinitions;
  std::function<void()> mDone;
};

/// The completion a route gives a member with a versioned-Node output (NR-36 rule 2): the output is recorded
/// in
/// @p step, each Node with the verbs @p verbsOf gives it, the call ends, then @p answer receives the items.
/// Only the first call is recorded; the route ignores a second answer.
template<typename Answer>
std::function<void(BatchResult<Answer>, std::vector<VersionedNode>)> recording_versions(
  std::function<void(BatchResult<Answer>)> answer, ModelChangeStep& step,
  std::function<uint8_t(const NodeId&)> verbsOf)
{
  auto call = step.call();
  return [answer = std::move(answer), call = std::move(call), verbsOf = std::move(verbsOf)](
           BatchResult<Answer> result, std::vector<VersionedNode> versioned)
  {
    if (!call->ended())
    {
      call->step().record(versioned, verbsOf);
      call->end();
    }
    answer(std::move(result));
  };
}

}  // namespace ua::detail
