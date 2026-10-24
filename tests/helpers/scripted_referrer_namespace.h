// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Real-node test namespace whose lookups, Reference removals and deletes a test can script.

#ifndef UA_TEST_SCRIPTED_REFERRER_NAMESPACE_H
#define UA_TEST_SCRIPTED_REFERRER_NAMESPACE_H

#include "ua_default_namespace.h"
#include "ua_node_id.h"
#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua::test
{

/// A namespace that keeps the default namespace's real node store and lets a test script how it answers
/// the address space, which reaches it in three ways when a Node in another namespace is deleted:
///
/// - the lookup of a referrer (`find_nodes_async`, `find_node`): a scripted Node answers a status instead of
///   itself;
/// - the removal of a referrer's half of a Reference (`remove_references_async`): a change at a scripted
///   referrer answers a status instead of removing, and the answers at a referrer can be held back; a change
///   whose referrer's lookup fails answers the lookup's status at once;
/// - the delete of one of its own Nodes (`delete_nodes_async`): a scripted Node is refused with a status,
///   and the answer can be held back.
///
/// Every answer a test does not script is the real node's or the real namespace's. Removal answers are
/// delivered by a post to the executor, never inline, as a namespace answering on its own worker does.
class ScriptedReferrerNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<ScriptedReferrerNamespace> create(
    string_view uri, boost::asio::any_io_executor executor);

  /// The lookup of @p nodeId answers @p status.
  void fail_lookups(const NodeId& nodeId, StatusCode status);

  /// Every removal of a Reference at @p referrer answers @p status and removes nothing.
  void answer_removals(const NodeId& referrer, StatusCode status);

  /// Holds back the answers to removals at @p referrer until @ref release_removals.
  void hold_removals(const NodeId& referrer);

  /// The removal answers held back now.
  std::size_t held_removals() const;

  /// Stops holding removal answers and delivers every one held back.
  void release_removals();

  /// The removals at @p referrer answered so far; counted once the answer's callback has returned.
  std::size_t answered_removals(const NodeId& referrer) const;

  /// The delete of @p nodeId answers @p status and deletes nothing.
  void refuse_deletes(const NodeId& nodeId, StatusCode status);

  /// Holds back the answer to the delete of @p nodeId until @ref release_deletes.
  void hold_deletes(const NodeId& nodeId);

  /// The delete answers held back now.
  std::size_t held_deletes() const;

  /// Stops holding delete answers and delivers every one held back.
  void release_deletes();

  /// Stops holding anything and delivers every answer held back.
  void release_everything();

  /// Removes each change's half as the default namespace does, unless the script answers it; every answer at
  /// a referrer this namespace holds is posted, or held back.
  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  /// Deletes each Node as the default namespace does, one at a time, unless the script refuses or holds it.
  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override;

  /// What the namespace's removal answers share, so that an answer delivered after the namespace is gone
  /// still counts.
  struct Script
  {
    mutable std::mutex mutex;
    std::unordered_map<NodeId, StatusCode> removalAnswers;
    std::unordered_set<NodeId> heldRemovals;
    std::vector<std::function<void()>> parkedRemovals;
    std::unordered_map<NodeId, std::size_t> answeredRemovals;
  };

protected:
  NodeResult resolve_here(const NodeId& nodeId) override;

private:
  ScriptedReferrerNamespace(string_view uri, boost::asio::any_io_executor executor);

  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<Script> mScript = std::make_shared<Script>();
  std::weak_ptr<ScriptedReferrerNamespace> mSelf;

  mutable std::mutex mMutex;
  std::unordered_map<NodeId, StatusCode> mLookupFailures;
  std::unordered_map<NodeId, StatusCode> mDeleteRefusals;
  std::unordered_set<NodeId> mHeldDeletes;
  std::vector<std::function<void()>> mParkedDeletes;
};

}  // namespace ua::test

#endif  // UA_TEST_SCRIPTED_REFERRER_NAMESPACE_H
