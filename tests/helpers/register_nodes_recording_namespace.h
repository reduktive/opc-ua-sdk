// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Real-node test namespace whose RegisterNodes delegate is recorded and scripted.

#ifndef UA_TEST_REGISTER_NODES_RECORDING_NAMESPACE_H
#define UA_TEST_REGISTER_NODES_RECORDING_NAMESPACE_H

#include "ua_default_namespace.h"
#include "ua_namespace_service_delegates.h"
#include "ua_node_id.h"
#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstddef>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace ua::test
{

/// A namespace that keeps the default namespace's real node store and is its own RegisterNodes delegate. It
/// records every NodeId it returns and every unregistration it is asked for, and the test scripts its
/// answers:
///
/// - `register_nodes_async` returns, for each item, the next NodeId of a list the test gives (@ref
/// alias_next),
///   or the item's own NodeId when the list is empty. It can answer at once on the calling thread, hold its
///   answer back, answer twice at once, answer and keep the call for a second answer later, or answer with
///   one NodeId more than it was asked for (a size the request does not match).
/// - `unregister_nodes_async` records the NodeIds and answers Good, or a status the test gives.
class RegisterNodesRecordingNamespace final
  : public default_ns::Namespace,
    public NamespaceRegisterNodesDelegate,
    public std::enable_shared_from_this<RegisterNodesRecordingNamespace>
{
public:
  /// How `register_nodes_async` answers.
  enum class RegisterAnswer
  {
    Now,  ///< One answer, on the calling thread.
    Hold,  ///< One answer, held back until @ref release_register_answers.
    Twice,  ///< Two answers, one after the other, on the calling thread.
    NowAndKeep,  ///< One answer on the calling thread; the call is kept for @ref answer_kept_calls_again.
    OneTooMany,  ///< One answer with one NodeId more than the items asked for.
  };

  static std::shared_ptr<RegisterNodesRecordingNamespace> create(
    string_view uri, boost::asio::any_io_executor executor);

  shared_ptr<NamespaceRegisterNodesDelegate> register_nodes_delegate() noexcept override;

  void answer_registers(RegisterAnswer how);

  /// The NodeIds the next answers return, in order, one per item, before the items' own NodeIds are used.
  void alias_next(std::vector<NodeId> nodeIds);

  std::size_t register_calls() const;
  std::size_t held_register_answers() const;

  /// Delivers every held answer on the calling thread, in order.
  void release_register_answers();

  /// Answers every kept call (@ref RegisterAnswer::NowAndKeep) a second time, on the calling thread.
  void answer_kept_calls_again();

  /// Later register answers carry @p status as their batch status, beside their NodeIds; Good restores it.
  void answer_batch_status(StatusCode status);

  /// Later unregistrations answer @p status; Good restores accepting them.
  void answer_unregisters(StatusCode status);

  /// Every NodeId a register answer returned, in order.
  std::vector<NodeId> returned() const;

  /// The NodeIds of each unregistration call, one entry per call, in order.
  std::vector<std::vector<NodeId>> unregister_calls() const;

  /// Every NodeId named by an unregistration call, in order.
  std::vector<NodeId> unregistered() const;

  /// How many times @p nodeId was named by an unregistration call.
  std::size_t unregistered_count(const NodeId& nodeId) const;

  /// Whether an unregistration was entered while this namespace's register call or answer was on the same
  /// thread's stack.
  bool unregistered_inside_a_register_answer() const;

  void register_nodes_async(
    const Context& context, std::vector<Item> items, RegisterCompleteCallback callback) noexcept override;
  void unregister_nodes_async(
    const Context& context, std::vector<Item> items, UnregisterCompleteCallback callback) noexcept override;

private:
  RegisterNodesRecordingNamespace(string_view uri, boost::asio::any_io_executor executor);

  /// An answer returning one NodeId per item, plus @p extra more. Called with the mutex held.
  BatchResult<NodeId> answer_locked(const std::vector<Item>& items, std::size_t extra);

  static void deliver(const RegisterCompleteCallback& callback, BatchResult<NodeId> answer);

  mutable std::mutex mMutex;
  RegisterAnswer mRegisterAnswer{RegisterAnswer::Now};
  std::deque<NodeId> mAliases;
  std::size_t mRegisterCalls{0};
  std::vector<std::function<void()>> mHeldAnswers;
  std::vector<std::pair<std::vector<Item>, RegisterCompleteCallback>> mKeptCalls;
  StatusCode mUnregisterAnswer;
  StatusCode mBatchStatus;
  std::vector<NodeId> mReturned;
  std::vector<std::vector<NodeId>> mUnregisterCalls;
  bool mUnregisteredInsideAnswer{false};
};

}  // namespace ua::test

#endif  // UA_TEST_REGISTER_NODES_RECORDING_NAMESPACE_H
