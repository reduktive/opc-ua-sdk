// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATE_MACHINE_RUNTIME_H
#define UA_STATE_MACHINE_RUNTIME_H

#include "ua_address_space.h"
#include "ua_audit_update_state_event_payload.h"
#include "ua_await_callback.h"
#include "ua_callback_safety.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include "ua_self_owning_operation.h"
#include "ua_to_result.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace ua
{
class EventSink;
}

namespace ua::server
{

struct StateMachineStateDescriptor
{
  NodeId id;
  QualifiedName name;
  uint32_t number{0};
  LocalizedText effectiveDisplayName;
};

struct StateMachineTransitionDescriptor
{
  NodeId machineId;
  NodeId transitionId;
  QualifiedName transitionName;
  std::optional<uint32_t> transitionNumber;
  /// The EventTypes of the Events the transition raises, one Event each, in the order its HasEffect
  /// References name them: every effect but an audit EventType, or TransitionEventType when there is none.
  std::vector<NodeId> eventTypes;
  /// The audit EventTypes its HasEffect References name, in their order. When the server audits, the
  /// transition's audit Event is raised once as each of them, or as AuditUpdateStateEventType when there is
  /// none.
  std::vector<NodeId> auditEventTypes;
  /// The BrowseName of the Method that caused the transition; empty for an automatic transition.
  QualifiedName methodName;
  StateMachineStateDescriptor fromState;
  StateMachineStateDescriptor toState;
  NodeId currentStateVariableId;
  NodeId currentStateIdPropertyId;
};

struct StateMachineTransitionResolution
{
  bool methodIsCause{false};
  std::optional<StateMachineTransitionDescriptor> enabledTransition;
};

using StateMachineTransitionResolutionResult = Result<StateMachineTransitionResolution>;
using OptionalMethodExecutableResult = Result<std::optional<bool>>;
using OptionalStateMachineActiveResult = Result<std::optional<bool>>;

namespace state_machine_detail
{

template<typename ResultType, typename Action>
void invoke_model_action_once(
  Action&& action, std::function<void(ResultType)> completion, Logger logger = {}) noexcept
{
  auto guardedCompletion = ua::detail::make_fire_once<ResultType>(std::move(completion));
  try
  {
    std::forward<Action>(action)(guardedCompletion);
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(
      logger, guardedCompletion, ResultType{ua::exception_to_status_code(std::current_exception())});
  }
}

}  // namespace state_machine_detail

class StateMachineModel
{
public:
  using ResolveCallback = std::function<void(StateMachineTransitionResolutionResult)>;
  using CommitCallback = std::function<void(VoidResult)>;

  StateMachineModel() = default;
  virtual ~StateMachineModel() = default;
  StateMachineModel(const StateMachineModel&) = delete;
  StateMachineModel& operator=(const StateMachineModel&) = delete;
  StateMachineModel(StateMachineModel&&) = delete;
  StateMachineModel& operator=(StateMachineModel&&) = delete;

  virtual void resolve_transition_async(
    const NodeId& machineId, const NodeId& methodId, ResolveCallback callback) noexcept = 0;
  virtual void resolve_automatic_transition_async(
    const NodeId& machineId, ResolveCallback callback) noexcept = 0;
  virtual void commit_transition_async(
    const StateMachineTransitionDescriptor& transition, CommitCallback callback) noexcept = 0;
};

std::shared_ptr<StateMachineModel> make_address_space_state_machine_model(AddressSpace addressSpace);

void evaluate_state_machine_method_executable_async(AddressSpace addressSpace, NodeId methodId,
  std::function<void(OptionalMethodExecutableResult)> callback) noexcept;

void evaluate_state_machine_variable_active_async(AddressSpace addressSpace, NodeId variableId,
  std::function<void(OptionalStateMachineActiveResult)> callback) noexcept;

/// Applies the Transition one Method call caused, and every automatic Transition that follows it.
///
/// A runtime serves one Method call and answers it once. It is owned by the work outstanding on it
/// (@ref ua::async::SelfOwningOperation): the completion of the model call it is waiting on holds it,
/// so a caller that releases it after @ref transition_after_method_async does not end the transition,
/// and a model that destroys that completion without calling it does. A runtime destroyed with its
/// transition still running answers `Bad_Shutdown` (`StateMachineTransitionDropped`).
///
/// The event sink is held weakly: an Event is raised only through a sink that still exists, and a
/// transition whose sink has gone answers `Bad_ResourceUnavailable` (`StateMachineEventSinkUnavailable`).
class StateMachineRuntime final : public ua::async::SelfOwningOperation<StateMachineRuntime>
{
public:
  using Completion = std::function<void(VoidResult)>;

  static std::shared_ptr<StateMachineRuntime> create(boost::asio::any_io_executor executor,
    std::shared_ptr<StateMachineModel> model, std::weak_ptr<EventSink> eventSink, Logger logger = {},
    std::optional<AuditUpdateStateEventPayload> auditEvent = std::nullopt);

  /// Answers the transition's completion `Bad_Shutdown` when the runtime is destroyed after it was
  /// accepted and before it answered. The completion is called on the destroying thread.
  ~StateMachineRuntime();
  StateMachineRuntime(const StateMachineRuntime&) = delete;
  StateMachineRuntime& operator=(const StateMachineRuntime&) = delete;
  StateMachineRuntime(StateMachineRuntime&&) = delete;
  StateMachineRuntime& operator=(StateMachineRuntime&&) = delete;

  /// Starts the Transition @p methodId caused on @p machineId; @p completion is called once with its
  /// outcome. The runtime keeps itself alive until then. A second call is answered `Bad_InvalidState`.
  void transition_after_method_async(NodeId machineId, NodeId methodId, Completion completion) noexcept;

private:
  friend class ua::async::SelfOwningOperation<StateMachineRuntime>;

  StateMachineRuntime(boost::asio::any_io_executor executor, std::shared_ptr<StateMachineModel> model,
    std::weak_ptr<EventSink> eventSink, Logger logger,
    std::optional<AuditUpdateStateEventPayload> auditEvent);

  void begin(NodeId machineId, NodeId methodId, Completion completion);

  /// Resolves the transition the Method caused, commits it, and keeps going while each commit enables
  /// an automatic one.
  ua::async::Task<> run();

  /// Answers the completion when the body could not be started.
  void fail_to_start(StatusCode status);

  void finish(VoidResult result);

  std::shared_ptr<StateMachineModel> mModel;
  std::weak_ptr<EventSink> mEventSink;
  std::optional<AuditUpdateStateEventPayload> mAuditEvent;
  /// The Method call this runtime serves, stored when it is accepted.
  NodeId mMachineId;
  NodeId mMethodId;
  /// One transition per runtime, and one answer for it. `mStarted` is taken the moment a call is
  /// accepted - before anything that could refuse it - so that every later call is refused rather
  /// than accepted and dropped. What the walk itself holds - the transition being committed, how many
  /// automatic ones have followed - lives in the coroutine's frame.
  bool mStarted{false};
  bool mFinished{false};
  Completion mCompletion;
};

}  // namespace ua::server

#endif  // UA_STATE_MACHINE_RUNTIME_H
