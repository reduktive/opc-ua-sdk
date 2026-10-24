// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_state_machine_runtime.h"

#include "ua_attribute_id.h"
#include "ua_audit_program_transition_event_payload.h"
#include "ua_callback_safety.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_generic_event.h"
#include "ua_instance_utils.h"
#include "ua_log_exception.h"
#include "ua_namespace_route.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_objecttype_id.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_sinks.h"
#include "ua_status_routing.h"
#include "ua_subtype_facts.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_variabletype_id.h"

#include <boost/asio/strand.hpp>

#include <algorithm>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ua::server
{
namespace
{

// What a step of a state-machine walk answers when an answer it acts on is not Good: a Bad answer is the
// step's own; an Uncertain one, with or without a value, is refused, since the runtime decides on it.
StatusCode lookup_not_good(const NodeId& nodeId, const StatusCode& answer) noexcept
{
  return ::ua::detail::lookup_failure(nodeId, answer, "StateMachineRuntime");
}

StatusCode references_not_good(const NodeId& nodeId, const StatusCode& answer) noexcept
{
  return server::detail::not_acted_on(
    server::detail::referencesAnswerUncertain, answer, "StateMachineRuntime", nodeId);
}

StatusCode read_not_good(const NodeId& nodeId, const StatusCode& answer) noexcept
{
  return server::detail::not_acted_on(
    server::detail::readAnswerUncertain, answer, "StateMachineRuntime", nodeId);
}

StatusCode ambiguous_transition(const NodeId& nodeId)
{
  std::unique_ptr<ua::ErrorDetail> detail = ErrorDetail::build("AmbiguousStateMachineTransition",
    "More than one Method-caused Transition is enabled from CurrentState.Id",
    "StateMachineModel")
                                              .context(ContextKeys::nodeId, to_string(nodeId));
  return StatusCode{Status::BadConfigurationError, std::move(detail)};
}

StatusCode automatic_transition_limit_exceeded(const NodeId& nodeId)
{
  std::unique_ptr<ua::ErrorDetail> detail = ErrorDetail::build("AutomaticTransitionLimitExceeded",
    "StateMachine automatic transitions did not reach a stable State",
    "StateMachineRuntime")
                                              .context(ContextKeys::nodeId, to_string(nodeId));
  return StatusCode{Status::BadConfigurationError, std::move(detail)};
}

std::string colliding_state_ids(const NodeId& firstState, const NodeId& secondState)
{
  return "first=" + to_string(firstState) + "; second=" + to_string(secondState);
}

StatusCode duplicate_state_browse_name(const NodeId& machineTypeId, const QualifiedName& browseName,
  const NodeId& firstState, const NodeId& secondState)
{
  std::unique_ptr<ua::ErrorDetail> detail =
    ErrorDetail::build("DuplicateStateBrowseName",
      "Two States in one StateMachine declare the same BrowseName",
      "StateMachineModel")
      .context(ContextKeys::nodeId, to_string(machineTypeId))
      .context(ContextKeys::nodeBrowseName, to_string(browseName))
      .context(ContextKeys::value, colliding_state_ids(firstState, secondState));
  return StatusCode{Status::BadConfigurationError, std::move(detail)};
}

StatusCode duplicate_state_number(
  const NodeId& machineTypeId, uint32_t stateNumber, const NodeId& firstState, const NodeId& secondState)
{
  std::unique_ptr<ua::ErrorDetail> detail =
    ErrorDetail::build("DuplicateStateNumber",
      "Two States in one StateMachine declare the same StateNumber",
      "StateMachineModel")
      .context(ContextKeys::nodeId, to_string(machineTypeId))
      .context(ContextKeys::fieldName, "StateNumber")
      .context(ContextKeys::actual, std::to_string(stateNumber))
      .context(ContextKeys::value, colliding_state_ids(firstState, secondState));
  return StatusCode{Status::BadConfigurationError, std::move(detail)};
}

StatusCode current_state_id_type_mismatch(const NodeId& nodeId)
{
  std::unique_ptr<ua::ErrorDetail> detail = ErrorDetail::build(
    "CurrentStateIdTypeMismatch", "CurrentState.Id does not contain a NodeId", "StateMachineModel")
                                              .context(ContextKeys::nodeId, to_string(nodeId));
  return StatusCode{Status::BadTypeMismatch, std::move(detail)};
}

StatusCode invalid_activity_topology(std::string_view code, std::string_view message, const NodeId& nodeId)
{
  std::unique_ptr<ua::ErrorDetail> detail =
    ErrorDetail::build(std::string{code}, std::string{message}, "StateMachineActivity")
      .context(ContextKeys::nodeId, to_string(nodeId));
  return StatusCode{Status::BadConfigurationError, std::move(detail)};
}

StatusCode state_display_name_type_mismatch(const NodeId& nodeId)
{
  std::unique_ptr<ua::ErrorDetail> detail = ErrorDetail::build(
    "StateDisplayNameTypeMismatch", "State DisplayName does not contain a LocalizedText", "StateMachineModel")
                                              .context(ContextKeys::nodeId, to_string(nodeId));
  return StatusCode{Status::BadTypeMismatch, std::move(detail)};
}

StatusCode state_number_type_mismatch(const NodeId& nodeId)
{
  std::unique_ptr<ua::ErrorDetail> detail = ErrorDetail::build(
    "StateNumberTypeMismatch", "StateNumber does not contain a UInt32", "StateMachineModel")
                                              .context(ContextKeys::nodeId, to_string(nodeId));
  return StatusCode{Status::BadTypeMismatch, std::move(detail)};
}

StatusCode transition_number_type_mismatch(const NodeId& nodeId)
{
  std::unique_ptr<ua::ErrorDetail> detail = ErrorDetail::build(
    "TransitionNumberTypeMismatch", "TransitionNumber does not contain a UInt32", "StateMachineModel")
                                              .context(ContextKeys::nodeId, to_string(nodeId));
  return StatusCode{Status::BadTypeMismatch, std::move(detail)};
}

std::vector<NodeId> local_forward_targets(const References& references, const NodeId& referenceType)
{
  std::vector<NodeId> targets;
  for (const auto& reference : references)
  {
    if (reference.is_forward() && !reference.is_remote() && reference.target_id().is_local() &&
        reference.type_id() == referenceType)
    {
      targets.push_back(reference.target_id().node_id());
    }
  }
  return targets;
}

std::vector<NodeId> local_inverse_targets(const References& references, const NodeId& referenceType)
{
  std::vector<NodeId> targets;
  for (const auto& reference : references)
  {
    if (!reference.is_forward() && !reference.is_remote() && reference.target_id().is_local() &&
        reference.type_id() == referenceType)
    {
      targets.push_back(reference.target_id().node_id());
    }
  }
  return targets;
}

/// The most components of a machine type this asks a namespace to resolve in one call.
///
/// A machine type declares as many components as its author wrote, and a Read of `Executable` over a
/// thousand Methods starts a thousand transition resolves at once - so the width of that one call is
/// the address space's choice multiplied by the client's, which is the shape a bound exists for.
/// `AddressSpaceImpl::find_nodes_async` is `noexcept` and allocates a slot per id, so an unbounded
/// request is also an unbounded allocation on a path that cannot report failing to make it. Large
/// enough that every realistic machine type is a single round.
constexpr size_t maxComponentsPerResolution = 64;

/// What a lookup of @p count nodes answers when the address space no longer exists: the batch and each
/// item fail with `address_space_gone`, so a walk reading the items reports that rather than a short
/// batch.
BatchResult<NodeAccessorResult> address_space_gone_batch(size_t count)
{
  const auto gone = ua::detail::address_space_gone("StateMachineRuntime");
  BatchResult<NodeAccessorResult> result;
  result.batchStatus = VoidResult{gone};
  result.items.assign(count, NodeAccessorResult{gone});
  return result;
}

// =============================================================================================
// Root tasks owned by the work outstanding on them (private to this translation unit)
// =============================================================================================
//
// The four operations below have no owner to hold their Task: two are reached through free
// functions, and the model's methods are called on a `shared_ptr<StateMachineModel>` the caller may
// drop the moment it returns. `ua::async::SelfOwningOperation` is what answers that - see its own
// documentation for why the work outstanding on an operation is what owns it, and why that is the
// same thing the callback chain these replace got from `ua::async::post_owning`.

template<typename Operation>
using SelfOwningOperation = ua::async::SelfOwningOperation<Operation>;

// =============================================================================================
// Is this Method the cause of an enabled transition?
// =============================================================================================

class EvaluateMethodExecutable final : public SelfOwningOperation<EvaluateMethodExecutable>
{
public:
  EvaluateMethodExecutable(
    AddressSpace addressSpace, NodeId methodId, std::function<void(OptionalMethodExecutableResult)> callback)
    : SelfOwningOperation(boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mMethodId(std::move(methodId)), mCallback(std::move(callback))
  {}

  static void start(
    AddressSpace addressSpace, NodeId methodId, std::function<void(OptionalMethodExecutableResult)> callback)
  {
    launch(std::make_shared<EvaluateMethodExecutable>(
      std::move(addressSpace), std::move(methodId), std::move(callback)));
  }

private:
  friend class SelfOwningOperation<EvaluateMethodExecutable>;

  void fail_to_start(StatusCode status)
  {
    finish(OptionalMethodExecutableResult{status});
  }

  void finish(OptionalMethodExecutableResult result)
  {
    auto callback = std::move(mCallback);
    mCallback = nullptr;
    ua::detail::invoke_user_callback(mLogger, callback, std::move(result));
  }

  ua::async::Task<> run()
  {
    try
    {
      finish(co_await evaluate());
    }
    catch (const ua::async::Abandoned& abandoned)
    {
      // ANSWERED, not rethrown. This is a root task and its caller is owed exactly one answer; a
      // rethrow here would store the exception in a promise nobody reads and leave the caller
      // waiting for ever. Nothing in this operation can be withdrawn today - it belongs to no
      // component and so adopts no token (R16) - and if that ever changes, "the operation was
      // abandoned" is the truthful thing to say rather than a converted internal error.
      finish(OptionalMethodExecutableResult{abandoned.status_code()});
    }
    catch (...)
    {
      ua::async::guarded(mLogger,
        [this] {
          finish(OptionalMethodExecutableResult{ua::exception_to_status_code(std::current_exception())});
        })();
    }
  }

  ua::async::Task<OptionalMethodExecutableResult> evaluate()
  {
    // The address space is locked only inside each step's initiation, so this operation - which every
    // completion it hands out owns - never keeps it alive across a suspension (ua_namespace.h, Ownership).
    auto methodId = mMethodId;

    auto method = co_await await_step<NodeAccessorResult>(
      [this, &methodId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_node_async(methodId, std::move(completion));
        else
          completion(NodeAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
      });
    if (!method.is_good())
    {
      co_return OptionalMethodExecutableResult{lookup_not_good(methodId, method.status_code())};
    }

    auto methodNode = std::move(method).value();
    auto references = co_await await_step<NodeAccessor::ReferencesResult>(
      [&methodNode](auto completion) { methodNode.get_references_async(std::move(completion)); });
    if (!references.is_good())
    {
      co_return OptionalMethodExecutableResult{references_not_good(methodId, references.status_code())};
    }

    // A Method owned by exactly one Object is the only shape a state machine can read as "this
    // Method belongs to that machine"; anything else says nothing about executability.
    const auto owners = local_inverse_targets(references.value(), NodeId{ReferenceTypeId::HasComponent});
    if (owners.size() != 1U)
    {
      co_return std::optional<bool>{};
    }

    // The model is built inside the initiation and released when it returns: the resolution it starts
    // owns itself, and a model kept in this frame would only hold the address space's handle across the
    // suspension.
    auto machineId = owners.front();
    auto resolution = co_await await_step<StateMachineTransitionResolutionResult>(
      [this, &machineId, &methodId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          make_address_space_state_machine_model(std::move(*addressSpace))
            ->resolve_transition_async(machineId, methodId, std::move(completion));
        }
        else
        {
          completion(
            StateMachineTransitionResolutionResult{ua::detail::address_space_gone("StateMachineRuntime")});
        }
      });
    if (!resolution.is_good())
    {
      co_return OptionalMethodExecutableResult{resolution.status_code()};
    }
    if (!resolution.value().methodIsCause)
    {
      co_return std::optional<bool>{};
    }
    co_return std::optional<bool>{resolution.value().enabledTransition.has_value()};
  }

  WeakAddressSpace mAddressSpace;
  NodeId mMethodId;
  std::function<void(OptionalMethodExecutableResult)> mCallback;
};

// =============================================================================================
// Is this state Variable's machine the active sub-machine?
// =============================================================================================

class EvaluateMachineActivity final : public SelfOwningOperation<EvaluateMachineActivity>
{
public:
  EvaluateMachineActivity(AddressSpace addressSpace, NodeId variableId,
    std::function<void(OptionalStateMachineActiveResult)> callback)
    : SelfOwningOperation(boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mVariableId(std::move(variableId)), mCallback(std::move(callback))
  {}

  static void start(AddressSpace addressSpace, NodeId variableId,
    std::function<void(OptionalStateMachineActiveResult)> callback)
  {
    launch(std::make_shared<EvaluateMachineActivity>(
      std::move(addressSpace), std::move(variableId), std::move(callback)));
  }

private:
  friend class SelfOwningOperation<EvaluateMachineActivity>;

  void fail_to_start(StatusCode status)
  {
    finish(OptionalStateMachineActiveResult{status});
  }

  void finish(OptionalStateMachineActiveResult result)
  {
    auto callback = std::move(mCallback);
    mCallback = nullptr;
    ua::detail::invoke_user_callback(mLogger, callback, std::move(result));
  }

  ua::async::Task<> run()
  {
    try
    {
      finish(co_await evaluate());
    }
    catch (const ua::async::Abandoned& abandoned)
    {
      // ANSWERED, not rethrown - see the note in EvaluateMethodExecutable::run.
      finish(OptionalStateMachineActiveResult{abandoned.status_code()});
    }
    catch (...)
    {
      ua::async::guarded(mLogger,
        [this] {
          finish(OptionalStateMachineActiveResult{ua::exception_to_status_code(std::current_exception())});
        })();
    }
  }

  /// Every step here names the node the next step asks about, so there is nothing to batch: the walk
  /// is `variable -> owning machine -> owning state -> parent machine -> its CurrentState.Id`, and no
  /// two of those are known at the same time.
  ua::async::Task<OptionalStateMachineActiveResult> evaluate()
  {
    // The address space is locked only inside each step's initiation (ua_namespace.h, Ownership).
    auto variableId = mVariableId;
    auto variable = co_await await_step<NodeAccessorResult>(
      [this, &variableId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_node_async(variableId, std::move(completion));
        else
          completion(NodeAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
      });
    if (!variable.is_good())
    {
      co_return OptionalStateMachineActiveResult{lookup_not_good(variableId, variable.status_code())};
    }

    auto variableNode = std::move(variable).value();
    const auto browseName = variableNode.get_browse_name();
    if (browseName != QualifiedName{0, "CurrentState"} && browseName != QualifiedName{0, "LastTransition"})
    {
      co_return std::optional<bool>{};
    }

    auto variableReferences = co_await await_step<NodeAccessor::ReferencesResult>(
      [&variableNode](auto completion) { variableNode.get_references_async(std::move(completion)); });
    if (!variableReferences.is_good())
    {
      co_return OptionalStateMachineActiveResult{
        references_not_good(variableId, variableReferences.status_code())};
    }

    const auto owners =
      local_inverse_targets(variableReferences.value(), NodeId{ReferenceTypeId::HasComponent});
    if (owners.empty())
    {
      co_return std::optional<bool>{};
    }
    if (owners.size() != 1U)
    {
      co_return OptionalStateMachineActiveResult{invalid_activity_topology("AmbiguousStateVariableOwner",
        "StateMachine state Variable has more than one inverse HasComponent owner",
        mVariableId)};
    }

    auto machineId = owners.front();
    auto machine = co_await await_step<NodeAccessorResult>(
      [this, &machineId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_node_async(machineId, std::move(completion));
        else
          completion(NodeAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
      });
    if (!machine.is_good())
    {
      co_return OptionalStateMachineActiveResult{lookup_not_good(machineId, machine.status_code())};
    }

    auto machineNode = std::move(machine).value();
    auto machineReferences = co_await await_step<NodeAccessor::ReferencesResult>(
      [&machineNode](auto completion) { machineNode.get_references_async(std::move(completion)); });
    if (!machineReferences.is_good())
    {
      co_return OptionalStateMachineActiveResult{
        references_not_good(machineId, machineReferences.status_code())};
    }

    // A machine nothing owns as a sub-machine is not a sub-machine, and its activity is not a
    // question this answers.
    const auto owningStates =
      local_inverse_targets(machineReferences.value(), NodeId{ReferenceTypeId::HasSubStateMachine});
    if (owningStates.empty())
    {
      co_return std::optional<bool>{};
    }
    if (owningStates.size() != 1U)
    {
      co_return OptionalStateMachineActiveResult{invalid_activity_topology("AmbiguousSubStateMachineOwner",
        "SubStateMachine has more than one inverse HasSubStateMachine owner",
        machineId)};
    }

    auto owningStateId = owningStates.front();
    auto owningState = co_await await_step<NodeAccessorResult>(
      [this, &owningStateId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_node_async(owningStateId, std::move(completion));
        else
          completion(NodeAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
      });
    if (!owningState.is_good())
    {
      co_return OptionalStateMachineActiveResult{lookup_not_good(owningStateId, owningState.status_code())};
    }

    auto owningStateNode = std::move(owningState).value();
    auto owningStateReferences = co_await await_step<NodeAccessor::ReferencesResult>(
      [&owningStateNode](auto completion) { owningStateNode.get_references_async(std::move(completion)); });
    if (!owningStateReferences.is_good())
    {
      co_return OptionalStateMachineActiveResult{
        references_not_good(owningStateId, owningStateReferences.status_code())};
    }

    const auto parentMachines =
      local_inverse_targets(owningStateReferences.value(), NodeId{ReferenceTypeId::HasComponent});
    if (parentMachines.size() != 1U)
    {
      co_return OptionalStateMachineActiveResult{invalid_activity_topology("InvalidSubStateMachineParent",
        "State owning a SubStateMachine must have exactly one inverse HasComponent parent",
        owningStateId)};
    }

    auto parentMachineId = parentMachines.front();
    auto parentCurrentState = co_await await_step<VariableAccessorResult>(
      [this, &parentMachineId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
            parentMachineId,
            NodeId{ReferenceTypeId::HasComponent},
            QualifiedName{0, "CurrentState"},
            std::move(completion));
        }
        else
        {
          completion(VariableAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
        }
      });
    if (!parentCurrentState.is_good())
    {
      co_return OptionalStateMachineActiveResult{
        lookup_not_good(parentMachineId, parentCurrentState.status_code())};
    }

    auto parentCurrentStateId = parentCurrentState.value().get_node_id();
    auto idProperty = co_await await_step<VariableAccessorResult>(
      [this, &parentCurrentStateId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
            parentCurrentStateId,
            NodeId{ReferenceTypeId::HasProperty},
            QualifiedName{0, "Id"},
            std::move(completion));
        }
        else
        {
          completion(VariableAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
        }
      });
    if (!idProperty.is_good())
    {
      co_return OptionalStateMachineActiveResult{
        lookup_not_good(parentCurrentStateId, idProperty.status_code())};
    }

    auto idVariable = std::move(idProperty).value();
    auto value = co_await await_step<DataValueResult>(
      [&idVariable](auto completion)
      {
        idVariable.read_value_async(
          // State-machine state: what the machine is doing, not what any Session may see of it.
          Duration{},
          true,
          ReadValueId{},
          /*caller=*/nullptr,
          std::move(completion));
      });
    if (!value.is_good())
    {
      co_return OptionalStateMachineActiveResult{
        read_not_good(idVariable.get_node_id(), value.status_code())};
    }
    const auto& currentStateStatus = value.value().status();
    if (currentStateStatus && !currentStateStatus.value().is_good())
    {
      co_return OptionalStateMachineActiveResult{
        read_not_good(idVariable.get_node_id(), currentStateStatus.value())};
    }

    const auto* currentStateId = value.value().value().try_as<NodeId>();
    if (currentStateId == nullptr)
    {
      co_return OptionalStateMachineActiveResult{current_state_id_type_mismatch(idVariable.get_node_id())};
    }
    co_return std::optional<bool>{*currentStateId == owningStateId};
  }

  WeakAddressSpace mAddressSpace;
  NodeId mVariableId;
  std::function<void(OptionalStateMachineActiveResult)> mCallback;
};

// =============================================================================================
// Which transition, if any, is enabled - and everything the event needs to describe it
// =============================================================================================

class ResolveTransition final : public SelfOwningOperation<ResolveTransition>
{
public:
  ResolveTransition(AddressSpace addressSpace, NodeId machineId, std::optional<NodeId> methodId,
    StateMachineModel::ResolveCallback callback)
    : SelfOwningOperation(boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mMachineId(std::move(machineId)), mMethodId(std::move(methodId)),
      mCallback(std::move(callback))
  {}

  static void start(AddressSpace addressSpace, NodeId machineId, std::optional<NodeId> methodId,
    StateMachineModel::ResolveCallback callback)
  {
    launch(std::make_shared<ResolveTransition>(
      std::move(addressSpace), std::move(machineId), std::move(methodId), std::move(callback)));
  }

private:
  friend class SelfOwningOperation<ResolveTransition>;

  /// One transition the walk is prepared to select, before the states it names are described.
  struct Candidate
  {
    NodeAccessor transition;
    NodeId fromState;
    NodeId toState;
    /// The targets of the transition's HasEffect References.
    std::vector<NodeId> effects;
  };

  /// A state the machine TYPE declares, kept only so that two of them carrying the same BrowseName or
  /// the same StateNumber can be refused.
  struct DeclaredState
  {
    NodeId id;
    QualifiedName browseName;
    uint32_t stateNumber;
  };

  void fail_to_start(StatusCode status)
  {
    finish(StateMachineTransitionResolutionResult{status});
  }

  void finish(StateMachineTransitionResolutionResult result)
  {
    auto callback = std::move(mCallback);
    mCallback = nullptr;
    ua::detail::invoke_user_callback(mLogger, callback, std::move(result));
  }

  ua::async::Task<> run()
  {
    try
    {
      finish(co_await resolve());
    }
    catch (const ua::async::Abandoned& abandoned)
    {
      // ANSWERED, not rethrown - see the note in EvaluateMethodExecutable::run.
      finish(StateMachineTransitionResolutionResult{abandoned.status_code()});
    }
    catch (...)
    {
      ua::async::guarded(mLogger,
        [this]
        {
          finish(
            StateMachineTransitionResolutionResult{ua::exception_to_status_code(std::current_exception())});
        })();
    }
  }

  /// Reads one already-resolved state into the descriptor a TransitionEvent carries: its BrowseName,
  /// its DisplayName and its StateNumber. Called for the transition's FromState and its ToState,
  /// which is the only reason it is a function of its own; the two nodes themselves are resolved
  /// together by the caller, because it knows both at once.
  ua::async::Task<Result<StateMachineStateDescriptor>> describe_state(NodeId stateId, NodeAccessor state)
  {
    StateMachineStateDescriptor descriptor;
    descriptor.id = stateId;
    descriptor.name = state.get_browse_name();

    const auto display = state.read_attribute(AttributeId::DisplayName);
    const auto* localized = display.try_as<LocalizedText>();
    if (localized == nullptr)
    {
      co_return Result<StateMachineStateDescriptor>{state_display_name_type_mismatch(stateId)};
    }
    descriptor.effectiveDisplayName = *localized;

    auto numberProperty = co_await await_step<VariableAccessorResult>(
      [this, &stateId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
            stateId,
            NodeId{ReferenceTypeId::HasProperty},
            QualifiedName{0, "StateNumber"},
            std::move(completion));
        }
        else
        {
          completion(VariableAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
        }
      });
    if (!numberProperty.is_good())
    {
      co_return Result<StateMachineStateDescriptor>{lookup_not_good(stateId, numberProperty.status_code())};
    }

    auto numberVariable = std::move(numberProperty).value();
    auto number = co_await await_step<DataValueResult>(
      [&numberVariable](auto completion)
      {
        numberVariable.read_value_async(
          Duration{}, true, ReadValueId{}, /*caller=*/nullptr, std::move(completion));
      });
    if (!number.is_good())
    {
      co_return Result<StateMachineStateDescriptor>{
        read_not_good(numberVariable.get_node_id(), number.status_code())};
    }
    const auto& stateNumberStatus = number.value().status();
    if (stateNumberStatus && !stateNumberStatus.value().is_good())
    {
      co_return Result<StateMachineStateDescriptor>{
        read_not_good(numberVariable.get_node_id(), stateNumberStatus.value())};
    }
    const auto* stateNumber = number.value().value().try_as<uint32_t>();
    if (stateNumber == nullptr)
    {
      co_return Result<StateMachineStateDescriptor>{state_number_type_mismatch(stateId)};
    }
    descriptor.number = *stateNumber;
    co_return descriptor;
  }

  /// The TransitionNumber Property of the transition @p transitionId (OPC 10000-16 4.4.10), which its
  /// TransitionEvent and an AuditProgramTransitionEvent carry; none when the transition has no such Property.
  ua::async::Task<Result<std::optional<uint32_t>>> transition_number(NodeId transitionId)
  {
    auto numberProperty = co_await await_step<VariableAccessorResult>(
      [this, &transitionId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
            transitionId,
            NodeId{ReferenceTypeId::HasProperty},
            QualifiedName{0, "TransitionNumber"},
            std::move(completion));
        }
        else
        {
          completion(VariableAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
        }
      });
    if (numberProperty.status_code().as_status() == Status::BadNodeIdUnknown)
    {
      co_return std::optional<uint32_t>{};
    }
    if (!numberProperty.is_good())
    {
      co_return Result<std::optional<uint32_t>>{lookup_not_good(transitionId, numberProperty.status_code())};
    }

    auto numberVariable = std::move(numberProperty).value();
    auto number = co_await await_step<DataValueResult>(
      [&numberVariable](auto completion)
      {
        numberVariable.read_value_async(
          Duration{}, true, ReadValueId{}, /*caller=*/nullptr, std::move(completion));
      });
    if (!number.is_good())
    {
      co_return Result<std::optional<uint32_t>>{
        read_not_good(numberVariable.get_node_id(), number.status_code())};
    }
    // The number is put on the transition's Events, so only a Good value is used.
    if (number.value().status() && !number.value().status()->is_good())
    {
      co_return Result<std::optional<uint32_t>>{
        read_not_good(numberVariable.get_node_id(), *number.value().status())};
    }
    const auto* transitionNumber = number.value().value().try_as<uint32_t>();
    if (transitionNumber == nullptr)
    {
      co_return Result<std::optional<uint32_t>>{transition_number_type_mismatch(transitionId)};
    }
    co_return std::optional<uint32_t>{*transitionNumber};
  }

  /// Whether this component is the transition the caller is asking about.
  ///
  /// The two questions are different enough to be worth naming apart. A METHOD call asks "is this
  /// Method among the transition's causes", by NodeId first and by BrowseName second. An AUTOMATIC
  /// step asks "is this a guarded transition out of the current state whose guard is an Else", which
  /// is the only kind that fires without a cause.
  ua::async::Task<BoolResult> component_is_selected(
    const std::vector<NodeId>& causes, const std::vector<NodeId>& guards, const QualifiedName& methodName)
  {
    if (!mMethodId)
    {
      auto guardId = guards.front();
      auto guard = co_await await_step<NodeAccessorResult>(
        [this, &guardId](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            addressSpace->find_node_async(guardId, std::move(completion));
          else
            completion(NodeAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
        });
      if (!guard.is_good())
      {
        co_return BoolResult{lookup_not_good(guardId, guard.status_code())};
      }

      auto guardNode = std::move(guard).value();
      auto guardType = co_await await_step<instance_utils::OptionalNodeIdResult>([&guardNode](auto completion)
        { instance_utils::get_local_type_definition_id_async(guardNode, std::move(completion)); });
      if (!guardType.is_good())
      {
        co_return BoolResult{references_not_good(guardId, guardType.status_code())};
      }
      const auto& guardTypeId = guardType.value();
      co_return BoolResult{
        guardTypeId.has_value() && guardTypeId.value() == NodeId{VariableTypeId::ElseGuardVariableType}};
    }

    if (causes.empty())
    {
      co_return BoolResult{false};
    }

    // The identity test costs nothing, so it is asked as far as it can be - which is the first cause
    // and no further. A Method that IS the first cause is answered without troubling a namespace at
    // all, which is the common shape and what the per-cause walk did. Past that first cause the walk
    // owes a BrowseName, and nothing later can be judged before it has one.
    if (causes.front() == *mMethodId)
    {
      co_return BoolResult{true};
    }

    // ONE resolution for every cause, and then the SAME walk as before over the answers.
    //
    // A Method can be a cause by identity or by name - an instance Method causing a transition its
    // TYPE declares - so a cause that is not this Method's NodeId still has to be resolved to compare
    // BrowseNames. Doing that one at a time cost a namespace a round trip per cause.
    //
    // The order below is the order the per-cause walk asked its questions in, and it is kept
    // deliberately: hoisting every NodeId comparison ahead of every resolution would answer `true`
    // for a cause that matches by identity sitting BEHIND one that does not resolve, where the walk
    // this replaces reported the failure. Prefetching may cost a resolution the old walk would not
    // have reached; it must not change the answer.
    auto causeIds = causes;
    auto resolved = co_await await_step<BatchResult<NodeAccessorResult>>(
      [this, &causeIds](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_nodes_async(causeIds, std::move(completion));
        else
          completion(address_space_gone_batch(causeIds.size()));
      });

    for (size_t k = 0; k < causeIds.size(); ++k)
    {
      if (causeIds[k] == *mMethodId)
      {
        co_return BoolResult{true};
      }

      // A short batch is a namespace answering fewer items than it was asked about, which is a
      // contract breach rather than an outcome for the cause.
      if (k >= resolved.items.size())
      {
        co_return BoolResult{StatusCode{Status::BadInternalError}};
      }
      if (!resolved.items[k].is_good())
      {
        co_return BoolResult{lookup_not_good(causeIds[k], resolved.items[k].status_code())};
      }

      // A Method carrying no BrowseName names nothing, so it matches nothing. Without this an unnamed
      // Method and an unnamed cause would compare equal - both empty - and select each other.
      if (!methodName.name().empty() && resolved.items[k].value().get_browse_name() == methodName)
      {
        co_return BoolResult{true};
      }
    }
    co_return BoolResult{false};
  }

  ua::async::Task<StateMachineTransitionResolutionResult> resolve()
  {
    // The address space is locked only inside each step's initiation, so this operation - which every
    // completion it hands out owns - never keeps it alive across a suspension (ua_namespace.h, Ownership).
    auto machineId = mMachineId;

    // --- the Method's name, which is the second way a cause can match -----------------------------
    QualifiedName methodName;
    if (mMethodId)
    {
      auto methodId = *mMethodId;
      auto method = co_await await_step<NodeAccessorResult>(
        [this, &methodId](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            addressSpace->find_node_async(methodId, std::move(completion));
          else
            completion(NodeAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
        });
      if (!method.is_good())
      {
        co_return StateMachineTransitionResolutionResult{lookup_not_good(methodId, method.status_code())};
      }
      methodName = method.value().get_browse_name();
    }

    // --- the machine, and the type that declares its states and transitions -----------------------
    auto machine = co_await await_step<NodeAccessorResult>(
      [this, &machineId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_node_async(machineId, std::move(completion));
        else
          completion(NodeAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
      });
    if (!machine.is_good())
    {
      co_return StateMachineTransitionResolutionResult{lookup_not_good(machineId, machine.status_code())};
    }

    auto machineNode = std::move(machine).value();
    auto machineTypeId =
      co_await await_step<instance_utils::OptionalNodeIdResult>([&machineNode](auto completion)
        { instance_utils::get_local_type_definition_id_async(machineNode, std::move(completion)); });
    if (!machineTypeId.is_good())
    {
      co_return StateMachineTransitionResolutionResult{
        references_not_good(machineId, machineTypeId.status_code())};
    }
    // A machine with no local type definition declares no transitions, which is an answer rather than
    // a failure.
    const auto& machineTypeDefinition = machineTypeId.value();
    if (!machineTypeDefinition)
    {
      co_return StateMachineTransitionResolution{};
    }
    auto typeId = machineTypeDefinition.value();

    // --- where the machine is now -----------------------------------------------------------------
    auto currentStateVariable = co_await await_step<VariableAccessorResult>(
      [this, &machineId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
            machineId,
            NodeId{ReferenceTypeId::HasComponent},
            QualifiedName{0, "CurrentState"},
            std::move(completion));
        }
        else
        {
          completion(VariableAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
        }
      });
    // No CurrentState is a machine that is not running one, not a broken machine; an address space that is
    // gone is neither, and is answered as such. An Uncertain answer, with or without the Variable, says
    // neither, and is refused.
    if (!currentStateVariable.is_good())
    {
      if (currentStateVariable.is_uncertain() ||
          ua::detail::is_address_space_gone(currentStateVariable.status_code()))
      {
        co_return StateMachineTransitionResolutionResult{
          lookup_not_good(machineId, currentStateVariable.status_code())};
      }
      co_return StateMachineTransitionResolution{};
    }

    auto currentStateVariableId = currentStateVariable.value().get_node_id();
    auto currentStateIdProperty = co_await await_step<VariableAccessorResult>(
      [this, &currentStateVariableId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
            currentStateVariableId,
            NodeId{ReferenceTypeId::HasProperty},
            QualifiedName{0, "Id"},
            std::move(completion));
        }
        else
        {
          completion(VariableAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
        }
      });
    if (!currentStateIdProperty.is_good())
    {
      co_return StateMachineTransitionResolutionResult{
        lookup_not_good(currentStateVariableId, currentStateIdProperty.status_code())};
    }

    auto idVariable = std::move(currentStateIdProperty).value();
    auto currentStateValue = co_await await_step<DataValueResult>(
      [&idVariable](auto completion) {
        idVariable.read_value_async(
          Duration{}, true, ReadValueId{}, /*caller=*/nullptr, std::move(completion));
      });
    if (!currentStateValue.is_good())
    {
      co_return StateMachineTransitionResolutionResult{
        read_not_good(idVariable.get_node_id(), currentStateValue.status_code())};
    }
    const auto& currentStateStatus = currentStateValue.value().status();
    if (currentStateStatus && !currentStateStatus.value().is_good())
    {
      co_return StateMachineTransitionResolutionResult{
        read_not_good(idVariable.get_node_id(), currentStateStatus.value())};
    }
    const auto* currentStatePointer = currentStateValue.value().value().try_as<NodeId>();
    if (currentStatePointer == nullptr)
    {
      co_return StateMachineTransitionResolutionResult{
        current_state_id_type_mismatch(idVariable.get_node_id())};
    }
    const NodeId currentStateId = *currentStatePointer;

    // --- everything the type declares -------------------------------------------------------------
    auto machineType = co_await await_step<NodeAccessorResult>(
      [this, &typeId](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_node_async(typeId, std::move(completion));
        else
          completion(NodeAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
      });
    if (!machineType.is_good())
    {
      co_return StateMachineTransitionResolutionResult{lookup_not_good(typeId, machineType.status_code())};
    }

    auto machineTypeNode = std::move(machineType).value();
    auto typeReferences = co_await await_step<NodeAccessor::ReferencesResult>(
      [&machineTypeNode](auto completion) { machineTypeNode.get_references_async(std::move(completion)); });
    if (!typeReferences.is_good())
    {
      co_return StateMachineTransitionResolutionResult{
        references_not_good(typeId, typeReferences.status_code())};
    }
    const auto componentIds =
      local_forward_targets(typeReferences.value(), NodeId{ReferenceTypeId::HasComponent});

    // --- the scan ---------------------------------------------------------------------------------
    //
    // Every component of the type is either a declared STATE, which carries a StateNumber and is
    // collected so that two of them cannot collide, or a declared TRANSITION, which is a candidate if
    // it is the one the caller is asking about. A component can be neither, and most are.
    std::vector<DeclaredState> declaredStates;
    std::vector<Candidate> candidates;
    bool methodIsCause = false;

    // ONE resolution for every component the type declares, in ROUNDS.
    //
    // They are all known before the scan starts, so asking about them one at a time cost a namespace
    // a round trip per component - and the component count is what dominates a transition resolve.
    // But that count is the address space's to choose, not this walk's, so the call it replaces them
    // with is bounded: a type with thousands of components would otherwise hand `find_nodes_async` -
    // which is `noexcept` and allocates a slot per id - a request sized by the model, and a Read of
    // `Executable` over a thousand Methods starts a thousand of these at once.
    BatchResult<NodeAccessorResult> resolvedComponents;
    size_t roundStart = 0;

    for (size_t componentIndex = 0; componentIndex < componentIds.size(); ++componentIndex)
    {
      if (componentIndex >= roundStart + resolvedComponents.items.size())
      {
        roundStart = componentIndex;
        const size_t roundEnd = std::min(roundStart + maxComponentsPerResolution, componentIds.size());
        std::vector<NodeId> ids(componentIds.begin() + static_cast<std::ptrdiff_t>(roundStart),
          componentIds.begin() + static_cast<std::ptrdiff_t>(roundEnd));
        resolvedComponents = co_await await_step<BatchResult<NodeAccessorResult>>(
          [this, &ids](auto completion)
          {
            if (auto addressSpace = mAddressSpace.lock())
              addressSpace->find_nodes_async(ids, std::move(completion));
            else
              completion(address_space_gone_batch(ids.size()));
          });
      }

      const auto& componentId = componentIds[componentIndex];
      auto id = componentId;
      const size_t slot = componentIndex - roundStart;
      // A short batch is a namespace answering fewer items than it was asked about, which is a
      // contract breach rather than an outcome for the component.
      if (slot >= resolvedComponents.items.size())
      {
        co_return StateMachineTransitionResolutionResult{StatusCode{Status::BadInternalError}};
      }
      if (!resolvedComponents.items[slot].is_good())
      {
        co_return StateMachineTransitionResolutionResult{
          lookup_not_good(componentId, resolvedComponents.items[slot].status_code())};
      }
      auto componentNode = std::move(resolvedComponents.items[slot]).value();

      auto stateNumberProperty = co_await await_step<VariableAccessorResult>(
        [this, &id](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*addressSpace),
              id,
              NodeId{ReferenceTypeId::HasProperty},
              QualifiedName{0, "StateNumber"},
              std::move(completion));
          }
          else
          {
            completion(VariableAccessorResult{ua::detail::address_space_gone("StateMachineRuntime")});
          }
        });
      if (!stateNumberProperty.is_good())
      {
        // No StateNumber means this component is not a declared state - a transition, a method, a
        // sub-machine. Anything else wrong with looking for it, an Uncertain answer included, is a failure.
        if (stateNumberProperty.status_code().as_status() != Status::BadNodeIdUnknown)
        {
          co_return StateMachineTransitionResolutionResult{
            lookup_not_good(id, stateNumberProperty.status_code())};
        }
      }
      else
      {
        auto numberVariable = std::move(stateNumberProperty).value();
        auto number = co_await await_step<DataValueResult>(
          [&numberVariable](auto completion)
          {
            numberVariable.read_value_async(
              Duration{}, true, ReadValueId{}, /*caller=*/nullptr, std::move(completion));
          });
        if (!number.is_good())
        {
          co_return StateMachineTransitionResolutionResult{
            read_not_good(numberVariable.get_node_id(), number.status_code())};
        }
        const auto& stateNumberStatus = number.value().status();
        if (stateNumberStatus && !stateNumberStatus.value().is_good())
        {
          co_return StateMachineTransitionResolutionResult{
            read_not_good(numberVariable.get_node_id(), stateNumberStatus.value())};
        }
        const auto* stateNumber = number.value().value().try_as<uint32_t>();
        if (stateNumber == nullptr)
        {
          co_return StateMachineTransitionResolutionResult{
            state_number_type_mismatch(numberVariable.get_node_id())};
        }
        declaredStates.push_back(
          DeclaredState{componentNode.get_node_id(), componentNode.get_browse_name(), *stateNumber});
      }

      auto componentReferences = co_await await_step<NodeAccessor::ReferencesResult>(
        [&componentNode](auto completion) { componentNode.get_references_async(std::move(completion)); });
      if (!componentReferences.is_good())
      {
        co_return StateMachineTransitionResolutionResult{
          references_not_good(componentId, componentReferences.status_code())};
      }

      const auto causes =
        local_forward_targets(componentReferences.value(), NodeId{ReferenceTypeId::HasCause});
      const auto fromStates =
        local_forward_targets(componentReferences.value(), NodeId{ReferenceTypeId::FromState});
      const auto toStates =
        local_forward_targets(componentReferences.value(), NodeId{ReferenceTypeId::ToState});
      const auto effects =
        local_forward_targets(componentReferences.value(), NodeId{ReferenceTypeId::HasEffect});
      const auto guards =
        local_forward_targets(componentReferences.value(), NodeId{ReferenceTypeId::HasGuard});

      // An automatic step only ever considers a guarded transition out of the current state, so the
      // shape is checked before the guard is fetched - which is what keeps the scan cheap on the many
      // components that are not one.
      const bool worthAsking = mMethodId.has_value() || (causes.empty() && fromStates.size() == 1U &&
                                                          fromStates[0] == currentStateId &&
                                                          toStates.size() == 1U && guards.size() == 1U);
      bool selected = false;
      if (worthAsking)
      {
        auto verdict = co_await component_is_selected(causes, guards, methodName);
        if (!verdict.is_good())
        {
          co_return StateMachineTransitionResolutionResult{verdict.status_code(), verdict.shared_detail()};
        }
        selected = verdict.value();
      }

      if (!selected)
      {
        continue;
      }

      if (mMethodId)
      {
        // The Method causes this transition, which is the answer to "may it be called" whether or not
        // the transition can fire from where the machine is now.
        methodIsCause = true;
        // A transition may have more than one effect (OPC 10000-16 4.4.10); its effects do not decide
        // whether it is taken.
        if (fromStates.size() != 1U || fromStates[0] != currentStateId || toStates.size() != 1U)
        {
          continue;
        }
      }

      candidates.push_back(Candidate{componentNode, fromStates[0], toStates[0], effects});
    }

    // --- what the scan found ----------------------------------------------------------------------
    for (size_t first = 0; first < declaredStates.size(); ++first)
    {
      for (size_t second = first + 1U; second < declaredStates.size(); ++second)
      {
        if (declaredStates[first].browseName == declaredStates[second].browseName)
        {
          co_return StateMachineTransitionResolutionResult{duplicate_state_browse_name(
            typeId, declaredStates[first].browseName, declaredStates[first].id, declaredStates[second].id)};
        }
        if (declaredStates[first].stateNumber == declaredStates[second].stateNumber)
        {
          co_return StateMachineTransitionResolutionResult{duplicate_state_number(
            typeId, declaredStates[first].stateNumber, declaredStates[first].id, declaredStates[second].id)};
        }
      }
    }

    if (candidates.empty())
    {
      co_return StateMachineTransitionResolution{methodIsCause, std::nullopt};
    }
    if (candidates.size() != 1U)
    {
      co_return StateMachineTransitionResolutionResult{ambiguous_transition(machineId)};
    }

    // --- describe the transition the event will carry ---------------------------------------------
    const auto& selectedCandidate = candidates.front();
    StateMachineTransitionDescriptor descriptor;
    descriptor.machineId = machineId;
    descriptor.transitionId = selectedCandidate.transition.get_node_id();
    descriptor.transitionName = selectedCandidate.transition.get_browse_name();
    descriptor.methodName = methodName;
    auto transitionNumber = co_await transition_number(descriptor.transitionId);
    if (!transitionNumber.is_good())
    {
      co_return StateMachineTransitionResolutionResult{transitionNumber.status_code()};
    }
    descriptor.transitionNumber = transitionNumber.value();
    auto eventTypes = co_await transition_event_types(selectedCandidate.effects);
    if (!eventTypes.is_good())
    {
      co_return StateMachineTransitionResolutionResult{eventTypes.status_code()};
    }
    descriptor.eventTypes = std::move(eventTypes.value().events);
    descriptor.auditEventTypes = std::move(eventTypes.value().audits);
    descriptor.currentStateVariableId = currentStateVariableId;
    descriptor.currentStateIdPropertyId = idVariable.get_node_id();

    // ONE resolution for both ends of the transition. They are named by the same candidate, so
    // there is never a moment when only one of them is known.
    //
    // A Transition may legally name the same state at both ends. The two sequential loads this
    // replaces asked twice, in two calls; asking one namespace for the same id twice in ONE call is a
    // demand no namespace had to meet before, and one that answers per distinct id would under-fill
    // the batch.
    const bool selfTransition = selectedCandidate.toState == selectedCandidate.fromState;
    std::vector<NodeId> endIds{selectedCandidate.fromState};
    if (!selfTransition)
    {
      endIds.push_back(selectedCandidate.toState);
    }
    auto ends = co_await await_step<BatchResult<NodeAccessorResult>>(
      [this, &endIds](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
          addressSpace->find_nodes_async(endIds, std::move(completion));
        else
          completion(address_space_gone_batch(endIds.size()));
      });
    if (ends.items.size() < endIds.size())
    {
      co_return StateMachineTransitionResolutionResult{StatusCode{Status::BadInternalError}};
    }
    // Asked in the order the two sequential loads asked them: everything about the FromState before
    // anything about the ToState, so a transition with both ends broken still answers about the
    // FromState.
    if (!ends.items[0].is_good())
    {
      co_return StateMachineTransitionResolutionResult{
        lookup_not_good(endIds[0], ends.items[0].status_code())};
    }

    auto fromState = co_await describe_state(endIds[0], ends.items[0].value());
    if (!fromState.is_good())
    {
      co_return StateMachineTransitionResolutionResult{fromState.status_code()};
    }
    descriptor.fromState = std::move(fromState).value();

    size_t toSlot = 1U;
    if (selfTransition)
    {
      toSlot = 0U;
    }
    if (!ends.items[toSlot].is_good())
    {
      co_return StateMachineTransitionResolutionResult{
        lookup_not_good(selectedCandidate.toState, ends.items[toSlot].status_code())};
    }

    auto toState = co_await describe_state(selectedCandidate.toState, ends.items[toSlot].value());
    if (!toState.is_good())
    {
      co_return StateMachineTransitionResolutionResult{toState.status_code()};
    }
    descriptor.toState = std::move(toState).value();

    co_return StateMachineTransitionResolution{mMethodId.has_value(), std::move(descriptor)};
  }

  /// The EventTypes a transition's effects name, split in two (OPC 10000-16 4.4.14): the Events it raises
  /// whenever it is triggered, each effect that is not an audit EventType or TransitionEventType when there
  /// is none; and the audit EventTypes, which it raises as its audit Event only when the server audits (OPC
  /// 10000-10 5.2.6). An effect whose type does not exist is not an audit EventType.
  struct EffectEventTypes
  {
    std::vector<NodeId> events;
    std::vector<NodeId> audits;
  };

  ua::async::Task<Result<EffectEventTypes>> transition_event_types(const std::vector<NodeId>& effects)
  {
    EffectEventTypes types;
    std::vector<NodeId>& eventTypes = types.events;
    if (!effects.empty())
    {
      auto found = co_await await_step<BatchResult<NodeAccessorResult>>(
        [this, &effects](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            addressSpace->find_nodes_async(effects, std::move(completion));
          else
            completion(address_space_gone_batch(effects.size()));
        });
      if (found.items.size() < effects.size())
      {
        co_return Result<EffectEventTypes>{StatusCode{Status::BadInternalError}};
      }
      std::vector<std::pair<NodeAccessor, NodeId>> starts;
      std::vector<std::size_t> startOf;
      std::vector<bool> audit(effects.size(), false);
      for (std::size_t k = 0; k < effects.size(); ++k)
      {
        if (found.items[k].status_code().as_status() == Status::BadNodeIdUnknown)
        {
          continue;
        }
        if (!found.items[k].is_good())
        {
          co_return Result<EffectEventTypes>{lookup_not_good(effects[k], found.items[k].status_code())};
        }
        starts.emplace_back(std::move(found.items[k]).value(), effects[k]);
        startOf.push_back(k);
      }
      if (!starts.empty())
      {
        const std::size_t walked = starts.size();
        auto ends = co_await await_step<std::vector<SupertypeWalkEnd>>(
          [this, &starts](auto completion)
          {
            auto addressSpace = mAddressSpace.lock();
            if (!addressSpace)
            {
              completion(std::vector<SupertypeWalkEnd>(starts.size(),
                SupertypeWalkEnd{
                  SupertypeWalkEnd::How::Failed, 0, ua::detail::address_space_gone("StateMachineRuntime")}));
              return;
            }
            walk_supertypes(
              *addressSpace,
              RequestInfo{},
              std::move(starts),
              addressSpace->limits().loopLimit,
              [](std::size_t, const NodeId& type) -> std::optional<int>
              {
                if (type == NodeId{ObjectTypeId::AuditEventType})
                {
                  return 1;
                }
                if (type == NodeId{ObjectTypeId::BaseEventType})
                {
                  return 0;
                }
                return std::nullopt;
              },
              std::move(completion));
          });
        if (ends.size() < walked)
        {
          co_return Result<EffectEventTypes>{StatusCode{Status::BadInternalError}};
        }
        for (std::size_t chain = 0; chain < walked; ++chain)
        {
          if (ends[chain].how == SupertypeWalkEnd::How::Failed)
          {
            StatusCode failure = ends[chain].failure;
            if (!failure.is_bad())
            {
              failure = StatusCode{Status::BadInternalError};
            }
            co_return Result<EffectEventTypes>{std::move(failure)};
          }
          audit[startOf[chain]] = ends[chain].how == SupertypeWalkEnd::How::Decided && ends[chain].value == 1;
        }
      }
      for (std::size_t k = 0; k < effects.size(); ++k)
      {
        (audit[k] ? types.audits : eventTypes).push_back(effects[k]);
      }
    }
    if (eventTypes.empty())
    {
      eventTypes.emplace_back(ObjectTypeId::TransitionEventType);
    }
    co_return types;
  }

  WeakAddressSpace mAddressSpace;
  NodeId mMachineId;
  std::optional<NodeId> mMethodId;
  StateMachineModel::ResolveCallback mCallback;
};

// =============================================================================================
// Write the machine into its new state, and put it back if only half of that works
// =============================================================================================

class CommitTransition final : public SelfOwningOperation<CommitTransition>
{
public:
  CommitTransition(AddressSpace addressSpace, StateMachineTransitionDescriptor transition,
    StateMachineModel::CommitCallback callback)
    : SelfOwningOperation(boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mTransition(std::move(transition)), mCallback(std::move(callback))
  {}

  static void start(AddressSpace addressSpace, StateMachineTransitionDescriptor transition,
    StateMachineModel::CommitCallback callback)
  {
    launch(std::make_shared<CommitTransition>(
      std::move(addressSpace), std::move(transition), std::move(callback)));
  }

private:
  friend class SelfOwningOperation<CommitTransition>;

  void fail_to_start(StatusCode status)
  {
    finish(VoidResult{status});
  }

  void finish(VoidResult result)
  {
    auto callback = std::move(mCallback);
    mCallback = nullptr;
    ua::detail::invoke_user_callback(mLogger, callback, std::move(result));
  }

  ua::async::Task<> run()
  {
    try
    {
      finish(co_await commit());
    }
    catch (const ua::async::Abandoned& abandoned)
    {
      // ANSWERED, not rethrown - see the note in EvaluateMethodExecutable::run.
      finish(VoidResult{abandoned.status_code()});
    }
    catch (...)
    {
      ua::async::guarded(
        mLogger, [this] { finish(VoidResult{ua::exception_to_status_code(std::current_exception())}); })();
    }
  }

  ua::async::Task<VoidResult> write_value(NodeId variableId, DataValue value)
  {
    // The address space is locked only inside the step's initiation (ua_namespace.h, Ownership).
    auto written = co_await await_step<VoidResult>(
      [this, &variableId, &value](auto completion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          instance_utils::write_variable_value_async(
            std::move(*addressSpace), variableId, value, std::move(completion));
        }
        else
        {
          completion(VoidResult{ua::detail::address_space_gone("StateMachineRuntime")});
        }
      });
    if (written.status_code() == Status::BadNotWritable)
    {
      // The state Variable is served by an application read handler with no write handler. The machine's
      // state then belongs to the application, which must install a write handler to receive the
      // transition the runtime commits; without one the transition cannot be applied. Said in the result
      // and the log, because the bare status gives no hint of the fix.
      mLogger.warning(
        "StateMachine transition could not be committed: state Variable {} has a read handler and no write "
        "handler; an application serving a state machine's state must install both",
        to_string(variableId));
      co_return VoidResult{StatusCode{Status::BadNotWritable,
        ErrorDetail::build("StateMachineStateNotWritable",
          "The state Variable is served by an application read handler with no write handler; an application "
          "serving a state machine's state must install a write handler to receive transitions",
          "StateMachineRuntime")
          .context(ContextKeys::nodeId, to_string(variableId))
          .cause(written.status_code())}};
    }
    co_return written;
  }

  /// CurrentState.Id is the machine's state; CurrentState is the text a client reads. They are two
  /// writes, so the pair can half-succeed - and a machine whose Id says one state while its text says
  /// another is worse than a machine that did not move. The Id goes back if the text will not follow,
  /// and the caller hears about the write that actually failed.
  ua::async::Task<VoidResult> commit()
  {
    auto idWrite =
      co_await write_value(mTransition.currentStateIdPropertyId, DataValue{Variant{mTransition.toState.id}});
    if (idWrite.is_bad())
    {
      co_return idWrite;
    }

    auto textWrite = co_await write_value(
      mTransition.currentStateVariableId, DataValue{Variant{mTransition.toState.effectiveDisplayName}});
    if (textWrite.is_good())
    {
      co_return VoidResult{};
    }

    auto rollback = co_await write_value(
      mTransition.currentStateIdPropertyId, DataValue{Variant{mTransition.fromState.id}});
    if (rollback.is_bad())
    {
      mLogger.error("StateMachine CurrentState.Id rollback failed after primary commit error: {}",
        to_string(rollback.status_code()));
    }
    co_return textWrite;
  }

  WeakAddressSpace mAddressSpace;
  StateMachineTransitionDescriptor mTransition;
  StateMachineModel::CommitCallback mCallback;
};

/// The state machine model over an address space.
///
/// Holds the address space weakly: a runtime created for a Call owns its model for as long as the
/// transition runs, and the runtime is owned by the completion it hands a namespace, which must not keep
/// the address space alive (ua_namespace.h, Ownership). Each call locks the address space only to start
/// its operation, and answers `address_space_gone` when it no longer exists.
class AddressSpaceStateMachineModel final : public StateMachineModel
{
public:
  explicit AddressSpaceStateMachineModel(const AddressSpace& addressSpace)
    : mAddressSpace(addressSpace.weak()), mLogger(addressSpace.logger())
  {}

  void resolve_transition_async(
    const NodeId& machineId, const NodeId& methodId, ResolveCallback callback) noexcept override
  {
    state_machine_detail::invoke_model_action_once<StateMachineTransitionResolutionResult>(
      [this, machineId, methodId](ResolveCallback operationCompletion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          ResolveTransition::start(
            std::move(*addressSpace), machineId, methodId, std::move(operationCompletion));
        }
        else
        {
          operationCompletion(
            StateMachineTransitionResolutionResult{ua::detail::address_space_gone("StateMachineModel")});
        }
      },
      std::move(callback),
      mLogger);
  }

  void resolve_automatic_transition_async(const NodeId& machineId, ResolveCallback callback) noexcept override
  {
    state_machine_detail::invoke_model_action_once<StateMachineTransitionResolutionResult>(
      [this, machineId](ResolveCallback operationCompletion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          ResolveTransition::start(
            std::move(*addressSpace), machineId, std::nullopt, std::move(operationCompletion));
        }
        else
        {
          operationCompletion(
            StateMachineTransitionResolutionResult{ua::detail::address_space_gone("StateMachineModel")});
        }
      },
      std::move(callback),
      mLogger);
  }

  void commit_transition_async(
    const StateMachineTransitionDescriptor& transition, CommitCallback callback) noexcept override
  {
    state_machine_detail::invoke_model_action_once<VoidResult>(
      [this, transition](CommitCallback operationCompletion)
      {
        if (auto addressSpace = mAddressSpace.lock())
        {
          CommitTransition::start(std::move(*addressSpace), transition, std::move(operationCompletion));
        }
        else
        {
          operationCompletion(VoidResult{ua::detail::address_space_gone("StateMachineModel")});
        }
      },
      std::move(callback),
      mLogger);
  }

private:
  WeakAddressSpace mAddressSpace;
  Logger mLogger;
};

std::vector<QualifiedName> path(std::initializer_list<std::string_view> names)
{
  std::vector<QualifiedName> result;
  result.reserve(names.size());
  for (const auto name : names)
    result.emplace_back(0, std::string{name});
  return result;
}

void set_state_fields(GenericEvent& event, std::string_view root, const StateMachineStateDescriptor& state)
{
  event.set_field(path({root}), Variant{state.effectiveDisplayName});
  event.set_field(path({root, "Id"}), Variant{state.id});
  event.set_field(path({root, "Name"}), Variant{state.name});
  event.set_field(path({root, "Number"}), Variant{state.number});
  event.set_field(path({root, "EffectiveDisplayName"}), Variant{state.effectiveDisplayName});
}

GenericEvent transition_event(const StateMachineTransitionDescriptor& transition, const NodeId& eventType)
{
  GenericEvent event{eventType};
  event.sourceNode = transition.machineId;
  event.sourceName = String{to_string(transition.machineId)};
  event.message = LocalizedText{"", "StateMachine transition"};
  event.severity = 1U;

  const auto transitionDisplay =
    LocalizedText{"", std::string{static_cast<std::string_view>(transition.transitionName.name())}};
  event.set_field(path({"Transition"}), Variant{transitionDisplay});
  event.set_field(path({"Transition", "Id"}), Variant{transition.transitionId});
  event.set_field(path({"Transition", "Name"}), Variant{transition.transitionName});
  if (transition.transitionNumber)
    event.set_field(path({"Transition", "Number"}), Variant{*transition.transitionNumber});
  event.set_field(path({"Transition", "EffectiveDisplayName"}), Variant{transitionDisplay});
  set_state_fields(event, "FromState", transition.fromState);
  set_state_fields(event, "ToState", transition.toState);
  return event;
}

/// Raises the transition's audit Event as @p auditType, an audit EventType one of its effects names: an Event
/// of that type (OPC 10000-16 4.4.14). An AuditProgramTransitionEvent also carries the transition's
/// TransitionNumber, its Status says whether a Program Control Method caused the transition, and its
/// SourceName names that Method, "Method/Start" for Start (OPC 10000-10 5.2.6). Any other audit EventType
/// carries the fields of AuditUpdateStateEventType.
void emit_audit_event(EventSink& sink, const AuditUpdateStateEventPayload& audit,
  const StateMachineTransitionDescriptor& transition, const NodeId& auditType)
{
  const std::string_view methodName = transition.methodName.name();
  if (auditType == NodeId{ObjectTypeId::AuditProgramTransitionEventType})
  {
    AuditProgramTransitionEventPayload event;
    static_cast<AuditUpdateStateEventPayload&>(event) = audit;
    event.eventType = auditType;
    event.status = !methodName.empty();
    if (!methodName.empty())
    {
      event.sourceName = String{"Method/" + std::string{methodName}};
    }
    if (transition.transitionNumber)
    {
      event.transitionNumber = *transition.transitionNumber;
    }
    sink.emit(event);
    return;
  }
  AuditUpdateStateEventPayload event = audit;
  event.eventType = auditType;
  sink.emit(event);
}

}  // namespace

std::shared_ptr<StateMachineModel> make_address_space_state_machine_model(AddressSpace addressSpace)
{
  return std::make_shared<AddressSpaceStateMachineModel>(std::move(addressSpace));
}

void evaluate_state_machine_method_executable_async(AddressSpace addressSpace, NodeId methodId,
  std::function<void(OptionalMethodExecutableResult)> callback) noexcept
{
  state_machine_detail::invoke_model_action_once<OptionalMethodExecutableResult>(
    [addressSpace, methodId = std::move(methodId)](auto operationCompletion) mutable
    { EvaluateMethodExecutable::start(addressSpace, std::move(methodId), std::move(operationCompletion)); },
    std::move(callback),
    addressSpace.logger());
}

void evaluate_state_machine_variable_active_async(AddressSpace addressSpace, NodeId variableId,
  std::function<void(OptionalStateMachineActiveResult)> callback) noexcept
{
  state_machine_detail::invoke_model_action_once<OptionalStateMachineActiveResult>(
    [addressSpace, variableId = std::move(variableId)](auto operationCompletion) mutable
    { EvaluateMachineActivity::start(addressSpace, std::move(variableId), std::move(operationCompletion)); },
    std::move(callback),
    addressSpace.logger());
}

std::shared_ptr<StateMachineRuntime> StateMachineRuntime::create(boost::asio::any_io_executor executor,
  std::shared_ptr<StateMachineModel> model, std::weak_ptr<EventSink> eventSink, Logger logger,
  std::optional<AuditUpdateStateEventPayload> auditEvent)
{
  return std::shared_ptr<StateMachineRuntime>{new StateMachineRuntime(
    std::move(executor), std::move(model), std::move(eventSink), std::move(logger), std::move(auditEvent))};
}

StateMachineRuntime::StateMachineRuntime(boost::asio::any_io_executor executor,
  std::shared_ptr<StateMachineModel> model, std::weak_ptr<EventSink> eventSink, Logger logger,
  std::optional<AuditUpdateStateEventPayload> auditEvent)
  : SelfOwningOperation(boost::asio::make_strand(std::move(executor)), std::move(logger)),
    mModel(std::move(model)), mEventSink(std::move(eventSink)), mAuditEvent(std::move(auditEvent))
{}

StateMachineRuntime::~StateMachineRuntime()
{
  // Reached with the transition still running only when the work that owned it was destroyed
  // unanswered: a model that destroyed the completion of the step it was given, or an executor torn
  // down with a step's turn still queued. The completion is owed its one answer all the same.
  if (!mStarted || mFinished)
  {
    return;
  }
  StatusCode dropped{Status::BadShutdown};
  try
  {
    dropped = StatusCode{Status::BadShutdown,
      ErrorDetail::build("StateMachineTransitionDropped",
        "The StateMachine transition was destroyed before it completed; its pending step was never answered",
        "StateMachineRuntime")
        .context(ContextKeys::nodeId, to_string(mMachineId))};
  }
  catch (...)
  {
    // Building the detail could not allocate; the status alone still answers the caller.
    ua::detail::ignore_expected_exception();
  }
  finish(VoidResult{std::move(dropped)});
}

void StateMachineRuntime::transition_after_method_async(
  NodeId machineId, NodeId methodId, Completion completion) noexcept
{
  // Owning, not borrowing: the caller may release the runtime as soon as this returns, and the call it
  // has just made is what keeps the runtime alive until it is answered.
  try
  {
    ua::async::post_owning(this,
      mStrand,
      mLogger,
      [machineId = std::move(machineId), methodId = std::move(methodId), completion = std::move(completion)](
        StateMachineRuntime& self) mutable
      { self.begin(std::move(machineId), std::move(methodId), std::move(completion)); })();
  }
  catch (...)
  {
    // The post could not be queued, and the completion went with the handler that held it: as with
    // `post_borrowing`, the one answer is lost only on this allocation-failure path. Logged, not thrown,
    // across this noexcept boundary.
    log_exception(
      mLogger, "StateMachineRuntime: the transition could not be started", std::current_exception());
  }
}

void StateMachineRuntime::begin(NodeId machineId, NodeId methodId, Completion completion)
{
  // ONE transition per runtime, ever - not one at a time. A runtime is created for a single Method
  // call, and a second call is refused whether the first is still walking or has already answered:
  // its completion has been given away, and the machine it would move is no longer the one it
  // resolved against. Taken BEFORE the model is checked, so that a runtime refused for want of a
  // model refuses the next caller too rather than accepting a call it will not answer.
  if (mStarted)
  {
    ua::detail::invoke_user_callback(mLogger, completion, VoidResult{Status::BadInvalidState});
    return;
  }
  mStarted = true;
  mCompletion = std::move(completion);
  mMachineId = std::move(machineId);
  mMethodId = std::move(methodId);
  if (!mModel)
  {
    finish(VoidResult{Status::BadInvalidState});
    return;
  }
  launch(shared_from_this());
}

void StateMachineRuntime::fail_to_start(StatusCode status)
{
  finish(VoidResult{std::move(status)});
}

/// @par The transition, and everything it sets off
/// A Method call moves the machine once, and each move can enable an automatic transition, which
/// moves it again. That is a loop, and it was a five-value `Step` enum across four handlers because a
/// callback chain has nowhere else to put one - `Committing` was reached from two different places
/// and had to know which.
ua::async::Task<> StateMachineRuntime::run()
{
  try
  {
    auto resolution = co_await await_step<StateMachineTransitionResolutionResult>([this](auto completion)
      { mModel->resolve_transition_async(mMachineId, mMethodId, std::move(completion)); });
    if (!resolution.is_good())
    {
      // The model's answer decides whether the machine moves, so an Uncertain one is not acted on.
      finish(VoidResult{server::detail::not_acted_on(
        server::detail::answerUncertain, resolution.status_code(), "StateMachineRuntime", mMachineId)});
      co_return;
    }
    auto& enabledTransition = resolution.value().enabledTransition;
    if (!enabledTransition)
    {
      // The Method caused nothing that can fire from where the machine is. That is not an error.
      finish(VoidResult{});
      co_return;
    }

    auto transition = std::move(enabledTransition.value());

    // Part 16: an automatic transition may enable another. The cap is what stops a model whose Else
    // guards form a cycle from moving the machine for ever.
    constexpr size_t maxAutomaticTransitions = 64U;
    for (size_t automatic = 0;; ++automatic)
    {
      auto commit = co_await await_step<VoidResult>([this, &transition](auto completion)
        { mModel->commit_transition_async(transition, std::move(completion)); });
      if (commit.is_bad())
      {
        finish(std::move(commit));
        co_return;
      }

      {
        // Locked once for every Event, and released before the next suspension (R7): the sink is the
        // server's event bus, and a transition that outlives its server raises nothing through it.
        const auto eventSink = mEventSink.lock();
        if (!eventSink)
        {
          std::unique_ptr<ua::ErrorDetail> detail = ErrorDetail::build("StateMachineEventSinkUnavailable",
            "StateMachine EventSink is unavailable",
            "StateMachineRuntime");
          finish(VoidResult{StatusCode{Status::BadResourceUnavailable, std::move(detail)}});
          co_return;
        }

        for (const auto& eventType : transition.eventTypes)
        {
          auto event = transition_event(transition, eventType);
          eventSink->emit(event);
        }
        if (mAuditEvent)
        {
          mAuditEvent->sourceNode = transition.machineId;
          mAuditEvent->oldStateId = Variant{transition.fromState.id};
          mAuditEvent->newStateId = Variant{transition.toState.id};
          if (transition.auditEventTypes.empty())
          {
            eventSink->emit(*mAuditEvent);
          }
          for (const auto& auditType : transition.auditEventTypes)
          {
            emit_audit_event(*eventSink, *mAuditEvent, transition, auditType);
          }
        }
      }

      auto next = co_await await_step<StateMachineTransitionResolutionResult>([this](auto completion)
        { mModel->resolve_automatic_transition_async(mMachineId, std::move(completion)); });
      if (!next.is_good())
      {
        finish(VoidResult{server::detail::not_acted_on(
          server::detail::answerUncertain, next.status_code(), "StateMachineRuntime", mMachineId)});
        co_return;
      }
      auto& nextTransition = next.value().enabledTransition;
      if (!nextTransition)
      {
        finish(VoidResult{});
        co_return;
      }
      if (automatic + 1U > maxAutomaticTransitions)
      {
        finish(VoidResult{automatic_transition_limit_exceeded(mMachineId)});
        co_return;
      }
      transition = std::move(nextTransition.value());
    }
  }
  catch (const ua::async::Abandoned& abandoned)
  {
    // ANSWERED, not rethrown. This runtime owes its caller exactly one answer for the Method call it
    // was created for, and it belongs to nothing that can withdraw one: it is owned by its outstanding
    // work, and work that is dropped destroys it, which the destructor answers.
    finish(VoidResult{abandoned.status_code()});
  }
  catch (...)
  {
    ua::async::guarded(
      mLogger, [this] { finish(VoidResult{ua::exception_to_status_code(std::current_exception())}); })();
  }
}

void StateMachineRuntime::finish(VoidResult result)
{
  if (mFinished)
    return;
  mFinished = true;
  auto completion = std::move(mCompletion);
  mCompletion = nullptr;
  ua::detail::invoke_user_callback(mLogger, completion, std::move(result));
}

}  // namespace ua::server
