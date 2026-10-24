// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_state_machine_runtime.h"

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_variabletype_id.h"
#include "ua_default_namespace.h"
#include "ua_value_source.h"

#include <mutex>
#include <optional>
#include <span>
#include <thread>

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <future>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ua::server
{
namespace
{

using namespace std::chrono_literals;

struct MachineFixture
{
  NodeId typeId;
  NodeId instanceId;
  NodeId methodId;
  NodeId currentStateIdPropertyId;
  NodeId firstStateId;
  NodeId secondStateId;
};

class StateMachineModelValidationTest : public ::testing::Test
{
protected:
  StateMachineModelValidationTest()
    : mAddressSpace(
        AddressSpace::create("urn:test:state-machine-model-validation", mExecutor.get_executor())),
      mModel(make_address_space_state_machine_model(mAddressSpace))
  {}

  NodeAccessor create_node(uint32_t numericId, NodeClass nodeClass, std::string_view browseName)
  {
    auto result = mAddressSpace.try_create_node_sync(NodeId{1, numericId}, nodeClass, {});
    if (result.is_bad())
      throw UaException{result.status_code()};
    auto node = std::move(result).value();
    node.set_browse_name(QualifiedName{0, std::string{browseName}});
    node.set_display_name(LocalizedText{"", std::string{browseName}});
    return node;
  }

  VariableAccessor create_property(
    NodeAccessor& parent, uint32_t numericId, std::string_view browseName, Variant value)
  {
    auto node = create_node(numericId, NodeClass::Variable, browseName);
    auto property = *node.as<VariableAccessor>();
    property.write_value_sync(DataValue{std::move(value)});
    parent.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, property.get_node_id());
    return property;
  }

  MachineFixture create_machine(uint32_t baseId, std::string_view firstName, uint32_t firstNumber,
    std::string_view secondName, uint32_t secondNumber)
  {
    auto type = create_node(baseId, NodeClass::ObjectType, "MachineType");
    auto instance = create_node(baseId + 1U, NodeClass::Object, "Machine");
    auto declaredMethod = create_node(baseId + 2U, NodeClass::Method, "Advance");
    auto instanceMethod = create_node(baseId + 11U, NodeClass::Method, "Advance");
    auto currentState = create_node(baseId + 3U, NodeClass::Variable, "CurrentState");
    auto firstState = create_node(baseId + 4U, NodeClass::Object, firstName);
    auto secondState = create_node(baseId + 5U, NodeClass::Object, secondName);
    auto transition = create_node(baseId + 6U, NodeClass::Object, "FirstToSecond");
    auto effect = create_node(baseId + 7U, NodeClass::ObjectType, "TransitionEventType");

    instance.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, type.get_node_id());
    instance.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, currentState.get_node_id());
    instance.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, instanceMethod.get_node_id());
    instanceMethod.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, instance.get_node_id(), false);
    create_property(currentState, baseId + 8U, "Id", Variant{firstState.get_node_id()});

    type.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, declaredMethod.get_node_id());
    declaredMethod.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, type.get_node_id(), false);
    type.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, firstState.get_node_id());
    type.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, secondState.get_node_id());
    type.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, transition.get_node_id());
    create_property(firstState, baseId + 9U, "StateNumber", Variant{firstNumber});
    create_property(secondState, baseId + 10U, "StateNumber", Variant{secondNumber});

    transition.add_reference_sync(NodeId{ReferenceTypeId::HasCause}, declaredMethod.get_node_id());
    transition.add_reference_sync(NodeId{ReferenceTypeId::FromState}, firstState.get_node_id());
    transition.add_reference_sync(NodeId{ReferenceTypeId::ToState}, secondState.get_node_id());
    transition.add_reference_sync(NodeId{ReferenceTypeId::HasEffect}, effect.get_node_id());

    return MachineFixture{.typeId = type.get_node_id(),
      .instanceId = instance.get_node_id(),
      .methodId = instanceMethod.get_node_id(),
      .currentStateIdPropertyId = NodeId{1, baseId + 8U},
      .firstStateId = firstState.get_node_id(),
      .secondStateId = secondState.get_node_id()};
  }

  StateMachineTransitionResolutionResult resolve(const MachineFixture& machine)
  {
    std::promise<StateMachineTransitionResolutionResult> completion;
    auto future = completion.get_future();
    mModel->resolve_transition_async(machine.instanceId,
      machine.methodId,
      [&completion](StateMachineTransitionResolutionResult result) mutable
      { completion.set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error{"state-machine model resolution did not complete"};
    return future.get();
  }

  VoidResult commit(const StateMachineTransitionDescriptor& transition)
  {
    std::promise<VoidResult> completion;
    auto future = completion.get_future();
    mModel->commit_transition_async(
      transition, [&completion](VoidResult result) mutable { completion.set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error{"state-machine commit did not complete"};
    return future.get();
  }

  StateMachineTransitionResolutionResult resolve_automatic(const NodeId& machineId)
  {
    std::promise<StateMachineTransitionResolutionResult> completion;
    auto future = completion.get_future();
    mModel->resolve_automatic_transition_async(machineId,
      [&completion](StateMachineTransitionResolutionResult result) mutable
      { completion.set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error{"automatic state-machine resolution did not complete"};
    return future.get();
  }

  OptionalMethodExecutableResult evaluate(const NodeId& methodId)
  {
    std::promise<OptionalMethodExecutableResult> completion;
    auto future = completion.get_future();
    evaluate_state_machine_method_executable_async(mAddressSpace,
      methodId,
      [&completion](OptionalMethodExecutableResult result) mutable
      { completion.set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error{"state-machine Method Executable evaluation did not complete"};
    return future.get();
  }

  OptionalStateMachineActiveResult evaluate_activity(const NodeId& variableId)
  {
    std::promise<OptionalStateMachineActiveResult> completion;
    auto future = completion.get_future();
    evaluate_state_machine_variable_active_async(mAddressSpace,
      variableId,
      [&completion](OptionalStateMachineActiveResult result) mutable
      { completion.set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error{"state-machine activity evaluation did not complete"};
    return future.get();
  }

  static void expect_collision(const StateMachineTransitionResolutionResult& result, std::string_view code,
    const MachineFixture& machine)
  {
    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code().value(), StatusCode{Status::BadConfigurationError}.value());
    const auto detail = result.shared_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, code);
    EXPECT_EQ(
      test_utils::error_context(detail.get(), ContextKeys::nodeId.value()), to_string(machine.typeId));
    const auto identities = test_utils::error_context(detail.get(), ContextKeys::value.value());
    EXPECT_NE(identities.find(to_string(machine.firstStateId)), std::string::npos);
    EXPECT_NE(identities.find(to_string(machine.secondStateId)), std::string::npos);
  }

  boost::asio::thread_pool mExecutor{1};
  AddressSpace mAddressSpace;
  std::shared_ptr<StateMachineModel> mModel;
};

// @relation(AC-SVR-SM-004-EXECUTABLE-TRACKS-STATE, scope=function)
TEST_F(StateMachineModelValidationTest, ExecutableTracksCurrentStateAcrossDeclarationAndInstanceMethods)
{
  const auto machine = create_machine(5000U, "Ready", 1U, "Running", 2U);

  const auto enabled = evaluate(machine.methodId);
  ASSERT_TRUE(enabled.is_good());
  ASSERT_TRUE(enabled.value().has_value());
  EXPECT_TRUE(*enabled.value());

  auto currentStateId = mAddressSpace.find_node_sync(machine.currentStateIdPropertyId).as<VariableAccessor>();
  ASSERT_TRUE(currentStateId.has_value());
  currentStateId->write_value_sync(DataValue{Variant{machine.secondStateId}});

  const auto disabled = evaluate(machine.methodId);
  ASSERT_TRUE(disabled.is_good());
  ASSERT_TRUE(disabled.value().has_value());
  EXPECT_FALSE(*disabled.value());
}

// @relation(AC-SVR-SM-004-EXECUTABLE-TRACKS-STATE, scope=function)
TEST_F(StateMachineModelValidationTest, MethodThatCausesNoTransitionFallsBackToStoredExecutable)
{
  const auto machine = create_machine(6000U, "Ready", 1U, "Running", 2U);
  auto unrelated = create_node(6999U, NodeClass::Method, "Inspect");
  auto owner = mAddressSpace.find_node_sync(machine.instanceId);
  owner.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, unrelated.get_node_id());
  unrelated.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, owner.get_node_id(), false);

  const auto result = evaluate(unrelated.get_node_id());

  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value().has_value());
}

// A transition may have more than one effect (OPC 10000-16 4.4.10), and its effects do not decide whether it
// is taken: its Method is executable from its FromState. Its Events are its effects that are not audit
// EventTypes, in the order its References name them; its audit effects are the types its audit Event is
// raised as when the server audits (OPC 10000-16 4.4.14, OPC 10000-10 5.2.6).
// @relation(AC-SVR-SM-004-EXECUTABLE-TRACKS-STATE, scope=function)
// @relation(AC-SVR-SM-011-HASEFFECT-FIRES-EVENT, scope=function)
TEST_F(StateMachineModelValidationTest, ATransitionWithSeveralEffectsIsTakenAndRaisesEachEffectButAnAuditOne)
{
  const auto machine = create_machine(9000U, "Ready", 1U, "Running", 2U);
  // The EventTypes the effects name, as namespace 0 declares them: an audit EventType two levels below
  // BaseEventType, and an EventType that is not one.
  const auto eventType = [this](ObjectTypeId id, std::string_view name, std::optional<ObjectTypeId> supertype)
  {
    auto type = mAddressSpace.try_create_node_sync(NodeId{id}, NodeClass::ObjectType, {}).value();
    type.set_browse_name(QualifiedName{0, std::string{name}});
    if (supertype)
      type.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, NodeId{*supertype}, false);
  };
  eventType(ObjectTypeId::BaseEventType, "BaseEventType", std::nullopt);
  eventType(ObjectTypeId::AuditEventType, "AuditEventType", ObjectTypeId::BaseEventType);
  eventType(
    ObjectTypeId::AuditUpdateStateEventType, "AuditUpdateStateEventType", ObjectTypeId::AuditEventType);
  eventType(
    ObjectTypeId::ProgramTransitionEventType, "ProgramTransitionEventType", ObjectTypeId::BaseEventType);
  auto transition = mAddressSpace.find_node_sync(NodeId{1, 9006U});
  transition.add_reference_sync(
    NodeId{ReferenceTypeId::HasEffect}, NodeId{ObjectTypeId::AuditUpdateStateEventType});
  transition.add_reference_sync(
    NodeId{ReferenceTypeId::HasEffect}, NodeId{ObjectTypeId::ProgramTransitionEventType});

  const auto executable = evaluate(machine.methodId);
  ASSERT_TRUE(executable.is_good()) << to_string(executable.status_code());
  ASSERT_TRUE(executable.value().has_value());
  EXPECT_TRUE(*executable.value());

  const auto resolution = resolve(machine);
  ASSERT_TRUE(resolution.is_good()) << to_string(resolution.status_code());
  ASSERT_TRUE(resolution.value().enabledTransition.has_value());
  EXPECT_EQ(resolution.value().enabledTransition->eventTypes,
    (std::vector<NodeId>{NodeId{1, 9007U}, NodeId{ObjectTypeId::ProgramTransitionEventType}}));
  EXPECT_EQ(resolution.value().enabledTransition->auditEventTypes,
    (std::vector<NodeId>{NodeId{ObjectTypeId::AuditUpdateStateEventType}}));
}

// @relation(AC-SVR-SM-005-INACTIVE-RETURNS-NULL, scope=function)
// @relation(AC-SVR-SM-006-SUBSTATEMACHINE-ACTIVE-WITH-PARENT, scope=function)
TEST_F(StateMachineModelValidationTest, StateVariablesTrackOwningParentStateAndRetainRichTypeErrors)
{
  auto parent = create_node(7000U, NodeClass::Object, "ParentMachine");
  auto parentCurrentState = create_node(7001U, NodeClass::Variable, "CurrentState");
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, parentCurrentState.get_node_id());
  parentCurrentState.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, parent.get_node_id(), false);
  auto owningState = create_node(7002U, NodeClass::Object, "Machining");
  auto inactiveState = create_node(7003U, NodeClass::Object, "Idle");
  for (auto* state : {&owningState, &inactiveState})
  {
    parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, state->get_node_id());
    state->add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, parent.get_node_id(), false);
  }
  auto parentStateId = create_property(parentCurrentState, 7004U, "Id", Variant{owningState.get_node_id()});

  auto subMachine = create_node(7010U, NodeClass::Object, "SubMachine");
  owningState.add_reference_sync(NodeId{ReferenceTypeId::HasSubStateMachine}, subMachine.get_node_id());
  subMachine.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubStateMachine}, owningState.get_node_id(), false);
  auto currentState = create_node(7011U, NodeClass::Variable, "CurrentState");
  auto lastTransition = create_node(7012U, NodeClass::Variable, "LastTransition");
  for (auto* stateVariable : {&currentState, &lastTransition})
  {
    subMachine.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, stateVariable->get_node_id());
    stateVariable->add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, subMachine.get_node_id(), false);

    const auto active = evaluate_activity(stateVariable->get_node_id());
    ASSERT_TRUE(active.is_good());
    ASSERT_TRUE(active.value().has_value());
    EXPECT_TRUE(*active.value());
  }

  parentStateId.write_value_sync(DataValue{Variant{inactiveState.get_node_id()}});
  for (const auto& variableId : {currentState.get_node_id(), lastTransition.get_node_id()})
  {
    const auto inactive = evaluate_activity(variableId);
    ASSERT_TRUE(inactive.is_good());
    ASSERT_TRUE(inactive.value().has_value());
    EXPECT_FALSE(*inactive.value());
  }

  parentStateId.write_value_sync(DataValue{Variant{String{"not-a-node-id"}}});
  const auto malformed = evaluate_activity(currentState.get_node_id());
  ASSERT_TRUE(malformed.is_bad());
  EXPECT_EQ(malformed.status_code().as_status(), Status::BadTypeMismatch);
  ASSERT_NE(malformed.shared_detail(), nullptr);
  EXPECT_EQ(malformed.shared_detail()->code, "CurrentStateIdTypeMismatch");
}

// @relation(AC-SVR-SM-005-INACTIVE-RETURNS-NULL, scope=function)
// @relation(AC-SVR-SM-006-SUBSTATEMACHINE-ACTIVE-WITH-PARENT, scope=function)
TEST_F(StateMachineModelValidationTest, ActivityDerivationIgnoresUnrelatedVariables)
{
  auto unrelated = create_node(7100U, NodeClass::Variable, "Temperature");
  const auto result = evaluate_activity(unrelated.get_node_id());

  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value().has_value());
}

// @relation(AC-SVR-SM-037-CHOICESTATE-GUARDS-TOTAL, scope=function)
TEST_F(StateMachineModelValidationTest, AutomaticResolutionSelectsElseGuardWithoutMethodCause)
{
  const auto machine = create_machine(8000U, "Idle", 1U, "Done", 2U);
  auto machineType = mAddressSpace.find_node_sync(machine.typeId);
  auto transition = create_node(8012U, NodeClass::Object, "AutomaticElse");
  auto guard = create_node(8013U, NodeClass::Variable, "Else");
  machineType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, transition.get_node_id());
  transition.add_reference_sync(NodeId{ReferenceTypeId::FromState}, machine.firstStateId);
  transition.add_reference_sync(NodeId{ReferenceTypeId::ToState}, machine.secondStateId);
  transition.add_reference_sync(NodeId{ReferenceTypeId::HasGuard}, guard.get_node_id());
  guard.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::ElseGuardVariableType});

  const auto result = resolve_automatic(machine.instanceId);

  ASSERT_TRUE(result.is_good());
  EXPECT_FALSE(result.value().methodIsCause);
  ASSERT_TRUE(result.value().enabledTransition.has_value());
  EXPECT_EQ(result.value().enabledTransition->transitionId, transition.get_node_id());
  EXPECT_EQ(result.value().enabledTransition->toState.id, machine.secondStateId);
}

// @relation(AC-SVR-SM-012-STATE-IDENTITIES-UNIQUE, scope=function)
// @relation(AC-COMP-SVR-SM-RUNTIME-05-STATE-IDENTITIES-UNIQUE, scope=function)
TEST_F(StateMachineModelValidationTest, DuplicateStateBrowseNameReturnsRichBadConfigurationError)
{
  const auto machine = create_machine(1000U, "Idle", 1U, "Idle", 2U);
  expect_collision(resolve(machine), "DuplicateStateBrowseName", machine);
}

// @relation(AC-SVR-SM-012-STATE-IDENTITIES-UNIQUE, scope=function)
// @relation(AC-COMP-SVR-SM-RUNTIME-05-STATE-IDENTITIES-UNIQUE, scope=function)
TEST_F(StateMachineModelValidationTest, DuplicateStateNumberReturnsRichBadConfigurationError)
{
  const auto machine = create_machine(2000U, "Idle", 7U, "Running", 7U);
  expect_collision(resolve(machine), "DuplicateStateNumber", machine);
}

// @relation(AC-SVR-SM-012-STATE-IDENTITIES-UNIQUE, scope=function)
// @relation(AC-COMP-SVR-SM-RUNTIME-05-STATE-IDENTITIES-UNIQUE, scope=function)
TEST_F(StateMachineModelValidationTest, DistinctStatesAndNestedReuseAreAccepted)
{
  const auto parent = create_machine(3000U, "Idle", 1U, "Running", 2U);
  const auto child = create_machine(4000U, "Idle", 1U, "Running", 2U);
  auto parentType = mAddressSpace.find_node_sync(parent.typeId);
  parentType.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, child.typeId);

  const auto parentResult = resolve(parent);
  ASSERT_TRUE(parentResult.is_good());
  ASSERT_TRUE(parentResult.value().enabledTransition.has_value());
  EXPECT_EQ(parentResult.value().enabledTransition->fromState.id, parent.firstStateId);
  EXPECT_EQ(parentResult.value().enabledTransition->toState.id, parent.secondStateId);

  const auto childResult = resolve(child);
  ASSERT_TRUE(childResult.is_good());
  ASSERT_TRUE(childResult.value().enabledTransition.has_value());
  EXPECT_EQ(childResult.value().enabledTransition->fromState.id, child.firstStateId);
  EXPECT_EQ(childResult.value().enabledTransition->toState.id, child.secondStateId);
}

/// A namespace that holds the first resolution it is asked for, and can then drop it unanswered.
///
/// A collaborator that goes away without answering is the one thing a self-owning operation cannot
/// survive on its own: its frame is suspended waiting for an answer that will never come, so unless
/// dropping the completion releases the operation, the operation - and the AddressSpace it holds -
/// lives for ever.
class DroppingNamespace final : public default_ns::Namespace
{
public:
  DroppingNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  /// The held completion is touched from two threads - written here on a pool thread, read and
  /// released by the test on the main one - so every access to it is under the mutex. The delegation
  /// below is deliberately outside it: the base namespace answers on the caller's thread and must
  /// never be entered holding a lock this namespace can be re-entered through.
  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    {
      const std::lock_guard<std::mutex> lock{mMutex};
      if (!mHeld)
      {
        mHeld = std::move(callback);
        return;
      }
    }
    default_ns::Namespace::find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  /// Declines the synchronous form, so the resolution really does reach `find_nodes_async`.
  std::optional<NodeResult> find_node(const NodeId&, std::optional<Duration>) override
  {
    return std::nullopt;
  }

  bool holding() const
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return static_cast<bool>(mHeld);
  }

  /// Destroys the completion without answering it.
  void drop()
  {
    std::function<void(BatchResult<NodeResult>)> held;
    {
      const std::lock_guard<std::mutex> lock{mMutex};
      held.swap(mHeld);
    }
    // Destroyed HERE, outside the lock: releasing the completion releases the operation waiting on
    // it, and that teardown must not run under a lock the operation could reach back through.
  }

private:
  mutable std::mutex mMutex;
  std::function<void(BatchResult<NodeResult>)> mHeld;
};

// An application that serves a state machine's state installs both handlers on its state Variables: the
// runtime decides the transition and commits it by writing CurrentState.Id and CurrentState, which reaches
// the application's write handler as "the machine moved to X"; the application applies it (or refuses it)
// and serves the result through its read handler. A state Variable with only a read handler cannot take the
// commit, and the refusal says why.
namespace
{

struct StateSource
{
  std::shared_ptr<std::mutex> mutex = std::make_shared<std::mutex>();
  std::shared_ptr<std::vector<Variant>> written = std::make_shared<std::vector<Variant>>();
};

/// Installs an application source on @p variableId: a read handler answering @p answer, and - when
/// @p writeStatus is set - a write handler that records each value and completes with that status.
void serve_state_variable(AddressSpace& addressSpace, const NodeId& variableId, Variant answer,
  std::optional<Status> writeStatus, StateSource source)
{
  auto variable = addressSpace.find_node_sync(variableId).as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  auto* external = (*variable)->external_value_source();
  ASSERT_NE(external, nullptr);
  ASSERT_TRUE(
    external
      ->set_value_source(make_value_source([answer](const ValueSource::ReadContext&,
                                             const Node&,
                                             const ReadValueId&,
                                             std::function<void(DataValueResult)>
                                               done) { done(DataValue{answer}); },
        writeStatus
          ? ValueSource::WriteValueHandler{[source, status = *writeStatus](const ValueSource::WriteContext&,
                                             const Node&,
                                             const WriteValue& write,
                                             std::function<void(ValueSource::WriteResult)>
                                               done)
              {
                {
                  const std::lock_guard<std::mutex> lock(*source.mutex);
                  source.written->push_back(write.value().value());
                }
                done(status == Status::Good ? ValueSource::WriteResult{ValueSource::Written{}}
                                            : ValueSource::WriteResult{StatusCode{status}});
              }}
          : ValueSource::WriteValueHandler{}))
      .is_good());
}

}  // namespace

// @verifies AC-SVR-SM-STATE-SOURCE-RECEIVES-THE-TRANSITION
TEST_F(StateMachineModelValidationTest, AnApplicationServingTheStateWithBothHandlersReceivesTheTransition)
{
  const auto machine = create_machine(5600U, "Ready", 1U, "Running", 2U);
  StateSource idSource;
  StateSource textSource;
  serve_state_variable(
    mAddressSpace, machine.currentStateIdPropertyId, Variant{machine.firstStateId}, Status::Good, idSource);
  serve_state_variable(
    mAddressSpace, NodeId{1, 5603U}, Variant{LocalizedText{"", "Ready"}}, Status::Good, textSource);

  const auto resolved = resolve(machine);
  ASSERT_TRUE(resolved.is_good());
  ASSERT_TRUE(resolved.value().enabledTransition.has_value());
  const auto committed = commit(*resolved.value().enabledTransition);
  EXPECT_TRUE(committed.is_good()) << to_string(committed.status_code());

  ASSERT_EQ(idSource.written->size(), 1u) << "the application's write handler never saw the transition";
  EXPECT_EQ(idSource.written->front().as<NodeId>(), machine.secondStateId);
  EXPECT_EQ(textSource.written->size(), 1u);
}

// @verifies AC-SVR-SM-STATE-SOURCE-RECEIVES-THE-TRANSITION
TEST_F(StateMachineModelValidationTest, AStateServedByAReadHandlerAloneRefusesTheCommitAndSaysWhy)
{
  const auto machine = create_machine(5700U, "Ready", 1U, "Running", 2U);
  serve_state_variable(mAddressSpace,
    machine.currentStateIdPropertyId,
    Variant{machine.firstStateId},
    std::nullopt,
    StateSource{});

  const auto resolved = resolve(machine);
  ASSERT_TRUE(resolved.is_good());
  ASSERT_TRUE(resolved.value().enabledTransition.has_value());
  const auto committed = commit(*resolved.value().enabledTransition);
  ASSERT_TRUE(committed.is_bad());
  EXPECT_EQ(committed.status_code().as_status(), Status::BadNotWritable);
  ASSERT_NE(committed.shared_detail(), nullptr);
  EXPECT_EQ(committed.shared_detail()->code, "StateMachineStateNotWritable")
    << "a read-only state Variable refused the commit without saying what to do about it";
}

// @verifies AC-SVR-SM-STATE-SOURCE-RECEIVES-THE-TRANSITION
TEST_F(StateMachineModelValidationTest, AStateSourceThatRefusesTheTransitionFailsTheCommitWithItsStatus)
{
  const auto machine = create_machine(5800U, "Ready", 1U, "Running", 2U);
  StateSource idSource;
  serve_state_variable(mAddressSpace,
    machine.currentStateIdPropertyId,
    Variant{machine.firstStateId},
    Status::BadNoCommunication,
    idSource);

  const auto resolved = resolve(machine);
  ASSERT_TRUE(resolved.is_good());
  ASSERT_TRUE(resolved.value().enabledTransition.has_value());
  const auto committed = commit(*resolved.value().enabledTransition);
  EXPECT_EQ(committed.status_code().as_status(), Status::BadNoCommunication);
  EXPECT_EQ(idSource.written->size(), 1u);
}

// Dropping a resolution unanswered releases the operation waiting on it.
//
// The callback chain this replaced got that from `ua::async::post_owning`, which strong-captured the
// flow into every completion it handed out: a collaborator that dropped the completion dropped the
// last reference to the flow with it. A coroutine cannot copy that - `await_callback` holds its owner
// WEAKLY by design - so the operation holds itself, and the completion is what gives that reference
// back. Without this the operation, its frame, and the AddressSpace it carries outlive the server.
//
// The caller's own callback is the probe: it owns a sentinel, so the sentinel expiring is the
// operation having been destroyed.
TEST(StateMachineOperationLifetime, DroppingAResolutionUnansweredReleasesTheOperation)
{
  boost::asio::thread_pool pool{1};
  auto addressSpace = AddressSpace::create("urn:test:state-machine-dropped", pool.get_executor());
  auto ns = make_shared<DroppingNamespace>("uri://state-machine-dropped", pool.get_executor());
  const uint16_t nsIndex = addressSpace.add_namespace_sync(ns);

  auto sentinel = std::make_shared<int>(0);
  std::weak_ptr<int> watch = sentinel;

  evaluate_state_machine_method_executable_async(addressSpace,
    NodeId{nsIndex, 5000U},
    [sentinel = std::move(sentinel)](OptionalMethodExecutableResult) { (void)sentinel; });

  for (int i = 0; (i < 200) && !ns->holding(); ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  ASSERT_TRUE(ns->holding()) << "the operation must be suspended on the namespace before it is dropped";
  ASSERT_FALSE(watch.expired()) << "and it must still be alive at that point";

  ns->drop();

  for (int i = 0; (i < 200) && !watch.expired(); ++i)
  {
    std::this_thread::sleep_for(5ms);
  }
  EXPECT_TRUE(watch.expired())
    << "an operation whose answer will never arrive must be released, not held for ever";

  ns.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// The model decides from the machine's CurrentState.Id whether a Method's transition can be taken, so an Id
// whose own status is Uncertain is not acted on: the resolution, and the Executable it decides, are refused
// Bad_InternalError (ReadAnswerUncertain) with that status as the inner status. Written Good again, the same
// Id decides as before.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(StateMachineModelValidationTest, ACurrentStateIdWhoseOwnStatusIsUncertainIsNotActedOn)
{
  const auto machine = create_machine(9300U, "Ready", 1U, "Running", 2U);
  auto currentStateId = mAddressSpace.find_node_sync(machine.currentStateIdPropertyId).as<VariableAccessor>();
  ASSERT_TRUE(currentStateId.has_value());
  currentStateId->write_value_sync(
    DataValue{Variant{machine.firstStateId}, StatusCode{Status::UncertainLastUsableValue}});

  const auto executable = evaluate(machine.methodId);
  const auto resolution = resolve(machine);
  for (const auto& [refused, subject] : {std::pair{executable.status_code(), "Executable"},
         std::pair{resolution.status_code(), "the resolution"}})
  {
    EXPECT_EQ(refused.as_status(), Status::BadInternalError) << subject << ": " << to_string(refused);
    ASSERT_NE(refused.shared_detail(), nullptr) << subject;
    EXPECT_EQ(refused.shared_detail()->code, "ReadAnswerUncertain") << subject;
    EXPECT_EQ(refused.shared_detail()->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value())
      << subject;
  }

  currentStateId->write_value_sync(DataValue{Variant{machine.firstStateId}});
  const auto control = evaluate(machine.methodId);
  ASSERT_TRUE(control.is_good()) << to_string(control.status_code());
  ASSERT_TRUE(control.value().has_value());
  EXPECT_TRUE(*control.value());
}

// The StateNumber of a State is put on the transition's Events, so a StateNumber whose own status is
// Uncertain is not acted on: the resolution is refused Bad_InternalError (ReadAnswerUncertain) with that
// status as the inner status.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(StateMachineModelValidationTest, AStateNumberWhoseOwnStatusIsUncertainIsNotActedOn)
{
  const auto machine = create_machine(9400U, "Ready", 1U, "Running", 2U);
  // create_machine gives the first State's StateNumber Property the identifier baseId + 9.
  auto stateNumber = mAddressSpace.find_node_sync(NodeId{1, 9409U}).as<VariableAccessor>();
  ASSERT_TRUE(stateNumber.has_value());
  stateNumber->write_value_sync(
    DataValue{Variant{uint32_t{1}}, StatusCode{Status::UncertainLastUsableValue}});

  const auto resolution = resolve(machine);

  EXPECT_EQ(resolution.status_code().as_status(), Status::BadInternalError)
    << to_string(resolution.status_code());
  ASSERT_NE(resolution.shared_detail(), nullptr);
  EXPECT_EQ(resolution.shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_EQ(resolution.shared_detail()->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
}

// A sub-StateMachine is active while its parent is in the State that owns it, decided from the parent's
// CurrentState.Id; an Id whose own status is Uncertain is not acted on, and the activity is refused
// Bad_InternalError (ReadAnswerUncertain) with that status as the inner status.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST_F(StateMachineModelValidationTest, AParentCurrentStateIdWhoseOwnStatusIsUncertainDecidesNoActivity)
{
  auto parent = create_node(9500U, NodeClass::Object, "ParentMachine");
  auto parentCurrentState = create_node(9501U, NodeClass::Variable, "CurrentState");
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, parentCurrentState.get_node_id());
  parentCurrentState.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, parent.get_node_id(), false);
  auto owningState = create_node(9502U, NodeClass::Object, "Machining");
  parent.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, owningState.get_node_id());
  owningState.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, parent.get_node_id(), false);
  auto parentStateId = create_property(parentCurrentState, 9503U, "Id", Variant{owningState.get_node_id()});
  auto subMachine = create_node(9510U, NodeClass::Object, "SubMachine");
  owningState.add_reference_sync(NodeId{ReferenceTypeId::HasSubStateMachine}, subMachine.get_node_id());
  subMachine.add_reference_sync(
    NodeId{ReferenceTypeId::HasSubStateMachine}, owningState.get_node_id(), false);
  auto currentState = create_node(9511U, NodeClass::Variable, "CurrentState");
  subMachine.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, currentState.get_node_id());
  currentState.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, subMachine.get_node_id(), false);
  parentStateId.write_value_sync(
    DataValue{Variant{owningState.get_node_id()}, StatusCode{Status::UncertainLastUsableValue}});

  const auto active = evaluate_activity(currentState.get_node_id());

  EXPECT_EQ(active.status_code().as_status(), Status::BadInternalError) << to_string(active.status_code());
  ASSERT_NE(active.shared_detail(), nullptr);
  EXPECT_EQ(active.shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_EQ(active.shared_detail()->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value());
}

}  // namespace
}  // namespace ua::server
