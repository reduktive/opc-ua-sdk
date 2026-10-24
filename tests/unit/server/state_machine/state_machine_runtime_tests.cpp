// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_state_machine_runtime.h"

#include "ua_audit_program_transition_event_payload.h"
#include "ua_audit_update_state_event_payload.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_generic_event.h"
#include "ua_objecttype_id.h"
#include "ua_sinks.h"
#include "ua_to_string.h"

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ua::server
{
namespace
{

class FakeStateMachineModel final : public StateMachineModel
{
public:
  void resolve_transition_async(
    const NodeId& machineId, const NodeId& methodId, ResolveCallback callback) noexcept override
  {
    ++resolveCalls;
    resolvedMachine = machineId;
    resolvedMethod = methodId;
    resolveCallback = std::move(callback);
  }

  void resolve_automatic_transition_async(const NodeId& machineId, ResolveCallback callback) noexcept override
  {
    ++automaticResolveCalls;
    automaticResolvedMachine = machineId;
    if (automaticResolutions.empty())
    {
      callback(StateMachineTransitionResolution{});
      return;
    }
    auto resolution = std::move(automaticResolutions.front());
    automaticResolutions.erase(automaticResolutions.begin());
    callback(std::move(resolution));
  }

  void commit_transition_async(
    const StateMachineTransitionDescriptor& transition, CommitCallback callback) noexcept override
  {
    ++commitCalls;
    committedTransition = transition;
    commitCallback = std::move(callback);
  }

  size_t resolveCalls{0};
  size_t automaticResolveCalls{0};
  size_t commitCalls{0};
  NodeId resolvedMachine;
  NodeId resolvedMethod;
  NodeId automaticResolvedMachine;
  std::vector<StateMachineTransitionResolutionResult> automaticResolutions;
  std::optional<StateMachineTransitionDescriptor> committedTransition;
  ResolveCallback resolveCallback;
  CommitCallback commitCallback;
};

class CapturingEventSink : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    sequence.push_back("emit");
    events.push_back(event.clone());
  }

  std::vector<std::string> sequence;
  std::vector<std::unique_ptr<BaseEvent>> events;
};

// Counts each Event it is given into a counter its creator owns, which outlives the sink.
class CountingEventSink final : public EventSink
{
public:
  explicit CountingEventSink(size_t& emitted) : mEmitted(&emitted)
  {}

  void emit(BaseEvent&) override
  {
    ++*mEmitted;
  }

private:
  size_t* mEmitted;
};

class ThrowingEventSink final : public EventSink
{
public:
  explicit ThrowingEventSink(StatusCode failure) : mFailure(std::move(failure))
  {}

  void emit(BaseEvent&) override
  {
    ++calls;
    throw UaException{mFailure};
  }

  size_t calls{0};

private:
  StatusCode mFailure;
};

StateMachineTransitionDescriptor descriptor()
{
  return StateMachineTransitionDescriptor{.machineId = NodeId{2, 100U},
    .transitionId = NodeId{2, 110U},
    .transitionName = QualifiedName{2, "ReadyToRunning"},
    .transitionNumber = 17U,
    .eventTypes = {NodeId{2, 120U}},
    .fromState =
      StateMachineStateDescriptor{
        NodeId{2, 130U}, QualifiedName{2, "Ready"}, 11U, LocalizedText{"en", "Ready display"}},
    .toState =
      StateMachineStateDescriptor{
        NodeId{2, 140U}, QualifiedName{2, "Running"}, 12U, LocalizedText{"en", "Running display"}},
    .currentStateVariableId = NodeId{2, 150U},
    .currentStateIdPropertyId = NodeId{2, 151U}};
}

void drain(boost::asio::io_context& context)
{
  context.restart();
  context.run();
}

struct RuntimeHarness
{
  boost::asio::io_context context;
  std::shared_ptr<FakeStateMachineModel> model{std::make_shared<FakeStateMachineModel>()};
  std::shared_ptr<CapturingEventSink> sinkOwner{std::make_shared<CapturingEventSink>()};
  CapturingEventSink& sink{*sinkOwner};
  std::shared_ptr<StateMachineRuntime> runtime{
    StateMachineRuntime::create(context.get_executor(), model, sinkOwner)};
  std::vector<VoidResult> completions;

  void start()
  {
    runtime->transition_after_method_async(NodeId{2, 100U},
      NodeId{2, 101U},
      [this](VoidResult result) { completions.push_back(std::move(result)); });
    drain(context);
  }

  void resolve(StateMachineTransitionResolutionResult result)
  {
    ASSERT_TRUE(model->resolveCallback);
    // Moved out, as a model that answers does: a completion left with the model would keep a runtime owned
    // by its work alive after it has answered.
    std::exchange(model->resolveCallback, nullptr)(std::move(result));
    drain(context);
  }

  void commit(VoidResult result)
  {
    ASSERT_TRUE(model->commitCallback);
    std::exchange(model->commitCallback, nullptr)(std::move(result));
    drain(context);
  }
};

// @relation(AC-COMP-SVR-SM-RUNTIME-01-UNIQUE-ENABLED-TRANSITION, scope=function)
TEST(StateMachineRuntimeTest, UnrelatedMethodIsSuccessfulNoOp)
{
  RuntimeHarness harness;
  harness.start();
  harness.resolve(StateMachineTransitionResolution{});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_TRUE(harness.completions[0].is_good());
  EXPECT_EQ(harness.model->resolveCalls, 1U);
  EXPECT_EQ(harness.model->commitCalls, 0U);
  EXPECT_TRUE(harness.sink.events.empty());
}

// @relation(AC-COMP-SVR-SM-RUNTIME-01-UNIQUE-ENABLED-TRANSITION, scope=function)
// @relation(AC-COMP-SVR-SM-RUNTIME-02-COMPLETE-STATE-EVENT, scope=function)
TEST(StateMachineRuntimeTest, UniqueEnabledTransitionCommitsAndEmitsForCalledObject)
{
  RuntimeHarness harness;
  harness.start();
  const auto transition = descriptor();
  harness.resolve(StateMachineTransitionResolution{true, transition});
  EXPECT_TRUE(harness.completions.empty());
  EXPECT_EQ(harness.model->commitCalls, 1U);
  ASSERT_TRUE(harness.model->committedTransition.has_value());
  EXPECT_EQ(harness.model->committedTransition->transitionId, transition.transitionId);

  harness.commit(VoidResult{});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_TRUE(harness.completions[0].is_good());
  ASSERT_EQ(harness.sink.events.size(), 1U);
  EXPECT_EQ(harness.sink.events[0]->eventType, transition.eventTypes.front());
  EXPECT_EQ(harness.sink.events[0]->sourceNode, transition.machineId);
}

// @relation(AC-SVR-SM-011-HASEFFECT-FIRES-EVENT, scope=function)
TEST(StateMachineRuntimeTest, ATransitionRaisesOneEventOfEachOfItsEventTypesInOrder)
{
  RuntimeHarness harness;
  harness.start();
  auto transition = descriptor();
  transition.eventTypes = {NodeId{2, 120U}, NodeId{2, 121U}};
  harness.resolve(StateMachineTransitionResolution{true, transition});
  harness.commit(VoidResult{});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_TRUE(harness.completions[0].is_good());
  ASSERT_EQ(harness.sink.events.size(), 2U);
  EXPECT_EQ(harness.sink.events[0]->eventType, (NodeId{2, 120U}));
  EXPECT_EQ(harness.sink.events[1]->eventType, (NodeId{2, 121U}));
  EXPECT_EQ(harness.sink.events[1]->sourceNode, transition.machineId);
}

// @relation(AC-SVR-SM-037-CHOICESTATE-GUARDS-TOTAL, scope=function)
TEST(StateMachineRuntimeTest, AutomaticTransitionCommitsBeforeMethodCompletion)
{
  RuntimeHarness harness;
  auto automatic = descriptor();
  automatic.transitionId = NodeId{2, 111U};
  automatic.fromState = automatic.toState;
  automatic.toState = StateMachineStateDescriptor{
    NodeId{2, 141U}, QualifiedName{2, "Settled"}, 13U, LocalizedText{"en", "Settled display"}};
  harness.model->automaticResolutions.emplace_back(StateMachineTransitionResolution{false, automatic});

  harness.start();
  harness.resolve(StateMachineTransitionResolution{true, descriptor()});
  harness.commit(VoidResult{});

  EXPECT_TRUE(harness.completions.empty());
  EXPECT_EQ(harness.model->automaticResolveCalls, 1U);
  EXPECT_EQ(harness.model->automaticResolvedMachine, NodeId(2, 100U));
  ASSERT_TRUE(harness.model->committedTransition.has_value());
  EXPECT_EQ(harness.model->committedTransition->transitionId, automatic.transitionId);

  harness.commit(VoidResult{});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_TRUE(harness.completions[0].is_good());
  EXPECT_EQ(harness.model->automaticResolveCalls, 2U);
  ASSERT_EQ(harness.sink.events.size(), 2U);
  EXPECT_EQ(harness.sink.events[1]->sourceNode, automatic.machineId);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-RICH-FAILURE-CHOKEPOINT, scope=function)
TEST(StateMachineRuntimeTest, AutomaticResolutionFailureIsLossless)
{
  RuntimeHarness harness;
  auto detail = std::shared_ptr<const ErrorDetail>{
    ErrorDetail::build("AutomaticResolveFailure", "automatic resolution failed", "test")};
  const StatusCode failure{Status::BadConfigurationError, detail};
  harness.model->automaticResolutions.emplace_back(failure);
  harness.start();
  harness.resolve(StateMachineTransitionResolution{true, descriptor()});
  harness.commit(VoidResult{});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_EQ(harness.completions[0].status_code().value(), failure.value());
  EXPECT_EQ(harness.completions[0].shared_detail(), detail);
}

// @relation(AC-SVR-SM-037-CHOICESTATE-GUARDS-TOTAL, scope=function)
TEST(StateMachineRuntimeTest, AutomaticTransitionCycleFailsAtBound)
{
  RuntimeHarness harness;
  for (size_t index = 0; index < 65U; ++index)
    harness.model->automaticResolutions.emplace_back(StateMachineTransitionResolution{false, descriptor()});
  harness.start();
  harness.resolve(StateMachineTransitionResolution{true, descriptor()});
  for (size_t index = 0; index < 65U; ++index)
    harness.commit(VoidResult{});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_EQ(harness.completions[0].status_code().as_status(), Status::BadConfigurationError);
  ASSERT_NE(harness.completions[0].shared_detail(), nullptr);
  EXPECT_EQ(harness.completions[0].shared_detail()->code, "AutomaticTransitionLimitExceeded");
  EXPECT_EQ(harness.model->commitCalls, 65U);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-01-UNIQUE-ENABLED-TRANSITION, scope=function)
TEST(StateMachineRuntimeTest, AmbiguousTransitionFailureIsLosslessAndHasNoEffects)
{
  RuntimeHarness harness;
  auto detail = std::shared_ptr<const ErrorDetail>{
    ErrorDetail::build("AmbiguousTransition", "More than one transition is enabled", "test")};
  const StatusCode failure{Status::BadConfigurationError, detail};
  harness.start();
  harness.resolve(StateMachineTransitionResolutionResult{failure});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_EQ(harness.completions[0].status_code().value(), failure.value());
  EXPECT_EQ(harness.completions[0].shared_detail(), detail);
  EXPECT_EQ(harness.model->commitCalls, 0U);
  EXPECT_TRUE(harness.sink.events.empty());
}

// @relation(AC-COMP-SVR-SM-RUNTIME-02-COMPLETE-STATE-EVENT, scope=function)
TEST(StateMachineRuntimeTest, EventStateSnapshotsContainEveryExactOptionalProperty)
{
  RuntimeHarness harness;
  const auto transition = descriptor();
  harness.start();
  harness.resolve(StateMachineTransitionResolution{true, transition});
  harness.commit(VoidResult{});

  ASSERT_EQ(harness.sink.events.size(), 1U);
  const auto& event = *harness.sink.events[0];
  const auto field = [&event](std::initializer_list<std::string_view> names)
  {
    std::vector<QualifiedName> path;
    for (const auto name : names)
      path.emplace_back(0, std::string{name});
    return event.resolve_field(path);
  };

  ASSERT_NE(field({"Transition"}).try_as<LocalizedText>(), nullptr);
  EXPECT_EQ(*field({"Transition", "Id"}).try_as<NodeId>(), transition.transitionId);
  EXPECT_EQ(*field({"Transition", "Name"}).try_as<QualifiedName>(), transition.transitionName);
  EXPECT_EQ(*field({"Transition", "Number"}).try_as<uint32_t>(), *transition.transitionNumber);
  EXPECT_EQ(*field({"FromState", "Id"}).try_as<NodeId>(), transition.fromState.id);
  EXPECT_EQ(*field({"FromState", "Name"}).try_as<QualifiedName>(), transition.fromState.name);
  EXPECT_EQ(*field({"FromState", "Number"}).try_as<uint32_t>(), transition.fromState.number);
  EXPECT_EQ(*field({"FromState", "EffectiveDisplayName"}).try_as<LocalizedText>(),
    transition.fromState.effectiveDisplayName);
  EXPECT_EQ(*field({"ToState", "Id"}).try_as<NodeId>(), transition.toState.id);
  EXPECT_EQ(*field({"ToState", "Name"}).try_as<QualifiedName>(), transition.toState.name);
  EXPECT_EQ(*field({"ToState", "Number"}).try_as<uint32_t>(), transition.toState.number);
  EXPECT_EQ(*field({"ToState", "EffectiveDisplayName"}).try_as<LocalizedText>(),
    transition.toState.effectiveDisplayName);
}

// @relation(AC-SVR-SM-035-AUDITUPDATESTATE-SOURCENODE, scope=function)
// @relation(AC-SVR-SM-036-AUDIT-STATE-IDS, scope=function)
TEST(StateMachineRuntimeTest, AuditedCommitEmitsMachineAndExactStateIds)
{
  boost::asio::io_context context;
  auto model = std::make_shared<FakeStateMachineModel>();
  auto sinkOwner = std::make_shared<CapturingEventSink>();
  auto& sink = *sinkOwner;
  AuditUpdateStateEventPayload auditEvent;
  auditEvent.sourceName = "Attribute/Call";
  auditEvent.methodId = NodeId{2, 101U};
  auto runtime =
    StateMachineRuntime::create(context.get_executor(), model, sinkOwner, {}, std::move(auditEvent));
  std::vector<VoidResult> completions;
  runtime->transition_after_method_async(NodeId{2, 100U},
    NodeId{2, 101U},
    [&completions](VoidResult result) { completions.push_back(std::move(result)); });
  drain(context);
  const auto transition = descriptor();
  model->resolveCallback(StateMachineTransitionResolution{true, transition});
  drain(context);
  model->commitCallback(VoidResult{});
  drain(context);

  ASSERT_EQ(completions.size(), 1U);
  EXPECT_TRUE(completions[0].is_good());
  ASSERT_EQ(sink.events.size(), 2U);
  const auto* audit = dynamic_cast<const AuditUpdateStateEventPayload*>(sink.events[1].get());
  ASSERT_NE(audit, nullptr);
  EXPECT_EQ(audit->sourceNode, transition.machineId);
  EXPECT_EQ(audit->sourceName, "Attribute/Call");
  EXPECT_EQ(audit->methodId, NodeId(2, 101U));
  ASSERT_NE(audit->oldStateId.try_as<NodeId>(), nullptr);
  EXPECT_EQ(*audit->oldStateId.try_as<NodeId>(), transition.fromState.id);
  ASSERT_NE(audit->newStateId.try_as<NodeId>(), nullptr);
  EXPECT_EQ(*audit->newStateId.try_as<NodeId>(), transition.toState.id);
}

// An audit EventType a transition's effect names is the type its audit Event is raised as (OPC 10000-16
// 4.4.14): an AuditProgramTransitionEvent carries the TransitionNumber, says a Program Control Method caused
// the transition and names that Method (OPC 10000-10 5.2.6); another audit EventType carries the fields of
// AuditUpdateStateEventType.
// @relation(AC-SVR-SM-011-HASEFFECT-FIRES-EVENT, scope=function)
TEST(StateMachineRuntimeTest, AnAuditEffectIsRaisedAsTheAuditEventTypeItNames)
{
  boost::asio::io_context context;
  auto model = std::make_shared<FakeStateMachineModel>();
  auto sinkOwner = std::make_shared<CapturingEventSink>();
  auto& sink = *sinkOwner;
  AuditUpdateStateEventPayload auditEvent;
  auditEvent.sourceName = "Attribute/Call";
  auditEvent.methodId = NodeId{2, 101U};
  auto runtime =
    StateMachineRuntime::create(context.get_executor(), model, sinkOwner, {}, std::move(auditEvent));
  std::vector<VoidResult> completions;
  runtime->transition_after_method_async(NodeId{2, 100U},
    NodeId{2, 101U},
    [&completions](VoidResult result) { completions.push_back(std::move(result)); });
  drain(context);
  auto transition = descriptor();
  transition.transitionNumber = 2U;
  transition.methodName = QualifiedName{0, "Start"};
  transition.auditEventTypes = {NodeId{ObjectTypeId::AuditProgramTransitionEventType}, NodeId{2, 125U}};
  model->resolveCallback(StateMachineTransitionResolution{true, transition});
  drain(context);
  model->commitCallback(VoidResult{});
  drain(context);

  ASSERT_EQ(completions.size(), 1U);
  EXPECT_TRUE(completions[0].is_good());
  ASSERT_EQ(sink.events.size(), 3U);
  const auto* program = dynamic_cast<const AuditProgramTransitionEventPayload*>(sink.events[1].get());
  ASSERT_NE(program, nullptr);
  EXPECT_EQ(program->eventType, NodeId{ObjectTypeId::AuditProgramTransitionEventType});
  EXPECT_EQ(program->transitionNumber, 2U);
  EXPECT_EQ(program->sourceName, "Method/Start");
  EXPECT_TRUE(program->status);
  EXPECT_EQ(program->sourceNode, transition.machineId);
  EXPECT_EQ(program->methodId, NodeId(2, 101U));
  ASSERT_NE(program->newStateId.try_as<NodeId>(), nullptr);
  EXPECT_EQ(*program->newStateId.try_as<NodeId>(), transition.toState.id);
  const auto* other = dynamic_cast<const AuditUpdateStateEventPayload*>(sink.events[2].get());
  ASSERT_NE(other, nullptr);
  EXPECT_EQ(other->eventType, (NodeId{2, 125U}));
  EXPECT_EQ(other->sourceName, "Attribute/Call");
  ASSERT_NE(other->oldStateId.try_as<NodeId>(), nullptr);
  EXPECT_EQ(*other->oldStateId.try_as<NodeId>(), transition.fromState.id);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-RICH-FAILURE-CHOKEPOINT, scope=function)
TEST(StateMachineRuntimeTest, ResolutionFailureIsLosslessAndHasNoEffects)
{
  RuntimeHarness harness;
  auto detail = std::shared_ptr<const ErrorDetail>{
    ErrorDetail::build("ResolveFailure", "transition resolution failed", "test")};
  const StatusCode failure{Status::BadNodeIdUnknown, detail};
  harness.start();
  harness.resolve(StateMachineTransitionResolutionResult{failure});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_EQ(harness.completions[0].status_code().value(), failure.value());
  EXPECT_EQ(harness.completions[0].shared_detail(), detail);
  EXPECT_EQ(harness.model->commitCalls, 0U);
  EXPECT_TRUE(harness.sink.events.empty());
}

// The model's resolution decides whether the machine moves, so an Uncertain answer is not acted on, whether
// or not it holds an enabled transition: the call completes Bad_InternalError (AnswerUncertain) with the
// model's code as the inner status, nothing is committed and no Event is emitted.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(StateMachineRuntimeTest, AnUncertainResolutionIsNotActedOnWithOrWithoutATransition)
{
  const StatusCode uncertain{Status::UncertainLastUsableValue};
  for (const bool withTransition : {true, false})
  {
    SCOPED_TRACE(withTransition ? "an Uncertain resolution holding a transition"
                                : "an Uncertain resolution without one");
    RuntimeHarness harness;
    harness.start();
    harness.resolve(withTransition ? StateMachineTransitionResolutionResult{StateMachineTransitionResolution{
                                                                              true, descriptor()},
                                       uncertain}
                                   : StateMachineTransitionResolutionResult{uncertain});

    ASSERT_EQ(harness.completions.size(), 1U);
    EXPECT_EQ(harness.completions[0].status_code().as_status(), Status::BadInternalError)
      << to_string(harness.completions[0].status_code());
    const auto& detail = harness.completions[0].shared_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, "AnswerUncertain");
    EXPECT_EQ(detail->innerStatus, uncertain.value());
    EXPECT_EQ(harness.model->commitCalls, 0U) << "a transition was committed on an Uncertain resolution";
    EXPECT_TRUE(harness.sink.events.empty());
  }
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-RICH-FAILURE-CHOKEPOINT, scope=function)
TEST(StateMachineRuntimeTest, CommitFailureIsLosslessAndEmitsNothing)
{
  RuntimeHarness harness;
  auto detail =
    std::shared_ptr<const ErrorDetail>{ErrorDetail::build("CommitFailure", "state commit failed", "test")};
  const StatusCode failure{Status::BadNotWritable, detail};
  harness.start();
  harness.resolve(StateMachineTransitionResolution{true, descriptor()});
  harness.commit(VoidResult{failure});

  ASSERT_EQ(harness.completions.size(), 1U);
  EXPECT_EQ(harness.completions[0].status_code().value(), failure.value());
  EXPECT_EQ(harness.completions[0].shared_detail(), detail);
  EXPECT_TRUE(harness.sink.events.empty());
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-RICH-FAILURE-CHOKEPOINT, scope=function)
TEST(StateMachineRuntimeTest, ThrowingEventSinkBecomesOneRichFailure)
{
  boost::asio::io_context context;
  auto model = std::make_shared<FakeStateMachineModel>();
  auto detail =
    std::shared_ptr<const ErrorDetail>{ErrorDetail::build("SinkFailure", "event sink failed", "test")};
  const StatusCode failure{Status::BadResourceUnavailable, detail};
  auto sinkOwner = std::make_shared<ThrowingEventSink>(failure);
  auto& sink = *sinkOwner;
  auto runtime = StateMachineRuntime::create(context.get_executor(), model, sinkOwner);
  std::vector<VoidResult> completions;
  runtime->transition_after_method_async(NodeId{2, 100U},
    NodeId{2, 101U},
    [&completions](VoidResult result) { completions.push_back(std::move(result)); });
  drain(context);
  model->resolveCallback(StateMachineTransitionResolution{true, descriptor()});
  drain(context);
  model->commitCallback(VoidResult{});
  drain(context);

  ASSERT_EQ(completions.size(), 1U);
  EXPECT_EQ(completions[0].status_code().value(), failure.value());
  EXPECT_EQ(completions[0].shared_detail(), detail);
  EXPECT_EQ(sink.calls, 1U);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-RICH-FAILURE-CHOKEPOINT, scope=function)
TEST(StateMachineRuntimeTest, DuplicateDependencyCompletionsCannotRepeatEffectsOrCompletion)
{
  RuntimeHarness harness;
  harness.start();
  // Taken from the model rather than copied: a copy left with the model is never called, and keeps the
  // runtime it owns, which owns the model, alive for ever.
  auto resolve = std::exchange(harness.model->resolveCallback, nullptr);
  resolve(StateMachineTransitionResolution{true, descriptor()});
  resolve(StateMachineTransitionResolution{true, descriptor()});
  drain(harness.context);
  EXPECT_EQ(harness.model->commitCalls, 1U);

  auto commit = std::exchange(harness.model->commitCallback, nullptr);
  commit(VoidResult{});
  commit(VoidResult{});
  drain(harness.context);

  EXPECT_EQ(harness.sink.events.size(), 1U);
  EXPECT_EQ(harness.completions.size(), 1U);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-OWNER-EXPIRY, scope=function)
TEST(StateMachineRuntimeTest, ATransitionWhoseCallerReleasesItCompletesOnce)
{
  boost::asio::io_context context;
  auto model = std::make_shared<FakeStateMachineModel>();
  auto sink = std::make_shared<CapturingEventSink>();
  size_t completions{0};
  auto runtime = StateMachineRuntime::create(context.get_executor(), model, sink);
  const std::weak_ptr<StateMachineRuntime> released = runtime;
  runtime->transition_after_method_async(
    NodeId{2, 100U}, NodeId{2, 101U}, [&completions](VoidResult) { ++completions; });
  drain(context);
  ASSERT_TRUE(model->resolveCallback);

  runtime.reset();
  std::exchange(model->resolveCallback, nullptr)(StateMachineTransitionResolution{true, descriptor()});
  drain(context);
  ASSERT_TRUE(model->commitCallback)
    << "the runtime its caller released did not go on to commit the transition";
  std::exchange(model->commitCallback, nullptr)(VoidResult{});
  drain(context);

  EXPECT_EQ(model->commitCalls, 1U) << "the commits of the new state";
  EXPECT_EQ(sink->events.size(), 1U) << "the Events emitted";
  EXPECT_EQ(completions, 1U) << "the calls of the runtime's completion";
  EXPECT_TRUE(released.expired()) << "the runtime is alive after its transition completed";
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-A-DROPPED-STEP-ANSWERS-ONCE, scope=function)
TEST(StateMachineRuntimeTest, ADroppedStepAnswersOnce)
{
  // The model drops the completion of the resolution or, once the transition is resolved, of its commit.
  const auto dropStep = [](bool commitDropped)
  {
    SCOPED_TRACE(commitDropped ? "the commit's completion dropped" : "the resolution's completion dropped");
    boost::asio::io_context context;
    auto model = std::make_shared<FakeStateMachineModel>();
    auto sink = std::make_shared<CapturingEventSink>();
    std::vector<VoidResult> completions;
    auto runtime = StateMachineRuntime::create(context.get_executor(), model, sink);
    const std::weak_ptr<StateMachineRuntime> released = runtime;
    runtime->transition_after_method_async(NodeId{2, 100U},
      NodeId{2, 101U},
      [&completions](VoidResult result) { completions.push_back(std::move(result)); });
    drain(context);
    ASSERT_TRUE(model->resolveCallback);
    if (commitDropped)
    {
      std::exchange(model->resolveCallback, nullptr)(StateMachineTransitionResolution{true, descriptor()});
      drain(context);
      ASSERT_TRUE(model->commitCallback);
    }

    runtime.reset();
    // The model destroys the completion it holds without calling it.
    model->resolveCallback = nullptr;
    model->commitCallback = nullptr;
    drain(context);

    EXPECT_TRUE(sink->events.empty()) << "the Events emitted";
    EXPECT_EQ(model->resolveCalls, 1U) << "the model's resolutions";
    EXPECT_EQ(model->commitCalls, commitDropped ? 1U : 0U) << "the model's commits";
    EXPECT_EQ(model->automaticResolveCalls, 0U) << "the model's automatic resolutions";
    EXPECT_TRUE(released.expired()) << "the runtime is alive after its step was dropped";
    ASSERT_EQ(completions.size(), 1U) << "the calls of the runtime's completion";
    EXPECT_EQ(completions[0].status_code().as_status(), Status::BadShutdown)
      << to_string(completions[0].status_code());
    ASSERT_NE(completions[0].shared_detail(), nullptr) << "the answer carries no ErrorDetail";
    EXPECT_EQ(completions[0].shared_detail()->code, "StateMachineTransitionDropped");
  };

  dropStep(false);
  dropStep(true);
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-A-DESTROYED-EVENT-SINK-RECEIVES-NOTHING, scope=function)
TEST(StateMachineRuntimeTest, ADestroyedEventSinkReceivesNothing)
{
  boost::asio::io_context context;
  auto model = std::make_shared<FakeStateMachineModel>();
  size_t emitted{0};
  auto sink = std::make_shared<CountingEventSink>(emitted);
  std::vector<VoidResult> completions;
  auto runtime = StateMachineRuntime::create(context.get_executor(), model, sink);
  runtime->transition_after_method_async(NodeId{2, 100U},
    NodeId{2, 101U},
    [&completions](VoidResult result) { completions.push_back(std::move(result)); });
  drain(context);
  ASSERT_TRUE(model->resolveCallback);
  std::exchange(model->resolveCallback, nullptr)(StateMachineTransitionResolution{true, descriptor()});
  drain(context);
  ASSERT_TRUE(model->commitCallback);

  sink.reset();
  std::exchange(model->commitCallback, nullptr)(VoidResult{});
  drain(context);

  ASSERT_EQ(completions.size(), 1U) << "the calls of the runtime's completion";
  EXPECT_EQ(completions[0].status_code().as_status(), Status::BadResourceUnavailable)
    << to_string(completions[0].status_code());
  ASSERT_NE(completions[0].shared_detail(), nullptr) << "the answer carries no ErrorDetail";
  EXPECT_EQ(completions[0].shared_detail()->code, "StateMachineEventSinkUnavailable");
  EXPECT_EQ(emitted, 0U) << "the Events the destroyed sink was given";
}

// @relation(AC-COMP-SVR-SM-RUNTIME-03-RICH-FAILURE-CHOKEPOINT, scope=function)
TEST(StateMachineModelAsyncSafetyTest, ThrowAfterTakingCompletionReportsOneRichFailure)
{
  auto detail = std::shared_ptr<const ErrorDetail>{
    ErrorDetail::build("FlowStartFailure", "state-machine flow start failed", "test")};
  const StatusCode failure{Status::BadResourceUnavailable, detail};
  std::vector<StateMachineTransitionResolutionResult> completions;

  state_machine_detail::invoke_model_action_once<StateMachineTransitionResolutionResult>(
    [failure](StateMachineModel::ResolveCallback completion)
    {
      auto flowOwnedCompletion = std::move(completion);
      if (!flowOwnedCompletion)
        throw std::logic_error{"the model flow did not take ownership of its completion"};
      throw UaException{failure};
    },
    [&completions](StateMachineTransitionResolutionResult result)
    { completions.push_back(std::move(result)); });

  ASSERT_EQ(completions.size(), 1U);
  EXPECT_EQ(completions[0].status_code().value(), failure.value());
  EXPECT_EQ(completions[0].shared_detail(), detail);
}

// A runtime that refused its first call because it had no model refuses the second one too.
//
// A runtime is created for ONE Method call and answers it once. Refusing for want of a model is an
// answer, so the call that follows must be refused rather than accepted - an accepted call whose
// completion is then dropped leaves its caller waiting for ever. Two booleans can drift apart where
// one state cannot, which is what this pins.
TEST(StateMachineRuntimeTest, ASecondCallIsRefusedEvenAfterTheFirstWasRefusedForWantOfAModel)
{
  boost::asio::io_context context;
  auto sinkOwner = std::make_shared<CapturingEventSink>();
  auto runtime = StateMachineRuntime::create(context.get_executor(), nullptr, sinkOwner);

  std::vector<VoidResult> answers;
  const auto call = [&]
  {
    runtime->transition_after_method_async(
      NodeId{1, 1}, NodeId{1, 2}, [&answers](VoidResult result) { answers.push_back(std::move(result)); });
    drain(context);
  };

  call();
  call();

  ASSERT_EQ(answers.size(), 2U) << "every call is owed exactly one answer, refusals included";
  EXPECT_EQ(answers[0].status_code(), Status::BadInvalidState);
  EXPECT_EQ(answers[1].status_code(), Status::BadInvalidState);
}

}  // namespace
}  // namespace ua::server