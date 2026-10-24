// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATE_MACHINE_ACCESS_H
#define UA_STATE_MACHINE_ACCESS_H

/// @file
/// @brief Tier-2 public `StateMachine` typed-access facade (client design section 8.18.1.b): the
/// per-`Connection`
///        accessor for the OPC-UA finite-state-machine hierarchy (Part 5 `StateMachineType`  to
///        `FiniteStateMachineType`  to  Part 10 `ProgramStateMachineType`). Each factory performs the
///        address-space pre-flight (Browse the machine's `CurrentState` / `LastTransition` components + their
///        `Id` / `TransitionTime` Properties, and  -  for the finite/program levels  -  the `AvailableStates`
///        / `AvailableTransitions` topology) then yields a cheap, copyable value handle. Returned by
///        `Connection::state_machine_accessor()`.
/// @ingroup client
///
/// The 3 handle classes model the spec-defined type hierarchy with public inheritance
/// (the design specification: spec-defined hierarchies use inheritance). A factory returns the CONCRETE
/// handle by value (never a sliced base); copies share one `shared_ptr` per-handle state so the cached
/// topology / method resolution is observed by every copy.
///
/// CL-SM-010/011 `subscribe_transitions_async` rides the section 8.13 event backbone (reached through the
/// `detail::SupportOps` event-subscriber interface)  -  see
/// `StateMachineAccessor::subscribe_transitions_async`.

#include "ua_call_method_result.h"
#include "ua_client_monitored_item.h"
#include "ua_date_time.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_variant.h"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace ua::client
{

namespace detail
{
class WireOps;
class SupportOps;
struct StateMachineHandleState;
struct FiniteStateMachineHandleState;
struct ProgramStateMachineHandleState;
struct StateMachineClientTestAccess;
}  // namespace detail

class Connection;
class StateMachineAccessor;

// ============================================================================
// 8.18.1.b Typed value structs
// ============================================================================

/// A decoded `StateVariableType` snapshot (client design section 8.18.1.b, CL-SM-001). @ref name mirrors the
/// `CurrentState` `LocalizedText` Value; @ref id is the `Id` Property's NodeId (state identity, CL-SM-003);
/// @ref statusCode carries the `CurrentState` `DataValue` quality (CL-SM-002  - `Bad_StateNotActive`
/// surfaces here while the outer `Result` stays Good), combined with the `Id` Property's quality
/// (`ua::detail::combined_status`) so that an Uncertain or Bad Id is not hidden behind a Good
/// CurrentState.
/// @ingroup client
struct StateVariable
{
  ua::LocalizedText name;  ///< CL-SM-001 - CurrentState LocalizedText; empty when its quality is Bad
  std::optional<ua::NodeId> id;  ///< CL-SM-003  -  state identity (Mandatory Id Property NodeId)
  std::optional<std::uint32_t> number;  ///< CL-SM-005  -  FiniteStateVariableType (not resolved v1)
  ua::StatusCode statusCode;  ///< CL-SM-002  -  the CurrentState quality combined with the Id quality
  std::optional<ua::DateTime> sourceTimestamp;  ///< the CurrentState DataValue source timestamp
};

/// A decoded `TransitionVariableType` snapshot (client design section 8.18.1.b, CL-SM-004). Returned by
/// @ref StateMachineHandle::last_transition_async.
/// @ingroup client
struct TransitionVariable
{
  ua::LocalizedText name;  ///< the LastTransition LocalizedText value
  std::optional<ua::NodeId> id;  ///< the Id Property NodeId (transition identity)
  std::optional<std::uint32_t> number;  ///< Optional Number Property (not resolved v1)
  std::optional<ua::DateTime> transitionTime;  ///< CL-SM-004  -  the TransitionTime Property value
  std::optional<ua::DateTime> effectiveTransitionTime;  ///< Optional (not resolved v1)
};

/// One state in a `FiniteStateMachineType`'s cached topology (client design section 8.18.1.b, CL-SM-005).
/// @ref stateId is the state object's NodeId. On a subtype this may be the distinct replicated Object;
/// @ref StateMachineHandle::current_state_is_async resolves it to the first-definition NodeId (CL-SM-006).
/// @ingroup client
struct AvailableState
{
  ua::NodeId
    stateId;  ///< CL-SM-005  -  the state object NodeId (the "Id" the current state compares against)
  ua::LocalizedText name;  ///< the state display name; empty when enrichment could not read it
  std::optional<std::uint32_t> number;  ///< the StateNumber Property; empty when unresolved
};

/// One transition in a `FiniteStateMachineType`'s cached topology (client design section 8.18.1.b,
/// CL-SM-005).
/// @ingroup client
struct AvailableTransition
{
  ua::NodeId transitionId;  ///< CL-SM-005  -  the transition object NodeId
  ua::LocalizedText name;  ///< the transition display name; empty when enrichment could not read it
  std::optional<std::uint32_t> number;  ///< the TransitionNumber Property; empty when unresolved
  std::optional<ua::NodeId> fromStateId;  ///< the FromState reference target; empty when unresolved
  std::optional<ua::NodeId> toStateId;  ///< the ToState reference target; empty when unresolved
};

/// Why a @ref FiniteStateMachineHandle's cached topology looks the way it does.
///
/// `AvailableStates` and `AvailableTransitions` are Optional (OPC 10000-16 4.4.2), so an empty topology is a
/// legitimate Good answer and an empty vector alone cannot say whether the server published the array at
/// all. These flags separate the two, and separate a metadata field the server does not have from one the
/// SDK could not resolve.
/// @ingroup client
struct TopologyProvenance
{
  /// The server published an `AvailableStates` Variable and the SDK read its Value with a Good status. False
  /// when the Variable is absent or its Value is Bad, so an empty list with this flag true is an array the
  /// server publishes empty.
  bool statesPublished = false;

  /// The server published an `AvailableTransitions` Variable and the SDK read its Value with a Good status,
  /// as
  /// @ref statesPublished.
  bool transitionsPublished = false;

  /// Every best-effort enrichment step succeeded. False means at least one of the DisplayName, StateNumber /
  /// TransitionNumber or FromState / ToState lookups failed, so some optional fields are empty because the
  /// SDK could not resolve them rather than because the server does not have them. The NodeIds are
  /// unaffected either way.
  bool enrichmentComplete = true;
};

/// A decoded `TransitionEventType` notification delivered to a @ref TransitionEventCallback (client design
/// section 8.18.1.b, CL-SM-010/011). @ref sourceNode is the emitting state-machine Object (the CL-SM-011
/// demux key);
/// @ref transitionId / @ref fromStateId / @ref toStateId are the `Id` Properties of the event's `Transition`
/// / `FromState` / `ToState` fields; @ref transitionName is the `Transition` `LocalizedText`; @ref time is
/// the BaseEventType `Time`.
/// @ingroup client
struct TransitionEventNotification
{
  ua::NodeId sourceNode;  ///< CL-SM-011  -  the emitting (sub-)state-machine identity (demux key)
  ua::NodeId transitionId;  ///< the Transition.Id Property NodeId
  ua::LocalizedText transitionName;  ///< the Transition field LocalizedText value
  ua::NodeId fromStateId;  ///< the FromState.Id Property NodeId
  ua::NodeId toStateId;  ///< the ToState.Id Property NodeId
  ua::DateTime time;  ///< the BaseEventType Time field
};

/// The callback a @ref ua::client::StateMachineAccessor::subscribe_transitions_async consumer registers;
/// invoked (on the executor) with each demux-matched @ref TransitionEventNotification.
using TransitionEventCallback = std::function<void(TransitionEventNotification)>;

/// The Part-10 `ProgramStateMachineType` causes (client design section 8.18.1.b). `Stop` is NOT a standard
/// Part-10 cause  -  it is a documented convenience mapped onto the `Halt` method for a running/suspended
/// program (see @ref ua::client::ProgramStateMachineHandle::invoke_async).
enum class ProgramMethod
{
  Start,
  Stop,
  Suspend,
  Resume,
  Reset,
  Halt,
};

/// Callback invoked for state variable result notifications.
using StateVariableResult = ua::Result<StateVariable>;
/// Callback invoked for transition variable result notifications.
using TransitionVariableResult = ua::Result<TransitionVariable>;

// ============================================================================
// 8.18.1.b Typed handles (spec-defined hierarchy  to  public inheritance)
// ============================================================================

/// A copyable value handle to a `StateMachineType` instance (client design section 8.18.1.b). Built async by
/// @ref StateMachineAccessor::state_machine_async after the address-space pre-flight; copies share the cached
/// resolution. The handle binds to its originating Connection's wire interface by a `weak_ptr` (never a
/// `weak_ptr<ConnectionImpl>`, section 8.2A.13): every op locks it and completes `Bad_ConnectionClosed` if
/// the Connection is gone. Not strand-serialized: each op posts through the tier-1 wire interface (which
/// serializes on the Connection strand internally) and delivers its completion on the Connection executor.
/// @ingroup client
class StateMachineHandle
{
public:
  /// Constructs an invalid sentinel handle (every op fast-fails).
  StateMachineHandle() = default;
  /// Returns or updates the state machine handle.
  StateMachineHandle(const StateMachineHandle&) = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  StateMachineHandle& operator=(const StateMachineHandle&) = default;
  /// Returns or updates the state machine handle.
  StateMachineHandle(StateMachineHandle&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  StateMachineHandle& operator=(StateMachineHandle&&) noexcept = default;
  virtual ~StateMachineHandle() = default;

  /// CL-SM-001  -  Reads `<machine>.CurrentState` (a `StateVariableType`) Value + its `Id` Property in one
  /// @param callback Completion callback that receives the operation result.
  /// batched Read. @ref StateVariable::name is the CurrentState LocalizedText; @ref StateVariable::id is the
  /// Id Property NodeId. CL-SM-002: when the CurrentState `DataValue.status_code` is Bad (e.g.
  /// `Bad_StateNotActive`) it is surfaced in @ref StateVariable::statusCode and the outer `Result` is Good.
  /// @ref StateVariable::statusCode is the CurrentState status and the Id Property's combined
  /// (`ua::detail::combined_status`), so an Uncertain or Bad Id is not hidden; the outer `Result` carries
  /// the Read's own code (a Good subcode or an Uncertain ServiceResult).
  void current_state_async(std::function<void(StateVariableResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously current state. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_current_state_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  StateVariable current_state_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to current state sync without throwing.
  ua::Result<StateVariable> try_current_state_sync() noexcept;

  /// CL-SM-004  -  Reads `<machine>.LastTransition` (a `TransitionVariableType`) + its `Id` /
  /// @param callback Completion callback that receives the operation result.
  /// `TransitionTime` Properties. If `LastTransition` is absent (Optional on `StateMachineType`) delivers
  /// `Bad_NotFound` with source `client.tier2.state_machine.last_transition_not_present`. The transition
  /// comes with the Read's code: the ServiceResult, LastTransition's status and the status of each `Id` /
  /// `TransitionTime` Property that is not Bad, combined (`ua::detail::combined_status`). A Bad `Id` or
  /// `TransitionTime` leaves that field unset; the transition time then comes from LastTransition's
  /// SourceTimestamp. A Bad code, or a LastTransition that is not Good and has no value, is answered without
  /// a transition.
  void last_transition_async(std::function<void(TransitionVariableResult)> callback) noexcept;
  /// @return The requested value.
  /// Synchronously last transition. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_last_transition_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  TransitionVariable last_transition_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to last transition sync without throwing.
  ua::Result<TransitionVariable> try_last_transition_sync() noexcept;

  /// CL-SM-003 / CL-SM-006  -  Reads `CurrentState.Id` and compares it to @p expectedStateId by state-object
  /// @param expectedStateId The expected state id.
  /// @param callback Completion callback that receives the operation result.
  /// identity (LocalizedText matching is not used  -  locale-fragile). Raw NodeId equality is the fast path.
  /// Otherwise both State Object NodeIds are resolved through their owning finite-state-machine ObjectType
  /// hierarchy to the Object where the State was first defined, so a caller may supply either the subtype's
  /// required replica or the supertype-origin NodeId. The answer comes with the `CurrentState.Id` Read's code
  /// (the ServiceResult and the value's status combined): a Bad code fails it, and an Uncertain code with a
  /// null value is answered without a value. The type-hierarchy lookups behind the comparison use only Good
  /// answers: an Uncertain one is refused with `Bad_InternalError` (`ReferencesAnswerUncertain` /
  /// `ReadAnswerUncertain`).
  void current_state_is_async(
    ua::NodeId expectedStateId, std::function<void(ua::Result<bool>)> callback) noexcept;
  /// @param expectedStateId The expectedstateid.
  /// @return The requested value.
  /// Synchronously current state is. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_current_state_is_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  bool current_state_is_sync(ua::NodeId expectedStateId);
  /// @param expectedStateId The expectedstateid.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to current state is sync without throwing.
  ua::Result<bool> try_current_state_is_sync(ua::NodeId expectedStateId) noexcept;

  /// @return The state-machine Object NodeId this handle targets (empty NodeId when the handle is a
  /// sentinel).
  [[nodiscard]] ua::NodeId machine_id() const noexcept;

protected:
  friend class StateMachineAccessor;
  friend struct ua::client::detail::StateMachineClientTestAccess;

  /// @param state The state.
  /// Returns or updates the state machine handle.
  explicit StateMachineHandle(std::shared_ptr<detail::StateMachineHandleState> state)
    : mState(std::move(state))
  {}

  /// The m state.
  std::shared_ptr<detail::StateMachineHandleState> mState;
};

/// A copyable value handle to a `FiniteStateMachineType` instance (client design section 8.18.1.b). Adds the
/// cached state/transition topology resolved at construction (CL-SM-005). See @ref StateMachineHandle for the
/// shared lifetime / interface-locking contract.
/// @ingroup client
class FiniteStateMachineHandle : public StateMachineHandle
{
public:
  FiniteStateMachineHandle() = default;

  /// @return The requested value.
  /// CL-SM-005  -  the cached `AvailableStates` topology (resolved at construction; empty on a sentinel).
  [[nodiscard]] std::vector<AvailableState> available_states() const noexcept;

  /// @return The requested value.
  /// CL-SM-005  -  the cached `AvailableTransitions` topology (resolved at construction; empty on a
  /// sentinel).
  [[nodiscard]] std::vector<AvailableTransition> available_transitions() const noexcept;

  /// @return Which topology arrays the server published, and whether enrichment completed.
  /// Read this before concluding anything from an empty or sparse topology: an empty vector alone cannot
  /// separate "the server publishes none" from "the SDK did not find what the server published". See
  /// @ref TopologyProvenance. A sentinel handle reports everything unpublished with enrichment complete.
  [[nodiscard]] TopologyProvenance topology_provenance() const noexcept;

  /// @param callback Completion callback that receives the operation result.
  /// CL-SM-005  -  re-resolves the `AvailableStates` / `AvailableTransitions` topology on demand (e.g. after
  /// an `on_model_change` for this machine). Atomically replaces the cached snapshot shared by every copy.
  /// The handle keeps the topology as its own state, so it uses only Good answers: an Uncertain one is
  /// refused with `Bad_InternalError` (`ReferencesAnswerUncertain` / `ReadAnswerUncertain`). A Bad
  /// `AvailableStates` / `AvailableTransitions` value leaves that list empty.
  void refresh_topology_async(std::function<void(ua::VoidResult)> callback) noexcept;
  /// Synchronously refresh topology. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail on failure.
  void refresh_topology_sync();
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to refresh topology sync without throwing.
  ua::VoidResult try_refresh_topology_sync() noexcept;

protected:
  friend class StateMachineAccessor;
  friend struct ua::client::detail::StateMachineClientTestAccess;

  /// @param state The state.
  /// Returns or updates the finite state machine handle.
  explicit FiniteStateMachineHandle(std::shared_ptr<detail::FiniteStateMachineHandleState> state);

  /// @return The most-derived state typed as its finite level (the concrete object is always at least a
  ///         `FiniteStateMachineHandleState`; null when the handle is a sentinel).
  [[nodiscard]] detail::FiniteStateMachineHandleState* finite_state() const noexcept;
};

/// A copyable value handle to a Part-10 `ProgramStateMachineType` instance (client design section 8.18.1.b).
/// Adds the method pre-flight (`Executable` Attribute) + the local state-method matrix guard around the wire
/// `Call`. See
/// @ref StateMachineHandle for the shared lifetime / interface-locking contract.
/// @ingroup client
class ProgramStateMachineHandle : public FiniteStateMachineHandle
{
public:
  ProgramStateMachineHandle() = default;

  /// CL-SM-007  -  Reads the resolved method node's `Executable` Attribute and delivers the decoded boolean.
  /// @param method The method.
  /// @param callback Completion callback that receives the operation result.
  /// The Attribute is volatile and is not cached. The flag comes with the Read's code (the ServiceResult and
  /// the Attribute's status combined): a Bad code fails it, and a code that is not Good on a null value is
  /// answered without a flag.
  void can_invoke_async(ProgramMethod method, std::function<void(ua::Result<bool>)> callback) noexcept;
  /// @param method The method.
  /// @return The requested value.
  /// Synchronously can invoke. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_can_invoke_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  bool can_invoke_sync(ProgramMethod method);
  /// @param method The method.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to can invoke sync without throwing.
  ua::Result<bool> try_can_invoke_sync(ProgramMethod method) noexcept;

  /// CL-SM-007/008/009  -  invokes @p method with @p args. Sequence:
  ///   1. Read the method's `Executable` Attribute  to  `false`  to  `Bad_NotExecutable` with source
  ///      `client.tier2.state_machine.method_not_executable` (no wire Call).
  ///   2. Read `CurrentState.Id` and check the local state-method matrix (CL-SM-009)  to  mismatch  to
  ///      `Bad_InvalidState` with source `client.tier2.state_machine.state_method_mismatch` (no wire Call).
  ///      Bypassed by @ref skip_local_state_check.
  ///   3. `Call` the method with @p args verbatim; the server `CallMethodResult` is surfaced verbatim (a Bad
  ///      per-call status chains beneath source `client.tier2.state_machine.method_call`). The Result holding
  ///      it carries the ServiceResult and the Method's statusCode combined (`ua::detail::combined_status`),
  ///      so a Good subcode or an Uncertain code the server answers reaches the caller.
  /// Steps 1 and 2 decide whether to Call, so they use only Good answers: an Uncertain `Executable` or
  /// `CurrentState.Id` answer is refused with `Bad_InternalError` (`ReadAnswerUncertain`) and nothing is
  /// called; a Bad `CurrentState.Id` value is no state, which the matrix treats as a mismatch.
  /// @param method Program method to invoke.
  /// @param args Positional method input arguments.
  /// @param callback Completion callback receiving the Call result.
  ///
  /// @note `Stop` routes to the same `Halt` method node but uses a STRICTER local matrix than `Halt`: it is
  /// valid only from Running / Suspended, not from Ready  -  a documented non-Part-10 convenience ("stop a
  /// running/suspended program"). Callers that want Halt-from-Ready must use `ProgramMethod::Halt`.
  void invoke_async(ProgramMethod method, std::vector<ua::Variant> args,
    std::function<void(ua::Result<ua::CallMethodResult>)> callback) noexcept;
  /// @param method The method.
  /// @param args The args.
  /// @return The requested value.
  /// Synchronously invoke. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_invoke_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  ua::CallMethodResult invoke_sync(ProgramMethod method, std::vector<ua::Variant> args);
  /// @param method The method.
  /// @param args The args.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to invoke sync without throwing.
  ua::Result<ua::CallMethodResult> try_invoke_sync(
    ProgramMethod method, std::vector<ua::Variant> args) noexcept;

  /// CL-SM-009 override  -  @return a copy of this handle whose @ref invoke_async bypasses the local
  /// state-method matrix check (use case: a custom subtype whose transitions do not match the standard
  /// Part-10 matrix). The `Executable` pre-flight and the wire `Call` are unchanged.
  [[nodiscard]] ProgramStateMachineHandle skip_local_state_check() const noexcept;

private:
  friend class StateMachineAccessor;
  friend struct ua::client::detail::StateMachineClientTestAccess;

  explicit ProgramStateMachineHandle(
    std::shared_ptr<detail::ProgramStateMachineHandleState> state, bool skipLocalStateCheck = false);

  /// @return The most-derived state typed as its program level (null when the handle is a sentinel).
  [[nodiscard]] detail::ProgramStateMachineHandleState* program_state() const noexcept;

  bool mSkipLocalStateCheck = false;  ///< CL-SM-009 override flag (per-handle, not shared across copies)
};

/// Callback invoked for state machine handle result notifications.
using StateMachineHandleResult = ua::Result<StateMachineHandle>;
/// Callback invoked for finite state machine handle result notifications.
using FiniteStateMachineHandleResult = ua::Result<FiniteStateMachineHandle>;
/// Callback invoked for program state machine handle result notifications.
using ProgramStateMachineHandleResult = ua::Result<ProgramStateMachineHandle>;

// ============================================================================
// 8.18.1.b StateMachineAccessor
// ============================================================================

/// The per-`Connection` tier-2 factory for the StateMachine typed handles (client design section 8.18.1.b). A
/// lightweight, copyable value handle over the same tier-1 wire interface as its parent @ref Connection,
/// reached via `Connection::state_machine_accessor()`. Each factory performs the address-space pre-flight
/// then yields a fully-resolved typed handle. The handle keeps what the pre-flight resolves, so the
/// pre-flight uses only Good answers: an Uncertain Browse or Read answer is refused with `Bad_InternalError`
/// (`ReferencesAnswerUncertain` / `ReadAnswerUncertain`). A Bad `AvailableStates` / `AvailableTransitions`
/// value leaves that list empty and the handle is still built.
///
/// **Cycle-safe (section 9.8.3).** The accessor and every handle hold only `weak_ptr` interface roles
/// (`detail::WireOps` + `detail::SupportOps`), never a `weak_ptr<ConnectionImpl>` (section 8.2A.13).
/// Locks are taken per op and bailed if gone.
/// @ingroup client
class StateMachineAccessor
{
public:
  /// Returns or updates the state machine accessor.
  StateMachineAccessor(const StateMachineAccessor&) = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  StateMachineAccessor& operator=(const StateMachineAccessor&) = default;
  /// Returns or updates the state machine accessor.
  StateMachineAccessor(StateMachineAccessor&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  StateMachineAccessor& operator=(StateMachineAccessor&&) noexcept = default;
  ~StateMachineAccessor() = default;

  /// @param machineId The machine id.
  /// @param callback Completion callback that receives the operation result.
  /// CL-SM-001/002  -  builds a base @ref StateMachineHandle for @p machineId (resolves `CurrentState` +
  /// `LastTransition` + their Properties).
  void state_machine_async(
    ua::NodeId machineId, std::function<void(StateMachineHandleResult)> callback) noexcept;
  /// @param machineId The machineid.
  /// @return The requested value.
  /// Synchronously state machine. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  StateMachineHandle state_machine_sync(ua::NodeId machineId);
  /// @param machineId The machineid.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to state machine sync without throwing.
  ua::Result<StateMachineHandle> try_state_machine_sync(ua::NodeId machineId) noexcept;

  /// @param machineId The machine id.
  /// @param callback Completion callback that receives the operation result.
  /// CL-SM-005/006  -  builds a @ref FiniteStateMachineHandle for @p machineId (base resolution + the
  /// `AvailableStates` / `AvailableTransitions` topology).
  void finite_state_machine_async(
    ua::NodeId machineId, std::function<void(FiniteStateMachineHandleResult)> callback) noexcept;
  /// @param machineId The machineid.
  /// @return The requested value.
  /// Synchronously finite state machine. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  FiniteStateMachineHandle finite_state_machine_sync(ua::NodeId machineId);
  /// @param machineId The machineid.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to finite state machine sync without throwing.
  ua::Result<FiniteStateMachineHandle> try_finite_state_machine_sync(ua::NodeId machineId) noexcept;

  /// @param machineId The machine id.
  /// @param callback Completion callback that receives the operation result.
  /// CL-SM-007/008/009  -  builds a @ref ProgramStateMachineHandle for @p machineId (finite resolution + the
  /// `Start` / `Suspend` / `Resume` / `Halt` / `Reset` method nodes).
  void program_state_machine_async(
    ua::NodeId machineId, std::function<void(ProgramStateMachineHandleResult)> callback) noexcept;
  /// @param machineId The machineid.
  /// @return The requested value.
  /// Synchronously program state machine. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  ProgramStateMachineHandle program_state_machine_sync(ua::NodeId machineId);
  /// @param machineId The machineid.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to program state machine sync without throwing.
  ua::Result<ProgramStateMachineHandle> try_program_state_machine_sync(ua::NodeId machineId) noexcept;

  /// CL-SM-010/011  -  subscribes to `TransitionEventType` events on @p machineId. Builds an `EventFilter`
  /// with an `OfType(TransitionEventType)` WhereClause plus SelectClauses for `Transition` / `FromState` /
  /// `ToState` and their `Id` Properties (CL-SM-010), rides the section 8.13 event backbone reached through
  /// the
  /// `detail::SupportOps` event-subscriber interface, and delivers a @ref TransitionEventNotification to
  /// @p onTransition for events whose `sourceNode == machineId` (the CL-SM-011 demux, captured in the
  /// callback closure at subscribe time). Returns the unified @ref ua::client::MonitoredItem (kind() ==
  /// Event); a gone Connection completes `Bad_ConnectionClosed`. Both callbacks run on the executor.
  /// @param machineId State-machine instance that emits transitions.
  /// @param onTransition Callback receiving matching transition events.
  /// @param callback Completion callback receiving the created MonitoredItem.
  void subscribe_transitions_async(ua::NodeId machineId, TransitionEventCallback onTransition,
    std::function<void(ua::client::MonitoredItemResult)> callback) noexcept;
  /// @param machineId The machineid.
  /// @param onTransition The ontransition.
  /// @return The requested value.
  /// Synchronously subscribe transitions. Blocks the calling thread until the operation completes, so it
  /// must not be called from the executor thread that has to run the completion. A Good subcode on the
  /// answer is not returned; try_subscribe_transitions_sync() returns it.
  /// @throws ua::UaException carrying the status and error detail when the Result is not Good.
  ua::client::MonitoredItem subscribe_transitions_sync(
    ua::NodeId machineId, TransitionEventCallback onTransition);
  /// @param machineId The machineid.
  /// @param onTransition The ontransition.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to subscribe transitions sync without throwing.
  ua::Result<ua::client::MonitoredItem> try_subscribe_transitions_sync(
    ua::NodeId machineId, TransitionEventCallback onTransition) noexcept;

private:
  friend class Connection;
  friend struct ua::client::detail::StateMachineClientTestAccess;

  StateMachineAccessor(std::weak_ptr<detail::WireOps> wireOps, std::weak_ptr<detail::SupportOps> supportOps,
    boost::asio::any_io_executor executor, ua::Logger logger = {});

  std::weak_ptr<detail::WireOps>
    mWireOps;  ///< upward wire interface (section 8.2A.13); locked per op, bail if gone
  std::weak_ptr<detail::SupportOps>
    mSupportOps;  ///< upward support interface (section 8.2A.13); locked per op
  boost::asio::any_io_executor mExecutor;  ///< where handles / boundary failures are delivered
  ua::Logger mLogger;  ///< logs advisory outcomes at the wire boundary (CL-DIAG-002/-015)
};

}  // namespace ua::client

#endif  // UA_STATE_MACHINE_ACCESS_H
