// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Strand-serialized condition/alarm instance: state machine plus address-space integration.
/// @ingroup server

#ifndef UA_CONDITION_INSTANCE_H
#define UA_CONDITION_INSTANCE_H

#include "ua_address_space.h"
#include "ua_base_event.h"
#include "ua_condition_logic.h"
#include <atomic>
#include "ua_dialog_condition_logic.h"
#include "ua_timer.h"
#include "ua_condition_state_snapshot.h"
#include "ua_data_value.h"
#include "ua_sinks.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_node_subtree.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/dispatch.hpp>
#include "ua_string.h"

#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace ua
{

namespace detail
{
/// Holds the Initialize and Attach bodies. Declared here only so @ref ConditionInstance can befriend
/// it; it is defined in the implementation, which is where every coroutine in this SDK lives.
class ConditionLifecycleOperation;
}  // namespace detail

/// A strand-serialized OPC UA condition/alarm instance wrapping a @ref ConditionLogic machine.
///
/// Owns a @ref ConditionLogic and serializes every state transition, event emission, and
/// address-space interaction through a private strand. The public API is callback-canonical:
/// each operation exposes an `*_async` core plus `*_sync` and `try_*_sync` convenience wrappers.
/// The instance is reference-counted via `enable_shared_from_this`; construct it only through
/// @ref create and hold it by `std::shared_ptr`.
///
/// Initialization is two-phase: call @ref create, then @ref initialize_async to integrate with
/// the address space (instantiate nodes, wire variables, register method handlers). When no
/// @ref AddressSpace is supplied to @ref create, the instance runs in logic-only mode: it drives
/// the state machine and emits events but creates no address-space nodes, method handlers, or
/// variable wiring.
/// @ingroup server
class ConditionInstance : public std::enable_shared_from_this<ConditionInstance>
{
public:
  /// Callback signalling completion of an `*_async` operation; the @ref VoidResult carries an
  /// @ref ErrorDetail on failure. Runs on an unspecified worker thread - do not block it.
  using CompleteCallback = std::function<void(VoidResult)>;

  /// Observer invoked when a bound input enters or leaves a communication-failure state.
  /// A bad @p status reports failure and retains its ErrorDetail; Good reports recovery.
  using InputCommunicationObserver =
    std::function<void(NodeId conditionId, NodeId inputNode, StatusCode status)>;

  /// Creates a condition instance and returns a shared owner; the canonical construction path.
  ///
  /// When @p addressSpace holds a value, call @ref initialize_async (or @ref attach_async) after
  /// creation to integrate the condition with the address space. Operations are serialized on a
  /// strand bound to @p executor.
  ///
  /// @param executor       Executor whose strand serializes all state access and async work.
  /// @param logic          The condition/alarm state machine this instance drives. Ownership is
  ///                       transferred; must not be null.
  /// @param conditionId    NodeId of the condition node this instance represents.
  /// @param sourceNode     NodeId of the source that owns the condition (the event SourceNode).
  /// @param sourceName     Human-readable source name reported on emitted events.
  /// @param eventSink      Sink that receives emitted condition/branch/audit events; held weakly,
  ///                       so the sink may outlive or predecease this instance safely.
  /// @param addressSpace   Address space to integrate with, or `std::nullopt` for logic-only mode.
  /// @param typeDefinition NodeId of the condition type to instantiate; defaults to an empty
  ///                       NodeId.
  /// @param inputCommunicationObserver Invoked when the bound input enters or leaves a
  ///                       communication-failure state, with this condition's id, the input node,
  ///                       and the status: a bad status reports the failure and retains its
  ///                       @ref ErrorDetail, Good reports recovery. Reached only once an input
  ///                       node has been bound - a condition with no input never notifies - and
  ///                       defaults to empty, in which case the state is tracked but not reported.
  /// @return A shared owner of the new instance.
  static std::shared_ptr<ConditionInstance> create(boost::asio::any_io_executor executor,
    std::unique_ptr<ConditionLogic> logic, NodeId conditionId, NodeId sourceNode, String sourceName,
    std::weak_ptr<EventSink> eventSink, std::optional<AddressSpace> addressSpace = std::nullopt,
    NodeId typeDefinition = NodeId{}, InputCommunicationObserver inputCommunicationObserver = {});

  ~ConditionInstance() = default;

  /// Not copyable: the instance owns strand-serialized state and a unique @ref ConditionLogic.
  ConditionInstance(const ConditionInstance&) = delete;
  ConditionInstance& operator=(const ConditionInstance&) = delete;
  /// Not movable: shared owners reference the instance by address via `shared_from_this`.
  ConditionInstance(ConditionInstance&&) = delete;
  ConditionInstance& operator=(ConditionInstance&&) = delete;

  // --- Initialization (address space integration) ---

  /// Integrates the condition into the address space, completing asynchronously.
  ///
  /// Instantiates the condition nodes, wires its variables, registers method handlers, and creates
  /// the HasCondition reference from the source. Work is posted to the instance's strand. A no-op
  /// (completing successfully) when no @ref AddressSpace was supplied to @ref create.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see initialize_sync, try_initialize_sync, attach_async
  void initialize_async(CompleteCallback callback);

  /// Integrates the condition into the address space, blocking until complete.
  /// @throws UaException if initialization fails.
  /// @see initialize_async, try_initialize_sync
  void initialize_sync();

  /// Integrates the condition into the address space, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see initialize_async, initialize_sync
  VoidResult try_initialize_sync() noexcept;

  // --- Attach (wrap existing nodes) ---

  /// Attaches to a pre-existing condition node in the address space, completing asynchronously.
  ///
  /// Reads the node's initial state, wires its variables, and registers method handlers, but does
  /// not instantiate new nodes - the condition node must already exist (for example, imported from
  /// NodeSet XML). Work is posted to the instance's strand. A no-op (completing successfully) when
  /// no @ref AddressSpace was supplied to @ref create.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @pre The condition node identified at @ref create already exists in the address space.
  /// @see attach_sync, try_attach_sync, initialize_async
  void attach_async(CompleteCallback callback);

  /// Attaches to a pre-existing condition node, blocking until complete.
  /// @throws UaException if attachment fails.
  /// @see attach_async, try_attach_sync
  void attach_sync();

  /// Attaches to a pre-existing condition node, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async, attach_sync
  VoidResult try_attach_sync() noexcept;

  // --- Enable/Disable ---

  /// Enables the condition, completing asynchronously.
  ///
  /// Transitions the condition into the enabled state and emits the resulting event(s). Work is
  /// posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see enable_sync, try_enable_sync, disable_async
  void enable_async(CompleteCallback callback);

  /// Enables the condition, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see enable_async, try_enable_sync
  void enable_sync();

  /// Enables the condition, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see enable_async, enable_sync
  VoidResult try_enable_sync() noexcept;

  /// Disables the condition, completing asynchronously.
  ///
  /// Transitions the condition into the disabled state and emits the resulting event(s). Work is
  /// posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see disable_sync, try_disable_sync, enable_async
  void disable_async(CompleteCallback callback);

  /// Disables the condition, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see disable_async, try_disable_sync
  void disable_sync();

  /// Disables the condition, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see disable_async, disable_sync
  VoidResult try_disable_sync() noexcept;

  // --- Activate/Deactivate (for AlarmConditionLogic) ---

  /// Activates the alarm at the given severity, completing asynchronously.
  ///
  /// Drives the active sub-state transition and emits the resulting event(s). Requires the
  /// underlying logic to be an alarm condition. Work is posted to the instance's strand.
  ///
  /// @param severity Alarm severity to report (OPC UA severity scale, 1-1000).
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see activate_sync, try_activate_sync, deactivate_async
  void activate_async(uint16_t severity, CompleteCallback callback);

  /// Activates the alarm at the given severity, blocking until complete.
  /// @param severity Alarm severity to report (OPC UA severity scale, 1-1000).
  /// @throws UaException if the transition fails.
  /// @see activate_async, try_activate_sync
  void activate_sync(uint16_t severity);

  /// Activates the alarm at the given severity, blocking until complete.
  /// @param severity Alarm severity to report (OPC UA severity scale, 1-1000).
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see activate_async, activate_sync
  VoidResult try_activate_sync(uint16_t severity) noexcept;

  /// Deactivates the alarm, completing asynchronously.
  ///
  /// Drives the inactive sub-state transition and emits the resulting event(s). Work is posted to
  /// the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see deactivate_sync, try_deactivate_sync, activate_async
  void deactivate_async(CompleteCallback callback);

  /// Deactivates the alarm, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see deactivate_async, try_deactivate_sync
  void deactivate_sync();

  /// Deactivates the alarm, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see deactivate_async, deactivate_sync
  VoidResult try_deactivate_sync() noexcept;

  // --- Acknowledge/Confirm ---

  /// Acknowledges the condition (or branch) identified by @p eventId, completing asynchronously.
  ///
  /// Applies the Acknowledge transition with the supplied operator comment and emits the resulting
  /// event(s). Work is posted to the instance's strand.
  ///
  /// @param eventId EventId identifying the trunk or branch state to acknowledge.
  /// @param comment Operator comment recorded with the acknowledgement.
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see acknowledge_sync, try_acknowledge_sync, confirm_async
  void acknowledge_async(ByteString eventId, LocalizedText comment, CompleteCallback callback);

  /// Acknowledges the condition (or branch) identified by @p eventId, blocking until complete.
  /// @param eventId EventId identifying the trunk or branch state to acknowledge.
  /// @param comment Operator comment recorded with the acknowledgement.
  /// @throws UaException if the transition fails.
  /// @see acknowledge_async, try_acknowledge_sync
  void acknowledge_sync(ByteString eventId, LocalizedText comment);

  /// Acknowledges the condition (or branch) identified by @p eventId, blocking until complete.
  /// @param eventId EventId identifying the trunk or branch state to acknowledge.
  /// @param comment Operator comment recorded with the acknowledgement.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see acknowledge_async, acknowledge_sync
  VoidResult try_acknowledge_sync(ByteString eventId, LocalizedText comment) noexcept;

  /// Confirms the condition (or branch) identified by @p eventId, completing asynchronously.
  ///
  /// Applies the Confirm transition with the supplied operator comment and emits the resulting
  /// event(s). Work is posted to the instance's strand.
  ///
  /// @param eventId EventId identifying the trunk or branch state to confirm.
  /// @param comment Operator comment recorded with the confirmation.
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see confirm_sync, try_confirm_sync, acknowledge_async
  void confirm_async(ByteString eventId, LocalizedText comment, CompleteCallback callback);

  /// Confirms the condition (or branch) identified by @p eventId, blocking until complete.
  /// @param eventId EventId identifying the trunk or branch state to confirm.
  /// @param comment Operator comment recorded with the confirmation.
  /// @throws UaException if the transition fails.
  /// @see confirm_async, try_confirm_sync
  void confirm_sync(ByteString eventId, LocalizedText comment);

  /// Confirms the condition (or branch) identified by @p eventId, blocking until complete.
  /// @param eventId EventId identifying the trunk or branch state to confirm.
  /// @param comment Operator comment recorded with the confirmation.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see confirm_async, confirm_sync
  VoidResult try_confirm_sync(ByteString eventId, LocalizedText comment) noexcept;

  // --- Add comment ---

  /// Adds an operator comment to the condition or branch by @p eventId, completing asynchronously.
  ///
  /// Records the comment without changing the acknowledged/confirmed state and emits the resulting
  /// event(s). Work is posted to the instance's strand.
  ///
  /// @param eventId EventId identifying the trunk or branch state to annotate.
  /// @param comment Operator comment to record.
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see add_comment_sync, try_add_comment_sync
  void add_comment_async(ByteString eventId, LocalizedText comment, CompleteCallback callback);

  /// Adds an operator comment to the condition (or branch) identified by @p eventId, blocking.
  /// @param eventId EventId identifying the trunk or branch state to annotate.
  /// @param comment Operator comment to record.
  /// @throws UaException if the operation fails.
  /// @see add_comment_async, try_add_comment_sync
  void add_comment_sync(ByteString eventId, LocalizedText comment);

  /// Adds an operator comment to the condition (or branch) identified by @p eventId, blocking.
  /// @param eventId EventId identifying the trunk or branch state to annotate.
  /// @param comment Operator comment to record.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see add_comment_async, add_comment_sync
  VoidResult try_add_comment_sync(ByteString eventId, LocalizedText comment) noexcept;

  // --- Client-call entry points (standard Condition methods) ---
  //
  // These mirror the standard OPC UA Condition methods invoked by clients via the
  // Call service. They run the operation AND emit the corresponding audit event -
  // the single source of truth shared by both the per-instance method-node handlers
  // (build_register_descriptors) and the NS0 type method-node handlers registered by
  // Conditions::register_condition_methods. The per-operation outcome rides inside the
  // CallMethodResult per OPC 10000-4 5.11.2; the outer CallResult stays Good unless a
  // service-internal failure occurred. @p userId is recorded as the ClientUserId on the
  // emitted state and audit event.

  /// Enables the condition (client Enable method) and emits an audit event.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_enable_async(String userId, CallMethodCompleteCallback complete);

  /// Disables the condition (client Disable method) and emits an audit event.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_disable_async(String userId, CallMethodCompleteCallback complete);

  /// Adds an operator comment (client AddComment method) and emits an audit event.
  /// @param eventId  EventId identifying the trunk or branch state to annotate.
  /// @param comment  Operator comment to record.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_add_comment_async(
    ByteString eventId, LocalizedText comment, String userId, CallMethodCompleteCallback complete);

  /// Acknowledges the condition (client Acknowledge method) and emits an audit event.
  /// @param eventId  EventId identifying the trunk or branch state to acknowledge.
  /// @param comment  Operator comment recorded with the acknowledgement.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_acknowledge_async(
    ByteString eventId, LocalizedText comment, String userId, CallMethodCompleteCallback complete);

  /// Confirms the condition (client Confirm method) and emits an audit event.
  /// @param eventId  EventId identifying the trunk or branch state to confirm.
  /// @param comment  Operator comment recorded with the confirmation.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_confirm_async(
    ByteString eventId, LocalizedText comment, String userId, CallMethodCompleteCallback complete);

  /// Shelves the alarm until it is explicitly unshelved (client OneShotShelve method) and emits an
  /// audit event.
  ///
  /// The `call_*` form of the shelving transitions exists so a Client can reach them by naming the
  /// CONDITION: OPC 10000-9 5.8.17.2/5.8.17.4/5.8.17.6 require every Server to accept ConditionId as
  /// the ObjectId, because a Server need not expose Condition instances in its AddressSpace at all,
  /// leaving ConditionId as the only handle a Client is guaranteed to hold.
  ///
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_one_shot_shelve_async(String userId, CallMethodCompleteCallback complete);

  /// Shelves the alarm for @p durationMs (client TimedShelve method) and emits an audit event.
  /// @param durationMs Shelving duration in milliseconds.
  /// @param userId     ClientUserId attributed to the call (may be empty).
  /// @param complete   Receives the @ref CallResult exactly once. Never throws.
  /// @see call_one_shot_shelve_async for why the ConditionId-addressed form exists.
  void call_timed_shelve_async(double durationMs, String userId, CallMethodCompleteCallback complete);

  /// Returns the alarm to the Unshelved state (client Unshelve method) and emits an audit event.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  /// @see call_one_shot_shelve_async for why the ConditionId-addressed form exists.
  void call_unshelve_async(String userId, CallMethodCompleteCallback complete);

  /// Suppresses the alarm (client Suppress method) and emits an audit event.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_suppress_async(String userId, CallMethodCompleteCallback complete);

  /// Clears suppression (client Unsuppress method) and emits an audit event.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_unsuppress_async(String userId, CallMethodCompleteCallback complete);

  /// Silences the alarm (client Silence method) and emits an audit event.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  void call_silence_async(String userId, CallMethodCompleteCallback complete);

  /// Takes the alarm out of service (client RemoveFromService method) and emits an audit event.
  ///
  /// Refused with Bad_MethodInvalid on an alarm that exposes no OutOfServiceState, which OPC 10000-9
  /// 5.8.12 requires of the instance rather than of the Method node.
  ///
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  /// @see call_one_shot_shelve_async for why the ConditionId-addressed form exists.
  void call_remove_from_service_async(String userId, CallMethodCompleteCallback complete);

  /// Returns the alarm to service (client PlaceInService method) and emits an audit event.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  /// @see call_one_shot_shelve_async for why the ConditionId-addressed form exists.
  void call_place_in_service_async(String userId, CallMethodCompleteCallback complete);

  /// Resets a latched alarm (client Reset method) and emits an audit event.
  /// @param userId   ClientUserId attributed to the call (may be empty).
  /// @param complete Receives the @ref CallResult exactly once. Never throws.
  /// @see call_one_shot_shelve_async for why the ConditionId-addressed form exists.
  void call_reset_async(String userId, CallMethodCompleteCallback complete);

  // --- Shelving ---

  /// Shelves the alarm for a fixed duration, completing asynchronously.
  ///
  /// Enters the TimedShelved sub-state and arms a timer that automatically unshelves the alarm when
  /// @p durationMs elapses. Work is posted to the instance's strand.
  ///
  /// @param durationMs Shelving duration in milliseconds.
  /// @param callback   Receives a @ref VoidResult that is good or carries an @ref ErrorDetail on failure.
  /// Never throws.
  /// @see timed_shelve_sync, try_timed_shelve_sync, one_shot_shelve_async, unshelve_async
  void timed_shelve_async(double durationMs, CompleteCallback callback);

  /// Shelves the alarm for a fixed duration, blocking until complete.
  /// @param durationMs Shelving duration in milliseconds.
  /// @throws UaException if the transition fails.
  /// @see timed_shelve_async, try_timed_shelve_sync
  void timed_shelve_sync(double durationMs);

  /// Shelves the alarm for a fixed duration, blocking until complete.
  /// @param durationMs Shelving duration in milliseconds.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see timed_shelve_async, timed_shelve_sync
  VoidResult try_timed_shelve_sync(double durationMs) noexcept;

  /// One-shot-shelves the alarm until its next state change, completing asynchronously.
  ///
  /// Enters the OneShotShelved sub-state; the alarm unshelves automatically on its next active
  /// transition. Work is posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see one_shot_shelve_sync, try_one_shot_shelve_sync, timed_shelve_async, unshelve_async
  void one_shot_shelve_async(CompleteCallback callback);

  /// One-shot-shelves the alarm until its next state change, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see one_shot_shelve_async, try_one_shot_shelve_sync
  void one_shot_shelve_sync();

  /// One-shot-shelves the alarm until its next state change, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see one_shot_shelve_async, one_shot_shelve_sync
  VoidResult try_one_shot_shelve_sync() noexcept;

  /// Unshelves the alarm, completing asynchronously.
  ///
  /// Returns the alarm to the Unshelved sub-state and cancels any pending shelving timer. Work is
  /// posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see unshelve_sync, try_unshelve_sync, timed_shelve_async, one_shot_shelve_async
  void unshelve_async(CompleteCallback callback);

  /// Unshelves the alarm, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see unshelve_async, try_unshelve_sync
  void unshelve_sync();

  /// Unshelves the alarm, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see unshelve_async, unshelve_sync
  VoidResult try_unshelve_sync() noexcept;

  // --- Suppress / Out-of-service ---

  /// Suppresses the alarm, completing asynchronously.
  ///
  /// Sets the SuppressedState to suppressed, hiding the alarm from clients while leaving it active.
  /// Work is posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see suppress_sync, try_suppress_sync, unsuppress_async
  void suppress_async(CompleteCallback callback);

  /// Suppresses the alarm, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see suppress_async, try_suppress_sync
  void suppress_sync();

  /// Suppresses the alarm, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see suppress_async, suppress_sync
  VoidResult try_suppress_sync() noexcept;

  /// Removes suppression from the alarm, completing asynchronously.
  ///
  /// Clears the SuppressedState. Work is posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see unsuppress_sync, try_unsuppress_sync, suppress_async
  void unsuppress_async(CompleteCallback callback);

  /// Removes suppression from the alarm, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see unsuppress_async, try_unsuppress_sync
  void unsuppress_sync();

  /// Removes suppression from the alarm, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see unsuppress_async, unsuppress_sync
  VoidResult try_unsuppress_sync() noexcept;

  /// Marks the alarm out of service, completing asynchronously.
  ///
  /// Sets the OutOfServiceState to out-of-service. Work is posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see remove_from_service_sync, try_remove_from_service_sync, place_in_service_async
  void remove_from_service_async(CompleteCallback callback);

  /// Marks the alarm out of service, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see remove_from_service_async, try_remove_from_service_sync
  void remove_from_service_sync();

  /// Marks the alarm out of service, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see remove_from_service_async, remove_from_service_sync
  VoidResult try_remove_from_service_sync() noexcept;

  /// Returns the alarm to service, completing asynchronously.
  ///
  /// Clears the OutOfServiceState. Work is posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see place_in_service_sync, try_place_in_service_sync, remove_from_service_async
  void place_in_service_async(CompleteCallback callback);

  /// Returns the alarm to service, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see place_in_service_async, try_place_in_service_sync
  void place_in_service_sync();

  /// Returns the alarm to service, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see place_in_service_async, place_in_service_sync
  VoidResult try_place_in_service_sync() noexcept;

  // --- Silence ---

  /// Silences the alarm's audible/visible annunciation, completing asynchronously.
  ///
  /// Sets the SilenceState to silenced without altering the alarm's active state. Work is posted to
  /// the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see silence_sync, try_silence_sync
  void silence_async(CompleteCallback callback);

  /// Silences the alarm's annunciation, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see silence_async, try_silence_sync
  void silence_sync();

  /// Silences the alarm's annunciation, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see silence_async, silence_sync
  VoidResult try_silence_sync() noexcept;

  // --- Reset (latched alarms) ---

  /// Resets a latched alarm, completing asynchronously.
  ///
  /// Clears the latched state of an alarm whose LatchedState has latched, allowing it to return to
  /// inactive once the underlying condition clears. Work is posted to the instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see reset_sync, try_reset_sync
  void reset_async(CompleteCallback callback);

  /// Resets a latched alarm, blocking until complete.
  /// @throws UaException if the transition fails.
  /// @see reset_async, try_reset_sync
  void reset_sync();

  /// Resets a latched alarm, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see reset_async, reset_sync
  VoidResult try_reset_sync() noexcept;

  // --- Dialog respond ---

  /// Responds to a dialog condition with the selected option, completing asynchronously.
  ///
  /// Applies the operator's response to a @ref DialogConditionLogic prompt. Work is posted to the
  /// instance's strand.
  ///
  /// @param selectedResponse Zero-based index of the chosen response option.
  /// @param callback         Receives a @ref VoidResult that is good or carries an
  ///                         @ref ErrorDetail on failure. Never throws.
  /// @see respond_sync, try_respond_sync
  void respond_async(int32_t selectedResponse, CompleteCallback callback);

  /// Responds to a dialog condition with the selected option, blocking until complete.
  /// @param selectedResponse Zero-based index of the chosen response option.
  /// @throws UaException if the response is rejected.
  /// @see respond_async, try_respond_sync
  void respond_sync(int32_t selectedResponse);

  /// Responds to a dialog condition with the selected option, blocking until complete.
  /// @param selectedResponse Zero-based index of the chosen response option.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see respond_async, respond_sync
  VoidResult try_respond_sync(int32_t selectedResponse) noexcept;

  // --- Input binding ---

  /// Binds the alarm to an input variable for automatic evaluation, completing asynchronously.
  ///
  /// Starts a periodic sampling timer that reads @p inputNode and feeds each value to the alarm's
  /// input evaluation, driving limit-violation transitions automatically. Requires an alarm
  /// condition and an @ref AddressSpace. Work is posted to the instance's strand.
  ///
  /// @param inputNode          NodeId of the variable to sample.
  /// @param samplingIntervalMs Sampling period in milliseconds.
  /// @param callback           Receives a @ref VoidResult that is good or carries an
  ///                           @ref ErrorDetail on failure. Never throws.
  /// @see bind_input_sync, try_bind_input_sync, unbind_input_async
  void bind_input_async(NodeId inputNode, double samplingIntervalMs, CompleteCallback callback);

  /// Binds the alarm to an input variable for automatic evaluation, blocking until complete.
  /// @param inputNode          NodeId of the variable to sample.
  /// @param samplingIntervalMs Sampling period in milliseconds.
  /// @throws UaException if binding fails.
  /// @see bind_input_async, try_bind_input_sync
  void bind_input_sync(NodeId inputNode, double samplingIntervalMs);

  /// Binds the alarm to an input variable for automatic evaluation, blocking until complete.
  /// @param inputNode          NodeId of the variable to sample.
  /// @param samplingIntervalMs Sampling period in milliseconds.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see bind_input_async, bind_input_sync
  VoidResult try_bind_input_sync(NodeId inputNode, double samplingIntervalMs) noexcept;

  /// Unbinds the input variable and cancels its sampling timer, completing asynchronously.
  ///
  /// A no-op (completing successfully) when no input is bound. Work is posted to the instance's
  /// strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see bind_input_async
  void unbind_input_async(CompleteCallback callback);

  // --- Refresh event ---

  /// Callback receiving the events built by @ref build_refresh_events_async; ownership of the
  /// returned @ref BaseEvent objects transfers to the callee. Runs on an unspecified worker thread.
  using BuildEventsCallback = std::function<void(std::vector<std::unique_ptr<BaseEvent>>)>;

  /// Builds refresh events for the current condition state, completing asynchronously.
  ///
  /// Produces one event for the trunk plus one per active branch, as required when servicing a
  /// ConditionRefresh. Work is posted to the instance's strand and the events are delivered to
  /// @p callback, which takes ownership.
  ///
  /// @param callback Receives the built events; ownership transfers to the callee.
  void build_refresh_events_async(BuildEventsCallback callback);

  // --- Close ---

  /// Closes the condition, completing asynchronously.
  ///
  /// Tears down the instance's state machine, cancels timers, and releases address-space
  /// integration. After close the instance accepts no further operations. Work is posted to the
  /// instance's strand.
  ///
  /// @param callback Receives a @ref VoidResult - good, or an @ref ErrorDetail on failure. Never throws.
  /// @see close_sync, try_close_sync
  void close_async(CompleteCallback callback);

  /// Closes the condition, blocking until complete.
  /// @throws UaException if closing fails.
  /// @see close_async, try_close_sync
  void close_sync();

  /// Closes the condition, blocking until complete.
  /// @return A @ref VoidResult holding an @ref ErrorDetail on failure. Never throws.
  /// @see close_async, close_sync
  VoidResult try_close_sync() noexcept;

  // --- Thread-safe accessors ---

  /// Returns a thread-safe immutable snapshot of the current condition state.
  ///
  /// Callable from any thread or strand without external synchronization. The returned snapshot is
  /// a fixed view of the state at the time of the call; later transitions produce new snapshots.
  ///
  /// @return Shared owner of the immutable state snapshot.
  std::shared_ptr<const ConditionStateSnapshot> snapshot() const;

  /// Returns the NodeId of the condition node. Immutable after construction; callable from any
  /// thread.
  /// @return The NodeId of the condition node.
  const NodeId& condition_id() const;

  /// Returns the NodeId of the condition's source node. Immutable after construction; callable from
  /// any thread.
  /// @return The NodeId of the condition's source node.
  const NodeId& source_node() const;

private:
  /// A Variable whose value reader the Condition bound. The accessor holds the Node, and with it the
  /// ExternalValueSource the Node's probe gave, which is valid only for the Node's lifetime.
  struct VariableWiring
  {
    NodeAccessor node;
    std::function<DataValue()> reader;
  };

  /// Descriptor for one wiring step. Each entry corresponds to one of the
  /// browse-name lookups in the legacy wire_condition_variables() pre-flip body.
  struct WireDescriptor
  {
    enum class Kind
    {
      TwoState,
      ConditionVariable,
      DirectChild,
      NestedValue
    };
    Kind kind{Kind::TwoState};
    QualifiedName browseName;
    // For TwoState
    std::function<LocalizedText()> currentStateReader;
    std::function<bool()> idReader;
    std::function<DateTime()> transitionTimeReader;
    // For ConditionVariable
    std::function<DataValue()> valueReader;
    std::function<DateTime()> timestampReader;
    // For DirectChild - uses valueReader and may clear CurrentRead for a configured-but-unavailable
    // limit Property.
    bool readable{true};
    // For NestedValue - resolves nestedPath segment-by-segment from the condition node (following the
    // matching nestedReferenceTypes) and installs valueReader on the final node. Used for nodes nested
    // below a sub-object, e.g. LimitState/CurrentState and LimitState/CurrentState/Id on a
    // FiniteStateMachine. nestedReferenceTypes[i] is the reference type to follow into nestedPath[i].
    std::vector<QualifiedName> nestedPath;
    std::vector<NodeId> nestedReferenceTypes;
  };

  /// Descriptor for one method-handler registration. Each entry corresponds
  /// to one of the entries in the legacy register_methods() pre-flip body.
  struct RegisterDescriptor
  {
    QualifiedName browseName;
    /// If true, the host descriptor is registered under ShelvingState
    /// (resolved at flow runtime); otherwise under the condition node.
    bool underShelvingState{false};
    /// True if registration failure must abort the flow (Enable/Disable/AddComment);
    /// false otherwise.
    bool fatalOnFailure{false};
    /// Factory: builds the MethodCallSource::CallHandler closure for this method.
    /// Captures `[me = weak_from_this()]` internally; closure body locks me at entry.
    std::function<MethodCallSource::CallHandler(std::weak_ptr<ConditionInstance>)> handlerFactory;
  };

  /// Per-flow heap-state for initialize_async.
  struct InitializeState
  {
    std::vector<WireDescriptor> wireDescriptors;
    std::vector<RegisterDescriptor> registerDescriptors;
    /// Cached source NodeAccessor across the HasCondition / notifier-hierarchy steps.
    std::optional<NodeAccessor> sourceAccessor;
    NodeId notifierReferenceType;
    CompleteCallback onComplete;
  };

  /// Per-request state for attach_async: what the body needs, and the answer it owes.
  struct AttachState
  {
    /// Descriptor for one read-initial-state step. The reader call shape is one
    /// of: read_bool_child(parent, child) -> std::optional<bool>, or
    /// read_uint16_property(name) -> std::optional<uint16_t>.
    struct StateBitReadDescriptor
    {
      /// Which reader shape this descriptor drives, selecting the apply callback to invoke.
      enum class Kind
      {
        BoolChild,  ///< Read a bool-valued child variable located under a named parent.
        Uint16Property  ///< Read a UInt16-valued property by its browse name.
      };
      Kind kind;  ///< Reader shape for this bit; selects @ref applyBool vs @ref applyUint16.
      std::string parentBrowseName;  ///< only used for BoolChild
      std::string childBrowseName;  ///< for BoolChild this is the child; for Uint16Property the property name
      /// Stores the read bool child onto the condition; invoked only when @ref kind is BoolChild.
      /// The optional is empty when the child is absent or unreadable, leaving the bit at its default.
      std::function<void(ConditionInstance&, std::optional<bool>)> applyBool;
      /// Stores the read UInt16 property onto the condition; invoked only when @ref kind is
      /// Uint16Property. The optional is empty when the property is absent or unreadable.
      std::function<void(ConditionInstance&, std::optional<uint16_t>)> applyUint16;
    };

    std::vector<StateBitReadDescriptor> stateBitReads;

    std::vector<WireDescriptor> wireDescriptors;
    std::vector<RegisterDescriptor> registerDescriptors;
    std::optional<NodeAccessor> sourceAccessor;
    NodeId notifierReferenceType;
    CompleteCallback onComplete;
  };

  ConditionInstance(boost::asio::any_io_executor executor, std::unique_ptr<ConditionLogic> logic,
    NodeId conditionId, NodeId sourceNode, String sourceName, std::weak_ptr<EventSink> eventSink,
    std::optional<AddressSpace> addressSpace, NodeId typeDefinition,
    InputCommunicationObserver inputCommunicationObserver);

  /// Apply a state transition result on the strand.
  void apply_transition(const ConditionStateTransition& transition);

  /// Execute timer start/cancel commands from a state transition.
  void process_timer_commands(const std::vector<TimerCommand>& commands);

  /// Build and emit a condition event, capturing the assigned EventId.
  void emit_condition_event();

  /// Emit a branch event (new branch, ack/confirm update, or deletion).
  void emit_branch_event(const BranchEventData& branchData);

  /// Update the snapshot from the current logic state via build_event.
  void update_snapshot();

  /// Notify all wired AS variables that their values may have changed.
  void notify_wired_variables();

  /// Emit an audit event for a condition method call.
  /// Stamp the fields every Condition audit Event shares and emit it.
  ///
  /// @param auditEvent The audit payload, already carrying whatever its own type adds.
  /// @param sourceName What drove the change, in the OPC 10000-9 section 5.10 convention: `Method/<name>`
  ///                   for a client Method call, and a non-Method description such as
  ///                   `Internal/Enable` for a transition the server made itself. It is the field an
  ///                   auditor filters on, and for `AuditConditionEnableEventType` -- shared by
  ///                   Enable and Disable -- it is the only field that says which of the two happened.
  void emit_audit_event(BaseEvent& auditEvent, std::string_view sourceName);

  /// Differentiates "logic returned bad transition" (per-op outcome - wire-level
  /// CallMethodResult per OPC UA Part 4 5.11.2) from "logic threw" (service-
  /// internal failure that should surface as a bad outer CallResult per the
  /// passive-forwarding invariant).
  enum class MethodCompletion
  {
    Returned,  // logic returned a transition (good or bad status)
    Threw,  // logic threw - exception caught + converted to StatusCode
  };

  using MethodCompleteCallback = std::function<void(MethodCompletion, VoidResult)>;

  /// Run a client-triggered method on the strand: set ClientUserId on the logic,
  /// execute the operation, and apply the resulting transition.
  /// Used by method handlers registered in build_register_descriptors() - NOT by the public *_async API.
  /// Both the operation and the completion are templated (not taken as std::function) so the caller's
  /// callables are posted straight through post_borrowing without a type-erasing std::function -
  /// avoiding the heap buffers clangsa mis-reads as leaks (cplusplus.NewDeleteLeaks). Defined
  /// out-of-line, instantiated only within this TU.
  ///
  /// @p eventId is the EventId the caller presented, for the operations that take one
  /// (Acknowledge / Confirm / AddComment); @p hasEventId distinguishes those operations from
  /// methods whose empty ByteString is not an EventId. Both are carried by value because the
  /// transition outcome is built after a strand hop.
  template<class Op, class MethodCompleteCb>
  void run_method_on_strand(
    String clientUserId, ByteString eventId, bool hasEventId, Op&& operation, MethodCompleteCb&& callback);

  /// If an input variable is bound and an address space is available,
  /// post a fire-and-forget read+evaluate to the strand.
  /// Called on the strand after a successful enable to handle pre-existing limit violations.
  void evaluate_input_if_bound();

  /// Apply one input read outcome on the strand, including communication state transitions.
  void handle_input_sample(DataValueResult readResult);

  /// Notify the manager that this condition's current bound input failed or recovered.
  void notify_input_communication_state(StatusCode status);

  // --- Initialize flow continuations (run on mStrand) ---

  /// Instantiates the condition object. The body awaits this as its first step.
  void instantiate_condition_object_async(std::function<void(NodeSubtreeResult)> completion);
  void complete_initialize_success();
  void fail_initialize(VoidResult bad);

  // --- Attach flow continuations (run on mStrand) ---

  void complete_attach_success();
  void fail_attach(VoidResult bad);

  // --- Wire-loop helpers (shared by both flows) ---

  /// Dispatch the wire descriptor at the current cursor on the active flow.
  /// `onStepComplete` is called (sometimes multiple times for sub-steps). A Variable the Condition does not
  /// have is skipped, since an Optional child need not exist; one that exists and cannot be wired is
  /// recorded by `refuse_wiring`.
  void dispatch_wire_descriptor(const WireDescriptor& desc, std::function<void()> onStepComplete);
  /// Records @p refusal as the wiring's first, when it is bad and none is recorded. On the strand.
  void refuse_wiring(VoidResult refusal);

  /// Resolve a nested browse path from the condition node segment-by-segment (following
  /// `referenceTypes[i]` into `path[i]`) and, on reaching the leaf, install `valueReader` as the
  /// node's read handler. Best-effort: any unresolved segment or non-value node skips silently.
  /// Each async hop re-posts to the strand. Used by the NestedValue wire kind (e.g. LimitState).
  void resolve_nested_and_install(std::vector<QualifiedName> path, std::vector<NodeId> referenceTypes,
    std::size_t index, NodeId parent, std::function<DataValue()> valueReader,
    std::function<void()> onComplete);

  /// Install `valueReader` as the read handler on the variable node `variableId` (best-effort).
  void install_value_read_handler(
    NodeId variableId, std::function<DataValue()> valueReader, std::function<void()> onComplete);

  /// Dispatch the register descriptor at the current cursor on the active flow.
  /// `onComplete` is invoked with the address-space-side resolve result.
  void dispatch_register_descriptor(
    const RegisterDescriptor& desc, NodeId parentNode, std::function<void(VoidResult)> onComplete);

  /// Build the wire descriptor list (15 entries) using `mSnapshot` for closure capture.
  std::vector<WireDescriptor> build_wire_descriptors() const;

  /// Common method-handler-inner trampoline for all 15 register-method
  /// descriptors and the type-node call_*_async entry points. Locks the weak
  /// instance, dispatches the operation through run_method_on_strand, and emits
  /// the audit event on success. Templated on the args tuple type so each
  /// MethodAdapter<Args> can share a single implementation.
  ///
  /// @p userId is read synchronously by the caller (e.g. from the borrowed
  /// MethodCallContext, whose lifetime ends when the handler returns) and passed
  /// by value - the context pointer must never be dereferenced after a strand hop.
  template<typename Args, typename OperationFn, typename AuditEmitFn>
  static void run_method_handler_inner(std::weak_ptr<ConditionInstance> me, const NodeId& objectId,
    const Args& args, String userId, CallMethodCompleteCallback complete, OperationFn operation,
    AuditEmitFn auditEmit);

  /// Build the register-method descriptor list. The condition-level methods are
  /// emitted with `underShelvingState == false`; the three shelving methods are
  /// emitted with `underShelvingState == true` to be resolved under ShelvingState.
  std::vector<RegisterDescriptor> build_register_descriptors() const;

  /// The Initialize and Attach bodies live in the implementation, so that no coroutine type appears
  /// in this public header. @see ua::detail::ConditionLifecycleOperation
  friend class ua::detail::ConditionLifecycleOperation;

  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  std::unique_ptr<ConditionLogic> mLogic;
  std::shared_ptr<ConditionStateSnapshot> mSnapshot;
  /// Time and ReceiveTime of the last Condition event emitted; the Condition node's Time and ReceiveTime
  /// report these, as its EventId reports that event's id. Strand-only. Unset before the first event.
  std::optional<DateTime> mLastEmittedTime;
  DateTime mLastEmittedReceiveTime{};
  /// Immutable snapshot of the current condition state as an event payload, refreshed on every
  /// transition by `update_snapshot()`. Node value-readers resolve their value through this payload's
  /// `resolve_field()` - the SAME resolver the emitted event uses - so a direct Read of any field equals
  /// the value carried by the event, by construction. Atomic: written on the strand, loaded by readers
  /// running on the read thread.
  std::atomic<std::shared_ptr<const BaseEvent>> mEventState;
  NodeId mConditionId;
  NodeId mSourceNode;
  String mSourceName;
  std::weak_ptr<EventSink> mEventSink;

  // --- AS integration members ---
  std::optional<AddressSpace> mAddressSpace;
  std::optional<NodeSubtree> mOwnedSubtree;
  NodeId mTypeDefinition;
  /// Logger for this instance's async continuations, sourced from mAddressSpace at construction (a
  /// no-op Logger for logic-only instances with no address space). A value handle that survives
  /// teardown; passed into the post helpers at each call site.
  ua::Logger mLogger;
  std::vector<VariableWiring> mWiredVariables;
  /// The first refusal met while wiring a Variable that exists: its namespace offers no value source, or
  /// refuses the source or the AccessLevel write. Initialize and attach fail with it. Strand-serialised.
  std::optional<VoidResult> mWiringRefusal;

  // --- In-flight flow state ---
  std::unique_ptr<InitializeState> mInitializeState;
  std::unique_ptr<AttachState> mAttachState;
  /// Cached ShelvingState NodeId resolved during register-loop traversal.
  /// std::nullopt before resolution; an empty NodeId means "no ShelvingState available".
  std::optional<NodeId> mResolvedShelvingStateId;

  // --- Timer management ---
  Timer mOnDelayTimer;
  Timer mOffDelayTimer;
  Timer mShelveTimer;
  Timer mReAlarmTimer;

  // --- Input binding ---
  NodeId mInputNode;
  Timer mSamplingTimer;
  InputCommunicationObserver mInputCommunicationObserver;
  bool mInputCommunicationFailed{false};
  bool mInputCommunicationEstablished{false};
  bool mWaitingForInitialInput{false};
};

}  // namespace ua

#endif  // !UA_CONDITION_INSTANCE_H
