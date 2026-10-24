// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATE_MACHINE_H
#define UA_STATE_MACHINE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_state_variable.h"
#include "ua_transition_variable.h"

namespace ua
{

struct MethodCallContext;

class StateMachine;
using StateMachineResult = Result<StateMachine>;

/// Address-space handle for the OPC UA StateMachineType ObjectType.
/// @ingroup ua_information_model
class StateMachine : public BaseObject
{
public:
  /// Constructs an empty `StateMachine` handle that references no node.
  StateMachine() = default;

  /// Completion callback for create_async: receives the created `StateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(StateMachineResult)>;
  /// Completion callback for attach_async: receives the attached `StateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(StateMachineResult)>;

  /// Creates a new `StateMachineType` instance under `parent`.
  ///
  /// Instantiates the type's full child tree and completes asynchronously. The
  /// callback runs on an unspecified worker thread - do not block it.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param complete     Receives the outcome: on success a `StateMachine` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `StateMachineType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_async
  static StateMachineResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `StateMachineType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `StateMachine` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static StateMachine create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `StateMachineType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `StateMachine` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `StateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static StateMachineResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `StateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `StateMachine` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static StateMachine attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `StateVariable` handle for the `CurrentState` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_current_state_sync, current_state_sync
  void current_state_async(std::function<void(StateVariableResult)> complete) const noexcept;
  /// Attaches a typed `StateVariable` handle for the `CurrentState` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateVariableResult try_current_state_sync() const noexcept;
  /// Attaches a typed `StateVariable` handle for the `CurrentState` child, blocking until complete.
  /// @return The `StateVariable` handle. A Good subcode is not returned; @ref try_current_state_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  StateVariable current_state_sync() const;

  /// Attaches a typed `TransitionVariable` handle for the `LastTransition` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_transition_sync, last_transition_sync
  void last_transition_async(std::function<void(TransitionVariableResult)> complete) const noexcept;
  /// Attaches a typed `TransitionVariable` handle for the `LastTransition` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionVariableResult try_last_transition_sync() const noexcept;
  /// Attaches a typed `TransitionVariable` handle for the `LastTransition` child, blocking until complete.
  /// @return The `TransitionVariable` handle. A Good subcode is not returned; @ref try_last_transition_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TransitionVariable last_transition_sync() const;

private:
  explicit StateMachine(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_STATE_MACHINE_H
