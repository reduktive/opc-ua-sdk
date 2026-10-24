// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EXCLUSIVE_LIMIT_STATE_MACHINE_H
#define UA_EXCLUSIVE_LIMIT_STATE_MACHINE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_state.h"
#include "ua_transition.h"

namespace ua
{

struct MethodCallContext;

class ExclusiveLimitStateMachine;
using ExclusiveLimitStateMachineResult = Result<ExclusiveLimitStateMachine>;

/// Address-space handle for the OPC UA ExclusiveLimitStateMachineType ObjectType.
/// @ingroup ua_information_model
class ExclusiveLimitStateMachine : public BaseObject
{
public:
  /// Constructs an empty `ExclusiveLimitStateMachine` handle that references no node.
  ExclusiveLimitStateMachine() = default;

  /// Completion callback for create_async: receives the created `ExclusiveLimitStateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ExclusiveLimitStateMachineResult)>;
  /// Completion callback for attach_async: receives the attached `ExclusiveLimitStateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ExclusiveLimitStateMachineResult)>;

  /// Creates a new `ExclusiveLimitStateMachineType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ExclusiveLimitStateMachine` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ExclusiveLimitStateMachineType` instance under `parent`, blocking until complete.  ///
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
  static ExclusiveLimitStateMachineResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ExclusiveLimitStateMachineType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ExclusiveLimitStateMachine` handle. A Good subcode is not returned; @ref
  /// try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ExclusiveLimitStateMachine create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ExclusiveLimitStateMachineType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ExclusiveLimitStateMachine` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ExclusiveLimitStateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ExclusiveLimitStateMachineResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ExclusiveLimitStateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ExclusiveLimitStateMachine` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ExclusiveLimitStateMachine attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `State` handle for the `HighHigh` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_high_high_sync, high_high_sync
  void high_high_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `HighHigh` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_high_high_sync() const noexcept;
  /// Attaches a typed `State` handle for the `HighHigh` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_high_high_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State high_high_sync() const;

  /// Attaches a typed `State` handle for the `High` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_high_sync, high_sync
  void high_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `High` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_high_sync() const noexcept;
  /// Attaches a typed `State` handle for the `High` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_high_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State high_sync() const;

  /// Attaches a typed `State` handle for the `Low` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_low_sync, low_sync
  void low_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `Low` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_low_sync() const noexcept;
  /// Attaches a typed `State` handle for the `Low` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_low_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State low_sync() const;

  /// Attaches a typed `State` handle for the `LowLow` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_low_low_sync, low_low_sync
  void low_low_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `LowLow` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_low_low_sync() const noexcept;
  /// Attaches a typed `State` handle for the `LowLow` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_low_low_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State low_low_sync() const;

  /// Attaches a typed `Transition` handle for the `LowLowToLow` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_low_low_to_low_sync, low_low_to_low_sync
  void low_low_to_low_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `LowLowToLow` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_low_low_to_low_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `LowLowToLow` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_low_low_to_low_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition low_low_to_low_sync() const;

  /// Attaches a typed `Transition` handle for the `LowToLowLow` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_low_to_low_low_sync, low_to_low_low_sync
  void low_to_low_low_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `LowToLowLow` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_low_to_low_low_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `LowToLowLow` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_low_to_low_low_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition low_to_low_low_sync() const;

  /// Attaches a typed `Transition` handle for the `HighHighToHigh` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_high_high_to_high_sync, high_high_to_high_sync
  void high_high_to_high_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `HighHighToHigh` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_high_high_to_high_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `HighHighToHigh` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_high_high_to_high_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition high_high_to_high_sync() const;

  /// Attaches a typed `Transition` handle for the `HighToHighHigh` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_high_to_high_high_sync, high_to_high_high_sync
  void high_to_high_high_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `HighToHighHigh` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_high_to_high_high_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `HighToHighHigh` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_high_to_high_high_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition high_to_high_high_sync() const;

private:
  explicit ExclusiveLimitStateMachine(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_EXCLUSIVE_LIMIT_STATE_MACHINE_H
