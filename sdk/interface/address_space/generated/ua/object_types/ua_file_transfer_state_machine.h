// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_FILE_TRANSFER_STATE_MACHINE_H
#define UA_FILE_TRANSFER_STATE_MACHINE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_initial_state.h"
#include "ua_state.h"
#include "ua_transition.h"

namespace ua
{

struct MethodCallContext;

class FileTransferStateMachine;
using FileTransferStateMachineResult = Result<FileTransferStateMachine>;

/// Address-space handle for the OPC UA FileTransferStateMachineType ObjectType.
/// @ingroup ua_information_model
class FileTransferStateMachine : public BaseObject
{
public:
  /// Constructs an empty `FileTransferStateMachine` handle that references no node.
  FileTransferStateMachine() = default;

  /// Synchronous handler for Reset(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using ResetHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for Reset(): starts the work and completes it through the callback, once, from any
  /// thread.
  using ResetAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `FileTransferStateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(FileTransferStateMachineResult)>;
  /// Completion callback for attach_async: receives the attached `FileTransferStateMachine` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(FileTransferStateMachineResult)>;

  /// Creates a new `FileTransferStateMachineType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `FileTransferStateMachine` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `FileTransferStateMachineType` instance under `parent`, blocking until complete.  ///
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
  static FileTransferStateMachineResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `FileTransferStateMachineType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `FileTransferStateMachine` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static FileTransferStateMachine create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `FileTransferStateMachineType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `FileTransferStateMachine` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `FileTransferStateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static FileTransferStateMachineResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `FileTransferStateMachineType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `FileTransferStateMachine` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static FileTransferStateMachine attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Reset` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_reset_method_sync, reset_method_sync
  void reset_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Reset` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_reset_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Reset` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_reset_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor reset_method_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `Reset` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_reset_handler_sync, set_reset_handler_sync
  void set_reset_handler_async(ResetHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Reset` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_reset_handler_sync(ResetHandler handler) const noexcept;
  /// Registers the synchronous `Reset` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_reset_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_reset_handler_sync(ResetHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Reset` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_reset_handler_sync, set_reset_handler_sync
  void set_reset_handler_async(
    ResetAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Reset` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_reset_handler_sync(ResetAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Reset` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_reset_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_reset_handler_sync(ResetAsyncHandler handler) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `InitialState` handle for the `Idle` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_idle_sync, idle_sync
  void idle_async(std::function<void(InitialStateResult)> complete) const noexcept;
  /// Attaches a typed `InitialState` handle for the `Idle` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  InitialStateResult try_idle_sync() const noexcept;
  /// Attaches a typed `InitialState` handle for the `Idle` child, blocking until complete.
  /// @return The `InitialState` handle. A Good subcode is not returned; @ref try_idle_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  InitialState idle_sync() const;

  /// Attaches a typed `State` handle for the `ReadPrepare` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_read_prepare_sync, read_prepare_sync
  void read_prepare_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `ReadPrepare` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_read_prepare_sync() const noexcept;
  /// Attaches a typed `State` handle for the `ReadPrepare` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_read_prepare_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State read_prepare_sync() const;

  /// Attaches a typed `State` handle for the `ReadTransfer` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_read_transfer_sync, read_transfer_sync
  void read_transfer_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `ReadTransfer` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_read_transfer_sync() const noexcept;
  /// Attaches a typed `State` handle for the `ReadTransfer` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_read_transfer_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State read_transfer_sync() const;

  /// Attaches a typed `State` handle for the `ApplyWrite` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_apply_write_sync, apply_write_sync
  void apply_write_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `ApplyWrite` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_apply_write_sync() const noexcept;
  /// Attaches a typed `State` handle for the `ApplyWrite` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_apply_write_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State apply_write_sync() const;

  /// Attaches a typed `State` handle for the `Error` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_error_sync, error_sync
  void error_async(std::function<void(StateResult)> complete) const noexcept;
  /// Attaches a typed `State` handle for the `Error` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  StateResult try_error_sync() const noexcept;
  /// Attaches a typed `State` handle for the `Error` child, blocking until complete.
  /// @return The `State` handle. A Good subcode is not returned; @ref try_error_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  State error_sync() const;

  /// Attaches a typed `Transition` handle for the `IdleToReadPrepare` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_idle_to_read_prepare_sync, idle_to_read_prepare_sync
  void idle_to_read_prepare_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `IdleToReadPrepare` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_idle_to_read_prepare_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `IdleToReadPrepare` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_idle_to_read_prepare_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition idle_to_read_prepare_sync() const;

  /// Attaches a typed `Transition` handle for the `ReadPrepareToReadTransfer` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_read_prepare_to_read_transfer_sync, read_prepare_to_read_transfer_sync
  void read_prepare_to_read_transfer_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadPrepareToReadTransfer` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_read_prepare_to_read_transfer_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadPrepareToReadTransfer` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref
  /// try_read_prepare_to_read_transfer_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition read_prepare_to_read_transfer_sync() const;

  /// Attaches a typed `Transition` handle for the `ReadTransferToIdle` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_read_transfer_to_idle_sync, read_transfer_to_idle_sync
  void read_transfer_to_idle_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadTransferToIdle` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_read_transfer_to_idle_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadTransferToIdle` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_read_transfer_to_idle_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition read_transfer_to_idle_sync() const;

  /// Attaches a typed `Transition` handle for the `IdleToApplyWrite` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_idle_to_apply_write_sync, idle_to_apply_write_sync
  void idle_to_apply_write_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `IdleToApplyWrite` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_idle_to_apply_write_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `IdleToApplyWrite` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_idle_to_apply_write_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition idle_to_apply_write_sync() const;

  /// Attaches a typed `Transition` handle for the `ApplyWriteToIdle` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_apply_write_to_idle_sync, apply_write_to_idle_sync
  void apply_write_to_idle_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ApplyWriteToIdle` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_apply_write_to_idle_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ApplyWriteToIdle` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_apply_write_to_idle_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition apply_write_to_idle_sync() const;

  /// Attaches a typed `Transition` handle for the `ReadPrepareToError` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_read_prepare_to_error_sync, read_prepare_to_error_sync
  void read_prepare_to_error_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadPrepareToError` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_read_prepare_to_error_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadPrepareToError` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_read_prepare_to_error_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition read_prepare_to_error_sync() const;

  /// Attaches a typed `Transition` handle for the `ReadTransferToError` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_read_transfer_to_error_sync, read_transfer_to_error_sync
  void read_transfer_to_error_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadTransferToError` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_read_transfer_to_error_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ReadTransferToError` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_read_transfer_to_error_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition read_transfer_to_error_sync() const;

  /// Attaches a typed `Transition` handle for the `ApplyWriteToError` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_apply_write_to_error_sync, apply_write_to_error_sync
  void apply_write_to_error_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ApplyWriteToError` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_apply_write_to_error_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ApplyWriteToError` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_apply_write_to_error_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition apply_write_to_error_sync() const;

  /// Attaches a typed `Transition` handle for the `ErrorToIdle` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_error_to_idle_sync, error_to_idle_sync
  void error_to_idle_async(std::function<void(TransitionResult)> complete) const noexcept;
  /// Attaches a typed `Transition` handle for the `ErrorToIdle` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TransitionResult try_error_to_idle_sync() const noexcept;
  /// Attaches a typed `Transition` handle for the `ErrorToIdle` child, blocking until complete.
  /// @return The `Transition` handle. A Good subcode is not returned; @ref try_error_to_idle_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Transition error_to_idle_sync() const;

private:
  explicit FileTransferStateMachine(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_FILE_TRANSFER_STATE_MACHINE_H
