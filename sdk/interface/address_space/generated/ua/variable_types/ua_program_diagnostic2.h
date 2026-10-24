// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PROGRAM_DIAGNOSTIC2_H
#define UA_PROGRAM_DIAGNOSTIC2_H

#include "ua_base_data_variable.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_base_data_variable.h"

namespace ua
{

class ProgramDiagnostic2;
using ProgramDiagnostic2Result = Result<ProgramDiagnostic2>;

/// Address-space handle for the OPC UA ProgramDiagnostic2Type VariableType.
/// @ingroup ua_information_model
class ProgramDiagnostic2 final : public BaseDataVariable
{
public:
  /// Constructs an empty `ProgramDiagnostic2` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  ProgramDiagnostic2() = default;

  /// Completion callback for create_async: receives the new `ProgramDiagnostic2` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ProgramDiagnostic2Result)>;
  /// Completion callback for attach_async: receives the wrapped `ProgramDiagnostic2` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ProgramDiagnostic2Result)>;

  /// Creates a new `ProgramDiagnostic2Type` variable under `parent`.
  ///
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @param complete     Receives the outcome: on success a `ProgramDiagnostic2` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `ProgramDiagnostic2Type` variable under `parent`, blocking until complete.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @return The new handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_async
  static ProgramDiagnostic2Result try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `ProgramDiagnostic2Type` variable under `parent`, blocking until complete.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @return The new `ProgramDiagnostic2` handle. A Good subcode is not returned; @ref try_create_sync
  /// returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ProgramDiagnostic2 create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `ProgramDiagnostic2Type` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `ProgramDiagnostic2` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ProgramDiagnostic2Type` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ProgramDiagnostic2Result try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ProgramDiagnostic2Type` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `ProgramDiagnostic2` handle. A Good subcode is not returned; @ref try_attach_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ProgramDiagnostic2 attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `LastTransitionTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_transition_time_property_sync, last_transition_time_property_sync
  void last_transition_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastTransitionTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_transition_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastTransitionTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_transition_time_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_transition_time_property_sync() const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `BaseDataVariable` handle for the `CreateSessionId` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_create_session_id_sync, create_session_id_sync
  void create_session_id_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `CreateSessionId` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_create_session_id_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `CreateSessionId` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_create_session_id_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable create_session_id_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `CreateClientName` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_create_client_name_sync, create_client_name_sync
  void create_client_name_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `CreateClientName` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_create_client_name_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `CreateClientName` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_create_client_name_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable create_client_name_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `InvocationCreationTime` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_invocation_creation_time_sync, invocation_creation_time_sync
  void invocation_creation_time_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `InvocationCreationTime` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_invocation_creation_time_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `InvocationCreationTime` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_invocation_creation_time_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable invocation_creation_time_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodCall` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_call_sync, last_method_call_sync
  void last_method_call_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodCall` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_method_call_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodCall` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_last_method_call_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_method_call_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodSessionId` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_session_id_sync, last_method_session_id_sync
  void last_method_session_id_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodSessionId` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_method_session_id_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodSessionId` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_last_method_session_id_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_method_session_id_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodInputArguments` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_input_arguments_sync, last_method_input_arguments_sync
  void last_method_input_arguments_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodInputArguments` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_method_input_arguments_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodInputArguments` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_last_method_input_arguments_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_method_input_arguments_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodOutputArguments` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_output_arguments_sync, last_method_output_arguments_sync
  void last_method_output_arguments_async(
    std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodOutputArguments` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_method_output_arguments_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodOutputArguments` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_last_method_output_arguments_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_method_output_arguments_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodInputValues` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_input_values_sync, last_method_input_values_sync
  void last_method_input_values_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodInputValues` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_method_input_values_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodInputValues` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_last_method_input_values_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_method_input_values_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodOutputValues` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_output_values_sync, last_method_output_values_sync
  void last_method_output_values_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodOutputValues` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_method_output_values_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodOutputValues` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_last_method_output_values_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_method_output_values_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodCallTime` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_call_time_sync, last_method_call_time_sync
  void last_method_call_time_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodCallTime` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_method_call_time_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodCallTime` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_last_method_call_time_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_method_call_time_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodReturnStatus` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_return_status_sync, last_method_return_status_sync
  void last_method_return_status_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodReturnStatus` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_method_return_status_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastMethodReturnStatus` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_last_method_return_status_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_method_return_status_sync() const;

private:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  ProgramDiagnostic2(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

private:
  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, VariableInstantiationAttributes attributes,
    CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_PROGRAM_DIAGNOSTIC2_H
