// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PROGRAM_DIAGNOSTIC_H
#define UA_PROGRAM_DIAGNOSTIC_H

#include "ua_base_data_variable.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

class ProgramDiagnostic;
using ProgramDiagnosticResult = Result<ProgramDiagnostic>;

/// Address-space handle for the OPC UA ProgramDiagnosticType VariableType.
/// @ingroup ua_information_model
class ProgramDiagnostic final : public BaseDataVariable
{
public:
  /// Constructs an empty `ProgramDiagnostic` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  ProgramDiagnostic() = default;

  /// Completion callback for create_async: receives the new `ProgramDiagnostic` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ProgramDiagnosticResult)>;
  /// Completion callback for attach_async: receives the wrapped `ProgramDiagnostic` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ProgramDiagnosticResult)>;

  /// Creates a new `ProgramDiagnosticType` variable under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ProgramDiagnostic` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `ProgramDiagnosticType` variable under `parent`, blocking until complete.
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
  static ProgramDiagnosticResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `ProgramDiagnosticType` variable under `parent`, blocking until complete.
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
  /// @return The new `ProgramDiagnostic` handle. A Good subcode is not returned; @ref try_create_sync returns
  /// it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ProgramDiagnostic create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `ProgramDiagnosticType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `ProgramDiagnostic` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ProgramDiagnosticType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ProgramDiagnosticResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ProgramDiagnosticType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `ProgramDiagnostic` handle. A Good subcode is not returned; @ref try_attach_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ProgramDiagnostic attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `CreateSessionId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_create_session_id_property_sync, create_session_id_property_sync
  void create_session_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CreateSessionId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_create_session_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CreateSessionId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_create_session_id_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property create_session_id_property_sync() const;

  /// Attaches a `Property` handle for the `CreateClientName` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_create_client_name_property_sync, create_client_name_property_sync
  void create_client_name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CreateClientName` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_create_client_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CreateClientName` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_create_client_name_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property create_client_name_property_sync() const;

  /// Attaches a `Property` handle for the `InvocationCreationTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_invocation_creation_time_property_sync, invocation_creation_time_property_sync
  void invocation_creation_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `InvocationCreationTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_invocation_creation_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `InvocationCreationTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_invocation_creation_time_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property invocation_creation_time_property_sync() const;

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

  /// Attaches a `Property` handle for the `LastMethodCall` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_call_property_sync, last_method_call_property_sync
  void last_method_call_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastMethodCall` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_method_call_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastMethodCall` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_method_call_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_method_call_property_sync() const;

  /// Attaches a `Property` handle for the `LastMethodSessionId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_session_id_property_sync, last_method_session_id_property_sync
  void last_method_session_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastMethodSessionId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_method_session_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastMethodSessionId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_method_session_id_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_method_session_id_property_sync() const;

  /// Attaches a `Property` handle for the `LastMethodInputArguments` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_input_arguments_property_sync, last_method_input_arguments_property_sync
  void last_method_input_arguments_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastMethodInputArguments` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_method_input_arguments_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastMethodInputArguments` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_method_input_arguments_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_method_input_arguments_property_sync() const;

  /// Attaches a `Property` handle for the `LastMethodOutputArguments` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_output_arguments_property_sync, last_method_output_arguments_property_sync
  void last_method_output_arguments_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastMethodOutputArguments` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_method_output_arguments_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastMethodOutputArguments` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_method_output_arguments_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_method_output_arguments_property_sync() const;

  /// Attaches a `Property` handle for the `LastMethodCallTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_call_time_property_sync, last_method_call_time_property_sync
  void last_method_call_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastMethodCallTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_method_call_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastMethodCallTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_method_call_time_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_method_call_time_property_sync() const;

  /// Attaches a `Property` handle for the `LastMethodReturnStatus` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_method_return_status_property_sync, last_method_return_status_property_sync
  void last_method_return_status_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastMethodReturnStatus` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_method_return_status_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastMethodReturnStatus` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_method_return_status_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_method_return_status_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `CreateSessionId` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_create_session_id_sync, read_create_session_id_sync
  void read_create_session_id_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `CreateSessionId` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_create_session_id_async gives it. Never throws.
  NodeIdResult try_read_create_session_id_sync() const noexcept;
  /// Reads the `CreateSessionId` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_create_session_id_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_create_session_id_sync() const;

  /// Reads the `CreateClientName` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_create_client_name_sync, read_create_client_name_sync
  void read_create_client_name_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `CreateClientName` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_create_client_name_async gives it. Never throws.
  StringResult try_read_create_client_name_sync() const noexcept;
  /// Reads the `CreateClientName` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_create_client_name_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_create_client_name_sync() const;

  /// Reads the `LastMethodCall` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_last_method_call_sync, read_last_method_call_sync
  void read_last_method_call_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `LastMethodCall` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_last_method_call_async gives it. Never throws.
  StringResult try_read_last_method_call_sync() const noexcept;
  /// Reads the `LastMethodCall` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_last_method_call_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_last_method_call_sync() const;

  /// Reads the `LastMethodSessionId` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_last_method_session_id_sync, read_last_method_session_id_sync
  void read_last_method_session_id_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `LastMethodSessionId` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_last_method_session_id_async gives it. Never
  /// throws.
  NodeIdResult try_read_last_method_session_id_sync() const noexcept;
  /// Reads the `LastMethodSessionId` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_last_method_session_id_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_last_method_session_id_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `CreateSessionId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_create_session_id_sync, write_create_session_id_sync
  void write_create_session_id_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CreateSessionId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_create_session_id_sync(NodeId value) const noexcept;
  /// Writes the `CreateSessionId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_create_session_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_create_session_id_sync(NodeId value) const;

  /// Writes the `CreateClientName` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_create_client_name_sync, write_create_client_name_sync
  void write_create_client_name_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CreateClientName` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_create_client_name_sync(String value) const noexcept;
  /// Writes the `CreateClientName` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_create_client_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_create_client_name_sync(String value) const;

  /// Writes the `LastMethodCall` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_last_method_call_sync, write_last_method_call_sync
  void write_last_method_call_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `LastMethodCall` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_last_method_call_sync(String value) const noexcept;
  /// Writes the `LastMethodCall` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_last_method_call_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_last_method_call_sync(String value) const;

  /// Writes the `LastMethodSessionId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_last_method_session_id_sync, write_last_method_session_id_sync
  void write_last_method_session_id_async(
    NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `LastMethodSessionId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_last_method_session_id_sync(NodeId value) const noexcept;
  /// Writes the `LastMethodSessionId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_last_method_session_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_last_method_session_id_sync(NodeId value) const;

private:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  ProgramDiagnostic(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

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

#endif  // UA_PROGRAM_DIAGNOSTIC_H
