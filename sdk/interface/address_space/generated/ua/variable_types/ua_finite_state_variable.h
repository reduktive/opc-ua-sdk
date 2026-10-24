// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_FINITE_STATE_VARIABLE_H
#define UA_FINITE_STATE_VARIABLE_H

#include "ua_base_data_variable.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

class FiniteStateVariable;
using FiniteStateVariableResult = Result<FiniteStateVariable>;

/// Address-space handle for the OPC UA FiniteStateVariableType VariableType.
/// @ingroup ua_information_model
class FiniteStateVariable final : public BaseDataVariable
{
public:
  /// Constructs an empty `FiniteStateVariable` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  FiniteStateVariable() = default;

  /// Completion callback for create_async: receives the new `FiniteStateVariable` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(FiniteStateVariableResult)>;
  /// Completion callback for attach_async: receives the wrapped `FiniteStateVariable` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(FiniteStateVariableResult)>;

  /// Creates a new `FiniteStateVariableType` variable under `parent`.
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
  /// @param complete     Receives the outcome: on success a `FiniteStateVariable` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `FiniteStateVariableType` variable under `parent`, blocking until complete.
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
  static FiniteStateVariableResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `FiniteStateVariableType` variable under `parent`, blocking until complete.
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
  /// @return The new `FiniteStateVariable` handle. A Good subcode is not returned; @ref try_create_sync
  /// returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static FiniteStateVariable create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `FiniteStateVariableType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `FiniteStateVariable` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `FiniteStateVariableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static FiniteStateVariableResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `FiniteStateVariableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `FiniteStateVariable` handle. A Good subcode is not returned; @ref try_attach_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static FiniteStateVariable attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Id` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_id_property_sync, id_property_sync
  void id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Id` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Id` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_id_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property id_property_sync() const;

  /// Attaches a `Property` handle for the `Name` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_name_property_sync, name_property_sync
  void name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Name` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Name` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_name_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property name_property_sync() const;

  /// Attaches a `Property` handle for the `Number` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_number_property_sync, number_property_sync
  void number_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Number` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_number_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Number` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_number_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property number_property_sync() const;

  /// Attaches a `Property` handle for the `EffectiveDisplayName` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_effective_display_name_property_sync, effective_display_name_property_sync
  void effective_display_name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EffectiveDisplayName` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_effective_display_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EffectiveDisplayName` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_effective_display_name_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property effective_display_name_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `Id` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_id_sync, read_id_sync
  void read_id_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `Id` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_id_async gives it. Never throws.
  NodeIdResult try_read_id_sync() const noexcept;
  /// Reads the `Id` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_id_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_id_sync() const;

  /// Reads the `Name` property value, typed as `QualifiedName`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_name_sync, read_name_sync
  void read_name_async(std::function<void(QualifiedNameResult)> complete) const noexcept;
  /// Reads the `Name` property value as `QualifiedName`, blocking until complete.
  /// @return The value with the read's code, as @ref read_name_async gives it. Never throws.
  QualifiedNameResult try_read_name_sync() const noexcept;
  /// Reads the `Name` property value as `QualifiedName`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_name_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  QualifiedName read_name_sync() const;

  /// Reads the `Number` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_number_sync, read_number_sync
  void read_number_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `Number` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_number_async gives it. Never throws.
  UInt32Result try_read_number_sync() const noexcept;
  /// Reads the `Number` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_number_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_number_sync() const;

  /// Reads the `EffectiveDisplayName` property value, typed as `LocalizedText`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_effective_display_name_sync, read_effective_display_name_sync
  void read_effective_display_name_async(std::function<void(LocalizedTextResult)> complete) const noexcept;
  /// Reads the `EffectiveDisplayName` property value as `LocalizedText`, blocking until complete.
  /// @return The value with the read's code, as @ref read_effective_display_name_async gives it. Never
  /// throws.
  LocalizedTextResult try_read_effective_display_name_sync() const noexcept;
  /// Reads the `EffectiveDisplayName` property value as `LocalizedText`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_effective_display_name_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  LocalizedText read_effective_display_name_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `Id` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_id_sync, write_id_sync
  void write_id_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Id` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_id_sync(NodeId value) const noexcept;
  /// Writes the `Id` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_id_sync(NodeId value) const;

  /// Writes the `Name` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_name_sync, write_name_sync
  void write_name_async(QualifiedName value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Name` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_name_sync(QualifiedName value) const noexcept;
  /// Writes the `Name` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_name_sync(QualifiedName value) const;

  /// Writes the `Number` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_number_sync, write_number_sync
  void write_number_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Number` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_number_sync(uint32_t value) const noexcept;
  /// Writes the `Number` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_number_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_number_sync(uint32_t value) const;

  /// Writes the `EffectiveDisplayName` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_effective_display_name_sync, write_effective_display_name_sync
  void write_effective_display_name_async(
    LocalizedText value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `EffectiveDisplayName` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_effective_display_name_sync(LocalizedText value) const noexcept;
  /// Writes the `EffectiveDisplayName` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_effective_display_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_effective_display_name_sync(LocalizedText value) const;

private:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  FiniteStateVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

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

#endif  // UA_FINITE_STATE_VARIABLE_H
