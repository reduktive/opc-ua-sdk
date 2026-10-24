// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SELECTION_LIST_H
#define UA_SELECTION_LIST_H

#include "ua_base_data_variable.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

class SelectionList;
using SelectionListResult = Result<SelectionList>;

/// Address-space handle for the OPC UA SelectionListType VariableType.
/// @ingroup ua_information_model
class SelectionList final : public BaseDataVariable
{
public:
  /// Constructs an empty `SelectionList` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  SelectionList() = default;

  /// Completion callback for create_async: receives the new `SelectionList` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(SelectionListResult)>;
  /// Completion callback for attach_async: receives the wrapped `SelectionList` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(SelectionListResult)>;

  /// Creates a new `SelectionListType` variable under `parent`.
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
  /// @param complete     Receives the outcome: on success a `SelectionList` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `SelectionListType` variable under `parent`, blocking until complete.
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
  static SelectionListResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `SelectionListType` variable under `parent`, blocking until complete.
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
  /// @return The new `SelectionList` handle. A Good subcode is not returned; @ref try_create_sync returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static SelectionList create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `SelectionListType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `SelectionList` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `SelectionListType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static SelectionListResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `SelectionListType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `SelectionList` handle. A Good subcode is not returned; @ref try_attach_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static SelectionList attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Selections` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_selections_property_sync, selections_property_sync
  void selections_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Selections` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_selections_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Selections` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_selections_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property selections_property_sync() const;

  /// Attaches a `Property` handle for the `SelectionDescriptions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_selection_descriptions_property_sync, selection_descriptions_property_sync
  void selection_descriptions_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SelectionDescriptions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_selection_descriptions_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SelectionDescriptions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_selection_descriptions_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property selection_descriptions_property_sync() const;

  /// Attaches a `Property` handle for the `RestrictToList` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_restrict_to_list_property_sync, restrict_to_list_property_sync
  void restrict_to_list_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `RestrictToList` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_restrict_to_list_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `RestrictToList` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_restrict_to_list_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property restrict_to_list_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `SelectionDescriptions` property value, typed as `LocalizedText`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_selection_descriptions_sync, read_selection_descriptions_sync
  void read_selection_descriptions_async(std::function<void(LocalizedTextResult)> complete) const noexcept;
  /// Reads the `SelectionDescriptions` property value as `LocalizedText`, blocking until complete.
  /// @return The value with the read's code, as @ref read_selection_descriptions_async gives it. Never
  /// throws.
  LocalizedTextResult try_read_selection_descriptions_sync() const noexcept;
  /// Reads the `SelectionDescriptions` property value as `LocalizedText`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_selection_descriptions_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  LocalizedText read_selection_descriptions_sync() const;

  /// Reads the `RestrictToList` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_restrict_to_list_sync, read_restrict_to_list_sync
  void read_restrict_to_list_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `RestrictToList` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_restrict_to_list_async gives it. Never throws.
  BoolResult try_read_restrict_to_list_sync() const noexcept;
  /// Reads the `RestrictToList` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_restrict_to_list_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_restrict_to_list_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `SelectionDescriptions` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_selection_descriptions_sync, write_selection_descriptions_sync
  void write_selection_descriptions_async(
    LocalizedText value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SelectionDescriptions` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_selection_descriptions_sync(LocalizedText value) const noexcept;
  /// Writes the `SelectionDescriptions` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_selection_descriptions_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_selection_descriptions_sync(LocalizedText value) const;

  /// Writes the `RestrictToList` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_restrict_to_list_sync, write_restrict_to_list_sync
  void write_restrict_to_list_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `RestrictToList` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_restrict_to_list_sync(bool value) const noexcept;
  /// Writes the `RestrictToList` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_restrict_to_list_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_restrict_to_list_sync(bool value) const;

private:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  SelectionList(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

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

#endif  // UA_SELECTION_LIST_H
