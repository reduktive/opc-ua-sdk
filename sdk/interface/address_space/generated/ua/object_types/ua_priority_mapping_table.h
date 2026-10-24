// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PRIORITY_MAPPING_TABLE_H
#define UA_PRIORITY_MAPPING_TABLE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class PriorityMappingTable;
using PriorityMappingTableResult = Result<PriorityMappingTable>;

/// Address-space handle for the OPC UA PriorityMappingTableType ObjectType.
/// @ingroup ua_information_model
class PriorityMappingTable : public BaseObject
{
public:
  /// Constructs an empty `PriorityMappingTable` handle that references no node.
  PriorityMappingTable() = default;

  /// Input arguments for the PriorityMappingTableType AddPriorityMappingEntry() method.
  struct AddPriorityMappingEntryInputArguments
  {
    String mappingUri;  ///< Mapping uri.
    String priorityLabel;  ///< Priority label.
    uint8_t priorityValuePcp{};  ///< Priority value pcp.
    uint32_t priorityValueDscp{};  ///< Priority value dscp.
  };

  /// Synchronous handler for AddPriorityMappingEntry(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using AddPriorityMappingEntryHandler =
    std::function<MethodResult<>(const MethodCall&, const AddPriorityMappingEntryInputArguments&)>;
  /// Asynchronous handler for AddPriorityMappingEntry(): starts the work and completes it through the
  /// callback, once, from any thread.
  using AddPriorityMappingEntryAsyncHandler = std::function<void(
    const MethodCall&, const AddPriorityMappingEntryInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the PriorityMappingTableType DeletePriorityMappingEntry() method.
  struct DeletePriorityMappingEntryInputArguments
  {
    String mappingUri;  ///< Mapping uri.
    String priorityLabel;  ///< Priority label.
  };

  /// Synchronous handler for DeletePriorityMappingEntry(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using DeletePriorityMappingEntryHandler =
    std::function<MethodResult<>(const MethodCall&, const DeletePriorityMappingEntryInputArguments&)>;
  /// Asynchronous handler for DeletePriorityMappingEntry(): starts the work and completes it through the
  /// callback, once, from any thread.
  using DeletePriorityMappingEntryAsyncHandler = std::function<void(
    const MethodCall&, const DeletePriorityMappingEntryInputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `PriorityMappingTable` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(PriorityMappingTableResult)>;
  /// Completion callback for attach_async: receives the attached `PriorityMappingTable` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(PriorityMappingTableResult)>;

  /// Creates a new `PriorityMappingTableType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `PriorityMappingTable` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `PriorityMappingTableType` instance under `parent`, blocking until complete.  ///
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
  static PriorityMappingTableResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `PriorityMappingTableType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `PriorityMappingTable` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static PriorityMappingTable create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `PriorityMappingTableType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `PriorityMappingTable` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `PriorityMappingTableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static PriorityMappingTableResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `PriorityMappingTableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `PriorityMappingTable` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static PriorityMappingTable attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `AddPriorityMappingEntry` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_priority_mapping_entry_method_sync, add_priority_mapping_entry_method_sync
  void add_priority_mapping_entry_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `AddPriorityMappingEntry` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_add_priority_mapping_entry_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `AddPriorityMappingEntry` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_add_priority_mapping_entry_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor add_priority_mapping_entry_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `DeletePriorityMappingEntry` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_delete_priority_mapping_entry_method_sync, delete_priority_mapping_entry_method_sync
  void delete_priority_mapping_entry_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `DeletePriorityMappingEntry` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_delete_priority_mapping_entry_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `DeletePriorityMappingEntry` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_delete_priority_mapping_entry_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor delete_priority_mapping_entry_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `PriorityMapppingEntries` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_priority_mappping_entries_property_sync, priority_mappping_entries_property_sync
  void priority_mappping_entries_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `PriorityMapppingEntries` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_priority_mappping_entries_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `PriorityMapppingEntries` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_priority_mappping_entries_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property priority_mappping_entries_property_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `AddPriorityMappingEntry` method, in
  /// place of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_priority_mapping_entry_handler_sync, set_add_priority_mapping_entry_handler_sync
  void set_add_priority_mapping_entry_handler_async(
    AddPriorityMappingEntryHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `AddPriorityMappingEntry` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_priority_mapping_entry_handler_sync(
    AddPriorityMappingEntryHandler handler) const noexcept;
  /// Registers the synchronous `AddPriorityMappingEntry` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_priority_mapping_entry_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_priority_mapping_entry_handler_sync(AddPriorityMappingEntryHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `AddPriorityMappingEntry` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_priority_mapping_entry_handler_sync, set_add_priority_mapping_entry_handler_sync
  void set_add_priority_mapping_entry_handler_async(
    AddPriorityMappingEntryAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `AddPriorityMappingEntry` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_priority_mapping_entry_handler_sync(
    AddPriorityMappingEntryAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `AddPriorityMappingEntry` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_priority_mapping_entry_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_priority_mapping_entry_handler_sync(AddPriorityMappingEntryAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `DeletePriorityMappingEntry` method,
  /// in place of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_delete_priority_mapping_entry_handler_sync, set_delete_priority_mapping_entry_handler_sync
  void set_delete_priority_mapping_entry_handler_async(
    DeletePriorityMappingEntryHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `DeletePriorityMappingEntry` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_delete_priority_mapping_entry_handler_sync(
    DeletePriorityMappingEntryHandler handler) const noexcept;
  /// Registers the synchronous `DeletePriorityMappingEntry` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_delete_priority_mapping_entry_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_delete_priority_mapping_entry_handler_sync(DeletePriorityMappingEntryHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `DeletePriorityMappingEntry` method,
  /// in place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_delete_priority_mapping_entry_handler_sync, set_delete_priority_mapping_entry_handler_sync
  void set_delete_priority_mapping_entry_handler_async(
    DeletePriorityMappingEntryAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `DeletePriorityMappingEntry` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_delete_priority_mapping_entry_handler_sync(
    DeletePriorityMappingEntryAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `DeletePriorityMappingEntry` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_delete_priority_mapping_entry_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_delete_priority_mapping_entry_handler_sync(DeletePriorityMappingEntryAsyncHandler handler) const;

private:
  explicit PriorityMappingTable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_PRIORITY_MAPPING_TABLE_H
