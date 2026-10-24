// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_OPERATION_LIMITS_H
#define UA_OPERATION_LIMITS_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class OperationLimits;
using OperationLimitsResult = Result<OperationLimits>;

/// Address-space handle for the OPC UA OperationLimitsType ObjectType.
/// @ingroup ua_information_model
class OperationLimits : public BaseObject
{
public:
  /// Constructs an empty `OperationLimits` handle that references no node.
  OperationLimits() = default;

  /// Completion callback for create_async: receives the created `OperationLimits` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(OperationLimitsResult)>;
  /// Completion callback for attach_async: receives the attached `OperationLimits` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(OperationLimitsResult)>;

  /// Creates a new `OperationLimitsType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `OperationLimits` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `OperationLimitsType` instance under `parent`, blocking until complete.  ///
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
  static OperationLimitsResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `OperationLimitsType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `OperationLimits` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static OperationLimits create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `OperationLimitsType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `OperationLimits` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `OperationLimitsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static OperationLimitsResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `OperationLimitsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `OperationLimits` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static OperationLimits attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `MaxNodesPerRead` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_read_property_sync, max_nodes_per_read_property_sync
  void max_nodes_per_read_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerRead` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_read_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerRead` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_read_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_read_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerHistoryReadData` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_history_read_data_property_sync, max_nodes_per_history_read_data_property_sync
  void max_nodes_per_history_read_data_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerHistoryReadData` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_history_read_data_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerHistoryReadData` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_history_read_data_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_history_read_data_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerHistoryReadEvents` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_history_read_events_property_sync,
  /// max_nodes_per_history_read_events_property_sync
  void max_nodes_per_history_read_events_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerHistoryReadEvents` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_history_read_events_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerHistoryReadEvents` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_history_read_events_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_history_read_events_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerWrite` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_write_property_sync, max_nodes_per_write_property_sync
  void max_nodes_per_write_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerWrite` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_write_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerWrite` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_write_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_write_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerHistoryUpdateData` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_history_update_data_property_sync,
  /// max_nodes_per_history_update_data_property_sync
  void max_nodes_per_history_update_data_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerHistoryUpdateData` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_history_update_data_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerHistoryUpdateData` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_history_update_data_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_history_update_data_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerHistoryUpdateEvents` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_history_update_events_property_sync,
  /// max_nodes_per_history_update_events_property_sync
  void max_nodes_per_history_update_events_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerHistoryUpdateEvents` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_history_update_events_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerHistoryUpdateEvents` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_history_update_events_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_history_update_events_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerMethodCall` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_method_call_property_sync, max_nodes_per_method_call_property_sync
  void max_nodes_per_method_call_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerMethodCall` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_method_call_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerMethodCall` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_method_call_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_method_call_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerBrowse` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_browse_property_sync, max_nodes_per_browse_property_sync
  void max_nodes_per_browse_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerBrowse` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_browse_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerBrowse` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_browse_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_browse_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerRegisterNodes` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_register_nodes_property_sync, max_nodes_per_register_nodes_property_sync
  void max_nodes_per_register_nodes_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerRegisterNodes` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_register_nodes_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerRegisterNodes` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_register_nodes_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_register_nodes_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerTranslateBrowsePathsToNodeIds` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_translate_browse_paths_to_node_ids_property_sync,
  /// max_nodes_per_translate_browse_paths_to_node_ids_property_sync
  void max_nodes_per_translate_browse_paths_to_node_ids_property_async(
    PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerTranslateBrowsePathsToNodeIds` property, blocking until
  /// complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_translate_browse_paths_to_node_ids_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerTranslateBrowsePathsToNodeIds` property, blocking until
  /// complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_translate_browse_paths_to_node_ids_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_translate_browse_paths_to_node_ids_property_sync() const;

  /// Attaches a `Property` handle for the `MaxNodesPerNodeManagement` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_nodes_per_node_management_property_sync, max_nodes_per_node_management_property_sync
  void max_nodes_per_node_management_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerNodeManagement` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_nodes_per_node_management_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxNodesPerNodeManagement` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_nodes_per_node_management_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_nodes_per_node_management_property_sync() const;

  /// Attaches a `Property` handle for the `MaxMonitoredItemsPerCall` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_monitored_items_per_call_property_sync, max_monitored_items_per_call_property_sync
  void max_monitored_items_per_call_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxMonitoredItemsPerCall` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_monitored_items_per_call_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxMonitoredItemsPerCall` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_monitored_items_per_call_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_monitored_items_per_call_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `MaxNodesPerRead` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_read_sync, read_max_nodes_per_read_sync
  void read_max_nodes_per_read_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerRead` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_read_async gives it. Never throws.
  UInt32Result try_read_max_nodes_per_read_sync() const noexcept;
  /// Reads the `MaxNodesPerRead` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_nodes_per_read_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_read_sync() const;

  /// Reads the `MaxNodesPerHistoryReadData` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_history_read_data_sync, read_max_nodes_per_history_read_data_sync
  void read_max_nodes_per_history_read_data_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerHistoryReadData` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_history_read_data_async gives it.
  /// Never throws.
  UInt32Result try_read_max_nodes_per_history_read_data_sync() const noexcept;
  /// Reads the `MaxNodesPerHistoryReadData` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_nodes_per_history_read_data_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_history_read_data_sync() const;

  /// Reads the `MaxNodesPerHistoryReadEvents` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_history_read_events_sync, read_max_nodes_per_history_read_events_sync
  void read_max_nodes_per_history_read_events_async(
    std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerHistoryReadEvents` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_history_read_events_async gives it.
  /// Never throws.
  UInt32Result try_read_max_nodes_per_history_read_events_sync() const noexcept;
  /// Reads the `MaxNodesPerHistoryReadEvents` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_nodes_per_history_read_events_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_history_read_events_sync() const;

  /// Reads the `MaxNodesPerWrite` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_write_sync, read_max_nodes_per_write_sync
  void read_max_nodes_per_write_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerWrite` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_write_async gives it. Never throws.
  UInt32Result try_read_max_nodes_per_write_sync() const noexcept;
  /// Reads the `MaxNodesPerWrite` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_nodes_per_write_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_write_sync() const;

  /// Reads the `MaxNodesPerHistoryUpdateData` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_history_update_data_sync, read_max_nodes_per_history_update_data_sync
  void read_max_nodes_per_history_update_data_async(
    std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerHistoryUpdateData` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_history_update_data_async gives it.
  /// Never throws.
  UInt32Result try_read_max_nodes_per_history_update_data_sync() const noexcept;
  /// Reads the `MaxNodesPerHistoryUpdateData` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_nodes_per_history_update_data_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_history_update_data_sync() const;

  /// Reads the `MaxNodesPerHistoryUpdateEvents` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_history_update_events_sync, read_max_nodes_per_history_update_events_sync
  void read_max_nodes_per_history_update_events_async(
    std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerHistoryUpdateEvents` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_history_update_events_async gives it.
  /// Never throws.
  UInt32Result try_read_max_nodes_per_history_update_events_sync() const noexcept;
  /// Reads the `MaxNodesPerHistoryUpdateEvents` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_nodes_per_history_update_events_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_history_update_events_sync() const;

  /// Reads the `MaxNodesPerMethodCall` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_method_call_sync, read_max_nodes_per_method_call_sync
  void read_max_nodes_per_method_call_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerMethodCall` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_method_call_async gives it. Never
  /// throws.
  UInt32Result try_read_max_nodes_per_method_call_sync() const noexcept;
  /// Reads the `MaxNodesPerMethodCall` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_nodes_per_method_call_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_method_call_sync() const;

  /// Reads the `MaxNodesPerBrowse` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_browse_sync, read_max_nodes_per_browse_sync
  void read_max_nodes_per_browse_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerBrowse` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_browse_async gives it. Never throws.
  UInt32Result try_read_max_nodes_per_browse_sync() const noexcept;
  /// Reads the `MaxNodesPerBrowse` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_nodes_per_browse_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_browse_sync() const;

  /// Reads the `MaxNodesPerRegisterNodes` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_register_nodes_sync, read_max_nodes_per_register_nodes_sync
  void read_max_nodes_per_register_nodes_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerRegisterNodes` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_register_nodes_async gives it. Never
  /// throws.
  UInt32Result try_read_max_nodes_per_register_nodes_sync() const noexcept;
  /// Reads the `MaxNodesPerRegisterNodes` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_nodes_per_register_nodes_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_register_nodes_sync() const;

  /// Reads the `MaxNodesPerTranslateBrowsePathsToNodeIds` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_translate_browse_paths_to_node_ids_sync,
  /// read_max_nodes_per_translate_browse_paths_to_node_ids_sync
  void read_max_nodes_per_translate_browse_paths_to_node_ids_async(
    std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerTranslateBrowsePathsToNodeIds` property value as `uint32_t`, blocking until
  /// complete.
  /// @return The value with the read's code, as @ref
  /// read_max_nodes_per_translate_browse_paths_to_node_ids_async gives it. Never throws.
  UInt32Result try_read_max_nodes_per_translate_browse_paths_to_node_ids_sync() const noexcept;
  /// Reads the `MaxNodesPerTranslateBrowsePathsToNodeIds` property value as `uint32_t`, blocking until
  /// complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_nodes_per_translate_browse_paths_to_node_ids_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_translate_browse_paths_to_node_ids_sync() const;

  /// Reads the `MaxNodesPerNodeManagement` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_nodes_per_node_management_sync, read_max_nodes_per_node_management_sync
  void read_max_nodes_per_node_management_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxNodesPerNodeManagement` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_nodes_per_node_management_async gives it. Never
  /// throws.
  UInt32Result try_read_max_nodes_per_node_management_sync() const noexcept;
  /// Reads the `MaxNodesPerNodeManagement` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_nodes_per_node_management_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_nodes_per_node_management_sync() const;

  /// Reads the `MaxMonitoredItemsPerCall` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_monitored_items_per_call_sync, read_max_monitored_items_per_call_sync
  void read_max_monitored_items_per_call_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxMonitoredItemsPerCall` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_monitored_items_per_call_async gives it. Never
  /// throws.
  UInt32Result try_read_max_monitored_items_per_call_sync() const noexcept;
  /// Reads the `MaxMonitoredItemsPerCall` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_monitored_items_per_call_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_monitored_items_per_call_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `MaxNodesPerRead` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_read_sync, write_max_nodes_per_read_sync
  void write_max_nodes_per_read_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerRead` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_read_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerRead` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_read_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_read_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerHistoryReadData` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_history_read_data_sync, write_max_nodes_per_history_read_data_sync
  void write_max_nodes_per_history_read_data_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerHistoryReadData` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_history_read_data_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerHistoryReadData` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_history_read_data_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_history_read_data_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerHistoryReadEvents` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_history_read_events_sync, write_max_nodes_per_history_read_events_sync
  void write_max_nodes_per_history_read_events_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerHistoryReadEvents` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_history_read_events_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerHistoryReadEvents` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_history_read_events_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_history_read_events_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerWrite` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_write_sync, write_max_nodes_per_write_sync
  void write_max_nodes_per_write_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerWrite` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_write_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerWrite` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_write_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_write_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerHistoryUpdateData` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_history_update_data_sync, write_max_nodes_per_history_update_data_sync
  void write_max_nodes_per_history_update_data_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerHistoryUpdateData` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_history_update_data_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerHistoryUpdateData` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_history_update_data_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_history_update_data_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerHistoryUpdateEvents` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_history_update_events_sync, write_max_nodes_per_history_update_events_sync
  void write_max_nodes_per_history_update_events_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerHistoryUpdateEvents` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_history_update_events_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerHistoryUpdateEvents` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_history_update_events_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_history_update_events_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerMethodCall` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_method_call_sync, write_max_nodes_per_method_call_sync
  void write_max_nodes_per_method_call_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerMethodCall` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_method_call_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerMethodCall` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_method_call_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_method_call_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerBrowse` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_browse_sync, write_max_nodes_per_browse_sync
  void write_max_nodes_per_browse_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerBrowse` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_browse_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerBrowse` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_browse_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_browse_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerRegisterNodes` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_register_nodes_sync, write_max_nodes_per_register_nodes_sync
  void write_max_nodes_per_register_nodes_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerRegisterNodes` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_register_nodes_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerRegisterNodes` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_register_nodes_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_register_nodes_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerTranslateBrowsePathsToNodeIds` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_translate_browse_paths_to_node_ids_sync,
  /// write_max_nodes_per_translate_browse_paths_to_node_ids_sync
  void write_max_nodes_per_translate_browse_paths_to_node_ids_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerTranslateBrowsePathsToNodeIds` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_translate_browse_paths_to_node_ids_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerTranslateBrowsePathsToNodeIds` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_translate_browse_paths_to_node_ids_sync
  /// returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_translate_browse_paths_to_node_ids_sync(uint32_t value) const;

  /// Writes the `MaxNodesPerNodeManagement` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_nodes_per_node_management_sync, write_max_nodes_per_node_management_sync
  void write_max_nodes_per_node_management_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxNodesPerNodeManagement` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_nodes_per_node_management_sync(uint32_t value) const noexcept;
  /// Writes the `MaxNodesPerNodeManagement` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_nodes_per_node_management_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_nodes_per_node_management_sync(uint32_t value) const;

  /// Writes the `MaxMonitoredItemsPerCall` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_monitored_items_per_call_sync, write_max_monitored_items_per_call_sync
  void write_max_monitored_items_per_call_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxMonitoredItemsPerCall` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_monitored_items_per_call_sync(uint32_t value) const noexcept;
  /// Writes the `MaxMonitoredItemsPerCall` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_monitored_items_per_call_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_monitored_items_per_call_sync(uint32_t value) const;

private:
  explicit OperationLimits(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_OPERATION_LIMITS_H
