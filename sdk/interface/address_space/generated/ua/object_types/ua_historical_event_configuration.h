// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORICAL_EVENT_CONFIGURATION_H
#define UA_HISTORICAL_EVENT_CONFIGURATION_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_folder.h"

namespace ua
{

struct MethodCallContext;

class HistoricalEventConfiguration;
using HistoricalEventConfigurationResult = Result<HistoricalEventConfiguration>;

/// Address-space handle for the OPC UA HistoricalEventConfigurationType ObjectType.
/// @ingroup ua_information_model
class HistoricalEventConfiguration : public BaseObject
{
public:
  /// Constructs an empty `HistoricalEventConfiguration` handle that references no node.
  HistoricalEventConfiguration() = default;

  /// Completion callback for create_async: receives the created `HistoricalEventConfiguration` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(HistoricalEventConfigurationResult)>;
  /// Completion callback for attach_async: receives the attached `HistoricalEventConfiguration` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(HistoricalEventConfigurationResult)>;

  /// Creates a new `HistoricalEventConfigurationType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `HistoricalEventConfiguration` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `HistoricalEventConfigurationType` instance under `parent`, blocking until complete.  ///
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
  static HistoricalEventConfigurationResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `HistoricalEventConfigurationType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `HistoricalEventConfiguration` handle. A Good subcode is not returned; @ref
  /// try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static HistoricalEventConfiguration create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `HistoricalEventConfigurationType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `HistoricalEventConfiguration` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `HistoricalEventConfigurationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static HistoricalEventConfigurationResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `HistoricalEventConfigurationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `HistoricalEventConfiguration` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static HistoricalEventConfiguration attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `StartOfArchive` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_start_of_archive_property_sync, start_of_archive_property_sync
  void start_of_archive_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `StartOfArchive` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_start_of_archive_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `StartOfArchive` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_start_of_archive_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property start_of_archive_property_sync() const;

  /// Attaches a `Property` handle for the `StartOfOnlineArchive` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_start_of_online_archive_property_sync, start_of_online_archive_property_sync
  void start_of_online_archive_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `StartOfOnlineArchive` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_start_of_online_archive_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `StartOfOnlineArchive` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_start_of_online_archive_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property start_of_online_archive_property_sync() const;

  /// Attaches a `Property` handle for the `SortByEventFields` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_sort_by_event_fields_property_sync, sort_by_event_fields_property_sync
  void sort_by_event_fields_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SortByEventFields` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_sort_by_event_fields_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SortByEventFields` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_sort_by_event_fields_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property sort_by_event_fields_property_sync() const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `Folder` handle for the `EventTypes` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_event_types_sync, event_types_sync
  void event_types_async(std::function<void(FolderResult)> complete) const noexcept;
  /// Attaches a typed `Folder` handle for the `EventTypes` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  FolderResult try_event_types_sync() const noexcept;
  /// Attaches a typed `Folder` handle for the `EventTypes` child, blocking until complete.
  /// @return The `Folder` handle. A Good subcode is not returned; @ref try_event_types_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Folder event_types_sync() const;

private:
  explicit HistoricalEventConfiguration(
    AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_HISTORICAL_EVENT_CONFIGURATION_H
