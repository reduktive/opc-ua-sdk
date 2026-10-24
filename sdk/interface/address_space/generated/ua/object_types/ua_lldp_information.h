// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_LLDP_INFORMATION_H
#define UA_LLDP_INFORMATION_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_lldp_remote_statistics.h"
#include "ua_lldp_local_system.h"
#include "ua_folder.h"

namespace ua
{

struct MethodCallContext;

class LldpInformation;
using LldpInformationResult = Result<LldpInformation>;

/// Address-space handle for the OPC UA LldpInformationType ObjectType.
/// @ingroup ua_information_model
class LldpInformation : public BaseObject
{
public:
  /// Constructs an empty `LldpInformation` handle that references no node.
  LldpInformation() = default;

  /// Completion callback for create_async: receives the created `LldpInformation` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(LldpInformationResult)>;
  /// Completion callback for attach_async: receives the attached `LldpInformation` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(LldpInformationResult)>;

  /// Creates a new `LldpInformationType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `LldpInformation` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `LldpInformationType` instance under `parent`, blocking until complete.  ///
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
  static LldpInformationResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `LldpInformationType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `LldpInformation` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static LldpInformation create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `LldpInformationType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `LldpInformation` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `LldpInformationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static LldpInformationResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `LldpInformationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `LldpInformation` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static LldpInformation attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `LldpRemoteStatistics` handle for the `RemoteStatistics` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_statistics_sync, remote_statistics_sync
  void remote_statistics_async(std::function<void(LldpRemoteStatisticsResult)> complete) const noexcept;
  /// Attaches a typed `LldpRemoteStatistics` handle for the `RemoteStatistics` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  LldpRemoteStatisticsResult try_remote_statistics_sync() const noexcept;
  /// Attaches a typed `LldpRemoteStatistics` handle for the `RemoteStatistics` child, blocking until
  /// complete.
  /// @return The `LldpRemoteStatistics` handle. A Good subcode is not returned; @ref
  /// try_remote_statistics_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  LldpRemoteStatistics remote_statistics_sync() const;

  /// Attaches a typed `LldpLocalSystem` handle for the `LocalSystemData` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_local_system_data_sync, local_system_data_sync
  void local_system_data_async(std::function<void(LldpLocalSystemResult)> complete) const noexcept;
  /// Attaches a typed `LldpLocalSystem` handle for the `LocalSystemData` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  LldpLocalSystemResult try_local_system_data_sync() const noexcept;
  /// Attaches a typed `LldpLocalSystem` handle for the `LocalSystemData` child, blocking until complete.
  /// @return The `LldpLocalSystem` handle. A Good subcode is not returned; @ref try_local_system_data_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  LldpLocalSystem local_system_data_sync() const;

  /// Attaches a typed `Folder` handle for the `Ports` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_ports_sync, ports_sync
  void ports_async(std::function<void(FolderResult)> complete) const noexcept;
  /// Attaches a typed `Folder` handle for the `Ports` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  FolderResult try_ports_sync() const noexcept;
  /// Attaches a typed `Folder` handle for the `Ports` child, blocking until complete.
  /// @return The `Folder` handle. A Good subcode is not returned; @ref try_ports_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Folder ports_sync() const;

private:
  explicit LldpInformation(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_LLDP_INFORMATION_H
