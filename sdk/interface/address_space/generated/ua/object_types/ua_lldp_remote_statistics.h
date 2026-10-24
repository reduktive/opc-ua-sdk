// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_LLDP_REMOTE_STATISTICS_H
#define UA_LLDP_REMOTE_STATISTICS_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_base_data_variable.h"

namespace ua
{

struct MethodCallContext;

class LldpRemoteStatistics;
using LldpRemoteStatisticsResult = Result<LldpRemoteStatistics>;

/// Address-space handle for the OPC UA LldpRemoteStatisticsType ObjectType.
/// @ingroup ua_information_model
class LldpRemoteStatistics : public BaseObject
{
public:
  /// Constructs an empty `LldpRemoteStatistics` handle that references no node.
  LldpRemoteStatistics() = default;

  /// Completion callback for create_async: receives the created `LldpRemoteStatistics` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(LldpRemoteStatisticsResult)>;
  /// Completion callback for attach_async: receives the attached `LldpRemoteStatistics` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(LldpRemoteStatisticsResult)>;

  /// Creates a new `LldpRemoteStatisticsType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `LldpRemoteStatistics` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `LldpRemoteStatisticsType` instance under `parent`, blocking until complete.  ///
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
  static LldpRemoteStatisticsResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `LldpRemoteStatisticsType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `LldpRemoteStatistics` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static LldpRemoteStatistics create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `LldpRemoteStatisticsType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `LldpRemoteStatistics` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `LldpRemoteStatisticsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static LldpRemoteStatisticsResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `LldpRemoteStatisticsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `LldpRemoteStatistics` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static LldpRemoteStatistics attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `BaseDataVariable` handle for the `LastChangeTime` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_change_time_sync, last_change_time_sync
  void last_change_time_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastChangeTime` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_last_change_time_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `LastChangeTime` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_last_change_time_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable last_change_time_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `RemoteInserts` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_inserts_sync, remote_inserts_sync
  void remote_inserts_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteInserts` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_remote_inserts_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteInserts` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_remote_inserts_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable remote_inserts_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `RemoteDeletes` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_deletes_sync, remote_deletes_sync
  void remote_deletes_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteDeletes` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_remote_deletes_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteDeletes` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_remote_deletes_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable remote_deletes_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `RemoteDrops` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_drops_sync, remote_drops_sync
  void remote_drops_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteDrops` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_remote_drops_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteDrops` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_remote_drops_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable remote_drops_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `RemoteAgeouts` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_ageouts_sync, remote_ageouts_sync
  void remote_ageouts_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteAgeouts` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_remote_ageouts_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteAgeouts` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_remote_ageouts_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable remote_ageouts_sync() const;

private:
  explicit LldpRemoteStatistics(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_LLDP_REMOTE_STATISTICS_H
