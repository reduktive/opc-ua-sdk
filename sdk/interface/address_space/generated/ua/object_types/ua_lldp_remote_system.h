// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_LLDP_REMOTE_SYSTEM_H
#define UA_LLDP_REMOTE_SYSTEM_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_base_data_variable.h"

namespace ua
{

struct MethodCallContext;

class LldpRemoteSystem;
using LldpRemoteSystemResult = Result<LldpRemoteSystem>;

/// Address-space handle for the OPC UA LldpRemoteSystemType ObjectType.
/// @ingroup ua_information_model
class LldpRemoteSystem : public BaseObject
{
public:
  /// Constructs an empty `LldpRemoteSystem` handle that references no node.
  LldpRemoteSystem() = default;

  /// Completion callback for create_async: receives the created `LldpRemoteSystem` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(LldpRemoteSystemResult)>;
  /// Completion callback for attach_async: receives the attached `LldpRemoteSystem` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(LldpRemoteSystemResult)>;

  /// Creates a new `LldpRemoteSystemType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `LldpRemoteSystem` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `LldpRemoteSystemType` instance under `parent`, blocking until complete.  ///
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
  static LldpRemoteSystemResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `LldpRemoteSystemType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `LldpRemoteSystem` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static LldpRemoteSystem create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `LldpRemoteSystemType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `LldpRemoteSystem` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `LldpRemoteSystemType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static LldpRemoteSystemResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `LldpRemoteSystemType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `LldpRemoteSystem` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static LldpRemoteSystem attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `BaseDataVariable` handle for the `TimeMark` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_time_mark_sync, time_mark_sync
  void time_mark_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `TimeMark` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_time_mark_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `TimeMark` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_time_mark_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable time_mark_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `RemoteIndex` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_index_sync, remote_index_sync
  void remote_index_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteIndex` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_remote_index_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteIndex` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_remote_index_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable remote_index_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `ChassisIdSubtype` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_chassis_id_subtype_sync, chassis_id_subtype_sync
  void chassis_id_subtype_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ChassisIdSubtype` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_chassis_id_subtype_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ChassisIdSubtype` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_chassis_id_subtype_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable chassis_id_subtype_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `ChassisId` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_chassis_id_sync, chassis_id_sync
  void chassis_id_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ChassisId` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_chassis_id_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ChassisId` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_chassis_id_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable chassis_id_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `PortIdSubtype` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_port_id_subtype_sync, port_id_subtype_sync
  void port_id_subtype_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `PortIdSubtype` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_port_id_subtype_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `PortIdSubtype` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_port_id_subtype_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable port_id_subtype_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `PortId` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_port_id_sync, port_id_sync
  void port_id_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `PortId` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_port_id_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `PortId` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_port_id_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable port_id_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `PortDescription` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_port_description_sync, port_description_sync
  void port_description_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `PortDescription` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_port_description_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `PortDescription` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_port_description_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable port_description_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `SystemName` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_system_name_sync, system_name_sync
  void system_name_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SystemName` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_system_name_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SystemName` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_system_name_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable system_name_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `SystemDescription` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_system_description_sync, system_description_sync
  void system_description_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SystemDescription` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_system_description_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SystemDescription` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_system_description_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable system_description_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `SystemCapabilitiesSupported` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_system_capabilities_supported_sync, system_capabilities_supported_sync
  void system_capabilities_supported_async(
    std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SystemCapabilitiesSupported` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_system_capabilities_supported_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SystemCapabilitiesSupported` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_system_capabilities_supported_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable system_capabilities_supported_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `SystemCapabilitiesEnabled` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_system_capabilities_enabled_sync, system_capabilities_enabled_sync
  void system_capabilities_enabled_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SystemCapabilitiesEnabled` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_system_capabilities_enabled_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SystemCapabilitiesEnabled` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_system_capabilities_enabled_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable system_capabilities_enabled_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `RemoteChanges` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_changes_sync, remote_changes_sync
  void remote_changes_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteChanges` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_remote_changes_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteChanges` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_remote_changes_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable remote_changes_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `RemoteTooManyNeighbors` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_too_many_neighbors_sync, remote_too_many_neighbors_sync
  void remote_too_many_neighbors_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteTooManyNeighbors` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_remote_too_many_neighbors_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteTooManyNeighbors` child, blocking until
  /// complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref
  /// try_remote_too_many_neighbors_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable remote_too_many_neighbors_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `ManagementAddress` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_management_address_sync, management_address_sync
  void management_address_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ManagementAddress` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_management_address_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `ManagementAddress` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_management_address_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable management_address_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `RemoteUnknownTlv` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_unknown_tlv_sync, remote_unknown_tlv_sync
  void remote_unknown_tlv_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteUnknownTlv` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_remote_unknown_tlv_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `RemoteUnknownTlv` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_remote_unknown_tlv_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable remote_unknown_tlv_sync() const;

private:
  explicit LldpRemoteSystem(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_LLDP_REMOTE_SYSTEM_H
