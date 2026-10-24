// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_IETF_BASE_NETWORK_INTERFACE_H
#define UA_IETF_BASE_NETWORK_INTERFACE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_base_data_variable.h"
#include "ua_analog_unit.h"

namespace ua
{

struct MethodCallContext;

class IetfBaseNetworkInterface;
using IetfBaseNetworkInterfaceResult = Result<IetfBaseNetworkInterface>;

/// Address-space handle for the OPC UA IetfBaseNetworkInterfaceType ObjectType.
/// @ingroup ua_information_model
class IetfBaseNetworkInterface : public BaseObject
{
public:
  /// Constructs an empty `IetfBaseNetworkInterface` handle that references no node.
  IetfBaseNetworkInterface() = default;

  /// Completion callback for create_async: receives the created `IetfBaseNetworkInterface` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(IetfBaseNetworkInterfaceResult)>;
  /// Completion callback for attach_async: receives the attached `IetfBaseNetworkInterface` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(IetfBaseNetworkInterfaceResult)>;

  /// Creates a new `IetfBaseNetworkInterfaceType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `IetfBaseNetworkInterface` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `IetfBaseNetworkInterfaceType` instance under `parent`, blocking until complete.  ///
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
  static IetfBaseNetworkInterfaceResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `IetfBaseNetworkInterfaceType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `IetfBaseNetworkInterface` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static IetfBaseNetworkInterface create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `IetfBaseNetworkInterfaceType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `IetfBaseNetworkInterface` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `IetfBaseNetworkInterfaceType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static IetfBaseNetworkInterfaceResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `IetfBaseNetworkInterfaceType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `IetfBaseNetworkInterface` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static IetfBaseNetworkInterface attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `BaseDataVariable` handle for the `AdminStatus` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_admin_status_sync, admin_status_sync
  void admin_status_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `AdminStatus` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_admin_status_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `AdminStatus` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_admin_status_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable admin_status_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `OperStatus` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_oper_status_sync, oper_status_sync
  void oper_status_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `OperStatus` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_oper_status_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `OperStatus` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_oper_status_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable oper_status_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `PhysAddress` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_phys_address_sync, phys_address_sync
  void phys_address_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `PhysAddress` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_phys_address_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `PhysAddress` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_phys_address_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable phys_address_sync() const;

  /// Attaches a typed `AnalogUnit` handle for the `Speed` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_speed_sync, speed_sync
  void speed_async(std::function<void(AnalogUnitResult)> complete) const noexcept;
  /// Attaches a typed `AnalogUnit` handle for the `Speed` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  AnalogUnitResult try_speed_sync() const noexcept;
  /// Attaches a typed `AnalogUnit` handle for the `Speed` child, blocking until complete.
  /// @return The `AnalogUnit` handle. A Good subcode is not returned; @ref try_speed_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  AnalogUnit speed_sync() const;

private:
  explicit IetfBaseNetworkInterface(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_IETF_BASE_NETWORK_INTERFACE_H
