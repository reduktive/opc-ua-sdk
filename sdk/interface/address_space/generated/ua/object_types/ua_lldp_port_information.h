// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_LLDP_PORT_INFORMATION_H
#define UA_LLDP_PORT_INFORMATION_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_folder.h"

namespace ua
{

struct MethodCallContext;

class LldpPortInformation;
using LldpPortInformationResult = Result<LldpPortInformation>;

/// Address-space handle for the OPC UA LldpPortInformationType ObjectType.
/// @ingroup ua_information_model
class LldpPortInformation : public BaseObject
{
public:
  /// Constructs an empty `LldpPortInformation` handle that references no node.
  LldpPortInformation() = default;

  /// Completion callback for create_async: receives the created `LldpPortInformation` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(LldpPortInformationResult)>;
  /// Completion callback for attach_async: receives the attached `LldpPortInformation` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(LldpPortInformationResult)>;

  /// Creates a new `LldpPortInformationType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `LldpPortInformation` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `LldpPortInformationType` instance under `parent`, blocking until complete.  ///
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
  static LldpPortInformationResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `LldpPortInformationType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `LldpPortInformation` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static LldpPortInformation create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `LldpPortInformationType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `LldpPortInformation` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `LldpPortInformationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static LldpPortInformationResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `LldpPortInformationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `LldpPortInformation` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static LldpPortInformation attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `IetfBaseNetworkInterfaceName` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_ietf_base_network_interface_name_property_sync, ietf_base_network_interface_name_property_sync
  void ietf_base_network_interface_name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IetfBaseNetworkInterfaceName` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_ietf_base_network_interface_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IetfBaseNetworkInterfaceName` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_ietf_base_network_interface_name_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property ietf_base_network_interface_name_property_sync() const;

  /// Attaches a `Property` handle for the `DestMacAddress` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_dest_mac_address_property_sync, dest_mac_address_property_sync
  void dest_mac_address_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `DestMacAddress` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_dest_mac_address_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `DestMacAddress` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_dest_mac_address_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property dest_mac_address_property_sync() const;

  /// Attaches a `Property` handle for the `PortIdSubtype` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_port_id_subtype_property_sync, port_id_subtype_property_sync
  void port_id_subtype_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `PortIdSubtype` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_port_id_subtype_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `PortIdSubtype` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_port_id_subtype_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property port_id_subtype_property_sync() const;

  /// Attaches a `Property` handle for the `PortId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_port_id_property_sync, port_id_property_sync
  void port_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `PortId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_port_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `PortId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_port_id_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property port_id_property_sync() const;

  /// Attaches a `Property` handle for the `PortDescription` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_port_description_property_sync, port_description_property_sync
  void port_description_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `PortDescription` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_port_description_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `PortDescription` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_port_description_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property port_description_property_sync() const;

  /// Attaches a `Property` handle for the `ManagementAddressTxPort` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_management_address_tx_port_property_sync, management_address_tx_port_property_sync
  void management_address_tx_port_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ManagementAddressTxPort` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_management_address_tx_port_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ManagementAddressTxPort` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_management_address_tx_port_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property management_address_tx_port_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `IetfBaseNetworkInterfaceName` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_ietf_base_network_interface_name_sync, read_ietf_base_network_interface_name_sync
  void read_ietf_base_network_interface_name_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `IetfBaseNetworkInterfaceName` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_ietf_base_network_interface_name_async gives it.
  /// Never throws.
  StringResult try_read_ietf_base_network_interface_name_sync() const noexcept;
  /// Reads the `IetfBaseNetworkInterfaceName` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_ietf_base_network_interface_name_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_ietf_base_network_interface_name_sync() const;

  /// Reads the `DestMacAddress` property value, typed as `uint8_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_dest_mac_address_sync, read_dest_mac_address_sync
  void read_dest_mac_address_async(std::function<void(UInt8Result)> complete) const noexcept;
  /// Reads the `DestMacAddress` property value as `uint8_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_dest_mac_address_async gives it. Never throws.
  UInt8Result try_read_dest_mac_address_sync() const noexcept;
  /// Reads the `DestMacAddress` property value as `uint8_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_dest_mac_address_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint8_t read_dest_mac_address_sync() const;

  /// Reads the `PortId` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_port_id_sync, read_port_id_sync
  void read_port_id_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `PortId` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_port_id_async gives it. Never throws.
  StringResult try_read_port_id_sync() const noexcept;
  /// Reads the `PortId` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_port_id_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_port_id_sync() const;

  /// Reads the `PortDescription` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_port_description_sync, read_port_description_sync
  void read_port_description_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `PortDescription` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_port_description_async gives it. Never throws.
  StringResult try_read_port_description_sync() const noexcept;
  /// Reads the `PortDescription` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_port_description_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_port_description_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `IetfBaseNetworkInterfaceName` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_ietf_base_network_interface_name_sync, write_ietf_base_network_interface_name_sync
  void write_ietf_base_network_interface_name_async(
    String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `IetfBaseNetworkInterfaceName` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_ietf_base_network_interface_name_sync(String value) const noexcept;
  /// Writes the `IetfBaseNetworkInterfaceName` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_ietf_base_network_interface_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_ietf_base_network_interface_name_sync(String value) const;

  /// Writes the `DestMacAddress` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_dest_mac_address_sync, write_dest_mac_address_sync
  void write_dest_mac_address_async(uint8_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `DestMacAddress` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_dest_mac_address_sync(uint8_t value) const noexcept;
  /// Writes the `DestMacAddress` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_dest_mac_address_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_dest_mac_address_sync(uint8_t value) const;

  /// Writes the `PortId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_port_id_sync, write_port_id_sync
  void write_port_id_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `PortId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_port_id_sync(String value) const noexcept;
  /// Writes the `PortId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_port_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_port_id_sync(String value) const;

  /// Writes the `PortDescription` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_port_description_sync, write_port_description_sync
  void write_port_description_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `PortDescription` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_port_description_sync(String value) const noexcept;
  /// Writes the `PortDescription` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_port_description_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_port_description_sync(String value) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `Folder` handle for the `RemoteSystemsData` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remote_systems_data_sync, remote_systems_data_sync
  void remote_systems_data_async(std::function<void(FolderResult)> complete) const noexcept;
  /// Attaches a typed `Folder` handle for the `RemoteSystemsData` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  FolderResult try_remote_systems_data_sync() const noexcept;
  /// Attaches a typed `Folder` handle for the `RemoteSystemsData` child, blocking until complete.
  /// @return The `Folder` handle. A Good subcode is not returned; @ref try_remote_systems_data_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Folder remote_systems_data_sync() const;

private:
  explicit LldpPortInformation(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_LLDP_PORT_INFORMATION_H
