// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_DIAGNOSTICS_H
#define UA_SERVER_DIAGNOSTICS_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class ServerDiagnostics;
using ServerDiagnosticsResult = Result<ServerDiagnostics>;

/// Address-space handle for the OPC UA ServerDiagnosticsType ObjectType.
/// @ingroup ua_information_model
class ServerDiagnostics : public BaseObject
{
public:
  /// Constructs an empty `ServerDiagnostics` handle that references no node.
  ServerDiagnostics() = default;

  /// Completion callback for create_async: receives the created `ServerDiagnostics` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ServerDiagnosticsResult)>;
  /// Completion callback for attach_async: receives the attached `ServerDiagnostics` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ServerDiagnosticsResult)>;

  /// Creates a new `ServerDiagnosticsType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ServerDiagnostics` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ServerDiagnosticsType` instance under `parent`, blocking until complete.  ///
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
  static ServerDiagnosticsResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ServerDiagnosticsType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ServerDiagnostics` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ServerDiagnostics create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ServerDiagnosticsType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ServerDiagnostics` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ServerDiagnosticsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ServerDiagnosticsResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ServerDiagnosticsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ServerDiagnostics` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ServerDiagnostics attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `EnabledFlag` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_enabled_flag_property_sync, enabled_flag_property_sync
  void enabled_flag_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EnabledFlag` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_enabled_flag_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EnabledFlag` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_enabled_flag_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property enabled_flag_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `EnabledFlag` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_enabled_flag_sync, read_enabled_flag_sync
  void read_enabled_flag_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `EnabledFlag` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_enabled_flag_async gives it. Never throws.
  BoolResult try_read_enabled_flag_sync() const noexcept;
  /// Reads the `EnabledFlag` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_enabled_flag_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_enabled_flag_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `EnabledFlag` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_enabled_flag_sync, write_enabled_flag_sync
  void write_enabled_flag_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `EnabledFlag` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_enabled_flag_sync(bool value) const noexcept;
  /// Writes the `EnabledFlag` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_enabled_flag_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_enabled_flag_sync(bool value) const;

private:
  explicit ServerDiagnostics(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_SERVER_DIAGNOSTICS_H
