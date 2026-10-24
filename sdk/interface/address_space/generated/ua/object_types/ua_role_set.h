// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ROLE_SET_H
#define UA_ROLE_SET_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class RoleSet;
using RoleSetResult = Result<RoleSet>;

/// Address-space handle for the OPC UA RoleSetType ObjectType.
/// @ingroup ua_information_model
class RoleSet : public BaseObject
{
public:
  /// Constructs an empty `RoleSet` handle that references no node.
  RoleSet() = default;

  /// Input arguments for the RoleSetType AddRole() method.
  struct AddRoleInputArguments
  {
    String roleName;  ///< Role name.
    String namespaceUri;  ///< Namespace uri.
  };

  /// Output arguments for the RoleSetType AddRole() method.
  struct AddRoleOutputArguments
  {
    NodeId roleNodeId;  ///< Role node id.
  };

  /// Synchronous handler for AddRole(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using AddRoleHandler =
    std::function<MethodResult<AddRoleOutputArguments>(const MethodCall&, const AddRoleInputArguments&)>;
  /// Asynchronous handler for AddRole(): starts the work and completes it through the callback, once, from
  /// any thread.
  using AddRoleAsyncHandler = std::function<void(
    const MethodCall&, const AddRoleInputArguments&, MethodResultCallback<AddRoleOutputArguments>)>;

  /// Input arguments for the RoleSetType RemoveRole() method.
  struct RemoveRoleInputArguments
  {
    NodeId roleNodeId;  ///< Role node id.
  };

  /// Synchronous handler for RemoveRole(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using RemoveRoleHandler = std::function<MethodResult<>(const MethodCall&, const RemoveRoleInputArguments&)>;
  /// Asynchronous handler for RemoveRole(): starts the work and completes it through the callback, once, from
  /// any thread.
  using RemoveRoleAsyncHandler =
    std::function<void(const MethodCall&, const RemoveRoleInputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `RoleSet` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(RoleSetResult)>;
  /// Completion callback for attach_async: receives the attached `RoleSet` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(RoleSetResult)>;

  /// Creates a new `RoleSetType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `RoleSet` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `RoleSetType` instance under `parent`, blocking until complete.  ///
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
  static RoleSetResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `RoleSetType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `RoleSet` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static RoleSet create_sync(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options);

  /// Wraps an existing node as a `RoleSetType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `RoleSet` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `RoleSetType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static RoleSetResult try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `RoleSetType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `RoleSet` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static RoleSet attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `AddRole` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_role_method_sync, add_role_method_sync
  void add_role_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `AddRole` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_add_role_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `AddRole` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_add_role_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor add_role_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RemoveRole` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_role_method_sync, remove_role_method_sync
  void remove_role_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveRole` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_remove_role_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveRole` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_remove_role_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor remove_role_method_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `AddRole` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_role_handler_sync, set_add_role_handler_sync
  void set_add_role_handler_async(
    AddRoleHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `AddRole` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_role_handler_sync(AddRoleHandler handler) const noexcept;
  /// Registers the synchronous `AddRole` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_role_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_role_handler_sync(AddRoleHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `AddRole` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_role_handler_sync, set_add_role_handler_sync
  void set_add_role_handler_async(
    AddRoleAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `AddRole` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_role_handler_sync(AddRoleAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `AddRole` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_role_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_role_handler_sync(AddRoleAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RemoveRole` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_role_handler_sync, set_remove_role_handler_sync
  void set_remove_role_handler_async(
    RemoveRoleHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RemoveRole` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_role_handler_sync(RemoveRoleHandler handler) const noexcept;
  /// Registers the synchronous `RemoveRole` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_role_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_role_handler_sync(RemoveRoleHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RemoveRole` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_role_handler_sync, set_remove_role_handler_sync
  void set_remove_role_handler_async(
    RemoveRoleAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RemoveRole` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_role_handler_sync(RemoveRoleAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RemoveRole` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_role_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_role_handler_sync(RemoveRoleAsyncHandler handler) const;

private:
  explicit RoleSet(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_ROLE_SET_H
