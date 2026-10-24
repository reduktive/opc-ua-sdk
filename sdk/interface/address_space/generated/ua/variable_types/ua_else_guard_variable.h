// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ELSE_GUARD_VARIABLE_H
#define UA_ELSE_GUARD_VARIABLE_H

#include "ua_base_data_variable.h"

namespace ua
{

class ElseGuardVariable;
using ElseGuardVariableResult = Result<ElseGuardVariable>;

/// Address-space handle for the OPC UA ElseGuardVariableType VariableType.
/// @ingroup ua_information_model
class ElseGuardVariable final : public BaseDataVariable
{
public:
  /// Constructs an empty `ElseGuardVariable` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  ElseGuardVariable() = default;

  /// Completion callback for create_async: receives the new `ElseGuardVariable` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ElseGuardVariableResult)>;
  /// Completion callback for attach_async: receives the wrapped `ElseGuardVariable` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ElseGuardVariableResult)>;

  /// Creates a new `ElseGuardVariableType` variable under `parent`.
  ///
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @param complete     Receives the outcome: on success a `ElseGuardVariable` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `ElseGuardVariableType` variable under `parent`, blocking until complete.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @return The new handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_async
  static ElseGuardVariableResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `ElseGuardVariableType` variable under `parent`, blocking until complete.
  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node
  /// and its subtree from the address space. Call `release()` to keep the node as
  /// permanent server content, or `remove_async()` to delete it eagerly. A handle
  /// obtained through `attach_*` owns nothing and only references the node.
  /// @param addressSpace Address space the variable is created in.
  /// @param parent       Parent node the new variable is organized under.
  /// @param browseName   Browse name for the new variable.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param attributes   Variable attributes (data type, value rank, access level, ...).
  /// @return The new `ElseGuardVariable` handle. A Good subcode is not returned; @ref try_create_sync returns
  /// it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ElseGuardVariable create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `ElseGuardVariableType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `ElseGuardVariable` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ElseGuardVariableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ElseGuardVariableResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ElseGuardVariableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `ElseGuardVariable` handle. A Good subcode is not returned; @ref try_attach_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ElseGuardVariable attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

private:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  ElseGuardVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

private:
  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, VariableInstantiationAttributes attributes,
    CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;
};

}  // namespace ua

#endif  // UA_ELSE_GUARD_VARIABLE_H
