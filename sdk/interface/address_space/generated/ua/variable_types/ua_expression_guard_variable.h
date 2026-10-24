// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EXPRESSION_GUARD_VARIABLE_H
#define UA_EXPRESSION_GUARD_VARIABLE_H

#include "ua_base_data_variable.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

class ExpressionGuardVariable;
using ExpressionGuardVariableResult = Result<ExpressionGuardVariable>;

/// Address-space handle for the OPC UA ExpressionGuardVariableType VariableType.
/// @ingroup ua_information_model
class ExpressionGuardVariable final : public BaseDataVariable
{
public:
  /// Constructs an empty `ExpressionGuardVariable` handle that refers to no node.
  ///
  /// Use create_async / attach_async (or their sync variants) to obtain a handle
  /// bound to a live address-space node.
  ExpressionGuardVariable() = default;

  /// Completion callback for create_async: receives the new `ExpressionGuardVariable` handle,
  /// or an @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ExpressionGuardVariableResult)>;
  /// Completion callback for attach_async: receives the wrapped `ExpressionGuardVariable` handle,
  /// or an @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ExpressionGuardVariableResult)>;

  /// Creates a new `ExpressionGuardVariableType` variable under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ExpressionGuardVariable` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, const VariableInstantiationAttributes& attributes,
    CreateCompleteCallback complete) noexcept;

  /// Creates a new `ExpressionGuardVariableType` variable under `parent`, blocking until complete.
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
  static ExpressionGuardVariableResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes) noexcept;

  /// Creates a new `ExpressionGuardVariableType` variable under `parent`, blocking until complete.
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
  /// @return The new `ExpressionGuardVariable` handle. A Good subcode is not returned; @ref try_create_sync
  /// returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ExpressionGuardVariable create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options,
    const VariableInstantiationAttributes& attributes);

  /// Wraps an existing node as a `ExpressionGuardVariableType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @param complete        Receives the outcome: on success a `ExpressionGuardVariable` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ExpressionGuardVariableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ExpressionGuardVariableResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ExpressionGuardVariableType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing variable to wrap.
  /// @return The `ExpressionGuardVariable` handle. A Good subcode is not returned; @ref try_attach_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ExpressionGuardVariable attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Expression` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_expression_property_sync, expression_property_sync
  void expression_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Expression` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_expression_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Expression` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_expression_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property expression_property_sync() const;

private:
  /// Binds the handle to an existing node; used internally by the create/attach flows.
  ///
  /// @param addressSpace Address space the node lives in.
  /// @param nodeId       Node id this handle refers to.
  /// @param owned        Owned subtree when the handle created the node (drives RAII
  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.
  ExpressionGuardVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

private:
  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, VariableInstantiationAttributes attributes,
    CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_EXPRESSION_GUARD_VARIABLE_H
