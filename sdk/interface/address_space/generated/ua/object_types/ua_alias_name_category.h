// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ALIAS_NAME_CATEGORY_H
#define UA_ALIAS_NAME_CATEGORY_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class AliasNameCategory;
using AliasNameCategoryResult = Result<AliasNameCategory>;

/// Address-space handle for the OPC UA AliasNameCategoryType ObjectType.
/// @ingroup ua_information_model
class AliasNameCategory : public BaseObject
{
public:
  /// Constructs an empty `AliasNameCategory` handle that references no node.
  AliasNameCategory() = default;

  /// Input arguments for the AliasNameCategoryType FindAlias() method.
  struct FindAliasInputArguments
  {
    String aliasNameSearchPattern;  ///< Alias name search pattern.
    NodeId referenceTypeFilter;  ///< Reference type filter.
  };

  /// Output arguments for the AliasNameCategoryType FindAlias() method.
  struct FindAliasOutputArguments
  {
    std::vector<Variant> aliasNodeList;  ///< Alias node list.
  };

  /// Synchronous handler for FindAlias(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using FindAliasHandler =
    std::function<MethodResult<FindAliasOutputArguments>(const MethodCall&, const FindAliasInputArguments&)>;
  /// Asynchronous handler for FindAlias(): starts the work and completes it through the callback, once, from
  /// any thread.
  using FindAliasAsyncHandler = std::function<void(
    const MethodCall&, const FindAliasInputArguments&, MethodResultCallback<FindAliasOutputArguments>)>;

  /// Completion callback for create_async: receives the created `AliasNameCategory` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(AliasNameCategoryResult)>;
  /// Completion callback for attach_async: receives the attached `AliasNameCategory` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(AliasNameCategoryResult)>;

  /// Creates a new `AliasNameCategoryType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `AliasNameCategory` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `AliasNameCategoryType` instance under `parent`, blocking until complete.  ///
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
  static AliasNameCategoryResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `AliasNameCategoryType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `AliasNameCategory` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static AliasNameCategory create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `AliasNameCategoryType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `AliasNameCategory` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `AliasNameCategoryType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static AliasNameCategoryResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `AliasNameCategoryType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `AliasNameCategory` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static AliasNameCategory attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `FindAlias` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_find_alias_method_sync, find_alias_method_sync
  void find_alias_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `FindAlias` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_find_alias_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `FindAlias` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_find_alias_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor find_alias_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `LastChange` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_change_property_sync, last_change_property_sync
  void last_change_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastChange` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_change_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastChange` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_last_change_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_change_property_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `FindAlias` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_find_alias_handler_sync, set_find_alias_handler_sync
  void set_find_alias_handler_async(
    FindAliasHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `FindAlias` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_find_alias_handler_sync(FindAliasHandler handler) const noexcept;
  /// Registers the synchronous `FindAlias` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_find_alias_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_find_alias_handler_sync(FindAliasHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `FindAlias` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_find_alias_handler_sync, set_find_alias_handler_sync
  void set_find_alias_handler_async(
    FindAliasAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `FindAlias` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_find_alias_handler_sync(FindAliasAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `FindAlias` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_find_alias_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_find_alias_handler_sync(FindAliasAsyncHandler handler) const;

private:
  explicit AliasNameCategory(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_ALIAS_NAME_CATEGORY_H
