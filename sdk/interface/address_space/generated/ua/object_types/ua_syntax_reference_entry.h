// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SYNTAX_REFERENCE_ENTRY_H
#define UA_SYNTAX_REFERENCE_ENTRY_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class SyntaxReferenceEntry;
using SyntaxReferenceEntryResult = Result<SyntaxReferenceEntry>;

/// Address-space handle for the OPC UA SyntaxReferenceEntryType ObjectType.
/// @ingroup ua_information_model
class SyntaxReferenceEntry : public BaseObject
{
public:
  /// Constructs an empty `SyntaxReferenceEntry` handle that references no node.
  SyntaxReferenceEntry() = default;

  /// Completion callback for create_async: receives the created `SyntaxReferenceEntry` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(SyntaxReferenceEntryResult)>;
  /// Completion callback for attach_async: receives the attached `SyntaxReferenceEntry` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(SyntaxReferenceEntryResult)>;

  /// Creates a new `SyntaxReferenceEntryType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `SyntaxReferenceEntry` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `SyntaxReferenceEntryType` instance under `parent`, blocking until complete.  ///
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
  static SyntaxReferenceEntryResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `SyntaxReferenceEntryType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `SyntaxReferenceEntry` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static SyntaxReferenceEntry create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `SyntaxReferenceEntryType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `SyntaxReferenceEntry` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `SyntaxReferenceEntryType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static SyntaxReferenceEntryResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `SyntaxReferenceEntryType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `SyntaxReferenceEntry` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static SyntaxReferenceEntry attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `CommonName` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_common_name_property_sync, common_name_property_sync
  void common_name_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CommonName` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_common_name_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CommonName` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_common_name_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property common_name_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `CommonName` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_common_name_sync, read_common_name_sync
  void read_common_name_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `CommonName` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_common_name_async gives it. Never throws.
  StringResult try_read_common_name_sync() const noexcept;
  /// Reads the `CommonName` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_common_name_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_common_name_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `CommonName` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_common_name_sync, write_common_name_sync
  void write_common_name_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CommonName` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_common_name_sync(String value) const noexcept;
  /// Writes the `CommonName` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_common_name_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_common_name_sync(String value) const;

private:
  explicit SyntaxReferenceEntry(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_SYNTAX_REFERENCE_ENTRY_H
