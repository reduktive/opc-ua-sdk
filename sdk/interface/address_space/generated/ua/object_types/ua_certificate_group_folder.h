// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CERTIFICATE_GROUP_FOLDER_H
#define UA_CERTIFICATE_GROUP_FOLDER_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_certificate_group.h"

namespace ua
{

struct MethodCallContext;

class CertificateGroupFolder;
using CertificateGroupFolderResult = Result<CertificateGroupFolder>;

/// Address-space handle for the OPC UA CertificateGroupFolderType ObjectType.
/// @ingroup ua_information_model
class CertificateGroupFolder : public BaseObject
{
public:
  /// Constructs an empty `CertificateGroupFolder` handle that references no node.
  CertificateGroupFolder() = default;

  /// Completion callback for create_async: receives the created `CertificateGroupFolder` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(CertificateGroupFolderResult)>;
  /// Completion callback for attach_async: receives the attached `CertificateGroupFolder` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(CertificateGroupFolderResult)>;

  /// Creates a new `CertificateGroupFolderType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `CertificateGroupFolder` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `CertificateGroupFolderType` instance under `parent`, blocking until complete.  ///
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
  static CertificateGroupFolderResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `CertificateGroupFolderType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `CertificateGroupFolder` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static CertificateGroupFolder create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `CertificateGroupFolderType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `CertificateGroupFolder` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `CertificateGroupFolderType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static CertificateGroupFolderResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `CertificateGroupFolderType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `CertificateGroupFolder` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static CertificateGroupFolder attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `CertificateGroup` handle for the `DefaultApplicationGroup` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_default_application_group_sync, default_application_group_sync
  void default_application_group_async(std::function<void(CertificateGroupResult)> complete) const noexcept;
  /// Attaches a typed `CertificateGroup` handle for the `DefaultApplicationGroup` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  CertificateGroupResult try_default_application_group_sync() const noexcept;
  /// Attaches a typed `CertificateGroup` handle for the `DefaultApplicationGroup` child, blocking until
  /// complete.
  /// @return The `CertificateGroup` handle. A Good subcode is not returned; @ref
  /// try_default_application_group_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  CertificateGroup default_application_group_sync() const;

  /// Attaches a typed `CertificateGroup` handle for the `DefaultHttpsGroup` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_default_https_group_sync, default_https_group_sync
  void default_https_group_async(std::function<void(CertificateGroupResult)> complete) const noexcept;
  /// Attaches a typed `CertificateGroup` handle for the `DefaultHttpsGroup` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  CertificateGroupResult try_default_https_group_sync() const noexcept;
  /// Attaches a typed `CertificateGroup` handle for the `DefaultHttpsGroup` child, blocking until complete.
  /// @return The `CertificateGroup` handle. A Good subcode is not returned; @ref try_default_https_group_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  CertificateGroup default_https_group_sync() const;

  /// Attaches a typed `CertificateGroup` handle for the `DefaultUserTokenGroup` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_default_user_token_group_sync, default_user_token_group_sync
  void default_user_token_group_async(std::function<void(CertificateGroupResult)> complete) const noexcept;
  /// Attaches a typed `CertificateGroup` handle for the `DefaultUserTokenGroup` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  CertificateGroupResult try_default_user_token_group_sync() const noexcept;
  /// Attaches a typed `CertificateGroup` handle for the `DefaultUserTokenGroup` child, blocking until
  /// complete.
  /// @return The `CertificateGroup` handle. A Good subcode is not returned; @ref
  /// try_default_user_token_group_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  CertificateGroup default_user_token_group_sync() const;

private:
  explicit CertificateGroupFolder(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_CERTIFICATE_GROUP_FOLDER_H
