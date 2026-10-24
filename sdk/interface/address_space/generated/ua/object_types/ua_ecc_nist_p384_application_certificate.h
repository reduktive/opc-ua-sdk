// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ECC_NIST_P384_APPLICATION_CERTIFICATE_H
#define UA_ECC_NIST_P384_APPLICATION_CERTIFICATE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class EccNistP384ApplicationCertificate;
using EccNistP384ApplicationCertificateResult = Result<EccNistP384ApplicationCertificate>;

/// Address-space handle for the OPC UA EccNistP384ApplicationCertificateType ObjectType.
/// @ingroup ua_information_model
class EccNistP384ApplicationCertificate : public BaseObject
{
public:
  /// Constructs an empty `EccNistP384ApplicationCertificate` handle that references no node.
  EccNistP384ApplicationCertificate() = default;

  /// Completion callback for create_async: receives the created `EccNistP384ApplicationCertificate` handle,
  /// or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(EccNistP384ApplicationCertificateResult)>;
  /// Completion callback for attach_async: receives the attached `EccNistP384ApplicationCertificate` handle,
  /// or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(EccNistP384ApplicationCertificateResult)>;

  /// Creates a new `EccNistP384ApplicationCertificateType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `EccNistP384ApplicationCertificate` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `EccNistP384ApplicationCertificateType` instance under `parent`, blocking until complete.
  /// ///
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
  static EccNistP384ApplicationCertificateResult try_create_sync(AddressSpace addressSpace,
    const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `EccNistP384ApplicationCertificateType` instance under `parent`, blocking until complete.
  /// ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `EccNistP384ApplicationCertificate` handle. A Good subcode is not returned; @ref
  /// try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static EccNistP384ApplicationCertificate create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `EccNistP384ApplicationCertificateType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `EccNistP384ApplicationCertificate` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `EccNistP384ApplicationCertificateType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static EccNistP384ApplicationCertificateResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `EccNistP384ApplicationCertificateType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `EccNistP384ApplicationCertificate` handle. A Good subcode is not returned; @ref
  /// try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static EccNistP384ApplicationCertificate attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance);

private:
  explicit EccNistP384ApplicationCertificate(
    AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_ECC_NIST_P384_APPLICATION_CERTIFICATE_H
