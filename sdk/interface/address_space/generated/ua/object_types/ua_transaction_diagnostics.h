// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TRANSACTION_DIAGNOSTICS_H
#define UA_TRANSACTION_DIAGNOSTICS_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class TransactionDiagnostics;
using TransactionDiagnosticsResult = Result<TransactionDiagnostics>;

/// Address-space handle for the OPC UA TransactionDiagnosticsType ObjectType.
/// @ingroup ua_information_model
class TransactionDiagnostics : public BaseObject
{
public:
  /// Constructs an empty `TransactionDiagnostics` handle that references no node.
  TransactionDiagnostics() = default;

  /// Completion callback for create_async: receives the created `TransactionDiagnostics` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(TransactionDiagnosticsResult)>;
  /// Completion callback for attach_async: receives the attached `TransactionDiagnostics` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(TransactionDiagnosticsResult)>;

  /// Creates a new `TransactionDiagnosticsType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `TransactionDiagnostics` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `TransactionDiagnosticsType` instance under `parent`, blocking until complete.  ///
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
  static TransactionDiagnosticsResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `TransactionDiagnosticsType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `TransactionDiagnostics` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static TransactionDiagnostics create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `TransactionDiagnosticsType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `TransactionDiagnostics` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `TransactionDiagnosticsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static TransactionDiagnosticsResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `TransactionDiagnosticsType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `TransactionDiagnostics` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static TransactionDiagnostics attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `StartTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_start_time_property_sync, start_time_property_sync
  void start_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `StartTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_start_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `StartTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_start_time_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property start_time_property_sync() const;

  /// Attaches a `Property` handle for the `EndTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_end_time_property_sync, end_time_property_sync
  void end_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EndTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_end_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EndTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_end_time_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property end_time_property_sync() const;

  /// Attaches a `Property` handle for the `Result` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_result_property_sync, result_property_sync
  void result_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Result` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_result_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Result` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_result_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property result_property_sync() const;

  /// Attaches a `Property` handle for the `AffectedTrustLists` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_affected_trust_lists_property_sync, affected_trust_lists_property_sync
  void affected_trust_lists_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `AffectedTrustLists` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_affected_trust_lists_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `AffectedTrustLists` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_affected_trust_lists_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property affected_trust_lists_property_sync() const;

  /// Attaches a `Property` handle for the `AffectedCertificateGroups` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_affected_certificate_groups_property_sync, affected_certificate_groups_property_sync
  void affected_certificate_groups_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `AffectedCertificateGroups` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_affected_certificate_groups_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `AffectedCertificateGroups` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_affected_certificate_groups_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property affected_certificate_groups_property_sync() const;

  /// Attaches a `Property` handle for the `Errors` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_errors_property_sync, errors_property_sync
  void errors_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Errors` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_errors_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Errors` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_errors_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property errors_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `Result` property value, typed as `StatusCode`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_result_sync, read_result_sync
  void read_result_async(std::function<void(Result<StatusCode>)> complete) const noexcept;
  /// Reads the `Result` property value as `StatusCode`, blocking until complete.
  /// @return The value with the read's code, as @ref read_result_async gives it. Never throws.
  Result<StatusCode> try_read_result_sync() const noexcept;
  /// Reads the `Result` property value as `StatusCode`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_result_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  StatusCode read_result_sync() const;

  /// Reads the `AffectedTrustLists` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_affected_trust_lists_sync, read_affected_trust_lists_sync
  void read_affected_trust_lists_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `AffectedTrustLists` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_affected_trust_lists_async gives it. Never throws.
  NodeIdResult try_read_affected_trust_lists_sync() const noexcept;
  /// Reads the `AffectedTrustLists` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_affected_trust_lists_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_affected_trust_lists_sync() const;

  /// Reads the `AffectedCertificateGroups` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_affected_certificate_groups_sync, read_affected_certificate_groups_sync
  void read_affected_certificate_groups_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `AffectedCertificateGroups` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_affected_certificate_groups_async gives it. Never
  /// throws.
  NodeIdResult try_read_affected_certificate_groups_sync() const noexcept;
  /// Reads the `AffectedCertificateGroups` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_affected_certificate_groups_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_affected_certificate_groups_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `Result` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_result_sync, write_result_sync
  void write_result_async(StatusCode value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Result` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_result_sync(StatusCode value) const noexcept;
  /// Writes the `Result` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_result_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_result_sync(StatusCode value) const;

  /// Writes the `AffectedTrustLists` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_affected_trust_lists_sync, write_affected_trust_lists_sync
  void write_affected_trust_lists_async(
    NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `AffectedTrustLists` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_affected_trust_lists_sync(NodeId value) const noexcept;
  /// Writes the `AffectedTrustLists` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_affected_trust_lists_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_affected_trust_lists_sync(NodeId value) const;

  /// Writes the `AffectedCertificateGroups` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_affected_certificate_groups_sync, write_affected_certificate_groups_sync
  void write_affected_certificate_groups_async(
    NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `AffectedCertificateGroups` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_affected_certificate_groups_sync(NodeId value) const noexcept;
  /// Writes the `AffectedCertificateGroups` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_affected_certificate_groups_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_affected_certificate_groups_sync(NodeId value) const;

private:
  explicit TransactionDiagnostics(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_TRANSACTION_DIAGNOSTICS_H
