// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CERTIFICATE_GROUP_H
#define UA_CERTIFICATE_GROUP_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_trust_list.h"
#include "ua_certificate_expiration_alarm.h"
#include "ua_trust_list_out_of_date_alarm.h"

namespace ua
{

struct MethodCallContext;

class CertificateGroup;
using CertificateGroupResult = Result<CertificateGroup>;

/// Address-space handle for the OPC UA CertificateGroupType ObjectType.
/// @ingroup ua_information_model
class CertificateGroup : public BaseObject
{
public:
  /// Constructs an empty `CertificateGroup` handle that references no node.
  CertificateGroup() = default;

  /// Output arguments for the CertificateGroupType GetRejectedList() method.
  struct GetRejectedListOutputArguments
  {
    std::vector<ByteString> certificates;  ///< Certificates.
  };

  /// Synchronous handler for GetRejectedList(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using GetRejectedListHandler =
    std::function<MethodResult<GetRejectedListOutputArguments>(const MethodCall&)>;
  /// Asynchronous handler for GetRejectedList(): starts the work and completes it through the callback, once,
  /// from any thread.
  using GetRejectedListAsyncHandler =
    std::function<void(const MethodCall&, MethodResultCallback<GetRejectedListOutputArguments>)>;

  /// Completion callback for create_async: receives the created `CertificateGroup` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(CertificateGroupResult)>;
  /// Completion callback for attach_async: receives the attached `CertificateGroup` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(CertificateGroupResult)>;

  /// Creates a new `CertificateGroupType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `CertificateGroup` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `CertificateGroupType` instance under `parent`, blocking until complete.  ///
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
  static CertificateGroupResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `CertificateGroupType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `CertificateGroup` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static CertificateGroup create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `CertificateGroupType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `CertificateGroup` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `CertificateGroupType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static CertificateGroupResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `CertificateGroupType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `CertificateGroup` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static CertificateGroup attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `GetRejectedList` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_rejected_list_method_sync, get_rejected_list_method_sync
  void get_rejected_list_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `GetRejectedList` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_get_rejected_list_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `GetRejectedList` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_get_rejected_list_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor get_rejected_list_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `CertificateTypes` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_certificate_types_property_sync, certificate_types_property_sync
  void certificate_types_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CertificateTypes` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_certificate_types_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CertificateTypes` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_certificate_types_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property certificate_types_property_sync() const;

  /// Attaches a `Property` handle for the `Purpose` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_purpose_property_sync, purpose_property_sync
  void purpose_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Purpose` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_purpose_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Purpose` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_purpose_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property purpose_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `CertificateTypes` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_certificate_types_sync, read_certificate_types_sync
  void read_certificate_types_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `CertificateTypes` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_certificate_types_async gives it. Never throws.
  NodeIdResult try_read_certificate_types_sync() const noexcept;
  /// Reads the `CertificateTypes` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_certificate_types_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_certificate_types_sync() const;

  /// Reads the `Purpose` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_purpose_sync, read_purpose_sync
  void read_purpose_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `Purpose` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_purpose_async gives it. Never throws.
  NodeIdResult try_read_purpose_sync() const noexcept;
  /// Reads the `Purpose` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_purpose_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_purpose_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `CertificateTypes` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_certificate_types_sync, write_certificate_types_sync
  void write_certificate_types_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CertificateTypes` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_certificate_types_sync(NodeId value) const noexcept;
  /// Writes the `CertificateTypes` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_certificate_types_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_certificate_types_sync(NodeId value) const;

  /// Writes the `Purpose` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_purpose_sync, write_purpose_sync
  void write_purpose_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Purpose` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_purpose_sync(NodeId value) const noexcept;
  /// Writes the `Purpose` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_purpose_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_purpose_sync(NodeId value) const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `GetRejectedList` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_rejected_list_handler_sync, set_get_rejected_list_handler_sync
  void set_get_rejected_list_handler_async(
    GetRejectedListHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `GetRejectedList` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_rejected_list_handler_sync(GetRejectedListHandler handler) const noexcept;
  /// Registers the synchronous `GetRejectedList` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_rejected_list_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_rejected_list_handler_sync(GetRejectedListHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `GetRejectedList` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_rejected_list_handler_sync, set_get_rejected_list_handler_sync
  void set_get_rejected_list_handler_async(
    GetRejectedListAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `GetRejectedList` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_rejected_list_handler_sync(GetRejectedListAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `GetRejectedList` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_rejected_list_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_rejected_list_handler_sync(GetRejectedListAsyncHandler handler) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `TrustList` handle for the `TrustList` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_trust_list_sync, trust_list_sync
  void trust_list_async(std::function<void(TrustListResult)> complete) const noexcept;
  /// Attaches a typed `TrustList` handle for the `TrustList` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TrustListResult try_trust_list_sync() const noexcept;
  /// Attaches a typed `TrustList` handle for the `TrustList` child, blocking until complete.
  /// @return The `TrustList` handle. A Good subcode is not returned; @ref try_trust_list_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TrustList trust_list_sync() const;

  /// Attaches a typed `CertificateExpirationAlarm` handle for the `CertificateExpired` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_certificate_expired_sync, certificate_expired_sync
  void certificate_expired_async(
    std::function<void(CertificateExpirationAlarmResult)> complete) const noexcept;
  /// Attaches a typed `CertificateExpirationAlarm` handle for the `CertificateExpired` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  CertificateExpirationAlarmResult try_certificate_expired_sync() const noexcept;
  /// Attaches a typed `CertificateExpirationAlarm` handle for the `CertificateExpired` child, blocking until
  /// complete.
  /// @return The `CertificateExpirationAlarm` handle. A Good subcode is not returned; @ref
  /// try_certificate_expired_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  CertificateExpirationAlarm certificate_expired_sync() const;

  /// Attaches a typed `TrustListOutOfDateAlarm` handle for the `TrustListOutOfDate` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_trust_list_out_of_date_sync, trust_list_out_of_date_sync
  void trust_list_out_of_date_async(
    std::function<void(TrustListOutOfDateAlarmResult)> complete) const noexcept;
  /// Attaches a typed `TrustListOutOfDateAlarm` handle for the `TrustListOutOfDate` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  TrustListOutOfDateAlarmResult try_trust_list_out_of_date_sync() const noexcept;
  /// Attaches a typed `TrustListOutOfDateAlarm` handle for the `TrustListOutOfDate` child, blocking until
  /// complete.
  /// @return The `TrustListOutOfDateAlarm` handle. A Good subcode is not returned; @ref
  /// try_trust_list_out_of_date_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  TrustListOutOfDateAlarm trust_list_out_of_date_sync() const;

private:
  explicit CertificateGroup(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_CERTIFICATE_GROUP_H
