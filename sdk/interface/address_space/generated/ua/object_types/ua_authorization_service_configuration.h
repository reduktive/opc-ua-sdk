// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AUTHORIZATION_SERVICE_CONFIGURATION_H
#define UA_AUTHORIZATION_SERVICE_CONFIGURATION_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class AuthorizationServiceConfiguration;
using AuthorizationServiceConfigurationResult = Result<AuthorizationServiceConfiguration>;

/// Address-space handle for the OPC UA AuthorizationServiceConfigurationType ObjectType.
/// @ingroup ua_information_model
class AuthorizationServiceConfiguration : public BaseObject
{
public:
  /// Constructs an empty `AuthorizationServiceConfiguration` handle that references no node.
  AuthorizationServiceConfiguration() = default;

  /// Completion callback for create_async: receives the created `AuthorizationServiceConfiguration` handle,
  /// or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(AuthorizationServiceConfigurationResult)>;
  /// Completion callback for attach_async: receives the attached `AuthorizationServiceConfiguration` handle,
  /// or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(AuthorizationServiceConfigurationResult)>;

  /// Creates a new `AuthorizationServiceConfigurationType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `AuthorizationServiceConfiguration` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `AuthorizationServiceConfigurationType` instance under `parent`, blocking until complete.
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
  static AuthorizationServiceConfigurationResult try_create_sync(AddressSpace addressSpace,
    const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `AuthorizationServiceConfigurationType` instance under `parent`, blocking until complete.
  /// ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `AuthorizationServiceConfiguration` handle. A Good subcode is not returned; @ref
  /// try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static AuthorizationServiceConfiguration create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `AuthorizationServiceConfigurationType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `AuthorizationServiceConfiguration` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `AuthorizationServiceConfigurationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static AuthorizationServiceConfigurationResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `AuthorizationServiceConfigurationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `AuthorizationServiceConfiguration` handle. A Good subcode is not returned; @ref
  /// try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static AuthorizationServiceConfiguration attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `ServiceUri` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_service_uri_property_sync, service_uri_property_sync
  void service_uri_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ServiceUri` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_service_uri_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ServiceUri` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_service_uri_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property service_uri_property_sync() const;

  /// Attaches a `Property` handle for the `ServiceCertificate` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_service_certificate_property_sync, service_certificate_property_sync
  void service_certificate_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ServiceCertificate` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_service_certificate_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ServiceCertificate` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_service_certificate_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property service_certificate_property_sync() const;

  /// Attaches a `Property` handle for the `IssuerEndpointUrl` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_issuer_endpoint_url_property_sync, issuer_endpoint_url_property_sync
  void issuer_endpoint_url_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IssuerEndpointUrl` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_issuer_endpoint_url_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IssuerEndpointUrl` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_issuer_endpoint_url_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property issuer_endpoint_url_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `ServiceUri` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_service_uri_sync, read_service_uri_sync
  void read_service_uri_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `ServiceUri` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_service_uri_async gives it. Never throws.
  StringResult try_read_service_uri_sync() const noexcept;
  /// Reads the `ServiceUri` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_service_uri_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_service_uri_sync() const;

  /// Reads the `ServiceCertificate` property value, typed as `ByteString`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_service_certificate_sync, read_service_certificate_sync
  void read_service_certificate_async(std::function<void(ByteStringResult)> complete) const noexcept;
  /// Reads the `ServiceCertificate` property value as `ByteString`, blocking until complete.
  /// @return The value with the read's code, as @ref read_service_certificate_async gives it. Never throws.
  ByteStringResult try_read_service_certificate_sync() const noexcept;
  /// Reads the `ServiceCertificate` property value as `ByteString`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_service_certificate_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  ByteString read_service_certificate_sync() const;

  /// Reads the `IssuerEndpointUrl` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_issuer_endpoint_url_sync, read_issuer_endpoint_url_sync
  void read_issuer_endpoint_url_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `IssuerEndpointUrl` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_issuer_endpoint_url_async gives it. Never throws.
  StringResult try_read_issuer_endpoint_url_sync() const noexcept;
  /// Reads the `IssuerEndpointUrl` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_issuer_endpoint_url_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_issuer_endpoint_url_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `ServiceUri` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_service_uri_sync, write_service_uri_sync
  void write_service_uri_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ServiceUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_service_uri_sync(String value) const noexcept;
  /// Writes the `ServiceUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_service_uri_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_service_uri_sync(String value) const;

  /// Writes the `ServiceCertificate` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_service_certificate_sync, write_service_certificate_sync
  void write_service_certificate_async(
    ByteString value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ServiceCertificate` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_service_certificate_sync(ByteString value) const noexcept;
  /// Writes the `ServiceCertificate` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_service_certificate_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_service_certificate_sync(ByteString value) const;

  /// Writes the `IssuerEndpointUrl` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_issuer_endpoint_url_sync, write_issuer_endpoint_url_sync
  void write_issuer_endpoint_url_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `IssuerEndpointUrl` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_issuer_endpoint_url_sync(String value) const noexcept;
  /// Writes the `IssuerEndpointUrl` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_issuer_endpoint_url_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_issuer_endpoint_url_sync(String value) const;

private:
  explicit AuthorizationServiceConfiguration(
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

#endif  // UA_AUTHORIZATION_SERVICE_CONFIGURATION_H
