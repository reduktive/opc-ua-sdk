// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORICAL_EXTERNAL_EVENT_SOURCE_H
#define UA_HISTORICAL_EXTERNAL_EVENT_SOURCE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class HistoricalExternalEventSource;
using HistoricalExternalEventSourceResult = Result<HistoricalExternalEventSource>;

/// Address-space handle for the OPC UA HistoricalExternalEventSourceType ObjectType.
/// @ingroup ua_information_model
class HistoricalExternalEventSource : public BaseObject
{
public:
  /// Constructs an empty `HistoricalExternalEventSource` handle that references no node.
  HistoricalExternalEventSource() = default;

  /// Completion callback for create_async: receives the created `HistoricalExternalEventSource` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(HistoricalExternalEventSourceResult)>;
  /// Completion callback for attach_async: receives the attached `HistoricalExternalEventSource` handle, or
  /// an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(HistoricalExternalEventSourceResult)>;

  /// Creates a new `HistoricalExternalEventSourceType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `HistoricalExternalEventSource` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `HistoricalExternalEventSourceType` instance under `parent`, blocking until complete.  ///
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
  static HistoricalExternalEventSourceResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `HistoricalExternalEventSourceType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `HistoricalExternalEventSource` handle. A Good subcode is not returned; @ref
  /// try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static HistoricalExternalEventSource create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `HistoricalExternalEventSourceType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `HistoricalExternalEventSource` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `HistoricalExternalEventSourceType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static HistoricalExternalEventSourceResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `HistoricalExternalEventSourceType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `HistoricalExternalEventSource` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static HistoricalExternalEventSource attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Server` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_server_property_sync, server_property_sync
  void server_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Server` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_server_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Server` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_server_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property server_property_sync() const;

  /// Attaches a `Property` handle for the `EndpointUrl` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_endpoint_url_property_sync, endpoint_url_property_sync
  void endpoint_url_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EndpointUrl` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_endpoint_url_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EndpointUrl` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_endpoint_url_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property endpoint_url_property_sync() const;

  /// Attaches a `Property` handle for the `SecurityMode` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_security_mode_property_sync, security_mode_property_sync
  void security_mode_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SecurityMode` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_security_mode_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SecurityMode` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_security_mode_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property security_mode_property_sync() const;

  /// Attaches a `Property` handle for the `SecurityPolicyUri` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_security_policy_uri_property_sync, security_policy_uri_property_sync
  void security_policy_uri_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SecurityPolicyUri` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_security_policy_uri_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SecurityPolicyUri` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_security_policy_uri_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property security_policy_uri_property_sync() const;

  /// Attaches a `Property` handle for the `IdentityTokenPolicy` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_identity_token_policy_property_sync, identity_token_policy_property_sync
  void identity_token_policy_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IdentityTokenPolicy` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_identity_token_policy_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IdentityTokenPolicy` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_identity_token_policy_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property identity_token_policy_property_sync() const;

  /// Attaches a `Property` handle for the `TransportProfileUri` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_transport_profile_uri_property_sync, transport_profile_uri_property_sync
  void transport_profile_uri_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `TransportProfileUri` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_transport_profile_uri_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `TransportProfileUri` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_transport_profile_uri_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property transport_profile_uri_property_sync() const;

  /// Attaches a `Property` handle for the `HistoricalEventFilter` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_historical_event_filter_property_sync, historical_event_filter_property_sync
  void historical_event_filter_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `HistoricalEventFilter` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_historical_event_filter_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `HistoricalEventFilter` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_historical_event_filter_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property historical_event_filter_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `Server` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_server_sync, read_server_sync
  void read_server_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `Server` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_server_async gives it. Never throws.
  StringResult try_read_server_sync() const noexcept;
  /// Reads the `Server` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_server_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_server_sync() const;

  /// Reads the `EndpointUrl` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_endpoint_url_sync, read_endpoint_url_sync
  void read_endpoint_url_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `EndpointUrl` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_endpoint_url_async gives it. Never throws.
  StringResult try_read_endpoint_url_sync() const noexcept;
  /// Reads the `EndpointUrl` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_endpoint_url_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_endpoint_url_sync() const;

  /// Reads the `SecurityPolicyUri` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_security_policy_uri_sync, read_security_policy_uri_sync
  void read_security_policy_uri_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `SecurityPolicyUri` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_security_policy_uri_async gives it. Never throws.
  StringResult try_read_security_policy_uri_sync() const noexcept;
  /// Reads the `SecurityPolicyUri` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_security_policy_uri_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_security_policy_uri_sync() const;

  /// Reads the `TransportProfileUri` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_transport_profile_uri_sync, read_transport_profile_uri_sync
  void read_transport_profile_uri_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `TransportProfileUri` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_transport_profile_uri_async gives it. Never throws.
  StringResult try_read_transport_profile_uri_sync() const noexcept;
  /// Reads the `TransportProfileUri` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_transport_profile_uri_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_transport_profile_uri_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `Server` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_server_sync, write_server_sync
  void write_server_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Server` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_server_sync(String value) const noexcept;
  /// Writes the `Server` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_server_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_server_sync(String value) const;

  /// Writes the `EndpointUrl` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_endpoint_url_sync, write_endpoint_url_sync
  void write_endpoint_url_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `EndpointUrl` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_endpoint_url_sync(String value) const noexcept;
  /// Writes the `EndpointUrl` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_endpoint_url_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_endpoint_url_sync(String value) const;

  /// Writes the `SecurityPolicyUri` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_security_policy_uri_sync, write_security_policy_uri_sync
  void write_security_policy_uri_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SecurityPolicyUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_security_policy_uri_sync(String value) const noexcept;
  /// Writes the `SecurityPolicyUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_security_policy_uri_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_security_policy_uri_sync(String value) const;

  /// Writes the `TransportProfileUri` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_transport_profile_uri_sync, write_transport_profile_uri_sync
  void write_transport_profile_uri_async(
    String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `TransportProfileUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_transport_profile_uri_sync(String value) const noexcept;
  /// Writes the `TransportProfileUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_transport_profile_uri_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_transport_profile_uri_sync(String value) const;

private:
  explicit HistoricalExternalEventSource(
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

#endif  // UA_HISTORICAL_EXTERNAL_EVENT_SOURCE_H
