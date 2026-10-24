// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ROLE_H
#define UA_ROLE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class Role;
using RoleResult = Result<Role>;

/// Address-space handle for the OPC UA RoleType ObjectType.
/// @ingroup ua_information_model
class Role : public BaseObject
{
public:
  /// Constructs an empty `Role` handle that references no node.
  Role() = default;

  /// Input arguments for the RoleType AddIdentity() method.
  struct AddIdentityInputArguments
  {
    Variant rule;  ///< Rule.
  };

  /// Synchronous handler for AddIdentity(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using AddIdentityHandler =
    std::function<MethodResult<>(const MethodCall&, const AddIdentityInputArguments&)>;
  /// Asynchronous handler for AddIdentity(): starts the work and completes it through the callback, once,
  /// from any thread.
  using AddIdentityAsyncHandler =
    std::function<void(const MethodCall&, const AddIdentityInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the RoleType RemoveIdentity() method.
  struct RemoveIdentityInputArguments
  {
    Variant rule;  ///< Rule.
  };

  /// Synchronous handler for RemoveIdentity(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using RemoveIdentityHandler =
    std::function<MethodResult<>(const MethodCall&, const RemoveIdentityInputArguments&)>;
  /// Asynchronous handler for RemoveIdentity(): starts the work and completes it through the callback, once,
  /// from any thread.
  using RemoveIdentityAsyncHandler =
    std::function<void(const MethodCall&, const RemoveIdentityInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the RoleType AddApplication() method.
  struct AddApplicationInputArguments
  {
    String applicationUri;  ///< Application uri.
  };

  /// Synchronous handler for AddApplication(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using AddApplicationHandler =
    std::function<MethodResult<>(const MethodCall&, const AddApplicationInputArguments&)>;
  /// Asynchronous handler for AddApplication(): starts the work and completes it through the callback, once,
  /// from any thread.
  using AddApplicationAsyncHandler =
    std::function<void(const MethodCall&, const AddApplicationInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the RoleType RemoveApplication() method.
  struct RemoveApplicationInputArguments
  {
    String applicationUri;  ///< Application uri.
  };

  /// Synchronous handler for RemoveApplication(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using RemoveApplicationHandler =
    std::function<MethodResult<>(const MethodCall&, const RemoveApplicationInputArguments&)>;
  /// Asynchronous handler for RemoveApplication(): starts the work and completes it through the callback,
  /// once, from any thread.
  using RemoveApplicationAsyncHandler =
    std::function<void(const MethodCall&, const RemoveApplicationInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the RoleType AddEndpoint() method.
  struct AddEndpointInputArguments
  {
    Variant endpoint;  ///< Endpoint.
  };

  /// Synchronous handler for AddEndpoint(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using AddEndpointHandler =
    std::function<MethodResult<>(const MethodCall&, const AddEndpointInputArguments&)>;
  /// Asynchronous handler for AddEndpoint(): starts the work and completes it through the callback, once,
  /// from any thread.
  using AddEndpointAsyncHandler =
    std::function<void(const MethodCall&, const AddEndpointInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the RoleType RemoveEndpoint() method.
  struct RemoveEndpointInputArguments
  {
    Variant endpoint;  ///< Endpoint.
  };

  /// Synchronous handler for RemoveEndpoint(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using RemoveEndpointHandler =
    std::function<MethodResult<>(const MethodCall&, const RemoveEndpointInputArguments&)>;
  /// Asynchronous handler for RemoveEndpoint(): starts the work and completes it through the callback, once,
  /// from any thread.
  using RemoveEndpointAsyncHandler =
    std::function<void(const MethodCall&, const RemoveEndpointInputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `Role` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(RoleResult)>;
  /// Completion callback for attach_async: receives the attached `Role` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(RoleResult)>;

  /// Creates a new `RoleType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `Role` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `RoleType` instance under `parent`, blocking until complete.  ///
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
  static RoleResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `RoleType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `Role` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static Role create_sync(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options);

  /// Wraps an existing node as a `RoleType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `Role` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `RoleType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static RoleResult try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `RoleType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `Role` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static Role attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `AddIdentity` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_identity_method_sync, add_identity_method_sync
  void add_identity_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `AddIdentity` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_add_identity_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `AddIdentity` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_add_identity_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor add_identity_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RemoveIdentity` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_identity_method_sync, remove_identity_method_sync
  void remove_identity_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveIdentity` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_remove_identity_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveIdentity` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_remove_identity_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor remove_identity_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `AddApplication` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_application_method_sync, add_application_method_sync
  void add_application_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `AddApplication` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_add_application_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `AddApplication` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_add_application_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor add_application_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RemoveApplication` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_application_method_sync, remove_application_method_sync
  void remove_application_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveApplication` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_remove_application_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveApplication` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_remove_application_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor remove_application_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `AddEndpoint` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_endpoint_method_sync, add_endpoint_method_sync
  void add_endpoint_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `AddEndpoint` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_add_endpoint_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `AddEndpoint` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_add_endpoint_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor add_endpoint_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RemoveEndpoint` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_endpoint_method_sync, remove_endpoint_method_sync
  void remove_endpoint_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveEndpoint` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_remove_endpoint_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveEndpoint` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_remove_endpoint_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor remove_endpoint_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Identities` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_identities_property_sync, identities_property_sync
  void identities_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Identities` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_identities_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Identities` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_identities_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property identities_property_sync() const;

  /// Attaches a `Property` handle for the `ApplicationsExclude` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_applications_exclude_property_sync, applications_exclude_property_sync
  void applications_exclude_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ApplicationsExclude` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_applications_exclude_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ApplicationsExclude` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_applications_exclude_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property applications_exclude_property_sync() const;

  /// Attaches a `Property` handle for the `Applications` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_applications_property_sync, applications_property_sync
  void applications_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Applications` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_applications_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Applications` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_applications_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property applications_property_sync() const;

  /// Attaches a `Property` handle for the `EndpointsExclude` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_endpoints_exclude_property_sync, endpoints_exclude_property_sync
  void endpoints_exclude_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EndpointsExclude` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_endpoints_exclude_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EndpointsExclude` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_endpoints_exclude_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property endpoints_exclude_property_sync() const;

  /// Attaches a `Property` handle for the `Endpoints` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_endpoints_property_sync, endpoints_property_sync
  void endpoints_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Endpoints` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_endpoints_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Endpoints` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_endpoints_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property endpoints_property_sync() const;

  /// Attaches a `Property` handle for the `CustomConfiguration` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_custom_configuration_property_sync, custom_configuration_property_sync
  void custom_configuration_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CustomConfiguration` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_custom_configuration_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CustomConfiguration` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_custom_configuration_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property custom_configuration_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `ApplicationsExclude` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_applications_exclude_sync, read_applications_exclude_sync
  void read_applications_exclude_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `ApplicationsExclude` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_applications_exclude_async gives it. Never throws.
  BoolResult try_read_applications_exclude_sync() const noexcept;
  /// Reads the `ApplicationsExclude` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_applications_exclude_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_applications_exclude_sync() const;

  /// Reads the `Applications` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_applications_sync, read_applications_sync
  void read_applications_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `Applications` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_applications_async gives it. Never throws.
  StringResult try_read_applications_sync() const noexcept;
  /// Reads the `Applications` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_applications_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_applications_sync() const;

  /// Reads the `EndpointsExclude` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_endpoints_exclude_sync, read_endpoints_exclude_sync
  void read_endpoints_exclude_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `EndpointsExclude` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_endpoints_exclude_async gives it. Never throws.
  BoolResult try_read_endpoints_exclude_sync() const noexcept;
  /// Reads the `EndpointsExclude` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_endpoints_exclude_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_endpoints_exclude_sync() const;

  /// Reads the `CustomConfiguration` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_custom_configuration_sync, read_custom_configuration_sync
  void read_custom_configuration_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `CustomConfiguration` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_custom_configuration_async gives it. Never throws.
  BoolResult try_read_custom_configuration_sync() const noexcept;
  /// Reads the `CustomConfiguration` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_custom_configuration_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_custom_configuration_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `ApplicationsExclude` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_applications_exclude_sync, write_applications_exclude_sync
  void write_applications_exclude_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ApplicationsExclude` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_applications_exclude_sync(bool value) const noexcept;
  /// Writes the `ApplicationsExclude` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_applications_exclude_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_applications_exclude_sync(bool value) const;

  /// Writes the `Applications` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_applications_sync, write_applications_sync
  void write_applications_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Applications` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_applications_sync(String value) const noexcept;
  /// Writes the `Applications` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_applications_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_applications_sync(String value) const;

  /// Writes the `EndpointsExclude` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_endpoints_exclude_sync, write_endpoints_exclude_sync
  void write_endpoints_exclude_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `EndpointsExclude` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_endpoints_exclude_sync(bool value) const noexcept;
  /// Writes the `EndpointsExclude` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_endpoints_exclude_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_endpoints_exclude_sync(bool value) const;

  /// Writes the `CustomConfiguration` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_custom_configuration_sync, write_custom_configuration_sync
  void write_custom_configuration_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CustomConfiguration` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_custom_configuration_sync(bool value) const noexcept;
  /// Writes the `CustomConfiguration` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_custom_configuration_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_custom_configuration_sync(bool value) const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `AddIdentity` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_identity_handler_sync, set_add_identity_handler_sync
  void set_add_identity_handler_async(
    AddIdentityHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `AddIdentity` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_identity_handler_sync(AddIdentityHandler handler) const noexcept;
  /// Registers the synchronous `AddIdentity` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_identity_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_identity_handler_sync(AddIdentityHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `AddIdentity` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_identity_handler_sync, set_add_identity_handler_sync
  void set_add_identity_handler_async(
    AddIdentityAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `AddIdentity` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_identity_handler_sync(AddIdentityAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `AddIdentity` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_identity_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_identity_handler_sync(AddIdentityAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RemoveIdentity` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_identity_handler_sync, set_remove_identity_handler_sync
  void set_remove_identity_handler_async(
    RemoveIdentityHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RemoveIdentity` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_identity_handler_sync(RemoveIdentityHandler handler) const noexcept;
  /// Registers the synchronous `RemoveIdentity` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_identity_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_identity_handler_sync(RemoveIdentityHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RemoveIdentity` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_identity_handler_sync, set_remove_identity_handler_sync
  void set_remove_identity_handler_async(
    RemoveIdentityAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RemoveIdentity` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_identity_handler_sync(RemoveIdentityAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RemoveIdentity` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_identity_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_identity_handler_sync(RemoveIdentityAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `AddApplication` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_application_handler_sync, set_add_application_handler_sync
  void set_add_application_handler_async(
    AddApplicationHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `AddApplication` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_application_handler_sync(AddApplicationHandler handler) const noexcept;
  /// Registers the synchronous `AddApplication` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_application_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_application_handler_sync(AddApplicationHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `AddApplication` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_application_handler_sync, set_add_application_handler_sync
  void set_add_application_handler_async(
    AddApplicationAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `AddApplication` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_application_handler_sync(AddApplicationAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `AddApplication` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_application_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_application_handler_sync(AddApplicationAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RemoveApplication` method, in place
  /// of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_application_handler_sync, set_remove_application_handler_sync
  void set_remove_application_handler_async(
    RemoveApplicationHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RemoveApplication` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_application_handler_sync(RemoveApplicationHandler handler) const noexcept;
  /// Registers the synchronous `RemoveApplication` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_application_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_application_handler_sync(RemoveApplicationHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RemoveApplication` method, in place
  /// of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_application_handler_sync, set_remove_application_handler_sync
  void set_remove_application_handler_async(
    RemoveApplicationAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RemoveApplication` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_application_handler_sync(RemoveApplicationAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RemoveApplication` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_application_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_application_handler_sync(RemoveApplicationAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `AddEndpoint` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_endpoint_handler_sync, set_add_endpoint_handler_sync
  void set_add_endpoint_handler_async(
    AddEndpointHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `AddEndpoint` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_endpoint_handler_sync(AddEndpointHandler handler) const noexcept;
  /// Registers the synchronous `AddEndpoint` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_endpoint_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_endpoint_handler_sync(AddEndpointHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `AddEndpoint` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_endpoint_handler_sync, set_add_endpoint_handler_sync
  void set_add_endpoint_handler_async(
    AddEndpointAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `AddEndpoint` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_endpoint_handler_sync(AddEndpointAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `AddEndpoint` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_endpoint_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_endpoint_handler_sync(AddEndpointAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RemoveEndpoint` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_endpoint_handler_sync, set_remove_endpoint_handler_sync
  void set_remove_endpoint_handler_async(
    RemoveEndpointHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RemoveEndpoint` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_endpoint_handler_sync(RemoveEndpointHandler handler) const noexcept;
  /// Registers the synchronous `RemoveEndpoint` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_endpoint_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_endpoint_handler_sync(RemoveEndpointHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RemoveEndpoint` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_endpoint_handler_sync, set_remove_endpoint_handler_sync
  void set_remove_endpoint_handler_async(
    RemoveEndpointAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RemoveEndpoint` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_endpoint_handler_sync(RemoveEndpointAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RemoveEndpoint` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_endpoint_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_endpoint_handler_sync(RemoveEndpointAsyncHandler handler) const;

private:
  explicit Role(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_ROLE_H
