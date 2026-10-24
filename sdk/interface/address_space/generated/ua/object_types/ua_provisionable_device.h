// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_PROVISIONABLE_DEVICE_H
#define UA_PROVISIONABLE_DEVICE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class ProvisionableDevice;
using ProvisionableDeviceResult = Result<ProvisionableDevice>;

/// Address-space handle for the OPC UA ProvisionableDeviceType ObjectType.
/// @ingroup ua_information_model
class ProvisionableDevice : public BaseObject
{
public:
  /// Constructs an empty `ProvisionableDevice` handle that references no node.
  ProvisionableDevice() = default;

  /// Output arguments for the ProvisionableDeviceType RequestTickets() method.
  struct RequestTicketsOutputArguments
  {
    std::vector<Variant> tickets;  ///< Tickets.
  };

  /// Synchronous handler for RequestTickets(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using RequestTicketsHandler = std::function<MethodResult<RequestTicketsOutputArguments>(const MethodCall&)>;
  /// Asynchronous handler for RequestTickets(): starts the work and completes it through the callback, once,
  /// from any thread.
  using RequestTicketsAsyncHandler =
    std::function<void(const MethodCall&, MethodResultCallback<RequestTicketsOutputArguments>)>;

  /// Input arguments for the ProvisionableDeviceType SetRegistrarEndpoints() method.
  struct SetRegistrarEndpointsInputArguments
  {
    std::vector<Variant> registrars;  ///< Registrars.
  };

  /// Synchronous handler for SetRegistrarEndpoints(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using SetRegistrarEndpointsHandler =
    std::function<MethodResult<>(const MethodCall&, const SetRegistrarEndpointsInputArguments&)>;
  /// Asynchronous handler for SetRegistrarEndpoints(): starts the work and completes it through the callback,
  /// once, from any thread.
  using SetRegistrarEndpointsAsyncHandler = std::function<void(
    const MethodCall&, const SetRegistrarEndpointsInputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `ProvisionableDevice` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ProvisionableDeviceResult)>;
  /// Completion callback for attach_async: receives the attached `ProvisionableDevice` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ProvisionableDeviceResult)>;

  /// Creates a new `ProvisionableDeviceType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ProvisionableDevice` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ProvisionableDeviceType` instance under `parent`, blocking until complete.  ///
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
  static ProvisionableDeviceResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ProvisionableDeviceType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ProvisionableDevice` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ProvisionableDevice create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ProvisionableDeviceType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ProvisionableDevice` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ProvisionableDeviceType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ProvisionableDeviceResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ProvisionableDeviceType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ProvisionableDevice` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ProvisionableDevice attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RequestTickets` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_request_tickets_method_sync, request_tickets_method_sync
  void request_tickets_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RequestTickets` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_request_tickets_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RequestTickets` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_request_tickets_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor request_tickets_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `SetRegistrarEndpoints` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_registrar_endpoints_method_sync, set_registrar_endpoints_method_sync
  void set_registrar_endpoints_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `SetRegistrarEndpoints` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_set_registrar_endpoints_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `SetRegistrarEndpoints` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_set_registrar_endpoints_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor set_registrar_endpoints_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `IsSingleton` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_is_singleton_property_sync, is_singleton_property_sync
  void is_singleton_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IsSingleton` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_is_singleton_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IsSingleton` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_is_singleton_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property is_singleton_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `IsSingleton` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_is_singleton_sync, read_is_singleton_sync
  void read_is_singleton_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `IsSingleton` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_is_singleton_async gives it. Never throws.
  BoolResult try_read_is_singleton_sync() const noexcept;
  /// Reads the `IsSingleton` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_is_singleton_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_is_singleton_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `IsSingleton` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_is_singleton_sync, write_is_singleton_sync
  void write_is_singleton_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `IsSingleton` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_is_singleton_sync(bool value) const noexcept;
  /// Writes the `IsSingleton` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_is_singleton_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_is_singleton_sync(bool value) const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `RequestTickets` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_request_tickets_handler_sync, set_request_tickets_handler_sync
  void set_request_tickets_handler_async(
    RequestTicketsHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RequestTickets` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_request_tickets_handler_sync(RequestTicketsHandler handler) const noexcept;
  /// Registers the synchronous `RequestTickets` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_request_tickets_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_request_tickets_handler_sync(RequestTicketsHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RequestTickets` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_request_tickets_handler_sync, set_request_tickets_handler_sync
  void set_request_tickets_handler_async(
    RequestTicketsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RequestTickets` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_request_tickets_handler_sync(RequestTicketsAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RequestTickets` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_request_tickets_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_request_tickets_handler_sync(RequestTicketsAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `SetRegistrarEndpoints` method, in
  /// place of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_set_registrar_endpoints_handler_sync, set_set_registrar_endpoints_handler_sync
  void set_set_registrar_endpoints_handler_async(
    SetRegistrarEndpointsHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `SetRegistrarEndpoints` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_set_registrar_endpoints_handler_sync(
    SetRegistrarEndpointsHandler handler) const noexcept;
  /// Registers the synchronous `SetRegistrarEndpoints` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_set_registrar_endpoints_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_set_registrar_endpoints_handler_sync(SetRegistrarEndpointsHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `SetRegistrarEndpoints` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_set_registrar_endpoints_handler_sync, set_set_registrar_endpoints_handler_sync
  void set_set_registrar_endpoints_handler_async(
    SetRegistrarEndpointsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `SetRegistrarEndpoints` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_set_registrar_endpoints_handler_sync(
    SetRegistrarEndpointsAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `SetRegistrarEndpoints` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_set_registrar_endpoints_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_set_registrar_endpoints_handler_sync(SetRegistrarEndpointsAsyncHandler handler) const;

private:
  explicit ProvisionableDevice(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_PROVISIONABLE_DEVICE_H
