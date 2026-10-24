// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REFERENCE_DEMO_DEMO_H
#define UA_REFERENCE_DEMO_DEMO_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_base_data_variable.h"
#include "ua_reference_demo_aliases.h"

namespace ua::reference_demo
{

using ::ua::MethodCallContext;

class Demo;
using DemoResult = ::ua::Result<Demo>;

// Helper representing an instantiated OPC UA `DemoType` object in the address space.
class Demo : public BaseObject
{
public:
  /// Constructs an empty `Demo` handle that references no node.
  Demo() = default;

  /// Input arguments for the DemoType Divide() method.
  struct DivideInputArguments
  {
    int32_t numerator{};  ///< Numerator.
    int32_t divisor{};  ///< Divisor.
  };

  /// Output arguments for the DemoType Divide() method.
  struct DivideOutputArguments
  {
    int32_t quotient{};  ///< Quotient.
  };

  /// Synchronous handler for Divide(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using DivideHandler = std::function<::ua::MethodResult<DivideOutputArguments>(
    const ::ua::MethodCall&, const DivideInputArguments&)>;
  /// Asynchronous handler for Divide(): starts the work and completes it through the callback, once, from any
  /// thread.
  using DivideAsyncHandler = std::function<void(
    const ::ua::MethodCall&, const DivideInputArguments&, ::ua::MethodResultCallback<DivideOutputArguments>)>;

  /// Completion callback for create_async: receives the created `Demo` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(DemoResult)>;
  /// Completion callback for attach_async: receives the attached `Demo` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(DemoResult)>;

  /// Creates a new `DemoType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `Demo` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `DemoType` instance under `parent`, blocking until complete.  ///
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
  static DemoResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `DemoType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `Demo` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static Demo create_sync(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options);

  /// Wraps an existing node as a `DemoType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `Demo` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `DemoType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static DemoResult try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `DemoType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `Demo` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static Demo attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `Divide` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_divide_method_sync, divide_method_sync
  void divide_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `Divide` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_divide_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `Divide` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_divide_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor divide_method_sync() const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `Divide` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_divide_handler_sync, set_divide_handler_sync
  void set_divide_handler_async(DivideHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `Divide` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_divide_handler_sync(DivideHandler handler) const noexcept;
  /// Registers the synchronous `Divide` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_divide_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_divide_handler_sync(DivideHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `Divide` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_divide_handler_sync, set_divide_handler_sync
  void set_divide_handler_async(
    DivideAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `Divide` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_divide_handler_sync(DivideAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `Divide` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_divide_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_divide_handler_sync(DivideAsyncHandler handler) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `BaseDataVariable` handle for the `UptimeSeconds` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_uptime_seconds_sync, uptime_seconds_sync
  void uptime_seconds_async(std::function<void(::ua::BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `UptimeSeconds` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  ::ua::BaseDataVariableResult try_uptime_seconds_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `UptimeSeconds` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_uptime_seconds_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  ::ua::BaseDataVariable uptime_seconds_sync() const;

  /// Attaches a typed `BaseDataVariable` handle for the `Setpoint` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_setpoint_sync, setpoint_sync
  void setpoint_async(std::function<void(::ua::BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `Setpoint` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  ::ua::BaseDataVariableResult try_setpoint_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `Setpoint` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_setpoint_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  ::ua::BaseDataVariable setpoint_sync() const;

private:
  explicit Demo(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua::reference_demo

#endif  // UA_REFERENCE_DEMO_DEMO_H
