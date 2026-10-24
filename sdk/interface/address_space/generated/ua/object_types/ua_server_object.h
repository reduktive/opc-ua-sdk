// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_OBJECT_H
#define UA_SERVER_OBJECT_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_server_status.h"
#include "ua_server_capabilities.h"
#include "ua_server_diagnostics.h"
#include "ua_vendor_server_info.h"
#include "ua_server_redundancy.h"
#include "ua_namespaces.h"

namespace ua
{

struct MethodCallContext;

class ServerObject;
using ServerObjectResult = Result<ServerObject>;

/// Address-space handle for the OPC UA ServerType ObjectType.
/// @ingroup ua_information_model
class ServerObject : public BaseObject
{
public:
  /// Constructs an empty `ServerObject` handle that references no node.
  ServerObject() = default;

  /// Input arguments for the ServerType GetMonitoredItems() method.
  struct GetMonitoredItemsInputArguments
  {
    uint32_t subscriptionId{};  ///< Subscription id.
  };

  /// Output arguments for the ServerType GetMonitoredItems() method.
  struct GetMonitoredItemsOutputArguments
  {
    std::vector<uint32_t> serverHandles;  ///< Server handles.
    std::vector<uint32_t> clientHandles;  ///< Client handles.
  };

  /// Synchronous handler for GetMonitoredItems(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using GetMonitoredItemsHandler = std::function<MethodResult<GetMonitoredItemsOutputArguments>(
    const MethodCall&, const GetMonitoredItemsInputArguments&)>;
  /// Asynchronous handler for GetMonitoredItems(): starts the work and completes it through the callback,
  /// once, from any thread.
  using GetMonitoredItemsAsyncHandler = std::function<void(const MethodCall&,
    const GetMonitoredItemsInputArguments&, MethodResultCallback<GetMonitoredItemsOutputArguments>)>;

  /// Input arguments for the ServerType ResendData() method.
  struct ResendDataInputArguments
  {
    uint32_t subscriptionId{};  ///< Subscription id.
  };

  /// Synchronous handler for ResendData(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using ResendDataHandler = std::function<MethodResult<>(const MethodCall&, const ResendDataInputArguments&)>;
  /// Asynchronous handler for ResendData(): starts the work and completes it through the callback, once, from
  /// any thread.
  using ResendDataAsyncHandler =
    std::function<void(const MethodCall&, const ResendDataInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the ServerType SetSubscriptionDurable() method.
  struct SetSubscriptionDurableInputArguments
  {
    uint32_t subscriptionId{};  ///< Subscription id.
    uint32_t lifetimeInHours{};  ///< Lifetime in hours.
  };

  /// Output arguments for the ServerType SetSubscriptionDurable() method.
  struct SetSubscriptionDurableOutputArguments
  {
    uint32_t revisedLifetimeInHours{};  ///< Revised lifetime in hours.
  };

  /// Synchronous handler for SetSubscriptionDurable(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using SetSubscriptionDurableHandler = std::function<MethodResult<SetSubscriptionDurableOutputArguments>(
    const MethodCall&, const SetSubscriptionDurableInputArguments&)>;
  /// Asynchronous handler for SetSubscriptionDurable(): starts the work and completes it through the
  /// callback, once, from any thread.
  using SetSubscriptionDurableAsyncHandler =
    std::function<void(const MethodCall&, const SetSubscriptionDurableInputArguments&,
      MethodResultCallback<SetSubscriptionDurableOutputArguments>)>;

  /// Input arguments for the ServerType RequestServerStateChange() method.
  struct RequestServerStateChangeInputArguments
  {
    Variant state;  ///< State.
    DateTime estimatedReturnTime{};  ///< Estimated return time.
    uint32_t secondsTillShutdown{};  ///< Seconds till shutdown.
    LocalizedText reason;  ///< Reason.
    bool restart{};  ///< Restart.
  };

  /// Synchronous handler for RequestServerStateChange(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using RequestServerStateChangeHandler =
    std::function<MethodResult<>(const MethodCall&, const RequestServerStateChangeInputArguments&)>;
  /// Asynchronous handler for RequestServerStateChange(): starts the work and completes it through the
  /// callback, once, from any thread.
  using RequestServerStateChangeAsyncHandler = std::function<void(
    const MethodCall&, const RequestServerStateChangeInputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `ServerObject` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ServerObjectResult)>;
  /// Completion callback for attach_async: receives the attached `ServerObject` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ServerObjectResult)>;

  /// Creates a new `ServerType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ServerObject` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ServerType` instance under `parent`, blocking until complete.  ///
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
  static ServerObjectResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ServerType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ServerObject` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ServerObject create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ServerType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ServerObject` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ServerType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ServerObjectResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ServerType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ServerObject` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ServerObject attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `GetMonitoredItems` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_monitored_items_method_sync, get_monitored_items_method_sync
  void get_monitored_items_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `GetMonitoredItems` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_get_monitored_items_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `GetMonitoredItems` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_get_monitored_items_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor get_monitored_items_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `ResendData` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_resend_data_method_sync, resend_data_method_sync
  void resend_data_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `ResendData` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_resend_data_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `ResendData` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_resend_data_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor resend_data_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `SetSubscriptionDurable` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_subscription_durable_method_sync, set_subscription_durable_method_sync
  void set_subscription_durable_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `SetSubscriptionDurable` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_set_subscription_durable_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `SetSubscriptionDurable` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_set_subscription_durable_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor set_subscription_durable_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RequestServerStateChange` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_request_server_state_change_method_sync, request_server_state_change_method_sync
  void request_server_state_change_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RequestServerStateChange` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_request_server_state_change_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RequestServerStateChange` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_request_server_state_change_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor request_server_state_change_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `ServerArray` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_server_array_property_sync, server_array_property_sync
  void server_array_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ServerArray` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_server_array_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ServerArray` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_server_array_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property server_array_property_sync() const;

  /// Attaches a `Property` handle for the `NamespaceArray` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_namespace_array_property_sync, namespace_array_property_sync
  void namespace_array_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `NamespaceArray` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_namespace_array_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `NamespaceArray` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_namespace_array_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property namespace_array_property_sync() const;

  /// Attaches a `Property` handle for the `UrisVersion` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_uris_version_property_sync, uris_version_property_sync
  void uris_version_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `UrisVersion` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_uris_version_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `UrisVersion` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_uris_version_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property uris_version_property_sync() const;

  /// Attaches a `Property` handle for the `ServiceLevel` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_service_level_property_sync, service_level_property_sync
  void service_level_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ServiceLevel` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_service_level_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ServiceLevel` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_service_level_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property service_level_property_sync() const;

  /// Attaches a `Property` handle for the `Auditing` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_auditing_property_sync, auditing_property_sync
  void auditing_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Auditing` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_auditing_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Auditing` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_auditing_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property auditing_property_sync() const;

  /// Attaches a `Property` handle for the `EstimatedReturnTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_estimated_return_time_property_sync, estimated_return_time_property_sync
  void estimated_return_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EstimatedReturnTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_estimated_return_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EstimatedReturnTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_estimated_return_time_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property estimated_return_time_property_sync() const;

  /// Attaches a `Property` handle for the `LocalTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_local_time_property_sync, local_time_property_sync
  void local_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LocalTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_local_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LocalTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_local_time_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property local_time_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `ServerArray` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_server_array_sync, read_server_array_sync
  void read_server_array_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `ServerArray` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_server_array_async gives it. Never throws.
  StringResult try_read_server_array_sync() const noexcept;
  /// Reads the `ServerArray` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_server_array_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_server_array_sync() const;

  /// Reads the `NamespaceArray` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_namespace_array_sync, read_namespace_array_sync
  void read_namespace_array_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `NamespaceArray` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_namespace_array_async gives it. Never throws.
  StringResult try_read_namespace_array_sync() const noexcept;
  /// Reads the `NamespaceArray` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_namespace_array_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_namespace_array_sync() const;

  /// Reads the `ServiceLevel` property value, typed as `uint8_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_service_level_sync, read_service_level_sync
  void read_service_level_async(std::function<void(UInt8Result)> complete) const noexcept;
  /// Reads the `ServiceLevel` property value as `uint8_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_service_level_async gives it. Never throws.
  UInt8Result try_read_service_level_sync() const noexcept;
  /// Reads the `ServiceLevel` property value as `uint8_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_service_level_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint8_t read_service_level_sync() const;

  /// Reads the `Auditing` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_auditing_sync, read_auditing_sync
  void read_auditing_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `Auditing` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_auditing_async gives it. Never throws.
  BoolResult try_read_auditing_sync() const noexcept;
  /// Reads the `Auditing` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_auditing_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_auditing_sync() const;

  /// Reads the `EstimatedReturnTime` property value, typed as `DateTime`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_estimated_return_time_sync, read_estimated_return_time_sync
  void read_estimated_return_time_async(std::function<void(DateTimeResult)> complete) const noexcept;
  /// Reads the `EstimatedReturnTime` property value as `DateTime`, blocking until complete.
  /// @return The value with the read's code, as @ref read_estimated_return_time_async gives it. Never throws.
  DateTimeResult try_read_estimated_return_time_sync() const noexcept;
  /// Reads the `EstimatedReturnTime` property value as `DateTime`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_estimated_return_time_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  DateTime read_estimated_return_time_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `ServerArray` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_server_array_sync, write_server_array_sync
  void write_server_array_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ServerArray` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_server_array_sync(String value) const noexcept;
  /// Writes the `ServerArray` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_server_array_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_server_array_sync(String value) const;

  /// Writes the `NamespaceArray` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_namespace_array_sync, write_namespace_array_sync
  void write_namespace_array_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `NamespaceArray` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_namespace_array_sync(String value) const noexcept;
  /// Writes the `NamespaceArray` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_namespace_array_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_namespace_array_sync(String value) const;

  /// Writes the `ServiceLevel` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_service_level_sync, write_service_level_sync
  void write_service_level_async(uint8_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ServiceLevel` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_service_level_sync(uint8_t value) const noexcept;
  /// Writes the `ServiceLevel` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_service_level_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_service_level_sync(uint8_t value) const;

  /// Writes the `Auditing` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_auditing_sync, write_auditing_sync
  void write_auditing_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Auditing` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_auditing_sync(bool value) const noexcept;
  /// Writes the `Auditing` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_auditing_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_auditing_sync(bool value) const;

  /// Writes the `EstimatedReturnTime` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_estimated_return_time_sync, write_estimated_return_time_sync
  void write_estimated_return_time_async(
    DateTime value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `EstimatedReturnTime` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_estimated_return_time_sync(DateTime value) const noexcept;
  /// Writes the `EstimatedReturnTime` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_estimated_return_time_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_estimated_return_time_sync(DateTime value) const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `GetMonitoredItems` method, in place
  /// of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_monitored_items_handler_sync, set_get_monitored_items_handler_sync
  void set_get_monitored_items_handler_async(
    GetMonitoredItemsHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `GetMonitoredItems` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_monitored_items_handler_sync(GetMonitoredItemsHandler handler) const noexcept;
  /// Registers the synchronous `GetMonitoredItems` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_monitored_items_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_monitored_items_handler_sync(GetMonitoredItemsHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `GetMonitoredItems` method, in place
  /// of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_monitored_items_handler_sync, set_get_monitored_items_handler_sync
  void set_get_monitored_items_handler_async(
    GetMonitoredItemsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `GetMonitoredItems` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_monitored_items_handler_sync(GetMonitoredItemsAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `GetMonitoredItems` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_monitored_items_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_monitored_items_handler_sync(GetMonitoredItemsAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `ResendData` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_resend_data_handler_sync, set_resend_data_handler_sync
  void set_resend_data_handler_async(
    ResendDataHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `ResendData` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_resend_data_handler_sync(ResendDataHandler handler) const noexcept;
  /// Registers the synchronous `ResendData` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_resend_data_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_resend_data_handler_sync(ResendDataHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `ResendData` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_resend_data_handler_sync, set_resend_data_handler_sync
  void set_resend_data_handler_async(
    ResendDataAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `ResendData` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_resend_data_handler_sync(ResendDataAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `ResendData` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_resend_data_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_resend_data_handler_sync(ResendDataAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `SetSubscriptionDurable` method, in
  /// place of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_set_subscription_durable_handler_sync, set_set_subscription_durable_handler_sync
  void set_set_subscription_durable_handler_async(
    SetSubscriptionDurableHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `SetSubscriptionDurable` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_set_subscription_durable_handler_sync(
    SetSubscriptionDurableHandler handler) const noexcept;
  /// Registers the synchronous `SetSubscriptionDurable` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_set_subscription_durable_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_set_subscription_durable_handler_sync(SetSubscriptionDurableHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `SetSubscriptionDurable` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_set_subscription_durable_handler_sync, set_set_subscription_durable_handler_sync
  void set_set_subscription_durable_handler_async(
    SetSubscriptionDurableAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `SetSubscriptionDurable` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_set_subscription_durable_handler_sync(
    SetSubscriptionDurableAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `SetSubscriptionDurable` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_set_subscription_durable_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_set_subscription_durable_handler_sync(SetSubscriptionDurableAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RequestServerStateChange` method, in
  /// place of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_request_server_state_change_handler_sync, set_request_server_state_change_handler_sync
  void set_request_server_state_change_handler_async(
    RequestServerStateChangeHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RequestServerStateChange` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_request_server_state_change_handler_sync(
    RequestServerStateChangeHandler handler) const noexcept;
  /// Registers the synchronous `RequestServerStateChange` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_request_server_state_change_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_request_server_state_change_handler_sync(RequestServerStateChangeHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RequestServerStateChange` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_request_server_state_change_handler_sync, set_request_server_state_change_handler_sync
  void set_request_server_state_change_handler_async(
    RequestServerStateChangeAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RequestServerStateChange` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_request_server_state_change_handler_sync(
    RequestServerStateChangeAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RequestServerStateChange` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_request_server_state_change_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_request_server_state_change_handler_sync(RequestServerStateChangeAsyncHandler handler) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `ServerStatus` handle for the `ServerStatus` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_server_status_sync, server_status_sync
  void server_status_async(std::function<void(ServerStatusResult)> complete) const noexcept;
  /// Attaches a typed `ServerStatus` handle for the `ServerStatus` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  ServerStatusResult try_server_status_sync() const noexcept;
  /// Attaches a typed `ServerStatus` handle for the `ServerStatus` child, blocking until complete.
  /// @return The `ServerStatus` handle. A Good subcode is not returned; @ref try_server_status_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  ServerStatus server_status_sync() const;

  /// Attaches a typed `ServerCapabilities` handle for the `ServerCapabilities` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_server_capabilities_sync, server_capabilities_sync
  void server_capabilities_async(std::function<void(ServerCapabilitiesResult)> complete) const noexcept;
  /// Attaches a typed `ServerCapabilities` handle for the `ServerCapabilities` child, blocking until
  /// complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  ServerCapabilitiesResult try_server_capabilities_sync() const noexcept;
  /// Attaches a typed `ServerCapabilities` handle for the `ServerCapabilities` child, blocking until
  /// complete.
  /// @return The `ServerCapabilities` handle. A Good subcode is not returned; @ref
  /// try_server_capabilities_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  ServerCapabilities server_capabilities_sync() const;

  /// Attaches a typed `ServerDiagnostics` handle for the `ServerDiagnostics` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_server_diagnostics_sync, server_diagnostics_sync
  void server_diagnostics_async(std::function<void(ServerDiagnosticsResult)> complete) const noexcept;
  /// Attaches a typed `ServerDiagnostics` handle for the `ServerDiagnostics` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  ServerDiagnosticsResult try_server_diagnostics_sync() const noexcept;
  /// Attaches a typed `ServerDiagnostics` handle for the `ServerDiagnostics` child, blocking until complete.
  /// @return The `ServerDiagnostics` handle. A Good subcode is not returned; @ref try_server_diagnostics_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  ServerDiagnostics server_diagnostics_sync() const;

  /// Attaches a typed `VendorServerInfo` handle for the `VendorServerInfo` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_vendor_server_info_sync, vendor_server_info_sync
  void vendor_server_info_async(std::function<void(VendorServerInfoResult)> complete) const noexcept;
  /// Attaches a typed `VendorServerInfo` handle for the `VendorServerInfo` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  VendorServerInfoResult try_vendor_server_info_sync() const noexcept;
  /// Attaches a typed `VendorServerInfo` handle for the `VendorServerInfo` child, blocking until complete.
  /// @return The `VendorServerInfo` handle. A Good subcode is not returned; @ref try_vendor_server_info_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  VendorServerInfo vendor_server_info_sync() const;

  /// Attaches a typed `ServerRedundancy` handle for the `ServerRedundancy` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_server_redundancy_sync, server_redundancy_sync
  void server_redundancy_async(std::function<void(ServerRedundancyResult)> complete) const noexcept;
  /// Attaches a typed `ServerRedundancy` handle for the `ServerRedundancy` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  ServerRedundancyResult try_server_redundancy_sync() const noexcept;
  /// Attaches a typed `ServerRedundancy` handle for the `ServerRedundancy` child, blocking until complete.
  /// @return The `ServerRedundancy` handle. A Good subcode is not returned; @ref try_server_redundancy_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  ServerRedundancy server_redundancy_sync() const;

  /// Attaches a typed `Namespaces` handle for the `Namespaces` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_namespaces_sync, namespaces_sync
  void namespaces_async(std::function<void(NamespacesResult)> complete) const noexcept;
  /// Attaches a typed `Namespaces` handle for the `Namespaces` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  NamespacesResult try_namespaces_sync() const noexcept;
  /// Attaches a typed `Namespaces` handle for the `Namespaces` child, blocking until complete.
  /// @return The `Namespaces` handle. A Good subcode is not returned; @ref try_namespaces_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Namespaces namespaces_sync() const;

private:
  explicit ServerObject(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_SERVER_OBJECT_H
