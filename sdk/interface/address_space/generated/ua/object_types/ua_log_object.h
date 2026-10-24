// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_LOG_OBJECT_H
#define UA_LOG_OBJECT_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class LogObject;
using LogObjectResult = Result<LogObject>;

/// Address-space handle for the OPC UA LogObjectType ObjectType.
/// @ingroup ua_information_model
class LogObject : public BaseObject
{
public:
  /// Constructs an empty `LogObject` handle that references no node.
  LogObject() = default;

  /// Input arguments for the LogObjectType GetRecords() method.
  struct GetRecordsInputArguments
  {
    DateTime startTime{};  ///< Start time.
    DateTime endTime{};  ///< End time.
    uint32_t maxReturnRecords{};  ///< Max return records.
    uint16_t minimumSeverity{};  ///< Minimum severity.
    Variant requestMask;  ///< Request mask.
    ByteString continuationPointIn;  ///< Continuation point in.
  };

  /// Output arguments for the LogObjectType GetRecords() method.
  struct GetRecordsOutputArguments
  {
    Variant results;  ///< Results.
    ByteString continuationPointOut;  ///< Continuation point out.
  };

  /// Synchronous handler for GetRecords(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using GetRecordsHandler = std::function<MethodResult<GetRecordsOutputArguments>(
    const MethodCall&, const GetRecordsInputArguments&)>;
  /// Asynchronous handler for GetRecords(): starts the work and completes it through the callback, once, from
  /// any thread.
  using GetRecordsAsyncHandler = std::function<void(
    const MethodCall&, const GetRecordsInputArguments&, MethodResultCallback<GetRecordsOutputArguments>)>;

  /// Completion callback for create_async: receives the created `LogObject` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(LogObjectResult)>;
  /// Completion callback for attach_async: receives the attached `LogObject` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(LogObjectResult)>;

  /// Creates a new `LogObjectType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `LogObject` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `LogObjectType` instance under `parent`, blocking until complete.  ///
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
  static LogObjectResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `LogObjectType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `LogObject` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static LogObject create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `LogObjectType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `LogObject` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `LogObjectType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static LogObjectResult try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `LogObjectType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `LogObject` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static LogObject attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `GetRecords` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_records_method_sync, get_records_method_sync
  void get_records_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `GetRecords` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_get_records_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `GetRecords` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_get_records_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor get_records_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `MaxRecords` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_records_property_sync, max_records_property_sync
  void max_records_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxRecords` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_records_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxRecords` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_max_records_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_records_property_sync() const;

  /// Attaches a `Property` handle for the `MaxStorageDuration` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_storage_duration_property_sync, max_storage_duration_property_sync
  void max_storage_duration_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxStorageDuration` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_storage_duration_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxStorageDuration` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_storage_duration_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_storage_duration_property_sync() const;

  /// Attaches a `Property` handle for the `MinimumSeverity` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_minimum_severity_property_sync, minimum_severity_property_sync
  void minimum_severity_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MinimumSeverity` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_minimum_severity_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MinimumSeverity` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_minimum_severity_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property minimum_severity_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `MaxRecords` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_records_sync, read_max_records_sync
  void read_max_records_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxRecords` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_records_async gives it. Never throws.
  UInt32Result try_read_max_records_sync() const noexcept;
  /// Reads the `MaxRecords` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_records_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_records_sync() const;

  /// Reads the `MinimumSeverity` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_minimum_severity_sync, read_minimum_severity_sync
  void read_minimum_severity_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `MinimumSeverity` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_minimum_severity_async gives it. Never throws.
  UInt16Result try_read_minimum_severity_sync() const noexcept;
  /// Reads the `MinimumSeverity` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_minimum_severity_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_minimum_severity_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `MaxRecords` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_records_sync, write_max_records_sync
  void write_max_records_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxRecords` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_records_sync(uint32_t value) const noexcept;
  /// Writes the `MaxRecords` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_records_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_records_sync(uint32_t value) const;

  /// Writes the `MinimumSeverity` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_minimum_severity_sync, write_minimum_severity_sync
  void write_minimum_severity_async(uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MinimumSeverity` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_minimum_severity_sync(uint16_t value) const noexcept;
  /// Writes the `MinimumSeverity` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_minimum_severity_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_minimum_severity_sync(uint16_t value) const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `GetRecords` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_records_handler_sync, set_get_records_handler_sync
  void set_get_records_handler_async(
    GetRecordsHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `GetRecords` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_records_handler_sync(GetRecordsHandler handler) const noexcept;
  /// Registers the synchronous `GetRecords` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_records_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_records_handler_sync(GetRecordsHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `GetRecords` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_records_handler_sync, set_get_records_handler_sync
  void set_get_records_handler_async(
    GetRecordsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `GetRecords` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_records_handler_sync(GetRecordsAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `GetRecords` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_records_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_records_handler_sync(GetRecordsAsyncHandler handler) const;

private:
  explicit LogObject(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_LOG_OBJECT_H
