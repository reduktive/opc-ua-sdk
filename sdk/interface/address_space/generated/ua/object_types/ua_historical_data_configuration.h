// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORICAL_DATA_CONFIGURATION_H
#define UA_HISTORICAL_DATA_CONFIGURATION_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_folder.h"

namespace ua
{

struct MethodCallContext;

class HistoricalDataConfiguration;
using HistoricalDataConfigurationResult = Result<HistoricalDataConfiguration>;

/// Address-space handle for the OPC UA HistoricalDataConfigurationType ObjectType.
/// @ingroup ua_information_model
class HistoricalDataConfiguration : public BaseObject
{
public:
  /// Constructs an empty `HistoricalDataConfiguration` handle that references no node.
  HistoricalDataConfiguration() = default;

  /// Completion callback for create_async: receives the created `HistoricalDataConfiguration` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(HistoricalDataConfigurationResult)>;
  /// Completion callback for attach_async: receives the attached `HistoricalDataConfiguration` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(HistoricalDataConfigurationResult)>;

  /// Creates a new `HistoricalDataConfigurationType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `HistoricalDataConfiguration` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `HistoricalDataConfigurationType` instance under `parent`, blocking until complete.  ///
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
  static HistoricalDataConfigurationResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `HistoricalDataConfigurationType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `HistoricalDataConfiguration` handle. A Good subcode is not returned; @ref
  /// try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static HistoricalDataConfiguration create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `HistoricalDataConfigurationType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `HistoricalDataConfiguration` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `HistoricalDataConfigurationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static HistoricalDataConfigurationResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `HistoricalDataConfigurationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `HistoricalDataConfiguration` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static HistoricalDataConfiguration attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Stepped` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_stepped_property_sync, stepped_property_sync
  void stepped_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Stepped` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_stepped_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Stepped` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_stepped_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property stepped_property_sync() const;

  /// Attaches a `Property` handle for the `Definition` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_definition_property_sync, definition_property_sync
  void definition_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Definition` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_definition_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Definition` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_definition_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property definition_property_sync() const;

  /// Attaches a `Property` handle for the `MaxTimeInterval` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_time_interval_property_sync, max_time_interval_property_sync
  void max_time_interval_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxTimeInterval` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_time_interval_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxTimeInterval` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_time_interval_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_time_interval_property_sync() const;

  /// Attaches a `Property` handle for the `MinTimeInterval` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_min_time_interval_property_sync, min_time_interval_property_sync
  void min_time_interval_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MinTimeInterval` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_min_time_interval_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MinTimeInterval` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_min_time_interval_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property min_time_interval_property_sync() const;

  /// Attaches a `Property` handle for the `ExceptionDeviation` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_exception_deviation_property_sync, exception_deviation_property_sync
  void exception_deviation_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ExceptionDeviation` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_exception_deviation_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ExceptionDeviation` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_exception_deviation_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property exception_deviation_property_sync() const;

  /// Attaches a `Property` handle for the `ExceptionDeviationFormat` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_exception_deviation_format_property_sync, exception_deviation_format_property_sync
  void exception_deviation_format_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ExceptionDeviationFormat` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_exception_deviation_format_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ExceptionDeviationFormat` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_exception_deviation_format_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property exception_deviation_format_property_sync() const;

  /// Attaches a `Property` handle for the `StartOfArchive` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_start_of_archive_property_sync, start_of_archive_property_sync
  void start_of_archive_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `StartOfArchive` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_start_of_archive_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `StartOfArchive` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_start_of_archive_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property start_of_archive_property_sync() const;

  /// Attaches a `Property` handle for the `StartOfOnlineArchive` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_start_of_online_archive_property_sync, start_of_online_archive_property_sync
  void start_of_online_archive_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `StartOfOnlineArchive` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_start_of_online_archive_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `StartOfOnlineArchive` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_start_of_online_archive_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property start_of_online_archive_property_sync() const;

  /// Attaches a `Property` handle for the `ServerTimestampSupported` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_server_timestamp_supported_property_sync, server_timestamp_supported_property_sync
  void server_timestamp_supported_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ServerTimestampSupported` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_server_timestamp_supported_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ServerTimestampSupported` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_server_timestamp_supported_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property server_timestamp_supported_property_sync() const;

  /// Attaches a `Property` handle for the `MaxTimeStoredValues` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_time_stored_values_property_sync, max_time_stored_values_property_sync
  void max_time_stored_values_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxTimeStoredValues` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_time_stored_values_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxTimeStoredValues` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_time_stored_values_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_time_stored_values_property_sync() const;

  /// Attaches a `Property` handle for the `MaxCountStoredValues` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_count_stored_values_property_sync, max_count_stored_values_property_sync
  void max_count_stored_values_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxCountStoredValues` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_count_stored_values_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxCountStoredValues` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_count_stored_values_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_count_stored_values_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `Stepped` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_stepped_sync, read_stepped_sync
  void read_stepped_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `Stepped` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_stepped_async gives it. Never throws.
  BoolResult try_read_stepped_sync() const noexcept;
  /// Reads the `Stepped` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_stepped_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_stepped_sync() const;

  /// Reads the `Definition` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_definition_sync, read_definition_sync
  void read_definition_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `Definition` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_definition_async gives it. Never throws.
  StringResult try_read_definition_sync() const noexcept;
  /// Reads the `Definition` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_definition_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_definition_sync() const;

  /// Reads the `ExceptionDeviation` property value, typed as `double`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_exception_deviation_sync, read_exception_deviation_sync
  void read_exception_deviation_async(std::function<void(DoubleResult)> complete) const noexcept;
  /// Reads the `ExceptionDeviation` property value as `double`, blocking until complete.
  /// @return The value with the read's code, as @ref read_exception_deviation_async gives it. Never throws.
  DoubleResult try_read_exception_deviation_sync() const noexcept;
  /// Reads the `ExceptionDeviation` property value as `double`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_exception_deviation_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  double read_exception_deviation_sync() const;

  /// Reads the `ServerTimestampSupported` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_server_timestamp_supported_sync, read_server_timestamp_supported_sync
  void read_server_timestamp_supported_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `ServerTimestampSupported` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_server_timestamp_supported_async gives it. Never
  /// throws.
  BoolResult try_read_server_timestamp_supported_sync() const noexcept;
  /// Reads the `ServerTimestampSupported` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_server_timestamp_supported_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_server_timestamp_supported_sync() const;

  /// Reads the `MaxCountStoredValues` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_count_stored_values_sync, read_max_count_stored_values_sync
  void read_max_count_stored_values_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxCountStoredValues` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_count_stored_values_async gives it. Never
  /// throws.
  UInt32Result try_read_max_count_stored_values_sync() const noexcept;
  /// Reads the `MaxCountStoredValues` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_count_stored_values_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_count_stored_values_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `Stepped` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_stepped_sync, write_stepped_sync
  void write_stepped_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Stepped` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_stepped_sync(bool value) const noexcept;
  /// Writes the `Stepped` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_stepped_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_stepped_sync(bool value) const;

  /// Writes the `Definition` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_definition_sync, write_definition_sync
  void write_definition_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Definition` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_definition_sync(String value) const noexcept;
  /// Writes the `Definition` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_definition_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_definition_sync(String value) const;

  /// Writes the `ExceptionDeviation` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_exception_deviation_sync, write_exception_deviation_sync
  void write_exception_deviation_async(double value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ExceptionDeviation` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_exception_deviation_sync(double value) const noexcept;
  /// Writes the `ExceptionDeviation` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_exception_deviation_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_exception_deviation_sync(double value) const;

  /// Writes the `ServerTimestampSupported` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_server_timestamp_supported_sync, write_server_timestamp_supported_sync
  void write_server_timestamp_supported_async(
    bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ServerTimestampSupported` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_server_timestamp_supported_sync(bool value) const noexcept;
  /// Writes the `ServerTimestampSupported` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_server_timestamp_supported_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_server_timestamp_supported_sync(bool value) const;

  /// Writes the `MaxCountStoredValues` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_count_stored_values_sync, write_max_count_stored_values_sync
  void write_max_count_stored_values_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxCountStoredValues` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_count_stored_values_sync(uint32_t value) const noexcept;
  /// Writes the `MaxCountStoredValues` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_count_stored_values_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_count_stored_values_sync(uint32_t value) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `Folder` handle for the `AggregateFunctions` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_aggregate_functions_sync, aggregate_functions_sync
  void aggregate_functions_async(std::function<void(FolderResult)> complete) const noexcept;
  /// Attaches a typed `Folder` handle for the `AggregateFunctions` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  FolderResult try_aggregate_functions_sync() const noexcept;
  /// Attaches a typed `Folder` handle for the `AggregateFunctions` child, blocking until complete.
  /// @return The `Folder` handle. A Good subcode is not returned; @ref try_aggregate_functions_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Folder aggregate_functions_sync() const;

private:
  explicit HistoricalDataConfiguration(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_HISTORICAL_DATA_CONFIGURATION_H
