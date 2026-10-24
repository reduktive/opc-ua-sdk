// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERIALIZATION_ENTITY_H
#define UA_SERIALIZATION_ENTITY_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_base_data_variable.h"

namespace ua
{

struct MethodCallContext;

class SerializationEntity;
using SerializationEntityResult = Result<SerializationEntity>;

/// Address-space handle for the OPC UA SerializationEntityType ObjectType.
/// @ingroup ua_information_model
class SerializationEntity : public BaseObject
{
public:
  /// Constructs an empty `SerializationEntity` handle that references no node.
  SerializationEntity() = default;

  /// Input arguments for the SerializationEntityType ConfigureSerialization() method.
  struct ConfigureSerializationInputArguments
  {
    std::vector<Variant> serializationFilterProperties;  ///< Serialization filter properties.
  };

  /// Output arguments for the SerializationEntityType ConfigureSerialization() method.
  struct ConfigureSerializationOutputArguments
  {
    std::vector<int32_t> results;  ///< Results.
  };

  /// Synchronous handler for ConfigureSerialization(): returns the outputs, a failure or a rejected input
  /// argument (see ua::MethodResult), for work that waits for nothing.
  using ConfigureSerializationHandler = std::function<MethodResult<ConfigureSerializationOutputArguments>(
    const MethodCall&, const ConfigureSerializationInputArguments&)>;
  /// Asynchronous handler for ConfigureSerialization(): starts the work and completes it through the
  /// callback, once, from any thread.
  using ConfigureSerializationAsyncHandler =
    std::function<void(const MethodCall&, const ConfigureSerializationInputArguments&,
      MethodResultCallback<ConfigureSerializationOutputArguments>)>;

  /// Completion callback for create_async: receives the created `SerializationEntity` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(SerializationEntityResult)>;
  /// Completion callback for attach_async: receives the attached `SerializationEntity` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(SerializationEntityResult)>;

  /// Creates a new `SerializationEntityType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `SerializationEntity` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `SerializationEntityType` instance under `parent`, blocking until complete.  ///
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
  static SerializationEntityResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `SerializationEntityType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `SerializationEntity` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static SerializationEntity create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `SerializationEntityType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `SerializationEntity` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `SerializationEntityType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static SerializationEntityResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `SerializationEntityType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `SerializationEntity` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static SerializationEntity attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `ConfigureSerialization` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_configure_serialization_method_sync, configure_serialization_method_sync
  void configure_serialization_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `ConfigureSerialization` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_configure_serialization_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `ConfigureSerialization` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref
  /// try_configure_serialization_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor configure_serialization_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `IncludeReferenceTypes` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_include_reference_types_property_sync, include_reference_types_property_sync
  void include_reference_types_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IncludeReferenceTypes` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_include_reference_types_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IncludeReferenceTypes` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_include_reference_types_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property include_reference_types_property_sync() const;

  /// Attaches a `Property` handle for the `ExcludeReferenceTypes` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_exclude_reference_types_property_sync, exclude_reference_types_property_sync
  void exclude_reference_types_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ExcludeReferenceTypes` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_exclude_reference_types_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ExcludeReferenceTypes` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_exclude_reference_types_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property exclude_reference_types_property_sync() const;

  /// Attaches a `Property` handle for the `SerializationDepth` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_serialization_depth_property_sync, serialization_depth_property_sync
  void serialization_depth_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SerializationDepth` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_serialization_depth_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SerializationDepth` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_serialization_depth_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property serialization_depth_property_sync() const;

  /// Attaches a `Property` handle for the `ConsiderSubElementSerializationProperties` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_consider_sub_element_serialization_properties_property_sync,
  /// consider_sub_element_serialization_properties_property_sync
  void consider_sub_element_serialization_properties_property_async(
    PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ConsiderSubElementSerializationProperties` property, blocking
  /// until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_consider_sub_element_serialization_properties_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ConsiderSubElementSerializationProperties` property, blocking
  /// until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_consider_sub_element_serialization_properties_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property consider_sub_element_serialization_properties_property_sync() const;

  /// Attaches a `Property` handle for the `CustomMetaDataProperties` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_custom_meta_data_properties_property_sync, custom_meta_data_properties_property_sync
  void custom_meta_data_properties_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CustomMetaDataProperties` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_custom_meta_data_properties_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CustomMetaDataProperties` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_custom_meta_data_properties_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property custom_meta_data_properties_property_sync() const;

  /// Attaches a `Property` handle for the `CustomMetaDataRef` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_custom_meta_data_ref_property_sync, custom_meta_data_ref_property_sync
  void custom_meta_data_ref_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CustomMetaDataRef` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_custom_meta_data_ref_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CustomMetaDataRef` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_custom_meta_data_ref_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property custom_meta_data_ref_property_sync() const;

  /// Attaches a `Property` handle for the `IncludeStatus` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_include_status_property_sync, include_status_property_sync
  void include_status_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IncludeStatus` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_include_status_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IncludeStatus` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_include_status_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property include_status_property_sync() const;

  /// Attaches a `Property` handle for the `IncludeSourceTimestamp` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_include_source_timestamp_property_sync, include_source_timestamp_property_sync
  void include_source_timestamp_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IncludeSourceTimestamp` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_include_source_timestamp_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IncludeSourceTimestamp` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_include_source_timestamp_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property include_source_timestamp_property_sync() const;

  /// Attaches a `Property` handle for the `IncludeDictionaryReference` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_include_dictionary_reference_property_sync, include_dictionary_reference_property_sync
  void include_dictionary_reference_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IncludeDictionaryReference` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_include_dictionary_reference_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IncludeDictionaryReference` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_include_dictionary_reference_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property include_dictionary_reference_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `IncludeReferenceTypes` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_include_reference_types_sync, read_include_reference_types_sync
  void read_include_reference_types_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `IncludeReferenceTypes` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_include_reference_types_async gives it. Never
  /// throws.
  NodeIdResult try_read_include_reference_types_sync() const noexcept;
  /// Reads the `IncludeReferenceTypes` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_include_reference_types_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_include_reference_types_sync() const;

  /// Reads the `ExcludeReferenceTypes` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_exclude_reference_types_sync, read_exclude_reference_types_sync
  void read_exclude_reference_types_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `ExcludeReferenceTypes` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_exclude_reference_types_async gives it. Never
  /// throws.
  NodeIdResult try_read_exclude_reference_types_sync() const noexcept;
  /// Reads the `ExcludeReferenceTypes` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_exclude_reference_types_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_exclude_reference_types_sync() const;

  /// Reads the `SerializationDepth` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_serialization_depth_sync, read_serialization_depth_sync
  void read_serialization_depth_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `SerializationDepth` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_serialization_depth_async gives it. Never throws.
  UInt16Result try_read_serialization_depth_sync() const noexcept;
  /// Reads the `SerializationDepth` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_serialization_depth_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_serialization_depth_sync() const;

  /// Reads the `ConsiderSubElementSerializationProperties` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_consider_sub_element_serialization_properties_sync,
  /// read_consider_sub_element_serialization_properties_sync
  void read_consider_sub_element_serialization_properties_async(
    std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `ConsiderSubElementSerializationProperties` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_consider_sub_element_serialization_properties_async
  /// gives it. Never throws.
  BoolResult try_read_consider_sub_element_serialization_properties_sync() const noexcept;
  /// Reads the `ConsiderSubElementSerializationProperties` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_consider_sub_element_serialization_properties_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_consider_sub_element_serialization_properties_sync() const;

  /// Reads the `CustomMetaDataRef` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_custom_meta_data_ref_sync, read_custom_meta_data_ref_sync
  void read_custom_meta_data_ref_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `CustomMetaDataRef` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_custom_meta_data_ref_async gives it. Never throws.
  NodeIdResult try_read_custom_meta_data_ref_sync() const noexcept;
  /// Reads the `CustomMetaDataRef` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_custom_meta_data_ref_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_custom_meta_data_ref_sync() const;

  /// Reads the `IncludeStatus` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_include_status_sync, read_include_status_sync
  void read_include_status_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `IncludeStatus` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_include_status_async gives it. Never throws.
  BoolResult try_read_include_status_sync() const noexcept;
  /// Reads the `IncludeStatus` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_include_status_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_include_status_sync() const;

  /// Reads the `IncludeSourceTimestamp` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_include_source_timestamp_sync, read_include_source_timestamp_sync
  void read_include_source_timestamp_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `IncludeSourceTimestamp` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_include_source_timestamp_async gives it. Never
  /// throws.
  BoolResult try_read_include_source_timestamp_sync() const noexcept;
  /// Reads the `IncludeSourceTimestamp` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_include_source_timestamp_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_include_source_timestamp_sync() const;

  /// Reads the `IncludeDictionaryReference` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_include_dictionary_reference_sync, read_include_dictionary_reference_sync
  void read_include_dictionary_reference_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `IncludeDictionaryReference` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_include_dictionary_reference_async gives it. Never
  /// throws.
  BoolResult try_read_include_dictionary_reference_sync() const noexcept;
  /// Reads the `IncludeDictionaryReference` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_include_dictionary_reference_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_include_dictionary_reference_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `IncludeReferenceTypes` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_include_reference_types_sync, write_include_reference_types_sync
  void write_include_reference_types_async(
    NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `IncludeReferenceTypes` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_include_reference_types_sync(NodeId value) const noexcept;
  /// Writes the `IncludeReferenceTypes` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_include_reference_types_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_include_reference_types_sync(NodeId value) const;

  /// Writes the `ExcludeReferenceTypes` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_exclude_reference_types_sync, write_exclude_reference_types_sync
  void write_exclude_reference_types_async(
    NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ExcludeReferenceTypes` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_exclude_reference_types_sync(NodeId value) const noexcept;
  /// Writes the `ExcludeReferenceTypes` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_exclude_reference_types_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_exclude_reference_types_sync(NodeId value) const;

  /// Writes the `SerializationDepth` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_serialization_depth_sync, write_serialization_depth_sync
  void write_serialization_depth_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SerializationDepth` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_serialization_depth_sync(uint16_t value) const noexcept;
  /// Writes the `SerializationDepth` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_serialization_depth_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_serialization_depth_sync(uint16_t value) const;

  /// Writes the `ConsiderSubElementSerializationProperties` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_consider_sub_element_serialization_properties_sync,
  /// write_consider_sub_element_serialization_properties_sync
  void write_consider_sub_element_serialization_properties_async(
    bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ConsiderSubElementSerializationProperties` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_consider_sub_element_serialization_properties_sync(bool value) const noexcept;
  /// Writes the `ConsiderSubElementSerializationProperties` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_consider_sub_element_serialization_properties_sync
  /// returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_consider_sub_element_serialization_properties_sync(bool value) const;

  /// Writes the `CustomMetaDataRef` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_custom_meta_data_ref_sync, write_custom_meta_data_ref_sync
  void write_custom_meta_data_ref_async(
    NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CustomMetaDataRef` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_custom_meta_data_ref_sync(NodeId value) const noexcept;
  /// Writes the `CustomMetaDataRef` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_custom_meta_data_ref_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_custom_meta_data_ref_sync(NodeId value) const;

  /// Writes the `IncludeStatus` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_include_status_sync, write_include_status_sync
  void write_include_status_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `IncludeStatus` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_include_status_sync(bool value) const noexcept;
  /// Writes the `IncludeStatus` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_include_status_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_include_status_sync(bool value) const;

  /// Writes the `IncludeSourceTimestamp` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_include_source_timestamp_sync, write_include_source_timestamp_sync
  void write_include_source_timestamp_async(
    bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `IncludeSourceTimestamp` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_include_source_timestamp_sync(bool value) const noexcept;
  /// Writes the `IncludeSourceTimestamp` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_include_source_timestamp_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_include_source_timestamp_sync(bool value) const;

  /// Writes the `IncludeDictionaryReference` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_include_dictionary_reference_sync, write_include_dictionary_reference_sync
  void write_include_dictionary_reference_async(
    bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `IncludeDictionaryReference` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_include_dictionary_reference_sync(bool value) const noexcept;
  /// Writes the `IncludeDictionaryReference` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_include_dictionary_reference_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_include_dictionary_reference_sync(bool value) const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `ConfigureSerialization` method, in
  /// place of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_configure_serialization_handler_sync, set_configure_serialization_handler_sync
  void set_configure_serialization_handler_async(
    ConfigureSerializationHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `ConfigureSerialization` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_configure_serialization_handler_sync(
    ConfigureSerializationHandler handler) const noexcept;
  /// Registers the synchronous `ConfigureSerialization` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_configure_serialization_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_configure_serialization_handler_sync(ConfigureSerializationHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `ConfigureSerialization` method, in
  /// place of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_configure_serialization_handler_sync, set_configure_serialization_handler_sync
  void set_configure_serialization_handler_async(
    ConfigureSerializationAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `ConfigureSerialization` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_configure_serialization_handler_sync(
    ConfigureSerializationAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `ConfigureSerialization` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_configure_serialization_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_configure_serialization_handler_sync(ConfigureSerializationAsyncHandler handler) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `BaseDataVariable` handle for the `SerializedData` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_serialized_data_sync, serialized_data_sync
  void serialized_data_async(std::function<void(BaseDataVariableResult)> complete) const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SerializedData` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  BaseDataVariableResult try_serialized_data_sync() const noexcept;
  /// Attaches a typed `BaseDataVariable` handle for the `SerializedData` child, blocking until complete.
  /// @return The `BaseDataVariable` handle. A Good subcode is not returned; @ref try_serialized_data_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  BaseDataVariable serialized_data_sync() const;

private:
  explicit SerializationEntity(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_SERIALIZATION_ENTITY_H
