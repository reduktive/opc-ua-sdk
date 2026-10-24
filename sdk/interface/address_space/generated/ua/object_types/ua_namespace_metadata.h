// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NAMESPACE_METADATA_H
#define UA_NAMESPACE_METADATA_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_address_space_file.h"

namespace ua
{

struct MethodCallContext;

class NamespaceMetadata;
using NamespaceMetadataResult = Result<NamespaceMetadata>;

/// Address-space handle for the OPC UA NamespaceMetadataType ObjectType.
/// @ingroup ua_information_model
class NamespaceMetadata : public BaseObject
{
public:
  /// Constructs an empty `NamespaceMetadata` handle that references no node.
  NamespaceMetadata() = default;

  /// Completion callback for create_async: receives the created `NamespaceMetadata` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(NamespaceMetadataResult)>;
  /// Completion callback for attach_async: receives the attached `NamespaceMetadata` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(NamespaceMetadataResult)>;

  /// Creates a new `NamespaceMetadataType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `NamespaceMetadata` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `NamespaceMetadataType` instance under `parent`, blocking until complete.  ///
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
  static NamespaceMetadataResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `NamespaceMetadataType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `NamespaceMetadata` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static NamespaceMetadata create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `NamespaceMetadataType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `NamespaceMetadata` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `NamespaceMetadataType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static NamespaceMetadataResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `NamespaceMetadataType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `NamespaceMetadata` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static NamespaceMetadata attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `NamespaceUri` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_namespace_uri_property_sync, namespace_uri_property_sync
  void namespace_uri_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `NamespaceUri` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_namespace_uri_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `NamespaceUri` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_namespace_uri_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property namespace_uri_property_sync() const;

  /// Attaches a `Property` handle for the `NamespaceVersion` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_namespace_version_property_sync, namespace_version_property_sync
  void namespace_version_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `NamespaceVersion` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_namespace_version_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `NamespaceVersion` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_namespace_version_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property namespace_version_property_sync() const;

  /// Attaches a `Property` handle for the `NamespacePublicationDate` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_namespace_publication_date_property_sync, namespace_publication_date_property_sync
  void namespace_publication_date_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `NamespacePublicationDate` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_namespace_publication_date_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `NamespacePublicationDate` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_namespace_publication_date_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property namespace_publication_date_property_sync() const;

  /// Attaches a `Property` handle for the `IsNamespaceSubset` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_is_namespace_subset_property_sync, is_namespace_subset_property_sync
  void is_namespace_subset_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `IsNamespaceSubset` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_is_namespace_subset_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `IsNamespaceSubset` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_is_namespace_subset_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property is_namespace_subset_property_sync() const;

  /// Attaches a `Property` handle for the `StaticNodeIdTypes` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_static_node_id_types_property_sync, static_node_id_types_property_sync
  void static_node_id_types_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `StaticNodeIdTypes` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_static_node_id_types_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `StaticNodeIdTypes` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_static_node_id_types_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property static_node_id_types_property_sync() const;

  /// Attaches a `Property` handle for the `StaticNumericNodeIdRange` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_static_numeric_node_id_range_property_sync, static_numeric_node_id_range_property_sync
  void static_numeric_node_id_range_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `StaticNumericNodeIdRange` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_static_numeric_node_id_range_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `StaticNumericNodeIdRange` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_static_numeric_node_id_range_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property static_numeric_node_id_range_property_sync() const;

  /// Attaches a `Property` handle for the `StaticStringNodeIdPattern` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_static_string_node_id_pattern_property_sync, static_string_node_id_pattern_property_sync
  void static_string_node_id_pattern_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `StaticStringNodeIdPattern` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_static_string_node_id_pattern_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `StaticStringNodeIdPattern` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_static_string_node_id_pattern_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property static_string_node_id_pattern_property_sync() const;

  /// Attaches a `Property` handle for the `DefaultRolePermissions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_default_role_permissions_property_sync, default_role_permissions_property_sync
  void default_role_permissions_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `DefaultRolePermissions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_default_role_permissions_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `DefaultRolePermissions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_default_role_permissions_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property default_role_permissions_property_sync() const;

  /// Attaches a `Property` handle for the `DefaultUserRolePermissions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_default_user_role_permissions_property_sync, default_user_role_permissions_property_sync
  void default_user_role_permissions_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `DefaultUserRolePermissions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_default_user_role_permissions_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `DefaultUserRolePermissions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_default_user_role_permissions_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property default_user_role_permissions_property_sync() const;

  /// Attaches a `Property` handle for the `DefaultAccessRestrictions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_default_access_restrictions_property_sync, default_access_restrictions_property_sync
  void default_access_restrictions_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `DefaultAccessRestrictions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_default_access_restrictions_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `DefaultAccessRestrictions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_default_access_restrictions_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property default_access_restrictions_property_sync() const;

  /// Attaches a `Property` handle for the `ConfigurationVersion` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_configuration_version_property_sync, configuration_version_property_sync
  void configuration_version_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ConfigurationVersion` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_configuration_version_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ConfigurationVersion` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_configuration_version_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property configuration_version_property_sync() const;

  /// Attaches a `Property` handle for the `ModelVersion` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_model_version_property_sync, model_version_property_sync
  void model_version_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ModelVersion` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_model_version_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ModelVersion` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_model_version_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property model_version_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `NamespaceUri` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_namespace_uri_sync, read_namespace_uri_sync
  void read_namespace_uri_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `NamespaceUri` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_namespace_uri_async gives it. Never throws.
  StringResult try_read_namespace_uri_sync() const noexcept;
  /// Reads the `NamespaceUri` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_namespace_uri_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_namespace_uri_sync() const;

  /// Reads the `NamespaceVersion` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_namespace_version_sync, read_namespace_version_sync
  void read_namespace_version_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `NamespaceVersion` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_namespace_version_async gives it. Never throws.
  StringResult try_read_namespace_version_sync() const noexcept;
  /// Reads the `NamespaceVersion` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_namespace_version_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_namespace_version_sync() const;

  /// Reads the `NamespacePublicationDate` property value, typed as `DateTime`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_namespace_publication_date_sync, read_namespace_publication_date_sync
  void read_namespace_publication_date_async(std::function<void(DateTimeResult)> complete) const noexcept;
  /// Reads the `NamespacePublicationDate` property value as `DateTime`, blocking until complete.
  /// @return The value with the read's code, as @ref read_namespace_publication_date_async gives it. Never
  /// throws.
  DateTimeResult try_read_namespace_publication_date_sync() const noexcept;
  /// Reads the `NamespacePublicationDate` property value as `DateTime`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_namespace_publication_date_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  DateTime read_namespace_publication_date_sync() const;

  /// Reads the `IsNamespaceSubset` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_is_namespace_subset_sync, read_is_namespace_subset_sync
  void read_is_namespace_subset_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `IsNamespaceSubset` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_is_namespace_subset_async gives it. Never throws.
  BoolResult try_read_is_namespace_subset_sync() const noexcept;
  /// Reads the `IsNamespaceSubset` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_is_namespace_subset_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_is_namespace_subset_sync() const;

  /// Reads the `StaticStringNodeIdPattern` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_static_string_node_id_pattern_sync, read_static_string_node_id_pattern_sync
  void read_static_string_node_id_pattern_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `StaticStringNodeIdPattern` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_static_string_node_id_pattern_async gives it. Never
  /// throws.
  StringResult try_read_static_string_node_id_pattern_sync() const noexcept;
  /// Reads the `StaticStringNodeIdPattern` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_static_string_node_id_pattern_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_static_string_node_id_pattern_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `NamespaceUri` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_namespace_uri_sync, write_namespace_uri_sync
  void write_namespace_uri_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `NamespaceUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_namespace_uri_sync(String value) const noexcept;
  /// Writes the `NamespaceUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_namespace_uri_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_namespace_uri_sync(String value) const;

  /// Writes the `NamespaceVersion` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_namespace_version_sync, write_namespace_version_sync
  void write_namespace_version_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `NamespaceVersion` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_namespace_version_sync(String value) const noexcept;
  /// Writes the `NamespaceVersion` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_namespace_version_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_namespace_version_sync(String value) const;

  /// Writes the `NamespacePublicationDate` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_namespace_publication_date_sync, write_namespace_publication_date_sync
  void write_namespace_publication_date_async(
    DateTime value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `NamespacePublicationDate` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_namespace_publication_date_sync(DateTime value) const noexcept;
  /// Writes the `NamespacePublicationDate` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_namespace_publication_date_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_namespace_publication_date_sync(DateTime value) const;

  /// Writes the `IsNamespaceSubset` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_is_namespace_subset_sync, write_is_namespace_subset_sync
  void write_is_namespace_subset_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `IsNamespaceSubset` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_is_namespace_subset_sync(bool value) const noexcept;
  /// Writes the `IsNamespaceSubset` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_is_namespace_subset_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_is_namespace_subset_sync(bool value) const;

  /// Writes the `StaticStringNodeIdPattern` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_static_string_node_id_pattern_sync, write_static_string_node_id_pattern_sync
  void write_static_string_node_id_pattern_async(
    String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `StaticStringNodeIdPattern` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_static_string_node_id_pattern_sync(String value) const noexcept;
  /// Writes the `StaticStringNodeIdPattern` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_static_string_node_id_pattern_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_static_string_node_id_pattern_sync(String value) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `AddressSpaceFile` handle for the `NamespaceFile` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_namespace_file_sync, namespace_file_sync
  void namespace_file_async(std::function<void(AddressSpaceFileResult)> complete) const noexcept;
  /// Attaches a typed `AddressSpaceFile` handle for the `NamespaceFile` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  AddressSpaceFileResult try_namespace_file_sync() const noexcept;
  /// Attaches a typed `AddressSpaceFile` handle for the `NamespaceFile` child, blocking until complete.
  /// @return The `AddressSpaceFile` handle. A Good subcode is not returned; @ref try_namespace_file_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  AddressSpaceFile namespace_file_sync() const;

private:
  explicit NamespaceMetadata(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_NAMESPACE_METADATA_H
