// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_APPLICATION_CONFIGURATION_FILE_H
#define UA_APPLICATION_CONFIGURATION_FILE_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class ApplicationConfigurationFile;
using ApplicationConfigurationFileResult = Result<ApplicationConfigurationFile>;

/// Address-space handle for the OPC UA ApplicationConfigurationFileType ObjectType.
/// @ingroup ua_information_model
class ApplicationConfigurationFile : public BaseObject
{
public:
  /// Constructs an empty `ApplicationConfigurationFile` handle that references no node.
  ApplicationConfigurationFile() = default;

  /// Completion callback for create_async: receives the created `ApplicationConfigurationFile` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ApplicationConfigurationFileResult)>;
  /// Completion callback for attach_async: receives the attached `ApplicationConfigurationFile` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ApplicationConfigurationFileResult)>;

  /// Creates a new `ApplicationConfigurationFileType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `ApplicationConfigurationFile` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ApplicationConfigurationFileType` instance under `parent`, blocking until complete.  ///
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
  static ApplicationConfigurationFileResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ApplicationConfigurationFileType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ApplicationConfigurationFile` handle. A Good subcode is not returned; @ref
  /// try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ApplicationConfigurationFile create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ApplicationConfigurationFileType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ApplicationConfigurationFile` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ApplicationConfigurationFileType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ApplicationConfigurationFileResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ApplicationConfigurationFileType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ApplicationConfigurationFile` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ApplicationConfigurationFile attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `AvailableNetworks` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_available_networks_property_sync, available_networks_property_sync
  void available_networks_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `AvailableNetworks` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_available_networks_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `AvailableNetworks` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_available_networks_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property available_networks_property_sync() const;

  /// Attaches a `Property` handle for the `AvailablePorts` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_available_ports_property_sync, available_ports_property_sync
  void available_ports_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `AvailablePorts` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_available_ports_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `AvailablePorts` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_available_ports_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property available_ports_property_sync() const;

  /// Attaches a `Property` handle for the `MaxEndpoints` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_endpoints_property_sync, max_endpoints_property_sync
  void max_endpoints_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxEndpoints` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_endpoints_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxEndpoints` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_max_endpoints_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_endpoints_property_sync() const;

  /// Attaches a `Property` handle for the `MaxCertificateGroups` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_certificate_groups_property_sync, max_certificate_groups_property_sync
  void max_certificate_groups_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxCertificateGroups` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_certificate_groups_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxCertificateGroups` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_certificate_groups_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_certificate_groups_property_sync() const;

  /// Attaches a `Property` handle for the `SecurityPolicyUris` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_security_policy_uris_property_sync, security_policy_uris_property_sync
  void security_policy_uris_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SecurityPolicyUris` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_security_policy_uris_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SecurityPolicyUris` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_security_policy_uris_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property security_policy_uris_property_sync() const;

  /// Attaches a `Property` handle for the `UserTokenTypes` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_user_token_types_property_sync, user_token_types_property_sync
  void user_token_types_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `UserTokenTypes` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_user_token_types_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `UserTokenTypes` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_user_token_types_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property user_token_types_property_sync() const;

  /// Attaches a `Property` handle for the `CertificateTypes` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_certificate_types_property_sync, certificate_types_property_sync
  void certificate_types_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CertificateTypes` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_certificate_types_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CertificateTypes` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_certificate_types_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property certificate_types_property_sync() const;

  /// Attaches a `Property` handle for the `CertificateGroupPurposes` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_certificate_group_purposes_property_sync, certificate_group_purposes_property_sync
  void certificate_group_purposes_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CertificateGroupPurposes` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_certificate_group_purposes_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CertificateGroupPurposes` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_certificate_group_purposes_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property certificate_group_purposes_property_sync() const;

  /// Attaches a `Property` handle for the `LastUpdateTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_update_time_property_sync, last_update_time_property_sync
  void last_update_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastUpdateTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_update_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastUpdateTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_update_time_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_update_time_property_sync() const;

  /// Attaches a `Property` handle for the `CurrentVersion` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_current_version_property_sync, current_version_property_sync
  void current_version_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CurrentVersion` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_current_version_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CurrentVersion` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_current_version_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property current_version_property_sync() const;

  /// Attaches a `Property` handle for the `ActivityTimeout` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_activity_timeout_property_sync, activity_timeout_property_sync
  void activity_timeout_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ActivityTimeout` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_activity_timeout_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ActivityTimeout` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_activity_timeout_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property activity_timeout_property_sync() const;

  /// Attaches a `Property` handle for the `SupportedDataType` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_supported_data_type_property_sync, supported_data_type_property_sync
  void supported_data_type_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SupportedDataType` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_supported_data_type_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SupportedDataType` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_supported_data_type_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property supported_data_type_property_sync() const;

  /// Attaches a `Property` handle for the `Size` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_size_property_sync, size_property_sync
  void size_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Size` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_size_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Size` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_size_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property size_property_sync() const;

  /// Attaches a `Property` handle for the `Writable` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_writable_property_sync, writable_property_sync
  void writable_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Writable` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_writable_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Writable` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_writable_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property writable_property_sync() const;

  /// Attaches a `Property` handle for the `UserWritable` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_user_writable_property_sync, user_writable_property_sync
  void user_writable_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `UserWritable` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_user_writable_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `UserWritable` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_user_writable_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property user_writable_property_sync() const;

  /// Attaches a `Property` handle for the `OpenCount` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_open_count_property_sync, open_count_property_sync
  void open_count_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `OpenCount` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_open_count_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `OpenCount` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_open_count_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property open_count_property_sync() const;

  /// Attaches a `Property` handle for the `MimeType` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_mime_type_property_sync, mime_type_property_sync
  void mime_type_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MimeType` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_mime_type_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MimeType` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_mime_type_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property mime_type_property_sync() const;

  /// Attaches a `Property` handle for the `MaxByteStringLength` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_byte_string_length_property_sync, max_byte_string_length_property_sync
  void max_byte_string_length_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxByteStringLength` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_byte_string_length_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxByteStringLength` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_byte_string_length_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_byte_string_length_property_sync() const;

  /// Attaches a `Property` handle for the `LastModifiedTime` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_last_modified_time_property_sync, last_modified_time_property_sync
  void last_modified_time_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LastModifiedTime` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_last_modified_time_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LastModifiedTime` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_last_modified_time_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property last_modified_time_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `AvailableNetworks` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_available_networks_sync, read_available_networks_sync
  void read_available_networks_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `AvailableNetworks` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_available_networks_async gives it. Never throws.
  StringResult try_read_available_networks_sync() const noexcept;
  /// Reads the `AvailableNetworks` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_available_networks_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_available_networks_sync() const;

  /// Reads the `MaxEndpoints` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_endpoints_sync, read_max_endpoints_sync
  void read_max_endpoints_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `MaxEndpoints` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_endpoints_async gives it. Never throws.
  UInt16Result try_read_max_endpoints_sync() const noexcept;
  /// Reads the `MaxEndpoints` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_endpoints_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_max_endpoints_sync() const;

  /// Reads the `MaxCertificateGroups` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_certificate_groups_sync, read_max_certificate_groups_sync
  void read_max_certificate_groups_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `MaxCertificateGroups` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_certificate_groups_async gives it. Never
  /// throws.
  UInt16Result try_read_max_certificate_groups_sync() const noexcept;
  /// Reads the `MaxCertificateGroups` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_certificate_groups_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_max_certificate_groups_sync() const;

  /// Reads the `CertificateTypes` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_certificate_types_sync, read_certificate_types_sync
  void read_certificate_types_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `CertificateTypes` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_certificate_types_async gives it. Never throws.
  NodeIdResult try_read_certificate_types_sync() const noexcept;
  /// Reads the `CertificateTypes` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_certificate_types_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_certificate_types_sync() const;

  /// Reads the `CertificateGroupPurposes` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_certificate_group_purposes_sync, read_certificate_group_purposes_sync
  void read_certificate_group_purposes_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `CertificateGroupPurposes` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_certificate_group_purposes_async gives it. Never
  /// throws.
  NodeIdResult try_read_certificate_group_purposes_sync() const noexcept;
  /// Reads the `CertificateGroupPurposes` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_certificate_group_purposes_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_certificate_group_purposes_sync() const;

  /// Reads the `SupportedDataType` property value, typed as `NodeId`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_supported_data_type_sync, read_supported_data_type_sync
  void read_supported_data_type_async(std::function<void(NodeIdResult)> complete) const noexcept;
  /// Reads the `SupportedDataType` property value as `NodeId`, blocking until complete.
  /// @return The value with the read's code, as @ref read_supported_data_type_async gives it. Never throws.
  NodeIdResult try_read_supported_data_type_sync() const noexcept;
  /// Reads the `SupportedDataType` property value as `NodeId`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_supported_data_type_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  NodeId read_supported_data_type_sync() const;

  /// Reads the `Size` property value, typed as `uint64_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_size_sync, read_size_sync
  void read_size_async(std::function<void(UInt64Result)> complete) const noexcept;
  /// Reads the `Size` property value as `uint64_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_size_async gives it. Never throws.
  UInt64Result try_read_size_sync() const noexcept;
  /// Reads the `Size` property value as `uint64_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_size_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint64_t read_size_sync() const;

  /// Reads the `Writable` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_writable_sync, read_writable_sync
  void read_writable_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `Writable` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_writable_async gives it. Never throws.
  BoolResult try_read_writable_sync() const noexcept;
  /// Reads the `Writable` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_writable_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_writable_sync() const;

  /// Reads the `UserWritable` property value, typed as `bool`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_user_writable_sync, read_user_writable_sync
  void read_user_writable_async(std::function<void(BoolResult)> complete) const noexcept;
  /// Reads the `UserWritable` property value as `bool`, blocking until complete.
  /// @return The value with the read's code, as @ref read_user_writable_async gives it. Never throws.
  BoolResult try_read_user_writable_sync() const noexcept;
  /// Reads the `UserWritable` property value as `bool`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_user_writable_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  bool read_user_writable_sync() const;

  /// Reads the `OpenCount` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_open_count_sync, read_open_count_sync
  void read_open_count_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `OpenCount` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_open_count_async gives it. Never throws.
  UInt16Result try_read_open_count_sync() const noexcept;
  /// Reads the `OpenCount` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_open_count_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_open_count_sync() const;

  /// Reads the `MimeType` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_mime_type_sync, read_mime_type_sync
  void read_mime_type_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `MimeType` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_mime_type_async gives it. Never throws.
  StringResult try_read_mime_type_sync() const noexcept;
  /// Reads the `MimeType` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_mime_type_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_mime_type_sync() const;

  /// Reads the `MaxByteStringLength` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_byte_string_length_sync, read_max_byte_string_length_sync
  void read_max_byte_string_length_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxByteStringLength` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_byte_string_length_async gives it. Never
  /// throws.
  UInt32Result try_read_max_byte_string_length_sync() const noexcept;
  /// Reads the `MaxByteStringLength` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_byte_string_length_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_byte_string_length_sync() const;

  /// Reads the `LastModifiedTime` property value, typed as `DateTime`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_last_modified_time_sync, read_last_modified_time_sync
  void read_last_modified_time_async(std::function<void(DateTimeResult)> complete) const noexcept;
  /// Reads the `LastModifiedTime` property value as `DateTime`, blocking until complete.
  /// @return The value with the read's code, as @ref read_last_modified_time_async gives it. Never throws.
  DateTimeResult try_read_last_modified_time_sync() const noexcept;
  /// Reads the `LastModifiedTime` property value as `DateTime`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_last_modified_time_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  DateTime read_last_modified_time_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `AvailableNetworks` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_available_networks_sync, write_available_networks_sync
  void write_available_networks_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `AvailableNetworks` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_available_networks_sync(String value) const noexcept;
  /// Writes the `AvailableNetworks` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_available_networks_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_available_networks_sync(String value) const;

  /// Writes the `MaxEndpoints` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_endpoints_sync, write_max_endpoints_sync
  void write_max_endpoints_async(uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxEndpoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_endpoints_sync(uint16_t value) const noexcept;
  /// Writes the `MaxEndpoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_endpoints_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_endpoints_sync(uint16_t value) const;

  /// Writes the `MaxCertificateGroups` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_certificate_groups_sync, write_max_certificate_groups_sync
  void write_max_certificate_groups_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxCertificateGroups` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_certificate_groups_sync(uint16_t value) const noexcept;
  /// Writes the `MaxCertificateGroups` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_certificate_groups_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_certificate_groups_sync(uint16_t value) const;

  /// Writes the `CertificateTypes` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_certificate_types_sync, write_certificate_types_sync
  void write_certificate_types_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CertificateTypes` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_certificate_types_sync(NodeId value) const noexcept;
  /// Writes the `CertificateTypes` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_certificate_types_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_certificate_types_sync(NodeId value) const;

  /// Writes the `CertificateGroupPurposes` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_certificate_group_purposes_sync, write_certificate_group_purposes_sync
  void write_certificate_group_purposes_async(
    NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CertificateGroupPurposes` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_certificate_group_purposes_sync(NodeId value) const noexcept;
  /// Writes the `CertificateGroupPurposes` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_certificate_group_purposes_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_certificate_group_purposes_sync(NodeId value) const;

  /// Writes the `SupportedDataType` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_supported_data_type_sync, write_supported_data_type_sync
  void write_supported_data_type_async(NodeId value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `SupportedDataType` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_supported_data_type_sync(NodeId value) const noexcept;
  /// Writes the `SupportedDataType` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_supported_data_type_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_supported_data_type_sync(NodeId value) const;

  /// Writes the `Size` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_size_sync, write_size_sync
  void write_size_async(uint64_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Size` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_size_sync(uint64_t value) const noexcept;
  /// Writes the `Size` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_size_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_size_sync(uint64_t value) const;

  /// Writes the `Writable` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_writable_sync, write_writable_sync
  void write_writable_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `Writable` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_writable_sync(bool value) const noexcept;
  /// Writes the `Writable` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_writable_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_writable_sync(bool value) const;

  /// Writes the `UserWritable` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_user_writable_sync, write_user_writable_sync
  void write_user_writable_async(bool value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `UserWritable` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_user_writable_sync(bool value) const noexcept;
  /// Writes the `UserWritable` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_user_writable_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_user_writable_sync(bool value) const;

  /// Writes the `OpenCount` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_open_count_sync, write_open_count_sync
  void write_open_count_async(uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `OpenCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_open_count_sync(uint16_t value) const noexcept;
  /// Writes the `OpenCount` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_open_count_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_open_count_sync(uint16_t value) const;

  /// Writes the `MimeType` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_mime_type_sync, write_mime_type_sync
  void write_mime_type_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MimeType` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_mime_type_sync(String value) const noexcept;
  /// Writes the `MimeType` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_mime_type_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_mime_type_sync(String value) const;

  /// Writes the `MaxByteStringLength` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_byte_string_length_sync, write_max_byte_string_length_sync
  void write_max_byte_string_length_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxByteStringLength` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_byte_string_length_sync(uint32_t value) const noexcept;
  /// Writes the `MaxByteStringLength` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_byte_string_length_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_byte_string_length_sync(uint32_t value) const;

  /// Writes the `LastModifiedTime` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_last_modified_time_sync, write_last_modified_time_sync
  void write_last_modified_time_async(
    DateTime value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `LastModifiedTime` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_last_modified_time_sync(DateTime value) const noexcept;
  /// Writes the `LastModifiedTime` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_last_modified_time_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_last_modified_time_sync(DateTime value) const;

private:
  explicit ApplicationConfigurationFile(
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

#endif  // UA_APPLICATION_CONFIGURATION_FILE_H
