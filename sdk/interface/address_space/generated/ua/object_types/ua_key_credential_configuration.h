// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_KEY_CREDENTIAL_CONFIGURATION_H
#define UA_KEY_CREDENTIAL_CONFIGURATION_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class KeyCredentialConfiguration;
using KeyCredentialConfigurationResult = Result<KeyCredentialConfiguration>;

/// Address-space handle for the OPC UA KeyCredentialConfigurationType ObjectType.
/// @ingroup ua_information_model
class KeyCredentialConfiguration : public BaseObject
{
public:
  /// Constructs an empty `KeyCredentialConfiguration` handle that references no node.
  KeyCredentialConfiguration() = default;

  /// Input arguments for the KeyCredentialConfigurationType GetEncryptingKey() method.
  struct GetEncryptingKeyInputArguments
  {
    String credentialId;  ///< Credential id.
    String requestedSecurityPolicyUri;  ///< Requested security policy uri.
  };

  /// Output arguments for the KeyCredentialConfigurationType GetEncryptingKey() method.
  struct GetEncryptingKeyOutputArguments
  {
    ByteString publicKey;  ///< Public key.
    String revisedSecurityPolicyUri;  ///< Revised security policy uri.
  };

  /// Synchronous handler for GetEncryptingKey(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using GetEncryptingKeyHandler = std::function<MethodResult<GetEncryptingKeyOutputArguments>(
    const MethodCall&, const GetEncryptingKeyInputArguments&)>;
  /// Asynchronous handler for GetEncryptingKey(): starts the work and completes it through the callback,
  /// once, from any thread.
  using GetEncryptingKeyAsyncHandler = std::function<void(const MethodCall&,
    const GetEncryptingKeyInputArguments&, MethodResultCallback<GetEncryptingKeyOutputArguments>)>;

  /// Input arguments for the KeyCredentialConfigurationType UpdateCredential() method.
  struct UpdateCredentialInputArguments
  {
    String credentialId;  ///< Credential id.
    ByteString credentialSecret;  ///< Credential secret.
    String certificateThumbprint;  ///< Certificate thumbprint.
    String securityPolicyUri;  ///< Security policy uri.
  };

  /// Synchronous handler for UpdateCredential(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using UpdateCredentialHandler =
    std::function<MethodResult<>(const MethodCall&, const UpdateCredentialInputArguments&)>;
  /// Asynchronous handler for UpdateCredential(): starts the work and completes it through the callback,
  /// once, from any thread.
  using UpdateCredentialAsyncHandler =
    std::function<void(const MethodCall&, const UpdateCredentialInputArguments&, MethodResultCallback<>)>;

  /// Synchronous handler for DeleteCredential(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using DeleteCredentialHandler = std::function<MethodResult<>(const MethodCall&)>;
  /// Asynchronous handler for DeleteCredential(): starts the work and completes it through the callback,
  /// once, from any thread.
  using DeleteCredentialAsyncHandler = std::function<void(const MethodCall&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `KeyCredentialConfiguration` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(KeyCredentialConfigurationResult)>;
  /// Completion callback for attach_async: receives the attached `KeyCredentialConfiguration` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(KeyCredentialConfigurationResult)>;

  /// Creates a new `KeyCredentialConfigurationType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `KeyCredentialConfiguration` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `KeyCredentialConfigurationType` instance under `parent`, blocking until complete.  ///
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
  static KeyCredentialConfigurationResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `KeyCredentialConfigurationType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `KeyCredentialConfiguration` handle. A Good subcode is not returned; @ref
  /// try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static KeyCredentialConfiguration create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `KeyCredentialConfigurationType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `KeyCredentialConfiguration` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `KeyCredentialConfigurationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static KeyCredentialConfigurationResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `KeyCredentialConfigurationType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `KeyCredentialConfiguration` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static KeyCredentialConfiguration attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `GetEncryptingKey` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_get_encrypting_key_method_sync, get_encrypting_key_method_sync
  void get_encrypting_key_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `GetEncryptingKey` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_get_encrypting_key_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `GetEncryptingKey` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_get_encrypting_key_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor get_encrypting_key_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `UpdateCredential` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_update_credential_method_sync, update_credential_method_sync
  void update_credential_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `UpdateCredential` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_update_credential_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `UpdateCredential` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_update_credential_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor update_credential_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `DeleteCredential` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_delete_credential_method_sync, delete_credential_method_sync
  void delete_credential_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `DeleteCredential` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_delete_credential_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `DeleteCredential` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_delete_credential_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor delete_credential_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `ResourceUri` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_resource_uri_property_sync, resource_uri_property_sync
  void resource_uri_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ResourceUri` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_resource_uri_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ResourceUri` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_resource_uri_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property resource_uri_property_sync() const;

  /// Attaches a `Property` handle for the `ProfileUri` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_profile_uri_property_sync, profile_uri_property_sync
  void profile_uri_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ProfileUri` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_profile_uri_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ProfileUri` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_profile_uri_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property profile_uri_property_sync() const;

  /// Attaches a `Property` handle for the `EndpointUrls` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_endpoint_urls_property_sync, endpoint_urls_property_sync
  void endpoint_urls_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `EndpointUrls` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_endpoint_urls_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `EndpointUrls` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_endpoint_urls_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property endpoint_urls_property_sync() const;

  /// Attaches a `Property` handle for the `CredentialId` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_credential_id_property_sync, credential_id_property_sync
  void credential_id_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `CredentialId` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_credential_id_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `CredentialId` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_credential_id_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property credential_id_property_sync() const;

  /// Attaches a `Property` handle for the `ServiceStatus` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_service_status_property_sync, service_status_property_sync
  void service_status_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ServiceStatus` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_service_status_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ServiceStatus` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_service_status_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property service_status_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `ResourceUri` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_resource_uri_sync, read_resource_uri_sync
  void read_resource_uri_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `ResourceUri` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_resource_uri_async gives it. Never throws.
  StringResult try_read_resource_uri_sync() const noexcept;
  /// Reads the `ResourceUri` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_resource_uri_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_resource_uri_sync() const;

  /// Reads the `ProfileUri` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_profile_uri_sync, read_profile_uri_sync
  void read_profile_uri_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `ProfileUri` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_profile_uri_async gives it. Never throws.
  StringResult try_read_profile_uri_sync() const noexcept;
  /// Reads the `ProfileUri` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_profile_uri_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_profile_uri_sync() const;

  /// Reads the `EndpointUrls` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_endpoint_urls_sync, read_endpoint_urls_sync
  void read_endpoint_urls_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `EndpointUrls` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_endpoint_urls_async gives it. Never throws.
  StringResult try_read_endpoint_urls_sync() const noexcept;
  /// Reads the `EndpointUrls` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_endpoint_urls_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_endpoint_urls_sync() const;

  /// Reads the `CredentialId` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_credential_id_sync, read_credential_id_sync
  void read_credential_id_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `CredentialId` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_credential_id_async gives it. Never throws.
  StringResult try_read_credential_id_sync() const noexcept;
  /// Reads the `CredentialId` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_credential_id_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_credential_id_sync() const;

  /// Reads the `ServiceStatus` property value, typed as `StatusCode`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_service_status_sync, read_service_status_sync
  void read_service_status_async(std::function<void(Result<StatusCode>)> complete) const noexcept;
  /// Reads the `ServiceStatus` property value as `StatusCode`, blocking until complete.
  /// @return The value with the read's code, as @ref read_service_status_async gives it. Never throws.
  Result<StatusCode> try_read_service_status_sync() const noexcept;
  /// Reads the `ServiceStatus` property value as `StatusCode`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_service_status_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  StatusCode read_service_status_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `ResourceUri` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_resource_uri_sync, write_resource_uri_sync
  void write_resource_uri_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ResourceUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_resource_uri_sync(String value) const noexcept;
  /// Writes the `ResourceUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_resource_uri_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_resource_uri_sync(String value) const;

  /// Writes the `ProfileUri` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_profile_uri_sync, write_profile_uri_sync
  void write_profile_uri_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ProfileUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_profile_uri_sync(String value) const noexcept;
  /// Writes the `ProfileUri` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_profile_uri_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_profile_uri_sync(String value) const;

  /// Writes the `EndpointUrls` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_endpoint_urls_sync, write_endpoint_urls_sync
  void write_endpoint_urls_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `EndpointUrls` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_endpoint_urls_sync(String value) const noexcept;
  /// Writes the `EndpointUrls` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_endpoint_urls_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_endpoint_urls_sync(String value) const;

  /// Writes the `CredentialId` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_credential_id_sync, write_credential_id_sync
  void write_credential_id_async(String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `CredentialId` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_credential_id_sync(String value) const noexcept;
  /// Writes the `CredentialId` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_credential_id_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_credential_id_sync(String value) const;

  /// Writes the `ServiceStatus` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_service_status_sync, write_service_status_sync
  void write_service_status_async(StatusCode value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ServiceStatus` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_service_status_sync(StatusCode value) const noexcept;
  /// Writes the `ServiceStatus` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_service_status_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_service_status_sync(StatusCode value) const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `GetEncryptingKey` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_encrypting_key_handler_sync, set_get_encrypting_key_handler_sync
  void set_get_encrypting_key_handler_async(
    GetEncryptingKeyHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `GetEncryptingKey` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_encrypting_key_handler_sync(GetEncryptingKeyHandler handler) const noexcept;
  /// Registers the synchronous `GetEncryptingKey` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_encrypting_key_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_encrypting_key_handler_sync(GetEncryptingKeyHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `GetEncryptingKey` method, in place
  /// of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_get_encrypting_key_handler_sync, set_get_encrypting_key_handler_sync
  void set_get_encrypting_key_handler_async(
    GetEncryptingKeyAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `GetEncryptingKey` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_get_encrypting_key_handler_sync(GetEncryptingKeyAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `GetEncryptingKey` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_get_encrypting_key_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_get_encrypting_key_handler_sync(GetEncryptingKeyAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `UpdateCredential` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_update_credential_handler_sync, set_update_credential_handler_sync
  void set_update_credential_handler_async(
    UpdateCredentialHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `UpdateCredential` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_update_credential_handler_sync(UpdateCredentialHandler handler) const noexcept;
  /// Registers the synchronous `UpdateCredential` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_update_credential_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_update_credential_handler_sync(UpdateCredentialHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `UpdateCredential` method, in place
  /// of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_update_credential_handler_sync, set_update_credential_handler_sync
  void set_update_credential_handler_async(
    UpdateCredentialAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `UpdateCredential` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_update_credential_handler_sync(UpdateCredentialAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `UpdateCredential` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_update_credential_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_update_credential_handler_sync(UpdateCredentialAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `DeleteCredential` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_delete_credential_handler_sync, set_delete_credential_handler_sync
  void set_delete_credential_handler_async(
    DeleteCredentialHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `DeleteCredential` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_delete_credential_handler_sync(DeleteCredentialHandler handler) const noexcept;
  /// Registers the synchronous `DeleteCredential` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_delete_credential_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_delete_credential_handler_sync(DeleteCredentialHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `DeleteCredential` method, in place
  /// of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_delete_credential_handler_sync, set_delete_credential_handler_sync
  void set_delete_credential_handler_async(
    DeleteCredentialAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `DeleteCredential` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_delete_credential_handler_sync(DeleteCredentialAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `DeleteCredential` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_delete_credential_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_delete_credential_handler_sync(DeleteCredentialAsyncHandler handler) const;

private:
  explicit KeyCredentialConfiguration(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_KEY_CREDENTIAL_CONFIGURATION_H
