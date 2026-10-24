// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TRUST_LIST_H
#define UA_TRUST_LIST_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class TrustList;
using TrustListResult = Result<TrustList>;

/// Address-space handle for the OPC UA TrustListType ObjectType.
/// @ingroup ua_information_model
class TrustList : public BaseObject
{
public:
  /// Constructs an empty `TrustList` handle that references no node.
  TrustList() = default;

  /// Input arguments for the TrustListType OpenWithMasks() method.
  struct OpenWithMasksInputArguments
  {
    uint32_t masks{};  ///< Masks.
  };

  /// Output arguments for the TrustListType OpenWithMasks() method.
  struct OpenWithMasksOutputArguments
  {
    uint32_t fileHandle{};  ///< File handle.
  };

  /// Synchronous handler for OpenWithMasks(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using OpenWithMasksHandler = std::function<MethodResult<OpenWithMasksOutputArguments>(
    const MethodCall&, const OpenWithMasksInputArguments&)>;
  /// Asynchronous handler for OpenWithMasks(): starts the work and completes it through the callback, once,
  /// from any thread.
  using OpenWithMasksAsyncHandler = std::function<void(const MethodCall&, const OpenWithMasksInputArguments&,
    MethodResultCallback<OpenWithMasksOutputArguments>)>;

  /// Input arguments for the TrustListType CloseAndUpdate() method.
  struct CloseAndUpdateInputArguments
  {
    uint32_t fileHandle{};  ///< File handle.
  };

  /// Output arguments for the TrustListType CloseAndUpdate() method.
  struct CloseAndUpdateOutputArguments
  {
    bool applyChangesRequired{};  ///< Apply changes required.
  };

  /// Synchronous handler for CloseAndUpdate(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using CloseAndUpdateHandler = std::function<MethodResult<CloseAndUpdateOutputArguments>(
    const MethodCall&, const CloseAndUpdateInputArguments&)>;
  /// Asynchronous handler for CloseAndUpdate(): starts the work and completes it through the callback, once,
  /// from any thread.
  using CloseAndUpdateAsyncHandler = std::function<void(const MethodCall&,
    const CloseAndUpdateInputArguments&, MethodResultCallback<CloseAndUpdateOutputArguments>)>;

  /// Input arguments for the TrustListType AddCertificate() method.
  struct AddCertificateInputArguments
  {
    ByteString certificate;  ///< Certificate.
    bool isTrustedCertificate{};  ///< Is trusted certificate.
  };

  /// Synchronous handler for AddCertificate(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using AddCertificateHandler =
    std::function<MethodResult<>(const MethodCall&, const AddCertificateInputArguments&)>;
  /// Asynchronous handler for AddCertificate(): starts the work and completes it through the callback, once,
  /// from any thread.
  using AddCertificateAsyncHandler =
    std::function<void(const MethodCall&, const AddCertificateInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the TrustListType RemoveCertificate() method.
  struct RemoveCertificateInputArguments
  {
    String thumbprint;  ///< Thumbprint.
    bool isTrustedCertificate{};  ///< Is trusted certificate.
  };

  /// Synchronous handler for RemoveCertificate(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using RemoveCertificateHandler =
    std::function<MethodResult<>(const MethodCall&, const RemoveCertificateInputArguments&)>;
  /// Asynchronous handler for RemoveCertificate(): starts the work and completes it through the callback,
  /// once, from any thread.
  using RemoveCertificateAsyncHandler =
    std::function<void(const MethodCall&, const RemoveCertificateInputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `TrustList` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(TrustListResult)>;
  /// Completion callback for attach_async: receives the attached `TrustList` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(TrustListResult)>;

  /// Creates a new `TrustListType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `TrustList` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `TrustListType` instance under `parent`, blocking until complete.  ///
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
  static TrustListResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `TrustListType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `TrustList` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static TrustList create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `TrustListType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `TrustList` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `TrustListType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static TrustListResult try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `TrustListType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `TrustList` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static TrustList attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `OpenWithMasks` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_open_with_masks_method_sync, open_with_masks_method_sync
  void open_with_masks_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `OpenWithMasks` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_open_with_masks_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `OpenWithMasks` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_open_with_masks_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor open_with_masks_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `CloseAndUpdate` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_close_and_update_method_sync, close_and_update_method_sync
  void close_and_update_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `CloseAndUpdate` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_close_and_update_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `CloseAndUpdate` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_close_and_update_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor close_and_update_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `AddCertificate` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_certificate_method_sync, add_certificate_method_sync
  void add_certificate_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `AddCertificate` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_add_certificate_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `AddCertificate` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_add_certificate_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor add_certificate_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RemoveCertificate` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_certificate_method_sync, remove_certificate_method_sync
  void remove_certificate_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveCertificate` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_remove_certificate_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveCertificate` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_remove_certificate_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor remove_certificate_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

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

  /// Attaches a `Property` handle for the `UpdateFrequency` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_update_frequency_property_sync, update_frequency_property_sync
  void update_frequency_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `UpdateFrequency` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_update_frequency_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `UpdateFrequency` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_update_frequency_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property update_frequency_property_sync() const;

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

  /// Attaches a `Property` handle for the `DefaultValidationOptions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_default_validation_options_property_sync, default_validation_options_property_sync
  void default_validation_options_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `DefaultValidationOptions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_default_validation_options_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `DefaultValidationOptions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_default_validation_options_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property default_validation_options_property_sync() const;

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

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `OpenWithMasks` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_open_with_masks_handler_sync, set_open_with_masks_handler_sync
  void set_open_with_masks_handler_async(
    OpenWithMasksHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `OpenWithMasks` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_open_with_masks_handler_sync(OpenWithMasksHandler handler) const noexcept;
  /// Registers the synchronous `OpenWithMasks` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_open_with_masks_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_open_with_masks_handler_sync(OpenWithMasksHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `OpenWithMasks` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_open_with_masks_handler_sync, set_open_with_masks_handler_sync
  void set_open_with_masks_handler_async(
    OpenWithMasksAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `OpenWithMasks` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_open_with_masks_handler_sync(OpenWithMasksAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `OpenWithMasks` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_open_with_masks_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_open_with_masks_handler_sync(OpenWithMasksAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `CloseAndUpdate` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_close_and_update_handler_sync, set_close_and_update_handler_sync
  void set_close_and_update_handler_async(
    CloseAndUpdateHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `CloseAndUpdate` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_close_and_update_handler_sync(CloseAndUpdateHandler handler) const noexcept;
  /// Registers the synchronous `CloseAndUpdate` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_close_and_update_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_close_and_update_handler_sync(CloseAndUpdateHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `CloseAndUpdate` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_close_and_update_handler_sync, set_close_and_update_handler_sync
  void set_close_and_update_handler_async(
    CloseAndUpdateAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `CloseAndUpdate` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_close_and_update_handler_sync(CloseAndUpdateAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `CloseAndUpdate` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_close_and_update_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_close_and_update_handler_sync(CloseAndUpdateAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `AddCertificate` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_certificate_handler_sync, set_add_certificate_handler_sync
  void set_add_certificate_handler_async(
    AddCertificateHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `AddCertificate` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_certificate_handler_sync(AddCertificateHandler handler) const noexcept;
  /// Registers the synchronous `AddCertificate` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_certificate_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_certificate_handler_sync(AddCertificateHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `AddCertificate` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_certificate_handler_sync, set_add_certificate_handler_sync
  void set_add_certificate_handler_async(
    AddCertificateAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `AddCertificate` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_certificate_handler_sync(AddCertificateAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `AddCertificate` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_certificate_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_certificate_handler_sync(AddCertificateAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RemoveCertificate` method, in place
  /// of any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_certificate_handler_sync, set_remove_certificate_handler_sync
  void set_remove_certificate_handler_async(
    RemoveCertificateHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RemoveCertificate` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_certificate_handler_sync(RemoveCertificateHandler handler) const noexcept;
  /// Registers the synchronous `RemoveCertificate` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_certificate_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_certificate_handler_sync(RemoveCertificateHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RemoveCertificate` method, in place
  /// of any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_certificate_handler_sync, set_remove_certificate_handler_sync
  void set_remove_certificate_handler_async(
    RemoveCertificateAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RemoveCertificate` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_certificate_handler_sync(RemoveCertificateAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RemoveCertificate` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_certificate_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_certificate_handler_sync(RemoveCertificateAsyncHandler handler) const;

private:
  explicit TrustList(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_TRUST_LIST_H
