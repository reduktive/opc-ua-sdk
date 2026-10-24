// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_USER_MANAGEMENT_H
#define UA_USER_MANAGEMENT_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"

namespace ua
{

struct MethodCallContext;

class UserManagement;
using UserManagementResult = Result<UserManagement>;

/// Address-space handle for the OPC UA UserManagementType ObjectType.
/// @ingroup ua_information_model
class UserManagement : public BaseObject
{
public:
  /// Constructs an empty `UserManagement` handle that references no node.
  UserManagement() = default;

  /// Input arguments for the UserManagementType AddUser() method.
  struct AddUserInputArguments
  {
    String userName;  ///< User name.
    String password;  ///< Password.
    Variant userConfiguration;  ///< User configuration.
    String description;  ///< Description.
  };

  /// Synchronous handler for AddUser(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using AddUserHandler = std::function<MethodResult<>(const MethodCall&, const AddUserInputArguments&)>;
  /// Asynchronous handler for AddUser(): starts the work and completes it through the callback, once, from
  /// any thread.
  using AddUserAsyncHandler =
    std::function<void(const MethodCall&, const AddUserInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the UserManagementType ModifyUser() method.
  struct ModifyUserInputArguments
  {
    String userName;  ///< User name.
    bool modifyPassword{};  ///< Modify password.
    String password;  ///< Password.
    bool modifyUserConfiguration{};  ///< Modify user configuration.
    Variant userConfiguration;  ///< User configuration.
    bool modifyDescription{};  ///< Modify description.
    String description;  ///< Description.
  };

  /// Synchronous handler for ModifyUser(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using ModifyUserHandler = std::function<MethodResult<>(const MethodCall&, const ModifyUserInputArguments&)>;
  /// Asynchronous handler for ModifyUser(): starts the work and completes it through the callback, once, from
  /// any thread.
  using ModifyUserAsyncHandler =
    std::function<void(const MethodCall&, const ModifyUserInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the UserManagementType RemoveUser() method.
  struct RemoveUserInputArguments
  {
    String userName;  ///< User name.
  };

  /// Synchronous handler for RemoveUser(): returns the outputs, a failure or a rejected input argument (see
  /// ua::MethodResult), for work that waits for nothing.
  using RemoveUserHandler = std::function<MethodResult<>(const MethodCall&, const RemoveUserInputArguments&)>;
  /// Asynchronous handler for RemoveUser(): starts the work and completes it through the callback, once, from
  /// any thread.
  using RemoveUserAsyncHandler =
    std::function<void(const MethodCall&, const RemoveUserInputArguments&, MethodResultCallback<>)>;

  /// Input arguments for the UserManagementType ChangePassword() method.
  struct ChangePasswordInputArguments
  {
    String oldPassword;  ///< Old password.
    String newPassword;  ///< New password.
  };

  /// Synchronous handler for ChangePassword(): returns the outputs, a failure or a rejected input argument
  /// (see ua::MethodResult), for work that waits for nothing.
  using ChangePasswordHandler =
    std::function<MethodResult<>(const MethodCall&, const ChangePasswordInputArguments&)>;
  /// Asynchronous handler for ChangePassword(): starts the work and completes it through the callback, once,
  /// from any thread.
  using ChangePasswordAsyncHandler =
    std::function<void(const MethodCall&, const ChangePasswordInputArguments&, MethodResultCallback<>)>;

  /// Completion callback for create_async: receives the created `UserManagement` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(UserManagementResult)>;
  /// Completion callback for attach_async: receives the attached `UserManagement` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(UserManagementResult)>;

  /// Creates a new `UserManagementType` instance under `parent`.
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
  /// @param complete     Receives the outcome: on success a `UserManagement` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `UserManagementType` instance under `parent`, blocking until complete.  ///
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
  static UserManagementResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `UserManagementType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `UserManagement` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static UserManagement create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `UserManagementType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `UserManagement` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `UserManagementType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static UserManagementResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `UserManagementType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `UserManagement` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static UserManagement attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Method accessors ---

  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor, or an @ref ErrorDetail
  /// on failure.
  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;

  /// Attaches a `MethodAccessor` for client-side invocation of the `AddUser` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_add_user_method_sync, add_user_method_sync
  void add_user_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `AddUser` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_add_user_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `AddUser` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_add_user_method_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor add_user_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `ModifyUser` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_modify_user_method_sync, modify_user_method_sync
  void modify_user_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `ModifyUser` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_modify_user_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `ModifyUser` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_modify_user_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor modify_user_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `RemoveUser` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_remove_user_method_sync, remove_user_method_sync
  void remove_user_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveUser` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_remove_user_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `RemoveUser` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_remove_user_method_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor remove_user_method_sync() const;

  /// Attaches a `MethodAccessor` for client-side invocation of the `ChangePassword` method.
  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_change_password_method_sync, change_password_method_sync
  void change_password_method_async(MethodAccessorCompleteCallback complete) const noexcept;
  /// Attaches a `MethodAccessor` for the `ChangePassword` method, blocking until complete.
  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.
  MethodAccessorResult try_change_password_method_sync() const noexcept;
  /// Attaches a `MethodAccessor` for the `ChangePassword` method, blocking until complete.
  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_change_password_method_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  MethodAccessor change_password_method_sync() const;

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `Users` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_users_property_sync, users_property_sync
  void users_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `Users` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_users_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `Users` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_users_property_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property users_property_sync() const;

  /// Attaches a `Property` handle for the `PasswordLength` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_password_length_property_sync, password_length_property_sync
  void password_length_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `PasswordLength` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_password_length_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `PasswordLength` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_password_length_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property password_length_property_sync() const;

  /// Attaches a `Property` handle for the `PasswordOptions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_password_options_property_sync, password_options_property_sync
  void password_options_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `PasswordOptions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_password_options_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `PasswordOptions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_password_options_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property password_options_property_sync() const;

  /// Attaches a `Property` handle for the `PasswordRestrictions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_password_restrictions_property_sync, password_restrictions_property_sync
  void password_restrictions_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `PasswordRestrictions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_password_restrictions_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `PasswordRestrictions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_password_restrictions_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property password_restrictions_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `PasswordRestrictions` property value, typed as `LocalizedText`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_password_restrictions_sync, read_password_restrictions_sync
  void read_password_restrictions_async(std::function<void(LocalizedTextResult)> complete) const noexcept;
  /// Reads the `PasswordRestrictions` property value as `LocalizedText`, blocking until complete.
  /// @return The value with the read's code, as @ref read_password_restrictions_async gives it. Never throws.
  LocalizedTextResult try_read_password_restrictions_sync() const noexcept;
  /// Reads the `PasswordRestrictions` property value as `LocalizedText`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_password_restrictions_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  LocalizedText read_password_restrictions_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `PasswordRestrictions` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_password_restrictions_sync, write_password_restrictions_sync
  void write_password_restrictions_async(
    LocalizedText value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `PasswordRestrictions` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_password_restrictions_sync(LocalizedText value) const noexcept;
  /// Writes the `PasswordRestrictions` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_password_restrictions_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_password_restrictions_sync(LocalizedText value) const;

  // --- Method handler registration ---

  /// Registers the synchronous handler invoked when a client calls the `AddUser` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_user_handler_sync, set_add_user_handler_sync
  void set_add_user_handler_async(
    AddUserHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `AddUser` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_user_handler_sync(AddUserHandler handler) const noexcept;
  /// Registers the synchronous `AddUser` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_user_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_user_handler_sync(AddUserHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `AddUser` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_add_user_handler_sync, set_add_user_handler_sync
  void set_add_user_handler_async(
    AddUserAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `AddUser` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_add_user_handler_sync(AddUserAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `AddUser` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_add_user_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_add_user_handler_sync(AddUserAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `ModifyUser` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_modify_user_handler_sync, set_modify_user_handler_sync
  void set_modify_user_handler_async(
    ModifyUserHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `ModifyUser` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_modify_user_handler_sync(ModifyUserHandler handler) const noexcept;
  /// Registers the synchronous `ModifyUser` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_modify_user_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_modify_user_handler_sync(ModifyUserHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `ModifyUser` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_modify_user_handler_sync, set_modify_user_handler_sync
  void set_modify_user_handler_async(
    ModifyUserAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `ModifyUser` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_modify_user_handler_sync(ModifyUserAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `ModifyUser` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_modify_user_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_modify_user_handler_sync(ModifyUserAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `RemoveUser` method, in place of any
  /// earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_user_handler_sync, set_remove_user_handler_sync
  void set_remove_user_handler_async(
    RemoveUserHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `RemoveUser` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_user_handler_sync(RemoveUserHandler handler) const noexcept;
  /// Registers the synchronous `RemoveUser` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_user_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_user_handler_sync(RemoveUserHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `RemoveUser` method, in place of any
  /// earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_remove_user_handler_sync, set_remove_user_handler_sync
  void set_remove_user_handler_async(
    RemoveUserAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `RemoveUser` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_remove_user_handler_sync(RemoveUserAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `RemoveUser` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_remove_user_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_remove_user_handler_sync(RemoveUserAsyncHandler handler) const;

  /// Registers the synchronous handler invoked when a client calls the `ChangePassword` method, in place of
  /// any earlier one.
  /// @param handler The synchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_change_password_handler_sync, set_change_password_handler_sync
  void set_change_password_handler_async(
    ChangePasswordHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the synchronous `ChangePassword` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_change_password_handler_sync(ChangePasswordHandler handler) const noexcept;
  /// Registers the synchronous `ChangePassword` handler, blocking until complete.
  /// @param handler The synchronous handler.
  /// A Good subcode is not returned; @ref try_set_change_password_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_change_password_handler_sync(ChangePasswordHandler handler) const;

  /// Registers the asynchronous handler invoked when a client calls the `ChangePassword` method, in place of
  /// any earlier one.
  /// @param handler The asynchronous handler.
  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_set_change_password_handler_sync, set_change_password_handler_sync
  void set_change_password_handler_async(
    ChangePasswordAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept;
  /// Registers the asynchronous `ChangePassword` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_set_change_password_handler_sync(ChangePasswordAsyncHandler handler) const noexcept;
  /// Registers the asynchronous `ChangePassword` handler, blocking until complete.
  /// @param handler The asynchronous handler.
  /// A Good subcode is not returned; @ref try_set_change_password_handler_sync returns it.
  /// @throws UaException when the registration is not Good, an Uncertain answer included.
  void set_change_password_handler_sync(ChangePasswordAsyncHandler handler) const;

private:
  explicit UserManagement(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_USER_MANAGEMENT_H
