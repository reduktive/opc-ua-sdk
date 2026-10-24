// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_user_management.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_call_method_result.h"
#include "ua_method_adapter.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

namespace ua
{
namespace
{

struct UserManagementTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::UserManagementType};
  }

  static QualifiedName users_browse_name()
  {
    return QualifiedName{0, "Users"};
  }

  static QualifiedName password_length_browse_name()
  {
    return QualifiedName{0, "PasswordLength"};
  }

  static QualifiedName password_options_browse_name()
  {
    return QualifiedName{0, "PasswordOptions"};
  }

  static QualifiedName password_restrictions_browse_name()
  {
    return QualifiedName{0, "PasswordRestrictions"};
  }

  static QualifiedName add_user_browse_name()
  {
    return QualifiedName{0, "AddUser"};
  }

  static QualifiedName modify_user_browse_name()
  {
    return QualifiedName{0, "ModifyUser"};
  }

  static QualifiedName remove_user_browse_name()
  {
    return QualifiedName{0, "RemoveUser"};
  }

  static QualifiedName change_password_browse_name()
  {
    return QualifiedName{0, "ChangePassword"};
  }
};

}  // namespace

UserManagement::UserManagement(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void UserManagement::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    UserManagementTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(UserManagementResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(UserManagementResult{
        UserManagement{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

UserManagementResult UserManagement::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UserManagementResult>(addressSpace.executor(),
      [&](std::function<void(UserManagementResult)> complete)
      {
        UserManagement::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

UserManagement UserManagement::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void UserManagement::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void UserManagement::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // UserManagementType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    UserManagementTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(UserManagementResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(UserManagementResult{::ua::detail::address_space_gone("UserManagement")});
        return;
      }
      complete(UserManagement{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

UserManagementResult UserManagement::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UserManagementResult>(addressSpace.executor(),
      [&](std::function<void(UserManagementResult)> complete)
      {
        UserManagement::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

UserManagement UserManagement::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void UserManagement::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void UserManagement::add_user_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    UserManagementTypeTraits::add_user_browse_name(),
    std::move(complete));
}

MethodAccessorResult UserManagement::try_add_user_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { add_user_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor UserManagement::add_user_method_sync() const
{
  return ::ua::detail::good_value(try_add_user_method_sync());
}

void UserManagement::modify_user_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    UserManagementTypeTraits::modify_user_browse_name(),
    std::move(complete));
}

MethodAccessorResult UserManagement::try_modify_user_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { modify_user_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor UserManagement::modify_user_method_sync() const
{
  return ::ua::detail::good_value(try_modify_user_method_sync());
}

void UserManagement::remove_user_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    UserManagementTypeTraits::remove_user_browse_name(),
    std::move(complete));
}

MethodAccessorResult UserManagement::try_remove_user_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { remove_user_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor UserManagement::remove_user_method_sync() const
{
  return ::ua::detail::good_value(try_remove_user_method_sync());
}

void UserManagement::change_password_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    UserManagementTypeTraits::change_password_browse_name(),
    std::move(complete));
}

MethodAccessorResult UserManagement::try_change_password_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { change_password_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor UserManagement::change_password_method_sync() const
{
  return ::ua::detail::good_value(try_change_password_method_sync());
}

// --- Common property helper ---

void UserManagement::find_property_async(
  QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Property>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasProperty},
    std::move(browseName),
    "UserManagement",
    std::move(complete));
}

// --- Property accessors ---

void UserManagement::users_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(UserManagementTypeTraits::users_browse_name(), std::move(complete));
}

PropertyResult UserManagement::try_users_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { users_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property UserManagement::users_property_sync() const
{
  return ::ua::detail::good_value(try_users_property_sync());
}

void UserManagement::password_length_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(UserManagementTypeTraits::password_length_browse_name(), std::move(complete));
}

PropertyResult UserManagement::try_password_length_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { password_length_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property UserManagement::password_length_property_sync() const
{
  return ::ua::detail::good_value(try_password_length_property_sync());
}

void UserManagement::password_options_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(UserManagementTypeTraits::password_options_browse_name(), std::move(complete));
}

PropertyResult UserManagement::try_password_options_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { password_options_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property UserManagement::password_options_property_sync() const
{
  return ::ua::detail::good_value(try_password_options_property_sync());
}

void UserManagement::password_restrictions_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(UserManagementTypeTraits::password_restrictions_browse_name(), std::move(complete));
}

PropertyResult UserManagement::try_password_restrictions_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { password_restrictions_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property UserManagement::password_restrictions_property_sync() const
{
  return ::ua::detail::good_value(try_password_restrictions_property_sync());
}

// --- Typed value read shortcuts ---

void UserManagement::read_password_restrictions_async(
  std::function<void(LocalizedTextResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(LocalizedTextResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<LocalizedText>(*mAddressSpace,
    mNodeId,
    UserManagementTypeTraits::password_restrictions_browse_name(),
    &Variant::is_localized_text,
    {"UserManagement", "password_restrictions", "UserManagement::read_password_restrictions_async"},
    std::move(complete));
}

LocalizedTextResult UserManagement::try_read_password_restrictions_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LocalizedTextResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(LocalizedTextResult)> complete)
      { read_password_restrictions_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

LocalizedText UserManagement::read_password_restrictions_sync() const
{
  return ::ua::detail::good_value(try_read_password_restrictions_sync());
}

// --- Typed value write shortcuts ---

void UserManagement::write_password_restrictions_async(
  LocalizedText value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    UserManagementTypeTraits::password_restrictions_browse_name(),
    "UserManagement",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult UserManagement::try_write_password_restrictions_sync(LocalizedText value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_password_restrictions_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::write_password_restrictions_sync(LocalizedText value) const
{
  try_write_password_restrictions_sync(value).value();
}

// --- Method handler registration ---

void UserManagement::set_add_user_handler_async(
  AddUserHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "UserManagement",
        "UserManagement::set_add_user_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String, Variant, String>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const String& in1, const Variant& in2, const String& in3)
        -> MethodResult<>
      {
        AddUserInputArguments typedIn{
          .userName = in0, .password = in1, .userConfiguration = in2, .description = in3};
        return handler(call, typedIn);
      },
      Inputs<String, String, Variant, String>{{Arg<String>{.name = "UserName"},
        Arg<String>{.name = "Password"},
        Arg<Variant>{.name = "UserConfiguration"},
        Arg<String>{.name = "Description"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, UserManagementTypeTraits::add_user_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult UserManagement::try_set_add_user_handler_sync(AddUserHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_user_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::set_add_user_handler_sync(AddUserHandler handler) const
{
  try_set_add_user_handler_sync(std::move(handler)).value();
}

void UserManagement::set_add_user_handler_async(
  AddUserAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "UserManagement",
        "UserManagement::set_add_user_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String, Variant, String>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const String& in0,
        const String& in1,
        const Variant& in2,
        const String& in3,
        MethodResultCallback<>
          complete)
      {
        AddUserInputArguments typedIn{
          .userName = in0, .password = in1, .userConfiguration = in2, .description = in3};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String, String, Variant, String>{{Arg<String>{.name = "UserName"},
        Arg<String>{.name = "Password"},
        Arg<Variant>{.name = "UserConfiguration"},
        Arg<String>{.name = "Description"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, UserManagementTypeTraits::add_user_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult UserManagement::try_set_add_user_handler_sync(AddUserAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_user_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::set_add_user_handler_sync(AddUserAsyncHandler handler) const
{
  try_set_add_user_handler_sync(std::move(handler)).value();
}

void UserManagement::set_modify_user_handler_async(
  ModifyUserHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "UserManagement",
        "UserManagement::set_modify_user_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, bool, String, bool, Variant, bool, String>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call,
        const String& in0,
        const bool& in1,
        const String& in2,
        const bool& in3,
        const Variant& in4,
        const bool& in5,
        const String& in6) -> MethodResult<>
      {
        ModifyUserInputArguments typedIn{.userName = in0,
          .modifyPassword = in1,
          .password = in2,
          .modifyUserConfiguration = in3,
          .userConfiguration = in4,
          .modifyDescription = in5,
          .description = in6};
        return handler(call, typedIn);
      },
      Inputs<String, bool, String, bool, Variant, bool, String>{{Arg<String>{.name = "UserName"},
        Arg<bool>{.name = "ModifyPassword"},
        Arg<String>{.name = "Password"},
        Arg<bool>{.name = "ModifyUserConfiguration"},
        Arg<Variant>{.name = "UserConfiguration"},
        Arg<bool>{.name = "ModifyDescription"},
        Arg<String>{.name = "Description"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, UserManagementTypeTraits::modify_user_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult UserManagement::try_set_modify_user_handler_sync(ModifyUserHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_modify_user_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::set_modify_user_handler_sync(ModifyUserHandler handler) const
{
  try_set_modify_user_handler_sync(std::move(handler)).value();
}

void UserManagement::set_modify_user_handler_async(
  ModifyUserAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "UserManagement",
        "UserManagement::set_modify_user_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, bool, String, bool, Variant, bool, String>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const String& in0,
        const bool& in1,
        const String& in2,
        const bool& in3,
        const Variant& in4,
        const bool& in5,
        const String& in6,
        MethodResultCallback<>
          complete)
      {
        ModifyUserInputArguments typedIn{.userName = in0,
          .modifyPassword = in1,
          .password = in2,
          .modifyUserConfiguration = in3,
          .userConfiguration = in4,
          .modifyDescription = in5,
          .description = in6};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String, bool, String, bool, Variant, bool, String>{{Arg<String>{.name = "UserName"},
        Arg<bool>{.name = "ModifyPassword"},
        Arg<String>{.name = "Password"},
        Arg<bool>{.name = "ModifyUserConfiguration"},
        Arg<Variant>{.name = "UserConfiguration"},
        Arg<bool>{.name = "ModifyDescription"},
        Arg<String>{.name = "Description"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, UserManagementTypeTraits::modify_user_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult UserManagement::try_set_modify_user_handler_sync(ModifyUserAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_modify_user_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::set_modify_user_handler_sync(ModifyUserAsyncHandler handler) const
{
  try_set_modify_user_handler_sync(std::move(handler)).value();
}

void UserManagement::set_remove_user_handler_async(
  RemoveUserHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "UserManagement",
        "UserManagement::set_remove_user_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const String& in0) -> MethodResult<>
      {
        RemoveUserInputArguments typedIn{.userName = in0};
        return handler(call, typedIn);
      },
      Inputs<String>{{Arg<String>{.name = "UserName"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, UserManagementTypeTraits::remove_user_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult UserManagement::try_set_remove_user_handler_sync(RemoveUserHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_user_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::set_remove_user_handler_sync(RemoveUserHandler handler) const
{
  try_set_remove_user_handler_sync(std::move(handler)).value();
}

void UserManagement::set_remove_user_handler_async(
  RemoveUserAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "UserManagement",
        "UserManagement::set_remove_user_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const String& in0, MethodResultCallback<> complete)
      {
        RemoveUserInputArguments typedIn{.userName = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String>{{Arg<String>{.name = "UserName"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, UserManagementTypeTraits::remove_user_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult UserManagement::try_set_remove_user_handler_sync(RemoveUserAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_user_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::set_remove_user_handler_sync(RemoveUserAsyncHandler handler) const
{
  try_set_remove_user_handler_sync(std::move(handler)).value();
}

void UserManagement::set_change_password_handler_async(
  ChangePasswordHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "UserManagement",
        "UserManagement::set_change_password_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String>, std::tuple<>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const String& in1) -> MethodResult<>
      {
        ChangePasswordInputArguments typedIn{.oldPassword = in0, .newPassword = in1};
        return handler(call, typedIn);
      },
      Inputs<String, String>{{Arg<String>{.name = "OldPassword"}, Arg<String>{.name = "NewPassword"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      UserManagementTypeTraits::change_password_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult UserManagement::try_set_change_password_handler_sync(ChangePasswordHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_change_password_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::set_change_password_handler_sync(ChangePasswordHandler handler) const
{
  try_set_change_password_handler_sync(std::move(handler)).value();
}

void UserManagement::set_change_password_handler_async(
  ChangePasswordAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "UserManagement",
        "UserManagement::set_change_password_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const String& in0, const String& in1, MethodResultCallback<> complete)
      {
        ChangePasswordInputArguments typedIn{.oldPassword = in0, .newPassword = in1};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String, String>{{Arg<String>{.name = "OldPassword"}, Arg<String>{.name = "NewPassword"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      UserManagementTypeTraits::change_password_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult UserManagement::try_set_change_password_handler_sync(
  ChangePasswordAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_change_password_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void UserManagement::set_change_password_handler_sync(ChangePasswordAsyncHandler handler) const
{
  try_set_change_password_handler_sync(std::move(handler)).value();
}

}  // namespace ua
