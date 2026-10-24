// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_role.h"

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

struct RoleTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::RoleType};
  }

  static QualifiedName identities_browse_name()
  {
    return QualifiedName{0, "Identities"};
  }

  static QualifiedName applications_exclude_browse_name()
  {
    return QualifiedName{0, "ApplicationsExclude"};
  }

  static QualifiedName applications_browse_name()
  {
    return QualifiedName{0, "Applications"};
  }

  static QualifiedName endpoints_exclude_browse_name()
  {
    return QualifiedName{0, "EndpointsExclude"};
  }

  static QualifiedName endpoints_browse_name()
  {
    return QualifiedName{0, "Endpoints"};
  }

  static QualifiedName custom_configuration_browse_name()
  {
    return QualifiedName{0, "CustomConfiguration"};
  }

  static QualifiedName add_identity_browse_name()
  {
    return QualifiedName{0, "AddIdentity"};
  }

  static QualifiedName remove_identity_browse_name()
  {
    return QualifiedName{0, "RemoveIdentity"};
  }

  static QualifiedName add_application_browse_name()
  {
    return QualifiedName{0, "AddApplication"};
  }

  static QualifiedName remove_application_browse_name()
  {
    return QualifiedName{0, "RemoveApplication"};
  }

  static QualifiedName add_endpoint_browse_name()
  {
    return QualifiedName{0, "AddEndpoint"};
  }

  static QualifiedName remove_endpoint_browse_name()
  {
    return QualifiedName{0, "RemoveEndpoint"};
  }
};

}  // namespace

Role::Role(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void Role::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    RoleTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(RoleResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(RoleResult{
        Role{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

RoleResult Role::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<RoleResult>(addressSpace.executor(),
      [&](std::function<void(RoleResult)> complete)
      {
        Role::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Role Role::create_sync(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void Role::create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void Role::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // RoleType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    RoleTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(RoleResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(RoleResult{::ua::detail::address_space_gone("Role")});
        return;
      }
      complete(Role{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

RoleResult Role::try_attach_sync(AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<RoleResult>(addressSpace.executor(),
      [&](std::function<void(RoleResult)> complete)
      {
        Role::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Role Role::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void Role::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void Role::add_identity_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    RoleTypeTraits::add_identity_browse_name(),
    std::move(complete));
}

MethodAccessorResult Role::try_add_identity_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { add_identity_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor Role::add_identity_method_sync() const
{
  return ::ua::detail::good_value(try_add_identity_method_sync());
}

void Role::remove_identity_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    RoleTypeTraits::remove_identity_browse_name(),
    std::move(complete));
}

MethodAccessorResult Role::try_remove_identity_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { remove_identity_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor Role::remove_identity_method_sync() const
{
  return ::ua::detail::good_value(try_remove_identity_method_sync());
}

void Role::add_application_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    RoleTypeTraits::add_application_browse_name(),
    std::move(complete));
}

MethodAccessorResult Role::try_add_application_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { add_application_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor Role::add_application_method_sync() const
{
  return ::ua::detail::good_value(try_add_application_method_sync());
}

void Role::remove_application_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    RoleTypeTraits::remove_application_browse_name(),
    std::move(complete));
}

MethodAccessorResult Role::try_remove_application_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { remove_application_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor Role::remove_application_method_sync() const
{
  return ::ua::detail::good_value(try_remove_application_method_sync());
}

void Role::add_endpoint_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    RoleTypeTraits::add_endpoint_browse_name(),
    std::move(complete));
}

MethodAccessorResult Role::try_add_endpoint_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { add_endpoint_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor Role::add_endpoint_method_sync() const
{
  return ::ua::detail::good_value(try_add_endpoint_method_sync());
}

void Role::remove_endpoint_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    RoleTypeTraits::remove_endpoint_browse_name(),
    std::move(complete));
}

MethodAccessorResult Role::try_remove_endpoint_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { remove_endpoint_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor Role::remove_endpoint_method_sync() const
{
  return ::ua::detail::good_value(try_remove_endpoint_method_sync());
}

// --- Common property helper ---

void Role::find_property_async(
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
    "Role",
    std::move(complete));
}

// --- Property accessors ---

void Role::identities_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(RoleTypeTraits::identities_browse_name(), std::move(complete));
}

PropertyResult Role::try_identities_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { identities_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Role::identities_property_sync() const
{
  return ::ua::detail::good_value(try_identities_property_sync());
}

void Role::applications_exclude_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(RoleTypeTraits::applications_exclude_browse_name(), std::move(complete));
}

PropertyResult Role::try_applications_exclude_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { applications_exclude_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Role::applications_exclude_property_sync() const
{
  return ::ua::detail::good_value(try_applications_exclude_property_sync());
}

void Role::applications_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(RoleTypeTraits::applications_browse_name(), std::move(complete));
}

PropertyResult Role::try_applications_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { applications_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Role::applications_property_sync() const
{
  return ::ua::detail::good_value(try_applications_property_sync());
}

void Role::endpoints_exclude_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(RoleTypeTraits::endpoints_exclude_browse_name(), std::move(complete));
}

PropertyResult Role::try_endpoints_exclude_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { endpoints_exclude_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Role::endpoints_exclude_property_sync() const
{
  return ::ua::detail::good_value(try_endpoints_exclude_property_sync());
}

void Role::endpoints_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(RoleTypeTraits::endpoints_browse_name(), std::move(complete));
}

PropertyResult Role::try_endpoints_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { endpoints_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Role::endpoints_property_sync() const
{
  return ::ua::detail::good_value(try_endpoints_property_sync());
}

void Role::custom_configuration_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(RoleTypeTraits::custom_configuration_browse_name(), std::move(complete));
}

PropertyResult Role::try_custom_configuration_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { custom_configuration_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property Role::custom_configuration_property_sync() const
{
  return ::ua::detail::good_value(try_custom_configuration_property_sync());
}

// --- Typed value read shortcuts ---

void Role::read_applications_exclude_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    RoleTypeTraits::applications_exclude_browse_name(),
    &Variant::is_boolean,
    {"Role", "applications_exclude", "Role::read_applications_exclude_async"},
    std::move(complete));
}

BoolResult Role::try_read_applications_exclude_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete)
      { read_applications_exclude_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool Role::read_applications_exclude_sync() const
{
  return ::ua::detail::good_value(try_read_applications_exclude_sync());
}

void Role::read_applications_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    RoleTypeTraits::applications_browse_name(),
    &Variant::is_string,
    {"Role", "applications", "Role::read_applications_async"},
    std::move(complete));
}

StringResult Role::try_read_applications_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_applications_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String Role::read_applications_sync() const
{
  return ::ua::detail::good_value(try_read_applications_sync());
}

void Role::read_endpoints_exclude_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    RoleTypeTraits::endpoints_exclude_browse_name(),
    &Variant::is_boolean,
    {"Role", "endpoints_exclude", "Role::read_endpoints_exclude_async"},
    std::move(complete));
}

BoolResult Role::try_read_endpoints_exclude_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_endpoints_exclude_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool Role::read_endpoints_exclude_sync() const
{
  return ::ua::detail::good_value(try_read_endpoints_exclude_sync());
}

void Role::read_custom_configuration_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    RoleTypeTraits::custom_configuration_browse_name(),
    &Variant::is_boolean,
    {"Role", "custom_configuration", "Role::read_custom_configuration_async"},
    std::move(complete));
}

BoolResult Role::try_read_custom_configuration_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete)
      { read_custom_configuration_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool Role::read_custom_configuration_sync() const
{
  return ::ua::detail::good_value(try_read_custom_configuration_sync());
}

// --- Typed value write shortcuts ---

void Role::write_applications_exclude_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    RoleTypeTraits::applications_exclude_browse_name(),
    "Role",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult Role::try_write_applications_exclude_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_applications_exclude_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::write_applications_exclude_sync(bool value) const
{
  try_write_applications_exclude_sync(value).value();
}

void Role::write_applications_async(String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    RoleTypeTraits::applications_browse_name(),
    "Role",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult Role::try_write_applications_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_applications_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::write_applications_sync(String value) const
{
  try_write_applications_sync(value).value();
}

void Role::write_endpoints_exclude_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    RoleTypeTraits::endpoints_exclude_browse_name(),
    "Role",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult Role::try_write_endpoints_exclude_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_endpoints_exclude_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::write_endpoints_exclude_sync(bool value) const
{
  try_write_endpoints_exclude_sync(value).value();
}

void Role::write_custom_configuration_async(
  bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    RoleTypeTraits::custom_configuration_browse_name(),
    "Role",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult Role::try_write_custom_configuration_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_custom_configuration_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::write_custom_configuration_sync(bool value) const
{
  try_write_custom_configuration_sync(value).value();
}

// --- Method handler registration ---

void Role::set_add_identity_handler_async(
  AddIdentityHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_add_identity_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const Variant& in0) -> MethodResult<>
      {
        AddIdentityInputArguments typedIn{.rule = in0};
        return handler(call, typedIn);
      },
      Inputs<Variant>{{Arg<Variant>{.name = "Rule"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::add_identity_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_add_identity_handler_sync(AddIdentityHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_identity_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_add_identity_handler_sync(AddIdentityHandler handler) const
{
  try_set_add_identity_handler_sync(std::move(handler)).value();
}

void Role::set_add_identity_handler_async(
  AddIdentityAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_add_identity_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Variant& in0, MethodResultCallback<> complete)
      {
        AddIdentityInputArguments typedIn{.rule = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Variant>{{Arg<Variant>{.name = "Rule"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::add_identity_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_add_identity_handler_sync(AddIdentityAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_identity_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_add_identity_handler_sync(AddIdentityAsyncHandler handler) const
{
  try_set_add_identity_handler_sync(std::move(handler)).value();
}

void Role::set_remove_identity_handler_async(
  RemoveIdentityHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_remove_identity_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const Variant& in0) -> MethodResult<>
      {
        RemoveIdentityInputArguments typedIn{.rule = in0};
        return handler(call, typedIn);
      },
      Inputs<Variant>{{Arg<Variant>{.name = "Rule"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::remove_identity_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_remove_identity_handler_sync(RemoveIdentityHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_identity_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_remove_identity_handler_sync(RemoveIdentityHandler handler) const
{
  try_set_remove_identity_handler_sync(std::move(handler)).value();
}

void Role::set_remove_identity_handler_async(
  RemoveIdentityAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_remove_identity_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Variant& in0, MethodResultCallback<> complete)
      {
        RemoveIdentityInputArguments typedIn{.rule = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Variant>{{Arg<Variant>{.name = "Rule"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::remove_identity_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_remove_identity_handler_sync(RemoveIdentityAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_identity_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_remove_identity_handler_sync(RemoveIdentityAsyncHandler handler) const
{
  try_set_remove_identity_handler_sync(std::move(handler)).value();
}

void Role::set_add_application_handler_async(
  AddApplicationHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_add_application_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const String& in0) -> MethodResult<>
      {
        AddApplicationInputArguments typedIn{.applicationUri = in0};
        return handler(call, typedIn);
      },
      Inputs<String>{{Arg<String>{.name = "ApplicationUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::add_application_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_add_application_handler_sync(AddApplicationHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_application_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_add_application_handler_sync(AddApplicationHandler handler) const
{
  try_set_add_application_handler_sync(std::move(handler)).value();
}

void Role::set_add_application_handler_async(
  AddApplicationAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_add_application_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const String& in0, MethodResultCallback<> complete)
      {
        AddApplicationInputArguments typedIn{.applicationUri = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String>{{Arg<String>{.name = "ApplicationUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::add_application_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_add_application_handler_sync(AddApplicationAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_application_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_add_application_handler_sync(AddApplicationAsyncHandler handler) const
{
  try_set_add_application_handler_sync(std::move(handler)).value();
}

void Role::set_remove_application_handler_async(
  RemoveApplicationHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "Role",
        "Role::set_remove_application_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const String& in0) -> MethodResult<>
      {
        RemoveApplicationInputArguments typedIn{.applicationUri = in0};
        return handler(call, typedIn);
      },
      Inputs<String>{{Arg<String>{.name = "ApplicationUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::remove_application_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_remove_application_handler_sync(RemoveApplicationHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_application_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_remove_application_handler_sync(RemoveApplicationHandler handler) const
{
  try_set_remove_application_handler_sync(std::move(handler)).value();
}

void Role::set_remove_application_handler_async(
  RemoveApplicationAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "Role",
        "Role::set_remove_application_handler_async",
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
        RemoveApplicationInputArguments typedIn{.applicationUri = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String>{{Arg<String>{.name = "ApplicationUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::remove_application_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_remove_application_handler_sync(RemoveApplicationAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_application_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_remove_application_handler_sync(RemoveApplicationAsyncHandler handler) const
{
  try_set_remove_application_handler_sync(std::move(handler)).value();
}

void Role::set_add_endpoint_handler_async(
  AddEndpointHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_add_endpoint_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const Variant& in0) -> MethodResult<>
      {
        AddEndpointInputArguments typedIn{.endpoint = in0};
        return handler(call, typedIn);
      },
      Inputs<Variant>{{Arg<Variant>{.name = "Endpoint"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::add_endpoint_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_add_endpoint_handler_sync(AddEndpointHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_endpoint_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_add_endpoint_handler_sync(AddEndpointHandler handler) const
{
  try_set_add_endpoint_handler_sync(std::move(handler)).value();
}

void Role::set_add_endpoint_handler_async(
  AddEndpointAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_add_endpoint_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Variant& in0, MethodResultCallback<> complete)
      {
        AddEndpointInputArguments typedIn{.endpoint = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Variant>{{Arg<Variant>{.name = "Endpoint"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::add_endpoint_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_add_endpoint_handler_sync(AddEndpointAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_add_endpoint_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_add_endpoint_handler_sync(AddEndpointAsyncHandler handler) const
{
  try_set_add_endpoint_handler_sync(std::move(handler)).value();
}

void Role::set_remove_endpoint_handler_async(
  RemoveEndpointHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_remove_endpoint_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const Variant& in0) -> MethodResult<>
      {
        RemoveEndpointInputArguments typedIn{.endpoint = in0};
        return handler(call, typedIn);
      },
      Inputs<Variant>{{Arg<Variant>{.name = "Endpoint"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::remove_endpoint_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_remove_endpoint_handler_sync(RemoveEndpointHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_endpoint_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_remove_endpoint_handler_sync(RemoveEndpointHandler handler) const
{
  try_set_remove_endpoint_handler_sync(std::move(handler)).value();
}

void Role::set_remove_endpoint_handler_async(
  RemoveEndpointAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(
        mAddressSpace, static_cast<bool>(handler), "Role", "Role::set_remove_endpoint_handler_async", done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const Variant& in0, MethodResultCallback<> complete)
      {
        RemoveEndpointInputArguments typedIn{.endpoint = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Variant>{{Arg<Variant>{.name = "Endpoint"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, RoleTypeTraits::remove_endpoint_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult Role::try_set_remove_endpoint_handler_sync(RemoveEndpointAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_remove_endpoint_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void Role::set_remove_endpoint_handler_sync(RemoveEndpointAsyncHandler handler) const
{
  try_set_remove_endpoint_handler_sync(std::move(handler)).value();
}

}  // namespace ua
