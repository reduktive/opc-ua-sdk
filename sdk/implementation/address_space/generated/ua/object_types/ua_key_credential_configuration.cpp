// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_key_credential_configuration.h"

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

struct KeyCredentialConfigurationTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::KeyCredentialConfigurationType};
  }

  static QualifiedName resource_uri_browse_name()
  {
    return QualifiedName{0, "ResourceUri"};
  }

  static QualifiedName profile_uri_browse_name()
  {
    return QualifiedName{0, "ProfileUri"};
  }

  static QualifiedName endpoint_urls_browse_name()
  {
    return QualifiedName{0, "EndpointUrls"};
  }

  static QualifiedName credential_id_browse_name()
  {
    return QualifiedName{0, "CredentialId"};
  }

  static QualifiedName service_status_browse_name()
  {
    return QualifiedName{0, "ServiceStatus"};
  }

  static QualifiedName get_encrypting_key_browse_name()
  {
    return QualifiedName{0, "GetEncryptingKey"};
  }

  static QualifiedName update_credential_browse_name()
  {
    return QualifiedName{0, "UpdateCredential"};
  }

  static QualifiedName delete_credential_browse_name()
  {
    return QualifiedName{0, "DeleteCredential"};
  }
};

}  // namespace

KeyCredentialConfiguration::KeyCredentialConfiguration(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void KeyCredentialConfiguration::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    KeyCredentialConfigurationTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(KeyCredentialConfigurationResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(KeyCredentialConfigurationResult{
        KeyCredentialConfiguration{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

KeyCredentialConfigurationResult KeyCredentialConfiguration::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<KeyCredentialConfigurationResult>(addressSpace.executor(),
      [&](std::function<void(KeyCredentialConfigurationResult)> complete)
      {
        KeyCredentialConfiguration::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

KeyCredentialConfiguration KeyCredentialConfiguration::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void KeyCredentialConfiguration::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void KeyCredentialConfiguration::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // KeyCredentialConfigurationType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    KeyCredentialConfigurationTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(KeyCredentialConfigurationResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(
          KeyCredentialConfigurationResult{::ua::detail::address_space_gone("KeyCredentialConfiguration")});
        return;
      }
      complete(KeyCredentialConfiguration{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

KeyCredentialConfigurationResult KeyCredentialConfiguration::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<KeyCredentialConfigurationResult>(addressSpace.executor(),
      [&](std::function<void(KeyCredentialConfigurationResult)> complete)
      {
        KeyCredentialConfiguration::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

KeyCredentialConfiguration KeyCredentialConfiguration::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void KeyCredentialConfiguration::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void KeyCredentialConfiguration::get_encrypting_key_method_async(
  MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    KeyCredentialConfigurationTypeTraits::get_encrypting_key_browse_name(),
    std::move(complete));
}

MethodAccessorResult KeyCredentialConfiguration::try_get_encrypting_key_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { get_encrypting_key_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor KeyCredentialConfiguration::get_encrypting_key_method_sync() const
{
  return ::ua::detail::good_value(try_get_encrypting_key_method_sync());
}

void KeyCredentialConfiguration::update_credential_method_async(
  MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    KeyCredentialConfigurationTypeTraits::update_credential_browse_name(),
    std::move(complete));
}

MethodAccessorResult KeyCredentialConfiguration::try_update_credential_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { update_credential_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor KeyCredentialConfiguration::update_credential_method_sync() const
{
  return ::ua::detail::good_value(try_update_credential_method_sync());
}

void KeyCredentialConfiguration::delete_credential_method_async(
  MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    KeyCredentialConfigurationTypeTraits::delete_credential_browse_name(),
    std::move(complete));
}

MethodAccessorResult KeyCredentialConfiguration::try_delete_credential_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { delete_credential_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor KeyCredentialConfiguration::delete_credential_method_sync() const
{
  return ::ua::detail::good_value(try_delete_credential_method_sync());
}

// --- Common property helper ---

void KeyCredentialConfiguration::find_property_async(
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
    "KeyCredentialConfiguration",
    std::move(complete));
}

// --- Property accessors ---

void KeyCredentialConfiguration::resource_uri_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialConfigurationTypeTraits::resource_uri_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialConfiguration::try_resource_uri_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { resource_uri_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property KeyCredentialConfiguration::resource_uri_property_sync() const
{
  return ::ua::detail::good_value(try_resource_uri_property_sync());
}

void KeyCredentialConfiguration::profile_uri_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialConfigurationTypeTraits::profile_uri_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialConfiguration::try_profile_uri_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { profile_uri_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property KeyCredentialConfiguration::profile_uri_property_sync() const
{
  return ::ua::detail::good_value(try_profile_uri_property_sync());
}

void KeyCredentialConfiguration::endpoint_urls_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialConfigurationTypeTraits::endpoint_urls_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialConfiguration::try_endpoint_urls_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { endpoint_urls_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property KeyCredentialConfiguration::endpoint_urls_property_sync() const
{
  return ::ua::detail::good_value(try_endpoint_urls_property_sync());
}

void KeyCredentialConfiguration::credential_id_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(KeyCredentialConfigurationTypeTraits::credential_id_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialConfiguration::try_credential_id_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { credential_id_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property KeyCredentialConfiguration::credential_id_property_sync() const
{
  return ::ua::detail::good_value(try_credential_id_property_sync());
}

void KeyCredentialConfiguration::service_status_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    KeyCredentialConfigurationTypeTraits::service_status_browse_name(), std::move(complete));
}

PropertyResult KeyCredentialConfiguration::try_service_status_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { service_status_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property KeyCredentialConfiguration::service_status_property_sync() const
{
  return ::ua::detail::good_value(try_service_status_property_sync());
}

// --- Typed value read shortcuts ---

void KeyCredentialConfiguration::read_resource_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::resource_uri_browse_name(),
    &Variant::is_string,
    {"KeyCredentialConfiguration", "resource_uri", "KeyCredentialConfiguration::read_resource_uri_async"},
    std::move(complete));
}

StringResult KeyCredentialConfiguration::try_read_resource_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_resource_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String KeyCredentialConfiguration::read_resource_uri_sync() const
{
  return ::ua::detail::good_value(try_read_resource_uri_sync());
}

void KeyCredentialConfiguration::read_profile_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::profile_uri_browse_name(),
    &Variant::is_string,
    {"KeyCredentialConfiguration", "profile_uri", "KeyCredentialConfiguration::read_profile_uri_async"},
    std::move(complete));
}

StringResult KeyCredentialConfiguration::try_read_profile_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_profile_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String KeyCredentialConfiguration::read_profile_uri_sync() const
{
  return ::ua::detail::good_value(try_read_profile_uri_sync());
}

void KeyCredentialConfiguration::read_endpoint_urls_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::endpoint_urls_browse_name(),
    &Variant::is_string,
    {"KeyCredentialConfiguration", "endpoint_urls", "KeyCredentialConfiguration::read_endpoint_urls_async"},
    std::move(complete));
}

StringResult KeyCredentialConfiguration::try_read_endpoint_urls_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_endpoint_urls_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String KeyCredentialConfiguration::read_endpoint_urls_sync() const
{
  return ::ua::detail::good_value(try_read_endpoint_urls_sync());
}

void KeyCredentialConfiguration::read_credential_id_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::credential_id_browse_name(),
    &Variant::is_string,
    {"KeyCredentialConfiguration", "credential_id", "KeyCredentialConfiguration::read_credential_id_async"},
    std::move(complete));
}

StringResult KeyCredentialConfiguration::try_read_credential_id_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_credential_id_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String KeyCredentialConfiguration::read_credential_id_sync() const
{
  return ::ua::detail::good_value(try_read_credential_id_sync());
}

void KeyCredentialConfiguration::read_service_status_async(
  std::function<void(Result<StatusCode>)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(Result<StatusCode>{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<StatusCode>(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::service_status_browse_name(),
    &Variant::is_status_code,
    {"KeyCredentialConfiguration", "service_status", "KeyCredentialConfiguration::read_service_status_async"},
    std::move(complete));
}

Result<StatusCode> KeyCredentialConfiguration::try_read_service_status_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<Result<StatusCode>>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(Result<StatusCode>)> complete)
      { read_service_status_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

StatusCode KeyCredentialConfiguration::read_service_status_sync() const
{
  return ::ua::detail::good_value(try_read_service_status_sync());
}

// --- Typed value write shortcuts ---

void KeyCredentialConfiguration::write_resource_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::resource_uri_browse_name(),
    "KeyCredentialConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialConfiguration::try_write_resource_uri_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_resource_uri_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::write_resource_uri_sync(String value) const
{
  try_write_resource_uri_sync(value).value();
}

void KeyCredentialConfiguration::write_profile_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::profile_uri_browse_name(),
    "KeyCredentialConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialConfiguration::try_write_profile_uri_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_profile_uri_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::write_profile_uri_sync(String value) const
{
  try_write_profile_uri_sync(value).value();
}

void KeyCredentialConfiguration::write_endpoint_urls_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::endpoint_urls_browse_name(),
    "KeyCredentialConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialConfiguration::try_write_endpoint_urls_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_endpoint_urls_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::write_endpoint_urls_sync(String value) const
{
  try_write_endpoint_urls_sync(value).value();
}

void KeyCredentialConfiguration::write_credential_id_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::credential_id_browse_name(),
    "KeyCredentialConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialConfiguration::try_write_credential_id_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_credential_id_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::write_credential_id_sync(String value) const
{
  try_write_credential_id_sync(value).value();
}

void KeyCredentialConfiguration::write_service_status_async(
  StatusCode value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    KeyCredentialConfigurationTypeTraits::service_status_browse_name(),
    "KeyCredentialConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult KeyCredentialConfiguration::try_write_service_status_sync(StatusCode value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_service_status_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::write_service_status_sync(StatusCode value) const
{
  try_write_service_status_sync(value).value();
}

// --- Method handler registration ---

void KeyCredentialConfiguration::set_get_encrypting_key_handler_async(
  GetEncryptingKeyHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "KeyCredentialConfiguration",
        "KeyCredentialConfiguration::set_get_encrypting_key_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String>, std::tuple<ByteString, String>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const String& in0, const String& in1) -> MethodResult<ByteString, String>
      {
        GetEncryptingKeyInputArguments typedIn{.credentialId = in0, .requestedSecurityPolicyUri = in1};
        return detail::method_result_from_struct<ByteString, String>(handler(call, typedIn),
          [](const GetEncryptingKeyOutputArguments& out)
          { return std::tuple<ByteString, String>{out.publicKey, out.revisedSecurityPolicyUri}; });
      },
      Inputs<String, String>{
        {Arg<String>{.name = "CredentialId"}, Arg<String>{.name = "RequestedSecurityPolicyUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      KeyCredentialConfigurationTypeTraits::get_encrypting_key_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult KeyCredentialConfiguration::try_set_get_encrypting_key_handler_sync(
  GetEncryptingKeyHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_encrypting_key_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::set_get_encrypting_key_handler_sync(GetEncryptingKeyHandler handler) const
{
  try_set_get_encrypting_key_handler_sync(std::move(handler)).value();
}

void KeyCredentialConfiguration::set_get_encrypting_key_handler_async(
  GetEncryptingKeyAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "KeyCredentialConfiguration",
        "KeyCredentialConfiguration::set_get_encrypting_key_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, String>, std::tuple<ByteString, String>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const String& in0,
        const String& in1,
        MethodResultCallback<ByteString, String>
          complete)
      {
        GetEncryptingKeyInputArguments typedIn{.credentialId = in0, .requestedSecurityPolicyUri = in1};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<GetEncryptingKeyOutputArguments>(
            std::move(complete),
            [](const GetEncryptingKeyOutputArguments& out)
            { return std::tuple<ByteString, String>{out.publicKey, out.revisedSecurityPolicyUri}; },
            logger,
            call.method_id()));
      },
      Inputs<String, String>{
        {Arg<String>{.name = "CredentialId"}, Arg<String>{.name = "RequestedSecurityPolicyUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      KeyCredentialConfigurationTypeTraits::get_encrypting_key_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult KeyCredentialConfiguration::try_set_get_encrypting_key_handler_sync(
  GetEncryptingKeyAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_encrypting_key_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::set_get_encrypting_key_handler_sync(
  GetEncryptingKeyAsyncHandler handler) const
{
  try_set_get_encrypting_key_handler_sync(std::move(handler)).value();
}

void KeyCredentialConfiguration::set_update_credential_handler_async(
  UpdateCredentialHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "KeyCredentialConfiguration",
        "KeyCredentialConfiguration::set_update_credential_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, ByteString, String, String>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call,
        const String& in0,
        const ByteString& in1,
        const String& in2,
        const String& in3) -> MethodResult<>
      {
        UpdateCredentialInputArguments typedIn{.credentialId = in0,
          .credentialSecret = in1,
          .certificateThumbprint = in2,
          .securityPolicyUri = in3};
        return handler(call, typedIn);
      },
      Inputs<String, ByteString, String, String>{{Arg<String>{.name = "CredentialId"},
        Arg<ByteString>{.name = "CredentialSecret"},
        Arg<String>{.name = "CertificateThumbprint"},
        Arg<String>{.name = "SecurityPolicyUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      KeyCredentialConfigurationTypeTraits::update_credential_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult KeyCredentialConfiguration::try_set_update_credential_handler_sync(
  UpdateCredentialHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_update_credential_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::set_update_credential_handler_sync(UpdateCredentialHandler handler) const
{
  try_set_update_credential_handler_sync(std::move(handler)).value();
}

void KeyCredentialConfiguration::set_update_credential_handler_async(
  UpdateCredentialAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "KeyCredentialConfiguration",
        "KeyCredentialConfiguration::set_update_credential_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<String, ByteString, String, String>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const String& in0,
        const ByteString& in1,
        const String& in2,
        const String& in3,
        MethodResultCallback<>
          complete)
      {
        UpdateCredentialInputArguments typedIn{.credentialId = in0,
          .credentialSecret = in1,
          .certificateThumbprint = in2,
          .securityPolicyUri = in3};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<String, ByteString, String, String>{{Arg<String>{.name = "CredentialId"},
        Arg<ByteString>{.name = "CredentialSecret"},
        Arg<String>{.name = "CertificateThumbprint"},
        Arg<String>{.name = "SecurityPolicyUri"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      KeyCredentialConfigurationTypeTraits::update_credential_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult KeyCredentialConfiguration::try_set_update_credential_handler_sync(
  UpdateCredentialAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_update_credential_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::set_update_credential_handler_sync(
  UpdateCredentialAsyncHandler handler) const
{
  try_set_update_credential_handler_sync(std::move(handler)).value();
}

void KeyCredentialConfiguration::set_delete_credential_handler_async(
  DeleteCredentialHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "KeyCredentialConfiguration",
        "KeyCredentialConfiguration::set_delete_credential_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call) -> MethodResult<> { return handler(call); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      KeyCredentialConfigurationTypeTraits::delete_credential_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult KeyCredentialConfiguration::try_set_delete_credential_handler_sync(
  DeleteCredentialHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_delete_credential_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::set_delete_credential_handler_sync(DeleteCredentialHandler handler) const
{
  try_set_delete_credential_handler_sync(std::move(handler)).value();
}

void KeyCredentialConfiguration::set_delete_credential_handler_async(
  DeleteCredentialAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "KeyCredentialConfiguration",
        "KeyCredentialConfiguration::set_delete_credential_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, MethodResultCallback<> complete) { handler(call, std::move(complete)); },
      Inputs<>{},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      KeyCredentialConfigurationTypeTraits::delete_credential_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult KeyCredentialConfiguration::try_set_delete_credential_handler_sync(
  DeleteCredentialAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_delete_credential_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void KeyCredentialConfiguration::set_delete_credential_handler_sync(
  DeleteCredentialAsyncHandler handler) const
{
  try_set_delete_credential_handler_sync(std::move(handler)).value();
}

}  // namespace ua
