// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_authorization_service_configuration.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

namespace ua
{
namespace
{

struct AuthorizationServiceConfigurationTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::AuthorizationServiceConfigurationType};
  }

  static QualifiedName service_uri_browse_name()
  {
    return QualifiedName{0, "ServiceUri"};
  }

  static QualifiedName service_certificate_browse_name()
  {
    return QualifiedName{0, "ServiceCertificate"};
  }

  static QualifiedName issuer_endpoint_url_browse_name()
  {
    return QualifiedName{0, "IssuerEndpointUrl"};
  }
};

}  // namespace

AuthorizationServiceConfiguration::AuthorizationServiceConfiguration(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void AuthorizationServiceConfiguration::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    AuthorizationServiceConfigurationTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(AuthorizationServiceConfigurationResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(AuthorizationServiceConfigurationResult{
        AuthorizationServiceConfiguration{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

AuthorizationServiceConfigurationResult AuthorizationServiceConfiguration::try_create_sync(
  AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AuthorizationServiceConfigurationResult>(addressSpace.executor(),
      [&](std::function<void(AuthorizationServiceConfigurationResult)> complete)
      {
        AuthorizationServiceConfiguration::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AuthorizationServiceConfiguration AuthorizationServiceConfiguration::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void AuthorizationServiceConfiguration::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void AuthorizationServiceConfiguration::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // AuthorizationServiceConfigurationType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    AuthorizationServiceConfigurationTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(AuthorizationServiceConfigurationResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(AuthorizationServiceConfigurationResult{
          ::ua::detail::address_space_gone("AuthorizationServiceConfiguration")});
        return;
      }
      complete(AuthorizationServiceConfiguration{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

AuthorizationServiceConfigurationResult AuthorizationServiceConfiguration::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<AuthorizationServiceConfigurationResult>(addressSpace.executor(),
      [&](std::function<void(AuthorizationServiceConfigurationResult)> complete)
      {
        AuthorizationServiceConfiguration::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

AuthorizationServiceConfiguration AuthorizationServiceConfiguration::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void AuthorizationServiceConfiguration::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void AuthorizationServiceConfiguration::find_property_async(
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
    "AuthorizationServiceConfiguration",
    std::move(complete));
}

// --- Property accessors ---

void AuthorizationServiceConfiguration::service_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuthorizationServiceConfigurationTypeTraits::service_uri_browse_name(), std::move(complete));
}

PropertyResult AuthorizationServiceConfiguration::try_service_uri_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { service_uri_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuthorizationServiceConfiguration::service_uri_property_sync() const
{
  return ::ua::detail::good_value(try_service_uri_property_sync());
}

void AuthorizationServiceConfiguration::service_certificate_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuthorizationServiceConfigurationTypeTraits::service_certificate_browse_name(), std::move(complete));
}

PropertyResult AuthorizationServiceConfiguration::try_service_certificate_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { service_certificate_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuthorizationServiceConfiguration::service_certificate_property_sync() const
{
  return ::ua::detail::good_value(try_service_certificate_property_sync());
}

void AuthorizationServiceConfiguration::issuer_endpoint_url_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    AuthorizationServiceConfigurationTypeTraits::issuer_endpoint_url_browse_name(), std::move(complete));
}

PropertyResult AuthorizationServiceConfiguration::try_issuer_endpoint_url_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { issuer_endpoint_url_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property AuthorizationServiceConfiguration::issuer_endpoint_url_property_sync() const
{
  return ::ua::detail::good_value(try_issuer_endpoint_url_property_sync());
}

// --- Typed value read shortcuts ---

void AuthorizationServiceConfiguration::read_service_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AuthorizationServiceConfigurationTypeTraits::service_uri_browse_name(),
    &Variant::is_string,
    {"AuthorizationServiceConfiguration",
      "service_uri",
      "AuthorizationServiceConfiguration::read_service_uri_async"},
    std::move(complete));
}

StringResult AuthorizationServiceConfiguration::try_read_service_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_service_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String AuthorizationServiceConfiguration::read_service_uri_sync() const
{
  return ::ua::detail::good_value(try_read_service_uri_sync());
}

void AuthorizationServiceConfiguration::read_service_certificate_async(
  std::function<void(ByteStringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ByteStringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<ByteString>(*mAddressSpace,
    mNodeId,
    AuthorizationServiceConfigurationTypeTraits::service_certificate_browse_name(),
    &Variant::is_byte_string,
    {"AuthorizationServiceConfiguration",
      "service_certificate",
      "AuthorizationServiceConfiguration::read_service_certificate_async"},
    std::move(complete));
}

ByteStringResult AuthorizationServiceConfiguration::try_read_service_certificate_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ByteStringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(ByteStringResult)> complete)
      { read_service_certificate_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ByteString AuthorizationServiceConfiguration::read_service_certificate_sync() const
{
  return ::ua::detail::good_value(try_read_service_certificate_sync());
}

void AuthorizationServiceConfiguration::read_issuer_endpoint_url_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    AuthorizationServiceConfigurationTypeTraits::issuer_endpoint_url_browse_name(),
    &Variant::is_string,
    {"AuthorizationServiceConfiguration",
      "issuer_endpoint_url",
      "AuthorizationServiceConfiguration::read_issuer_endpoint_url_async"},
    std::move(complete));
}

StringResult AuthorizationServiceConfiguration::try_read_issuer_endpoint_url_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_issuer_endpoint_url_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String AuthorizationServiceConfiguration::read_issuer_endpoint_url_sync() const
{
  return ::ua::detail::good_value(try_read_issuer_endpoint_url_sync());
}

// --- Typed value write shortcuts ---

void AuthorizationServiceConfiguration::write_service_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuthorizationServiceConfigurationTypeTraits::service_uri_browse_name(),
    "AuthorizationServiceConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuthorizationServiceConfiguration::try_write_service_uri_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_service_uri_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuthorizationServiceConfiguration::write_service_uri_sync(String value) const
{
  try_write_service_uri_sync(value).value();
}

void AuthorizationServiceConfiguration::write_service_certificate_async(
  ByteString value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuthorizationServiceConfigurationTypeTraits::service_certificate_browse_name(),
    "AuthorizationServiceConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuthorizationServiceConfiguration::try_write_service_certificate_sync(
  ByteString value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_service_certificate_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuthorizationServiceConfiguration::write_service_certificate_sync(ByteString value) const
{
  try_write_service_certificate_sync(value).value();
}

void AuthorizationServiceConfiguration::write_issuer_endpoint_url_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    AuthorizationServiceConfigurationTypeTraits::issuer_endpoint_url_browse_name(),
    "AuthorizationServiceConfiguration",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult AuthorizationServiceConfiguration::try_write_issuer_endpoint_url_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_issuer_endpoint_url_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void AuthorizationServiceConfiguration::write_issuer_endpoint_url_sync(String value) const
{
  try_write_issuer_endpoint_url_sync(value).value();
}

}  // namespace ua
