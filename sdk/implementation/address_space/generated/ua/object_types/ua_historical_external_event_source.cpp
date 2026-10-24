// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_historical_external_event_source.h"

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

struct HistoricalExternalEventSourceTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::HistoricalExternalEventSourceType};
  }

  static QualifiedName server_browse_name()
  {
    return QualifiedName{0, "Server"};
  }

  static QualifiedName endpoint_url_browse_name()
  {
    return QualifiedName{0, "EndpointUrl"};
  }

  static QualifiedName security_mode_browse_name()
  {
    return QualifiedName{0, "SecurityMode"};
  }

  static QualifiedName security_policy_uri_browse_name()
  {
    return QualifiedName{0, "SecurityPolicyUri"};
  }

  static QualifiedName identity_token_policy_browse_name()
  {
    return QualifiedName{0, "IdentityTokenPolicy"};
  }

  static QualifiedName transport_profile_uri_browse_name()
  {
    return QualifiedName{0, "TransportProfileUri"};
  }

  static QualifiedName historical_event_filter_browse_name()
  {
    return QualifiedName{0, "HistoricalEventFilter"};
  }
};

}  // namespace

HistoricalExternalEventSource::HistoricalExternalEventSource(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void HistoricalExternalEventSource::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    HistoricalExternalEventSourceTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(HistoricalExternalEventSourceResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(HistoricalExternalEventSourceResult{
        HistoricalExternalEventSource{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

HistoricalExternalEventSourceResult HistoricalExternalEventSource::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<HistoricalExternalEventSourceResult>(addressSpace.executor(),
      [&](std::function<void(HistoricalExternalEventSourceResult)> complete)
      {
        HistoricalExternalEventSource::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

HistoricalExternalEventSource HistoricalExternalEventSource::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void HistoricalExternalEventSource::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void HistoricalExternalEventSource::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // HistoricalExternalEventSourceType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    HistoricalExternalEventSourceTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(HistoricalExternalEventSourceResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(HistoricalExternalEventSourceResult{
          ::ua::detail::address_space_gone("HistoricalExternalEventSource")});
        return;
      }
      complete(HistoricalExternalEventSource{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

HistoricalExternalEventSourceResult HistoricalExternalEventSource::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<HistoricalExternalEventSourceResult>(addressSpace.executor(),
      [&](std::function<void(HistoricalExternalEventSourceResult)> complete)
      {
        HistoricalExternalEventSource::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

HistoricalExternalEventSource HistoricalExternalEventSource::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void HistoricalExternalEventSource::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void HistoricalExternalEventSource::find_property_async(
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
    "HistoricalExternalEventSource",
    std::move(complete));
}

// --- Property accessors ---

void HistoricalExternalEventSource::server_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(HistoricalExternalEventSourceTypeTraits::server_browse_name(), std::move(complete));
}

PropertyResult HistoricalExternalEventSource::try_server_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { server_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalExternalEventSource::server_property_sync() const
{
  return ::ua::detail::good_value(try_server_property_sync());
}

void HistoricalExternalEventSource::endpoint_url_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalExternalEventSourceTypeTraits::endpoint_url_browse_name(), std::move(complete));
}

PropertyResult HistoricalExternalEventSource::try_endpoint_url_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { endpoint_url_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalExternalEventSource::endpoint_url_property_sync() const
{
  return ::ua::detail::good_value(try_endpoint_url_property_sync());
}

void HistoricalExternalEventSource::security_mode_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalExternalEventSourceTypeTraits::security_mode_browse_name(), std::move(complete));
}

PropertyResult HistoricalExternalEventSource::try_security_mode_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { security_mode_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalExternalEventSource::security_mode_property_sync() const
{
  return ::ua::detail::good_value(try_security_mode_property_sync());
}

void HistoricalExternalEventSource::security_policy_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalExternalEventSourceTypeTraits::security_policy_uri_browse_name(), std::move(complete));
}

PropertyResult HistoricalExternalEventSource::try_security_policy_uri_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { security_policy_uri_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalExternalEventSource::security_policy_uri_property_sync() const
{
  return ::ua::detail::good_value(try_security_policy_uri_property_sync());
}

void HistoricalExternalEventSource::identity_token_policy_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalExternalEventSourceTypeTraits::identity_token_policy_browse_name(), std::move(complete));
}

PropertyResult HistoricalExternalEventSource::try_identity_token_policy_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { identity_token_policy_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalExternalEventSource::identity_token_policy_property_sync() const
{
  return ::ua::detail::good_value(try_identity_token_policy_property_sync());
}

void HistoricalExternalEventSource::transport_profile_uri_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalExternalEventSourceTypeTraits::transport_profile_uri_browse_name(), std::move(complete));
}

PropertyResult HistoricalExternalEventSource::try_transport_profile_uri_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { transport_profile_uri_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalExternalEventSource::transport_profile_uri_property_sync() const
{
  return ::ua::detail::good_value(try_transport_profile_uri_property_sync());
}

void HistoricalExternalEventSource::historical_event_filter_property_async(
  PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(
    HistoricalExternalEventSourceTypeTraits::historical_event_filter_browse_name(), std::move(complete));
}

PropertyResult HistoricalExternalEventSource::try_historical_event_filter_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { historical_event_filter_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property HistoricalExternalEventSource::historical_event_filter_property_sync() const
{
  return ::ua::detail::good_value(try_historical_event_filter_property_sync());
}

// --- Typed value read shortcuts ---

void HistoricalExternalEventSource::read_server_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    HistoricalExternalEventSourceTypeTraits::server_browse_name(),
    &Variant::is_string,
    {"HistoricalExternalEventSource", "server", "HistoricalExternalEventSource::read_server_async"},
    std::move(complete));
}

StringResult HistoricalExternalEventSource::try_read_server_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_server_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String HistoricalExternalEventSource::read_server_sync() const
{
  return ::ua::detail::good_value(try_read_server_sync());
}

void HistoricalExternalEventSource::read_endpoint_url_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    HistoricalExternalEventSourceTypeTraits::endpoint_url_browse_name(),
    &Variant::is_string,
    {"HistoricalExternalEventSource",
      "endpoint_url",
      "HistoricalExternalEventSource::read_endpoint_url_async"},
    std::move(complete));
}

StringResult HistoricalExternalEventSource::try_read_endpoint_url_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_endpoint_url_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String HistoricalExternalEventSource::read_endpoint_url_sync() const
{
  return ::ua::detail::good_value(try_read_endpoint_url_sync());
}

void HistoricalExternalEventSource::read_security_policy_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    HistoricalExternalEventSourceTypeTraits::security_policy_uri_browse_name(),
    &Variant::is_string,
    {"HistoricalExternalEventSource",
      "security_policy_uri",
      "HistoricalExternalEventSource::read_security_policy_uri_async"},
    std::move(complete));
}

StringResult HistoricalExternalEventSource::try_read_security_policy_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_security_policy_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String HistoricalExternalEventSource::read_security_policy_uri_sync() const
{
  return ::ua::detail::good_value(try_read_security_policy_uri_sync());
}

void HistoricalExternalEventSource::read_transport_profile_uri_async(
  std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    HistoricalExternalEventSourceTypeTraits::transport_profile_uri_browse_name(),
    &Variant::is_string,
    {"HistoricalExternalEventSource",
      "transport_profile_uri",
      "HistoricalExternalEventSource::read_transport_profile_uri_async"},
    std::move(complete));
}

StringResult HistoricalExternalEventSource::try_read_transport_profile_uri_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete)
      { read_transport_profile_uri_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String HistoricalExternalEventSource::read_transport_profile_uri_sync() const
{
  return ::ua::detail::good_value(try_read_transport_profile_uri_sync());
}

// --- Typed value write shortcuts ---

void HistoricalExternalEventSource::write_server_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalExternalEventSourceTypeTraits::server_browse_name(),
    "HistoricalExternalEventSource",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalExternalEventSource::try_write_server_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_server_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void HistoricalExternalEventSource::write_server_sync(String value) const
{
  try_write_server_sync(value).value();
}

void HistoricalExternalEventSource::write_endpoint_url_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalExternalEventSourceTypeTraits::endpoint_url_browse_name(),
    "HistoricalExternalEventSource",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalExternalEventSource::try_write_endpoint_url_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_endpoint_url_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void HistoricalExternalEventSource::write_endpoint_url_sync(String value) const
{
  try_write_endpoint_url_sync(value).value();
}

void HistoricalExternalEventSource::write_security_policy_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalExternalEventSourceTypeTraits::security_policy_uri_browse_name(),
    "HistoricalExternalEventSource",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalExternalEventSource::try_write_security_policy_uri_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_security_policy_uri_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void HistoricalExternalEventSource::write_security_policy_uri_sync(String value) const
{
  try_write_security_policy_uri_sync(value).value();
}

void HistoricalExternalEventSource::write_transport_profile_uri_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    HistoricalExternalEventSourceTypeTraits::transport_profile_uri_browse_name(),
    "HistoricalExternalEventSource",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult HistoricalExternalEventSource::try_write_transport_profile_uri_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_transport_profile_uri_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void HistoricalExternalEventSource::write_transport_profile_uri_sync(String value) const
{
  try_write_transport_profile_uri_sync(value).value();
}

}  // namespace ua
