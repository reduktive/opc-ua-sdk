// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_object.h"

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

struct ServerTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::ServerType};
  }

  static QualifiedName server_array_browse_name()
  {
    return QualifiedName{0, "ServerArray"};
  }

  static QualifiedName namespace_array_browse_name()
  {
    return QualifiedName{0, "NamespaceArray"};
  }

  static QualifiedName uris_version_browse_name()
  {
    return QualifiedName{0, "UrisVersion"};
  }

  static QualifiedName server_status_browse_name()
  {
    return QualifiedName{0, "ServerStatus"};
  }

  static QualifiedName service_level_browse_name()
  {
    return QualifiedName{0, "ServiceLevel"};
  }

  static QualifiedName auditing_browse_name()
  {
    return QualifiedName{0, "Auditing"};
  }

  static QualifiedName estimated_return_time_browse_name()
  {
    return QualifiedName{0, "EstimatedReturnTime"};
  }

  static QualifiedName local_time_browse_name()
  {
    return QualifiedName{0, "LocalTime"};
  }

  static QualifiedName server_capabilities_browse_name()
  {
    return QualifiedName{0, "ServerCapabilities"};
  }

  static QualifiedName server_diagnostics_browse_name()
  {
    return QualifiedName{0, "ServerDiagnostics"};
  }

  static QualifiedName vendor_server_info_browse_name()
  {
    return QualifiedName{0, "VendorServerInfo"};
  }

  static QualifiedName server_redundancy_browse_name()
  {
    return QualifiedName{0, "ServerRedundancy"};
  }

  static QualifiedName namespaces_browse_name()
  {
    return QualifiedName{0, "Namespaces"};
  }

  static QualifiedName get_monitored_items_browse_name()
  {
    return QualifiedName{0, "GetMonitoredItems"};
  }

  static QualifiedName resend_data_browse_name()
  {
    return QualifiedName{0, "ResendData"};
  }

  static QualifiedName set_subscription_durable_browse_name()
  {
    return QualifiedName{0, "SetSubscriptionDurable"};
  }

  static QualifiedName request_server_state_change_browse_name()
  {
    return QualifiedName{0, "RequestServerStateChange"};
  }
};

}  // namespace

ServerObject::ServerObject(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void ServerObject::create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    ServerTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(ServerObjectResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(ServerObjectResult{
        ServerObject{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}, code});
    });
}

ServerObjectResult ServerObject::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerObjectResult>(addressSpace.executor(),
      [&](std::function<void(ServerObjectResult)> complete)
      {
        ServerObject::create_async(std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerObject ServerObject::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void ServerObject::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void ServerObject::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // ServerObjectType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    ServerTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(ServerObjectResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(ServerObjectResult{::ua::detail::address_space_gone("ServerObject")});
        return;
      }
      complete(ServerObject{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

ServerObjectResult ServerObject::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerObjectResult>(addressSpace.executor(),
      [&](std::function<void(ServerObjectResult)> complete)
      {
        ServerObject::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerObject ServerObject::attach_sync(AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void ServerObject::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

void ServerObject::get_monitored_items_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerTypeTraits::get_monitored_items_browse_name(),
    std::move(complete));
}

MethodAccessorResult ServerObject::try_get_monitored_items_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { get_monitored_items_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ServerObject::get_monitored_items_method_sync() const
{
  return ::ua::detail::good_value(try_get_monitored_items_method_sync());
}

void ServerObject::resend_data_method_async(MethodAccessorCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(MethodAccessorResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerTypeTraits::resend_data_browse_name(),
    std::move(complete));
}

MethodAccessorResult ServerObject::try_resend_data_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { resend_data_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ServerObject::resend_data_method_sync() const
{
  return ::ua::detail::good_value(try_resend_data_method_sync());
}

void ServerObject::set_subscription_durable_method_async(
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
    ServerTypeTraits::set_subscription_durable_browse_name(),
    std::move(complete));
}

MethodAccessorResult ServerObject::try_set_subscription_durable_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { set_subscription_durable_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ServerObject::set_subscription_durable_method_sync() const
{
  return ::ua::detail::good_value(try_set_subscription_durable_method_sync());
}

void ServerObject::request_server_state_change_method_async(
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
    ServerTypeTraits::request_server_state_change_browse_name(),
    std::move(complete));
}

MethodAccessorResult ServerObject::try_request_server_state_change_method_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<MethodAccessorResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(MethodAccessorResult)> complete)
      { request_server_state_change_method_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

MethodAccessor ServerObject::request_server_state_change_method_sync() const
{
  return ::ua::detail::good_value(try_request_server_state_change_method_sync());
}

// --- Common property helper ---

void ServerObject::find_property_async(
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
    "ServerObject",
    std::move(complete));
}

// --- Property accessors ---

void ServerObject::server_array_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerTypeTraits::server_array_browse_name(), std::move(complete));
}

PropertyResult ServerObject::try_server_array_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { server_array_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerObject::server_array_property_sync() const
{
  return ::ua::detail::good_value(try_server_array_property_sync());
}

void ServerObject::namespace_array_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerTypeTraits::namespace_array_browse_name(), std::move(complete));
}

PropertyResult ServerObject::try_namespace_array_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { namespace_array_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerObject::namespace_array_property_sync() const
{
  return ::ua::detail::good_value(try_namespace_array_property_sync());
}

void ServerObject::uris_version_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerTypeTraits::uris_version_browse_name(), std::move(complete));
}

PropertyResult ServerObject::try_uris_version_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { uris_version_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerObject::uris_version_property_sync() const
{
  return ::ua::detail::good_value(try_uris_version_property_sync());
}

void ServerObject::service_level_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerTypeTraits::service_level_browse_name(), std::move(complete));
}

PropertyResult ServerObject::try_service_level_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { service_level_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerObject::service_level_property_sync() const
{
  return ::ua::detail::good_value(try_service_level_property_sync());
}

void ServerObject::auditing_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerTypeTraits::auditing_browse_name(), std::move(complete));
}

PropertyResult ServerObject::try_auditing_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { auditing_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerObject::auditing_property_sync() const
{
  return ::ua::detail::good_value(try_auditing_property_sync());
}

void ServerObject::estimated_return_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerTypeTraits::estimated_return_time_browse_name(), std::move(complete));
}

PropertyResult ServerObject::try_estimated_return_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete)
      { estimated_return_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerObject::estimated_return_time_property_sync() const
{
  return ::ua::detail::good_value(try_estimated_return_time_property_sync());
}

void ServerObject::local_time_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(ServerTypeTraits::local_time_browse_name(), std::move(complete));
}

PropertyResult ServerObject::try_local_time_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { local_time_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property ServerObject::local_time_property_sync() const
{
  return ::ua::detail::good_value(try_local_time_property_sync());
}

// --- Typed value read shortcuts ---

void ServerObject::read_server_array_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::server_array_browse_name(),
    &Variant::is_string,
    {"ServerObject", "server_array", "ServerObject::read_server_array_async"},
    std::move(complete));
}

StringResult ServerObject::try_read_server_array_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_server_array_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String ServerObject::read_server_array_sync() const
{
  return ::ua::detail::good_value(try_read_server_array_sync());
}

void ServerObject::read_namespace_array_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::namespace_array_browse_name(),
    &Variant::is_string,
    {"ServerObject", "namespace_array", "ServerObject::read_namespace_array_async"},
    std::move(complete));
}

StringResult ServerObject::try_read_namespace_array_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_namespace_array_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String ServerObject::read_namespace_array_sync() const
{
  return ::ua::detail::good_value(try_read_namespace_array_sync());
}

void ServerObject::read_service_level_async(std::function<void(UInt8Result)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(UInt8Result{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<uint8_t>(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::service_level_browse_name(),
    &Variant::is_uint8,
    {"ServerObject", "service_level", "ServerObject::read_service_level_async"},
    std::move(complete));
}

UInt8Result ServerObject::try_read_service_level_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<UInt8Result>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(UInt8Result)> complete) { read_service_level_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

uint8_t ServerObject::read_service_level_sync() const
{
  return ::ua::detail::good_value(try_read_service_level_sync());
}

void ServerObject::read_auditing_async(std::function<void(BoolResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(BoolResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<bool>(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::auditing_browse_name(),
    &Variant::is_boolean,
    {"ServerObject", "auditing", "ServerObject::read_auditing_async"},
    std::move(complete));
}

BoolResult ServerObject::try_read_auditing_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<BoolResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(BoolResult)> complete) { read_auditing_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

bool ServerObject::read_auditing_sync() const
{
  return ::ua::detail::good_value(try_read_auditing_sync());
}

void ServerObject::read_estimated_return_time_async(
  std::function<void(DateTimeResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(DateTimeResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<DateTime>(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::estimated_return_time_browse_name(),
    &Variant::is_date_time,
    {"ServerObject", "estimated_return_time", "ServerObject::read_estimated_return_time_async"},
    std::move(complete));
}

DateTimeResult ServerObject::try_read_estimated_return_time_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<DateTimeResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(DateTimeResult)> complete)
      { read_estimated_return_time_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

DateTime ServerObject::read_estimated_return_time_sync() const
{
  return ::ua::detail::good_value(try_read_estimated_return_time_sync());
}

// --- Typed value write shortcuts ---

void ServerObject::write_server_array_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::server_array_browse_name(),
    "ServerObject",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerObject::try_write_server_array_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_server_array_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::write_server_array_sync(String value) const
{
  try_write_server_array_sync(value).value();
}

void ServerObject::write_namespace_array_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::namespace_array_browse_name(),
    "ServerObject",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerObject::try_write_namespace_array_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_namespace_array_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::write_namespace_array_sync(String value) const
{
  try_write_namespace_array_sync(value).value();
}

void ServerObject::write_service_level_async(
  uint8_t value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::service_level_browse_name(),
    "ServerObject",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerObject::try_write_service_level_sync(uint8_t value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_service_level_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::write_service_level_sync(uint8_t value) const
{
  try_write_service_level_sync(value).value();
}

void ServerObject::write_auditing_async(bool value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::auditing_browse_name(),
    "ServerObject",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerObject::try_write_auditing_sync(bool value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_auditing_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::write_auditing_sync(bool value) const
{
  try_write_auditing_sync(value).value();
}

void ServerObject::write_estimated_return_time_async(
  DateTime value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    ServerTypeTraits::estimated_return_time_browse_name(),
    "ServerObject",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult ServerObject::try_write_estimated_return_time_sync(DateTime value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { write_estimated_return_time_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::write_estimated_return_time_sync(DateTime value) const
{
  try_write_estimated_return_time_sync(value).value();
}

// --- Method handler registration ---

void ServerObject::set_get_monitored_items_handler_async(
  GetMonitoredItemsHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ServerObject",
        "ServerObject::set_get_monitored_items_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<std::vector<uint32_t>, std::vector<uint32_t>>> adapter{
      [handler = std::move(handler)](const MethodCall& call,
        const uint32_t& in0) -> MethodResult<std::vector<uint32_t>, std::vector<uint32_t>>
      {
        GetMonitoredItemsInputArguments typedIn{.subscriptionId = in0};
        return detail::method_result_from_struct<std::vector<uint32_t>, std::vector<uint32_t>>(
          handler(call, typedIn),
          [](const GetMonitoredItemsOutputArguments& out) {
            return std::tuple<std::vector<uint32_t>, std::vector<uint32_t>>{
              out.serverHandles, out.clientHandles};
          });
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "SubscriptionId"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, ServerTypeTraits::get_monitored_items_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ServerObject::try_set_get_monitored_items_handler_sync(
  GetMonitoredItemsHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_monitored_items_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::set_get_monitored_items_handler_sync(GetMonitoredItemsHandler handler) const
{
  try_set_get_monitored_items_handler_sync(std::move(handler)).value();
}

void ServerObject::set_get_monitored_items_handler_async(
  GetMonitoredItemsAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ServerObject",
        "ServerObject::set_get_monitored_items_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<std::vector<uint32_t>, std::vector<uint32_t>>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const uint32_t& in0,
        MethodResultCallback<std::vector<uint32_t>, std::vector<uint32_t>>
          complete)
      {
        GetMonitoredItemsInputArguments typedIn{.subscriptionId = in0};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<GetMonitoredItemsOutputArguments>(
            std::move(complete),
            [](const GetMonitoredItemsOutputArguments& out) {
              return std::tuple<std::vector<uint32_t>, std::vector<uint32_t>>{
                out.serverHandles, out.clientHandles};
            },
            logger,
            call.method_id()));
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "SubscriptionId"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, ServerTypeTraits::get_monitored_items_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ServerObject::try_set_get_monitored_items_handler_sync(
  GetMonitoredItemsAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_get_monitored_items_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::set_get_monitored_items_handler_sync(GetMonitoredItemsAsyncHandler handler) const
{
  try_set_get_monitored_items_handler_sync(std::move(handler)).value();
}

void ServerObject::set_resend_data_handler_async(
  ResendDataHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ServerObject",
        "ServerObject::set_resend_data_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call, const uint32_t& in0) -> MethodResult<>
      {
        ResendDataInputArguments typedIn{.subscriptionId = in0};
        return handler(call, typedIn);
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "SubscriptionId"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, ServerTypeTraits::resend_data_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ServerObject::try_set_resend_data_handler_sync(ResendDataHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_resend_data_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::set_resend_data_handler_sync(ResendDataHandler handler) const
{
  try_set_resend_data_handler_sync(std::move(handler)).value();
}

void ServerObject::set_resend_data_handler_async(
  ResendDataAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ServerObject",
        "ServerObject::set_resend_data_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](
        const MethodCall& call, const uint32_t& in0, MethodResultCallback<> complete)
      {
        ResendDataInputArguments typedIn{.subscriptionId = in0};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<uint32_t>{{Arg<uint32_t>{.name = "SubscriptionId"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(
      *mAddressSpace, mNodeId, ServerTypeTraits::resend_data_browse_name(), std::move(adapter), done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ServerObject::try_set_resend_data_handler_sync(ResendDataAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_resend_data_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::set_resend_data_handler_sync(ResendDataAsyncHandler handler) const
{
  try_set_resend_data_handler_sync(std::move(handler)).value();
}

void ServerObject::set_set_subscription_durable_handler_async(
  SetSubscriptionDurableHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ServerObject",
        "ServerObject::set_set_subscription_durable_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, uint32_t>, std::tuple<uint32_t>> adapter{
      [handler = std::move(handler)](
        const MethodCall& call, const uint32_t& in0, const uint32_t& in1) -> MethodResult<uint32_t>
      {
        SetSubscriptionDurableInputArguments typedIn{.subscriptionId = in0, .lifetimeInHours = in1};
        return detail::method_result_from_struct<uint32_t>(handler(call, typedIn),
          [](const SetSubscriptionDurableOutputArguments& out)
          { return std::tuple<uint32_t>{out.revisedLifetimeInHours}; });
      },
      Inputs<uint32_t, uint32_t>{
        {Arg<uint32_t>{.name = "SubscriptionId"}, Arg<uint32_t>{.name = "LifetimeInHours"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ServerTypeTraits::set_subscription_durable_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ServerObject::try_set_set_subscription_durable_handler_sync(
  SetSubscriptionDurableHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_set_subscription_durable_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::set_set_subscription_durable_handler_sync(SetSubscriptionDurableHandler handler) const
{
  try_set_set_subscription_durable_handler_sync(std::move(handler)).value();
}

void ServerObject::set_set_subscription_durable_handler_async(
  SetSubscriptionDurableAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ServerObject",
        "ServerObject::set_set_subscription_durable_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<uint32_t, uint32_t>, std::tuple<uint32_t>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const uint32_t& in0,
        const uint32_t& in1,
        MethodResultCallback<uint32_t>
          complete)
      {
        SetSubscriptionDurableInputArguments typedIn{.subscriptionId = in0, .lifetimeInHours = in1};
        handler(call,
          typedIn,
          detail::struct_method_result_callback<SetSubscriptionDurableOutputArguments>(
            std::move(complete),
            [](const SetSubscriptionDurableOutputArguments& out)
            { return std::tuple<uint32_t>{out.revisedLifetimeInHours}; },
            logger,
            call.method_id()));
      },
      Inputs<uint32_t, uint32_t>{
        {Arg<uint32_t>{.name = "SubscriptionId"}, Arg<uint32_t>{.name = "LifetimeInHours"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ServerTypeTraits::set_subscription_durable_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ServerObject::try_set_set_subscription_durable_handler_sync(
  SetSubscriptionDurableAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_set_subscription_durable_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::set_set_subscription_durable_handler_sync(SetSubscriptionDurableAsyncHandler handler) const
{
  try_set_set_subscription_durable_handler_sync(std::move(handler)).value();
}

void ServerObject::set_request_server_state_change_handler_async(
  RequestServerStateChangeHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ServerObject",
        "ServerObject::set_request_server_state_change_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant, DateTime, uint32_t, LocalizedText, bool>, std::tuple<>> adapter{
      [handler = std::move(handler)](const MethodCall& call,
        const Variant& in0,
        const DateTime& in1,
        const uint32_t& in2,
        const LocalizedText& in3,
        const bool& in4) -> MethodResult<>
      {
        RequestServerStateChangeInputArguments typedIn{.state = in0,
          .estimatedReturnTime = in1,
          .secondsTillShutdown = in2,
          .reason = in3,
          .restart = in4};
        return handler(call, typedIn);
      },
      Inputs<Variant, DateTime, uint32_t, LocalizedText, bool>{{Arg<Variant>{.name = "State"},
        Arg<DateTime>{.name = "EstimatedReturnTime"},
        Arg<uint32_t>{.name = "SecondsTillShutdown"},
        Arg<LocalizedText>{.name = "Reason"},
        Arg<bool>{.name = "Restart"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ServerTypeTraits::request_server_state_change_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ServerObject::try_set_request_server_state_change_handler_sync(
  RequestServerStateChangeHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_request_server_state_change_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::set_request_server_state_change_handler_sync(RequestServerStateChangeHandler handler) const
{
  try_set_request_server_state_change_handler_sync(std::move(handler)).value();
}

void ServerObject::set_request_server_state_change_handler_async(
  RequestServerStateChangeAsyncHandler handler, std::function<void(VoidResult)> done) const noexcept
{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "ServerObject",
        "ServerObject::set_request_server_state_change_handler_async",
        done))
  {
    return;
  }
  try
  {
    MethodAdapter<std::tuple<Variant, DateTime, uint32_t, LocalizedText, bool>, std::tuple<>> adapter{
      [handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call,
        const Variant& in0,
        const DateTime& in1,
        const uint32_t& in2,
        const LocalizedText& in3,
        const bool& in4,
        MethodResultCallback<>
          complete)
      {
        RequestServerStateChangeInputArguments typedIn{.state = in0,
          .estimatedReturnTime = in1,
          .secondsTillShutdown = in2,
          .reason = in3,
          .restart = in4};
        handler(call, typedIn, std::move(complete));
      },
      Inputs<Variant, DateTime, uint32_t, LocalizedText, bool>{{Arg<Variant>{.name = "State"},
        Arg<DateTime>{.name = "EstimatedReturnTime"},
        Arg<uint32_t>{.name = "SecondsTillShutdown"},
        Arg<LocalizedText>{.name = "Reason"},
        Arg<bool>{.name = "Restart"}}},
      mAddressSpace->logger()};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      ServerTypeTraits::request_server_state_change_browse_name(),
      std::move(adapter),
      done);
  }
  catch (...)
  {
    done(VoidResult{::ua::exception_to_status_code(std::current_exception())});
  }
}

VoidResult ServerObject::try_set_request_server_state_change_handler_sync(
  RequestServerStateChangeAsyncHandler handler) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete)
      { set_request_server_state_change_handler_async(std::move(handler), std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void ServerObject::set_request_server_state_change_handler_sync(
  RequestServerStateChangeAsyncHandler handler) const
{
  try_set_request_server_state_change_handler_sync(std::move(handler)).value();
}

// --- Child-object accessors ---

void ServerObject::server_status_async(std::function<void(ServerStatusResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ServerStatusResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<ServerStatus>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerTypeTraits::server_status_browse_name(),
    "ServerObject",
    std::move(complete));
}

ServerStatusResult ServerObject::try_server_status_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerStatusResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(ServerStatusResult)> complete) { server_status_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerStatus ServerObject::server_status_sync() const
{
  return ::ua::detail::good_value(try_server_status_sync());
}

void ServerObject::server_capabilities_async(
  std::function<void(ServerCapabilitiesResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ServerCapabilitiesResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<ServerCapabilities>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerTypeTraits::server_capabilities_browse_name(),
    "ServerObject",
    std::move(complete));
}

ServerCapabilitiesResult ServerObject::try_server_capabilities_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerCapabilitiesResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(ServerCapabilitiesResult)> complete)
      { server_capabilities_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerCapabilities ServerObject::server_capabilities_sync() const
{
  return ::ua::detail::good_value(try_server_capabilities_sync());
}

void ServerObject::server_diagnostics_async(
  std::function<void(ServerDiagnosticsResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ServerDiagnosticsResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<ServerDiagnostics>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerTypeTraits::server_diagnostics_browse_name(),
    "ServerObject",
    std::move(complete));
}

ServerDiagnosticsResult ServerObject::try_server_diagnostics_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerDiagnosticsResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(ServerDiagnosticsResult)> complete)
      { server_diagnostics_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerDiagnostics ServerObject::server_diagnostics_sync() const
{
  return ::ua::detail::good_value(try_server_diagnostics_sync());
}

void ServerObject::vendor_server_info_async(
  std::function<void(VendorServerInfoResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VendorServerInfoResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<VendorServerInfo>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerTypeTraits::vendor_server_info_browse_name(),
    "ServerObject",
    std::move(complete));
}

VendorServerInfoResult ServerObject::try_vendor_server_info_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VendorServerInfoResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VendorServerInfoResult)> complete)
      { vendor_server_info_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

VendorServerInfo ServerObject::vendor_server_info_sync() const
{
  return ::ua::detail::good_value(try_vendor_server_info_sync());
}

void ServerObject::server_redundancy_async(
  std::function<void(ServerRedundancyResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(ServerRedundancyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<ServerRedundancy>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerTypeTraits::server_redundancy_browse_name(),
    "ServerObject",
    std::move(complete));
}

ServerRedundancyResult ServerObject::try_server_redundancy_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ServerRedundancyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(ServerRedundancyResult)> complete)
      { server_redundancy_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

ServerRedundancy ServerObject::server_redundancy_sync() const
{
  return ::ua::detail::good_value(try_server_redundancy_sync());
}

void ServerObject::namespaces_async(std::function<void(NamespacesResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(NamespacesResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Namespaces>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    ServerTypeTraits::namespaces_browse_name(),
    "ServerObject",
    std::move(complete));
}

NamespacesResult ServerObject::try_namespaces_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<NamespacesResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(NamespacesResult)> complete) { namespaces_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Namespaces ServerObject::namespaces_sync() const
{
  return ::ua::detail::good_value(try_namespaces_sync());
}

}  // namespace ua
